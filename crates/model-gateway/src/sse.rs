use crate::{DecoderLimits, GatewayError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Bounded, byte-oriented SSE framing. UTF-8 and CRLF can split across any
/// packet. CR, LF and CRLF delimit lines. This parser deliberately rejects an
/// ambiguous duplicate event field and never reconnects using an event ID.
/// An incomplete final event is not repaired or emitted at EOF.
pub struct SseParser {
    limits: DecoderLimits,
    line: Vec<u8>,
    data: String,
    data_seen: bool,
    event: Option<String>,
    event_seen: bool,
    frame_bytes: usize,
    total: usize,
    first_line: bool,
    skip_lf: bool,
    poisoned: bool,
}

impl SseParser {
    pub fn new(limits: DecoderLimits) -> Self {
        Self {
            limits,
            line: Vec::new(),
            data: String::new(),
            data_seen: false,
            event: None,
            event_seen: false,
            frame_bytes: 0,
            total: 0,
            first_line: true,
            skip_lf: false,
            poisoned: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>> {
        if self.poisoned {
            return Err(GatewayError::protocol("SSE parser is already invalid"));
        }
        let result = self.feed_inner(bytes);
        if result.is_err() {
            self.poisoned = true;
            self.line.clear();
            self.data.clear();
            self.event = None;
        }
        result
    }

    fn feed_inner(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>> {
        self.total = self
            .total
            .checked_add(bytes.len())
            .ok_or_else(|| GatewayError::protocol("SSE byte overflow"))?;
        if self.total > self.limits.max_total_bytes {
            return Err(GatewayError::protocol("SSE response byte bound"));
        }
        let mut out = Vec::new();
        for &byte in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            self.frame_bytes = self
                .frame_bytes
                .checked_add(1)
                .ok_or_else(|| GatewayError::protocol("SSE event overflow"))?;
            if self.frame_bytes > self.limits.max_event_bytes {
                return Err(GatewayError::protocol("SSE event byte bound"));
            }
            match byte {
                b'\r' | b'\n' => {
                    self.consume_line(&mut out)?;
                    self.skip_lf = byte == b'\r';
                }
                _ => {
                    if self.line.len() >= self.limits.max_event_bytes {
                        return Err(GatewayError::protocol("SSE line byte bound"));
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(out)
    }

    fn consume_line(&mut self, out: &mut Vec<SseEvent>) -> Result<()> {
        let raw = std::mem::take(&mut self.line);
        let mut line =
            std::str::from_utf8(&raw).map_err(|_| GatewayError::protocol("invalid SSE UTF-8"))?;
        if self.first_line {
            self.first_line = false;
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }
        if line.is_empty() {
            if self.data_seen {
                out.push(SseEvent {
                    event: self.event.take(),
                    data: std::mem::take(&mut self.data),
                });
            }
            self.data.clear();
            self.data_seen = false;
            self.event = None;
            self.event_seen = false;
            self.frame_bytes = 0;
        } else if !line.starts_with(':') {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match name {
                "data" => {
                    if self.data_seen {
                        self.data.push('\n');
                    }
                    self.data.push_str(value);
                    self.data_seen = true;
                }
                "event" => {
                    if self.event_seen {
                        return Err(GatewayError::protocol("duplicate SSE event field"));
                    }
                    self.event_seen = true;
                    self.event = if value.is_empty() {
                        None
                    } else {
                        Some(value.into())
                    };
                }
                // Resume IDs, retry hints and unrelated fields cannot create
                // a reconnect or an executable provider event.
                _ => {}
            }
        }
        // Keep one reusable line allocation; processing is linear and does not
        // repeatedly drain and shift the remaining network packet.
        self.line = raw;
        self.line.clear();
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        if self.poisoned {
            return Err(GatewayError::protocol("invalid SSE stream"));
        }
        if !self.line.is_empty() || self.data_seen || self.event_seen {
            Err(GatewayError::protocol("truncated SSE frame"))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_packet_splits_preserve_unicode_multiline_and_all_line_endings() {
        for ending in ["\r\n", "\n", "\r"] {
            let wire = format!(
                "\u{feff}: heartbeat{ending}event: message{ending}data: {{\"text\":\"ş😀\",{ending}data: \"value\":1}}{ending}{ending}"
            );
            for chunk in 1..wire.len() {
                let mut parser = SseParser::new(DecoderLimits::default());
                let mut events = Vec::new();
                for bytes in wire.as_bytes().chunks(chunk) {
                    events.extend(parser.feed(bytes).unwrap());
                }
                parser.finish().unwrap();
                assert_eq!(events.len(), 1);
                assert_eq!(crate::strict_json(&events[0].data).unwrap()["text"], "ş😀");
                assert_eq!(events[0].event.as_deref(), Some("message"));
            }
        }
    }

    #[test]
    fn incomplete_frames_and_invalid_utf8_never_become_complete_events() {
        for wire in [b"data: {}".as_slice(), b"data: {}\n", b"event: message\n"] {
            let mut parser = SseParser::new(DecoderLimits::default());
            assert!(parser.feed(wire).unwrap().is_empty());
            assert!(parser.finish().is_err());
        }
        let mut parser = SseParser::new(DecoderLimits::default());
        assert!(parser.feed(b"data: \xff\n\n").is_err());
    }

    #[test]
    fn event_line_comment_and_total_bounds_are_enforced() {
        for wire in [
            b"data: 123456789\n\n".as_slice(),
            b":aaa\n:aaa\n:aaa\n",
            b"unknown: many bytes\n",
        ] {
            let mut parser = SseParser::new(DecoderLimits {
                max_event_bytes: 8,
                ..DecoderLimits::default()
            });
            assert!(parser.feed(wire).is_err());
        }
        let mut parser = SseParser::new(DecoderLimits {
            max_total_bytes: 16,
            ..DecoderLimits::default()
        });
        for _ in 0..4 {
            assert!(parser.feed(b":h\n\n").unwrap().is_empty());
        }
        assert!(parser.feed(b":h\n\n").is_err());
    }

    #[test]
    fn any_framing_error_permanently_poison_the_parser() {
        for wire in [
            b"data: \xff\n\n".as_slice(),
            b"event: a\nevent: b\ndata: {}\n\n",
        ] {
            let mut parser = SseParser::new(DecoderLimits::default());
            assert!(parser.feed(wire).is_err());
            assert!(parser.feed(b"data: {}\n\n").is_err());
            assert!(parser.finish().is_err());
        }
    }

    #[test]
    fn empty_data_multiple_events_comments_and_unrelated_fields_follow_sse_framing() {
        let mut parser = SseParser::new(DecoderLimits::default());
        let events = parser.feed(b": comment\r\nid: unused\r\nretry: 1\r\nignored: x\r\ndata:\r\n\r\nevent:\ndata: one\ndata:  two\n\n").unwrap();
        parser.finish().unwrap();
        assert_eq!(
            events,
            vec![
                SseEvent {
                    event: None,
                    data: "".into()
                },
                SseEvent {
                    event: None,
                    data: "one\n two".into()
                }
            ]
        );
    }

    #[test]
    fn crlf_split_between_packets_does_not_create_a_second_blank_line() {
        let mut parser = SseParser::new(DecoderLimits::default());
        assert!(parser.feed(b"data: one\r").unwrap().is_empty());
        assert!(parser.feed(b"\ndata: two\r").unwrap().is_empty());
        let events = parser.feed(b"\n\r").unwrap();
        assert_eq!(events[0].data, "one\ntwo");
        assert!(parser.feed(b"\n").unwrap().is_empty());
        parser.finish().unwrap();
    }
}
