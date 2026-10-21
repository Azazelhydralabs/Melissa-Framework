//! Versioned authenticated encryption for trusted-host persistence.
//!
//! The caller provides a key; this module neither provisions nor persists it.
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use std::fmt;
use zeroize::Zeroizing;

use crate::{StoreError, StoreResult};

const HEADER: &[u8; 8] = b"MLSENC\x01\x01";
const NONCE_BYTES: usize = 24;
/// Header + random nonce + Poly1305 tag, independent of plaintext length.
pub const ENVELOPE_OVERHEAD: u64 = 48;

pub fn stored_len_for_plain(plain_bytes: u64) -> StoreResult<u64> {
    plain_bytes
        .checked_add(ENVELOPE_OVERHEAD)
        .ok_or_else(|| StoreError::Invalid("encrypted length overflow".into()))
}

#[derive(Clone)]
pub struct StoreKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for StoreKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreKey([REDACTED])")
    }
}

impl StoreKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn generate() -> StoreResult<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| StoreError::Crypto)?;
        Ok(Self(bytes))
    }

    /// Each call uses a fresh OS-random 192-bit nonce. Domain-separated AAD is
    /// required from the owner of the stored record.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> StoreResult<Vec<u8>> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Crypto)?;
        let associated = authenticated_header(aad)?;
        let cipher = XChaCha20Poly1305::new((&*self.0).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &associated,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        let size = usize::try_from(stored_len_for_plain(plaintext.len() as u64)?)
            .map_err(|_| StoreError::Invalid("encrypted length exceeds address space".into()))?;
        let mut envelope = Vec::new();
        envelope
            .try_reserve_exact(size)
            .map_err(|_| StoreError::Invalid("encrypted allocation exceeds capacity".into()))?;
        envelope.extend_from_slice(HEADER);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn open(&self, envelope: &[u8], aad: &[u8]) -> StoreResult<Vec<u8>> {
        if envelope.len() < ENVELOPE_OVERHEAD as usize {
            return Err(StoreError::Crypto);
        }
        if &envelope[..HEADER.len()] != HEADER {
            return Err(StoreError::Unsupported("encrypted envelope header".into()));
        }
        let associated = authenticated_header(aad)?;
        let nonce: &[u8; NONCE_BYTES] = envelope[HEADER.len()..HEADER.len() + NONCE_BYTES]
            .try_into()
            .map_err(|_| StoreError::Crypto)?;
        XChaCha20Poly1305::new((&*self.0).into())
            .decrypt(
                nonce.into(),
                Payload {
                    msg: &envelope[HEADER.len() + NONCE_BYTES..],
                    aad: &associated,
                },
            )
            .map_err(|_| StoreError::Crypto)
    }
}

fn authenticated_header(aad: &[u8]) -> StoreResult<Vec<u8>> {
    let size = HEADER
        .len()
        .checked_add(aad.len())
        .ok_or_else(|| StoreError::Invalid("AAD length overflow".into()))?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| StoreError::Invalid("AAD allocation exceeds capacity".into()))?;
    value.extend_from_slice(HEADER);
    value.extend_from_slice(aad);
    Ok(value)
}
