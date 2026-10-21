//! Real grammar-backed syntax index for Rust, Python, JS, TS and TSX.
use crate::{Error, Repository, RepositorySnapshot, Result, check_cancel, discovery::language};
use serde::Serialize;
use std::{
    ops::ControlFlow,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Serialize)]
pub struct SyntaxSymbol {
    pub path: String,
    pub file_digest: String,
    pub language: String,
    pub name: String,
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub utf16_column: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct PolyglotIndex {
    pub snapshot_digest: String,
    pub symbols: Vec<SyntaxSymbol>,
    pub syntax_errors: Vec<String>,
    pub unsupported_files: Vec<String>,
    pub resolution: String,
    pub grammar_versions: Vec<String>,
}
impl PolyglotIndex {
    pub fn build(
        repo: &Repository,
        snapshot: &RepositorySnapshot,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        repo.validate_snapshot(snapshot, cancel)?;
        let mut out = Self {
            snapshot_digest: snapshot.digest.clone(),
            symbols: vec![],
            syntax_errors: vec![],
            unsupported_files: vec![],
            resolution: "syntactic; use LSP for semantic references".into(),
            grammar_versions: vec![
                "rust=0.24.2".into(),
                "python=0.25.0".into(),
                "javascript=0.25.0".into(),
                "typescript/tsx=0.23.2".into(),
            ],
        };
        let mut nodes = 0;
        for file in &snapshot.files {
            check_cancel(cancel)?;
            let Some(lang) = language(&file.path) else {
                out.unsupported_files.push(file.path.clone());
                continue;
            };
            let (version, bytes) = repo.read(&file.path)?;
            if version != *file {
                return Err(Error::Stale("polyglot source"));
            }
            std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("source UTF-8"))?;
            let grammar = match lang {
                "rust" => tree_sitter_rust::LANGUAGE,
                "python" => tree_sitter_python::LANGUAGE,
                "javascript" => tree_sitter_javascript::LANGUAGE,
                "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
                "tsx" => tree_sitter_typescript::LANGUAGE_TSX,
                _ => unreachable!(),
            };
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&grammar.into())
                .map_err(|_| Error::Unsupported("grammar ABI"))?;
            let start = Instant::now();
            let mut progress = |_: &tree_sitter::ParseState| {
                if cancel.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(60) {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            let mut input = |offset: usize, _| bytes.get(offset..).unwrap_or_default();
            let tree = parser
                .parse_with_options(
                    &mut input,
                    None,
                    Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
                )
                .ok_or(Error::Quota("syntax deadline"))?;
            if tree.root_node().has_error() {
                out.syntax_errors.push(file.path.clone());
            }
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                check_cancel(cancel)?;
                nodes += 1;
                if nodes > 1_000_000 {
                    return Err(Error::Quota("syntax nodes"));
                }
                let k = node.kind();
                let declaration = matches!(
                    k,
                    "function_item"
                        | "struct_item"
                        | "enum_item"
                        | "trait_item"
                        | "mod_item"
                        | "function_definition"
                        | "class_definition"
                        | "function_declaration"
                        | "class_declaration"
                        | "interface_declaration"
                        | "type_alias_declaration"
                        | "method_definition"
                        | "variable_declarator"
                );
                if declaration && let Some(name) = node.child_by_field_name("name") {
                    let text = name
                        .utf8_text(&bytes)
                        .map_err(|_| Error::Invalid("symbol UTF-8"))?;
                    let pos = name.start_position();
                    let line_start = name.start_byte().saturating_sub(pos.column);
                    let col = std::str::from_utf8(&bytes[line_start..name.start_byte()])
                        .map_err(|_| Error::Invalid("symbol column"))?
                        .encode_utf16()
                        .count();
                    out.symbols.push(SyntaxSymbol {
                        path: file.path.clone(),
                        file_digest: file.digest.clone(),
                        language: lang.into(),
                        name: text.into(),
                        kind: k.into(),
                        start_byte: name.start_byte(),
                        end_byte: name.end_byte(),
                        line: pos.row,
                        utf16_column: col,
                    });
                }
                for i in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(i as u32) {
                        stack.push(child);
                    }
                }
            }
        }
        repo.validate_snapshot(snapshot, cancel)?;
        Ok(out)
    }
}
