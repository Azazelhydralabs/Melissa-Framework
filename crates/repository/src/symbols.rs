//! Real Tree-sitter Rust syntax index. Syntactic occurrences are not LSP name
//! resolution; comments and string literals never become identifier references.
use crate::{Error, Repository, RepositorySnapshot, Result, check_cancel};
use serde::Serialize;
use std::{
    ops::ControlFlow,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tree_sitter::{Node, ParseOptions, Parser};

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub path: String,
    pub file_digest: String,
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub byte_column: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct Occurrence {
    pub path: String,
    pub file_digest: String,
    pub name: String,
    pub start_byte: usize,
    pub line: usize,
    pub byte_column: usize,
    pub resolution: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct SyntaxIndex {
    pub snapshot_digest: String,
    pub parser_version: String,
    pub grammar_version: String,
    pub symbols: Vec<Symbol>,
    pub occurrences: Vec<Occurrence>,
    pub files_with_syntax_errors: Vec<String>,
    pub skipped_non_rust_files: Vec<String>,
}
impl SyntaxIndex {
    pub fn build(
        repo: &Repository,
        snapshot: &RepositorySnapshot,
        cancel: &AtomicBool,
        per_file_budget: Duration,
    ) -> Result<Self> {
        if per_file_budget.is_zero() || per_file_budget > Duration::from_secs(60) {
            return Err(Error::Invalid("AST parse time envelope"));
        }
        repo.validate_snapshot(snapshot, cancel)?;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|_| Error::Unsupported("Rust grammar ABI"))?;
        let mut result = Self {
            snapshot_digest: snapshot.digest.clone(),
            parser_version: "tree-sitter/0.27.1".into(),
            grammar_version: "tree-sitter-rust/0.24.2".into(),
            symbols: vec![],
            occurrences: vec![],
            files_with_syntax_errors: vec![],
            skipped_non_rust_files: vec![],
        };
        let mut nodes = 0usize;
        for f in &snapshot.files {
            check_cancel(cancel)?;
            if !f.path.ends_with(".rs") {
                result.skipped_non_rust_files.push(f.path.clone());
                continue;
            }
            let (current, bytes) = repo.read(&f.path)?;
            if current != *f {
                return Err(Error::Stale("AST source changed"));
            }
            std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("Rust source must be UTF-8"))?;
            let start = Instant::now();
            let mut progress = |_: &tree_sitter::ParseState| {
                if cancel.load(Ordering::SeqCst) || start.elapsed() > per_file_budget {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            let mut read = |offset: usize, _| bytes.get(offset..).unwrap_or_default();
            let tree = parser.parse_with_options(
                &mut read,
                None,
                Some(ParseOptions::new().progress_callback(&mut progress)),
            );
            let Some(tree) = tree else {
                check_cancel(cancel)?;
                return Err(Error::Quota("AST parse deadline"));
            };
            if tree.root_node().has_error() {
                result.files_with_syntax_errors.push(f.path.clone());
            }
            let mut stack = vec![(tree.root_node(), String::new())];
            while let Some((node, scope)) = stack.pop() {
                check_cancel(cancel)?;
                nodes += 1;
                if nodes > 1_000_000 {
                    return Err(Error::Quota("AST node count"));
                }
                if start.elapsed() > per_file_budget {
                    return Err(Error::Quota("AST traversal deadline"));
                }
                let kind = node.kind();
                let declaration = matches!(
                    kind,
                    "function_item"
                        | "struct_item"
                        | "enum_item"
                        | "trait_item"
                        | "mod_item"
                        | "type_item"
                        | "const_item"
                        | "static_item"
                        | "macro_definition"
                );
                let name_node = if declaration {
                    node.child_by_field_name("name")
                } else {
                    None
                };
                if let Some(name) = name_node {
                    let name = text(name, &bytes)?;
                    let point = node.start_position();
                    result.symbols.push(Symbol {
                        path: f.path.clone(),
                        file_digest: f.digest.clone(),
                        name: name.into(),
                        kind: kind.into(),
                        scope: scope.clone(),
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        line: point.row + 1,
                        byte_column: point.column,
                    });
                }
                if matches!(kind, "identifier" | "type_identifier" | "field_identifier") {
                    let point = node.start_position();
                    result.occurrences.push(Occurrence {
                        path: f.path.clone(),
                        file_digest: f.digest.clone(),
                        name: text(node, &bytes)?.into(),
                        start_byte: node.start_byte(),
                        line: point.row + 1,
                        byte_column: point.column,
                        resolution: "syntactic_occurrence_not_semantically_resolved".into(),
                    });
                }
                let next_scope = if let Some(n) = name_node {
                    let n = text(n, &bytes)?;
                    if scope.is_empty() {
                        n.to_string()
                    } else {
                        format!("{scope}::{n}")
                    }
                } else if kind == "impl_item" {
                    let ty = node
                        .child_by_field_name("type")
                        .map(|n| text(n, &bytes))
                        .transpose()?
                        .unwrap_or("?");
                    format!("{scope}::impl<{ty}>")
                } else {
                    scope
                };
                let mut cursor = node.walk();
                let mut children: Vec<_> = node.named_children(&mut cursor).collect();
                children.reverse();
                stack.extend(
                    children
                        .into_iter()
                        .map(|child| (child, next_scope.clone())),
                );
            }
        }
        Ok(result)
    }
    pub fn lookup<'a>(
        &'a self,
        repo: &Repository,
        snapshot: &RepositorySnapshot,
        name: &str,
        cancel: &AtomicBool,
    ) -> Result<Vec<&'a Symbol>> {
        if self.snapshot_digest != snapshot.digest {
            return Err(Error::Stale("index snapshot binding"));
        }
        repo.validate_snapshot(snapshot, cancel)?;
        Ok(self.symbols.iter().filter(|s| s.name == name).collect())
    }
    pub fn references<'a>(
        &'a self,
        repo: &Repository,
        snapshot: &RepositorySnapshot,
        name: &str,
        cancel: &AtomicBool,
    ) -> Result<Vec<&'a Occurrence>> {
        if self.snapshot_digest != snapshot.digest {
            return Err(Error::Stale("index snapshot binding"));
        }
        repo.validate_snapshot(snapshot, cancel)?;
        Ok(self.occurrences.iter().filter(|s| s.name == name).collect())
    }
}
fn text<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str> {
    node.utf8_text(source)
        .map_err(|_| Error::Invalid("AST UTF-8 range"))
}
