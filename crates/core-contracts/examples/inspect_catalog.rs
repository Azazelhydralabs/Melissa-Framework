//! Development inspection of definitions. This is not the CODE-12 product CLI.
use melissa_core_contracts::catalog::{Catalog, DefinitionReadiness};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Serialize)]
struct Counts {
    profiles: usize,
    workers: usize,
    tools: usize,
    aliases: usize,
    modules: usize,
    backlog_items: usize,
    evaluation_definitions: usize,
}

#[derive(Serialize)]
struct Inspection {
    schema_version: &'static str,
    evidence_level: &'static str,
    counts: Counts,
    readiness: DefinitionReadiness,
}

fn inspect(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::load(root)?;
    let report = Inspection {
        schema_version: "melissa.catalog-inspection/v1",
        evidence_level: "local_typed_definition_validation_only",
        counts: Counts {
            profiles: catalog.profiles.len(),
            workers: catalog.workers.len(),
            tools: catalog.tools.tools.len(),
            aliases: catalog.aliases.aliases.len(),
            modules: catalog.modules.modules.len(),
            backlog_items: catalog.backlog.items.len(),
            evaluation_definitions: catalog
                .profiles
                .values()
                .map(|profile| profile.evaluation_cases.len())
                .sum(),
        },
        readiness: catalog.readiness(),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    Ok(())
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let root = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    if arguments.next().is_some() {
        eprintln!("usage: inspect_catalog [project-root]");
        return ExitCode::FAILURE;
    }
    match inspect(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("catalog validation failed: {error}");
            ExitCode::FAILURE
        }
    }
}
