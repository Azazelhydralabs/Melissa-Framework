//! Ephemeral SQLite FTS5 index. Persistent source bytes live only in encrypted
//! host storage; the index can always be rebuilt from authenticated sources.
use crate::{Error, Namespace, Result, digest, require};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Documents,
    Code,
    Science,
    Cyber,
    Game,
    Skills,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub version: String,
    pub namespace: Namespace,
    pub domain: Domain,
    pub content: String,
    pub digest: String,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
    pub symbols: Vec<String>,
    pub links: Vec<String>,
}
impl Source {
    pub fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        require(
            !self.id.trim().is_empty()
                && !self.version.trim().is_empty()
                && digest(self.content.as_bytes()) == self.digest
                && self.observed_at_ms < self.valid_until_ms,
            "invalid source identity, bytes or freshness",
        )
    }
}
/// A current-source inventory supplied by the host after source revalidation.
/// Neither a search result nor model memory can populate this automatically.
#[derive(Debug, Clone)]
pub struct SearchScope {
    pub namespace: Namespace,
    pub domain: Domain,
    pub now_ms: u64,
    pub current: BTreeMap<String, (String, String)>,
}
impl SearchScope {
    pub fn allows(&self, s: &Source) -> bool {
        s.namespace == self.namespace
            && s.domain == self.domain
            && s.observed_at_ms <= self.now_ms
            && self.now_ms < s.valid_until_ms
            && self
                .current
                .get(&s.id)
                .is_some_and(|(v, d)| v == &s.version && d == &s.digest)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub source: Source,
    pub lexical_rank: Option<usize>,
    pub graph_match: bool,
    pub authority: String,
}

pub fn search(
    sources: &[Source],
    scope: &SearchScope,
    query: &str,
    symbols: &[String],
    limit: usize,
) -> Result<Vec<Hit>> {
    scope.namespace.validate()?;
    require(
        (1..=256).contains(&limit) && query.len() <= 65536,
        "search page or query limit",
    )?;
    let mut ids = BTreeSet::new();
    let eligible: Vec<_> = sources.iter().filter(|s| scope.allows(s)).collect();
    for s in &eligible {
        s.validate()?;
        require(
            ids.insert(s.id.clone()),
            "duplicate current source identity",
        )?;
    }
    let db = Connection::open_in_memory().map_err(sql)?;
    db.execute_batch("CREATE VIRTUAL TABLE corpus USING fts5(body, tokenize='unicode61');")
        .map_err(sql)?;
    for (i, s) in eligible.iter().enumerate() {
        db.execute(
            "INSERT INTO corpus(rowid,body) VALUES(?1,?2)",
            params![i as i64 + 1, s.content],
        )
        .map_err(sql)?;
    }
    // Model punctuation never becomes FTS syntax, SQL, a column selector or NEAR.
    let terms: Vec<_> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let mut lexical = BTreeMap::new();
    if !terms.is_empty() {
        let escaped = terms
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(" OR ");
        let mut stmt = db
            .prepare("SELECT rowid FROM corpus WHERE corpus MATCH ?1 ORDER BY bm25(corpus),rowid")
            .map_err(sql)?;
        let rows = stmt
            .query_map([escaped], |r| r.get::<_, i64>(0))
            .map_err(sql)?;
        for (rank, row) in rows.enumerate() {
            lexical.insert(row.map_err(sql)? as usize - 1, rank);
        }
    }
    let seed_ids: BTreeSet<_> = eligible
        .iter()
        .filter(|s| s.symbols.iter().any(|x| symbols.contains(x)))
        .map(|s| s.id.as_str())
        .collect();
    let mut hits = Vec::new();
    for (i, s) in eligible.iter().enumerate() {
        let graph = seed_ids.contains(s.id.as_str())
            || s.links.iter().any(|id| seed_ids.contains(id.as_str()));
        if lexical.contains_key(&i) || graph {
            hits.push(Hit {
                source: (*s).clone(),
                lexical_rank: lexical.get(&i).copied(),
                graph_match: graph,
                authority: "untrusted_data".into(),
            });
        }
    }
    hits.sort_by(|a, b| {
        b.graph_match
            .cmp(&a.graph_match)
            .then(
                a.lexical_rank
                    .unwrap_or(usize::MAX)
                    .cmp(&b.lexical_rank.unwrap_or(usize::MAX)),
            )
            .then(a.source.id.cmp(&b.source.id))
    });
    let mut seen = BTreeSet::new();
    hits.retain(|h| seen.insert(h.source.digest.clone()));
    hits.truncate(limit);
    Ok(hits)
}
fn sql(_: rusqlite::Error) -> Error {
    Error("CODE-07 SQLite FTS operation failed".into())
}
