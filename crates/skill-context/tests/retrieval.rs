mod common;
use common::*;
use melissa_skill_context::retrieval::*;
#[test]
fn actual_sqlite_fts_bm25_finds_lexical_and_symbol_graph_evidence() {
    let mut a = source("source:calc", "function add implementation");
    a.symbols.push("pkg:add".into());
    let mut b = source("source:test", "exercise plus operands");
    b.links.push(a.id.clone());
    let c = source("unrelated", "paint a blue window");
    let all = vec![a, b, c];
    let sc = scope(&all);
    let hits = search(&all, &sc, "add", &["pkg:add".into()], 10).unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].source.id, "source:calc");
    assert!(hits.iter().all(|h| h.graph_match));
    assert!(hits[0].lexical_rank.is_some());
    assert_eq!(hits[0].authority, "untrusted_data");
}
#[test]
fn metadata_namespace_domain_freshness_and_live_source_version_precede_ranking() {
    let good = source("good", "needle");
    let mut other = source("other", "needle");
    other.namespace.project = "other".into();
    let mut engagement = source("engagement", "needle");
    engagement.namespace.engagement = Some("engagement:b".into());
    let mut stale = source("stale", "needle");
    stale.valid_until_ms = 5;
    let mut wrongdomain = source("science", "needle");
    wrongdomain.domain = Domain::Science;
    let all = vec![good, other, engagement, stale, wrongdomain];
    let sc = scope(&all);
    let hits = search(&all, &sc, "needle", &[], 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].source.id, "good");
    let mut changed = sc.clone();
    changed.current.get_mut("good").unwrap().1 = "wrong".into();
    assert!(
        search(&all, &changed, "needle", &[], 10)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn rerank_deduplicates_source_bytes_and_does_not_interpret_fts_or_sql_injection() {
    let all = vec![
        source("a", "literal table corpus"),
        source("b", "literal table corpus"),
    ];
    let sc = scope(&all);
    assert_eq!(search(&all, &sc, "literal", &[], 10).unwrap().len(), 1);
    assert!(search(&all, &sc, "\"; DROP TABLE corpus; --", &[], 10).is_ok());
    assert_eq!(search(&all, &sc, "literal", &[], 10).unwrap().len(), 1);
}
#[test]
fn current_source_digest_is_authenticated_and_duplicate_identity_is_rejected() {
    let mut s = source("a", "text");
    s.content = "changed bytes".into();
    let sc = scope(&[s.clone()]);
    assert!(search(&[s], &sc, "text", &[], 10).is_err());
    let all = vec![source("a", "text"), source("a", "text")];
    assert!(search(&all, &scope(&all), "text", &[], 10).is_err());
}
