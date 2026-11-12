//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-types`.
//!
//! `sbo-types` is THE `Id` / `Path` / `Action` grammar (Q36): sbo-core::message
//! and sbo-wasm re-export it, the zkVM guest uses it directly. It must agree
//! with the spec grammar in `conformance/identifiers.json`.

use sbo_types::action::Action;
use sbo_types::id::Id;
use sbo_types::path::Path;
use serde_json::Value;
use std::path::PathBuf;

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

fn judge(suite: &str, results: Vec<(String, bool, bool, String)>, expected_fail: &[(&str, &str)]) {
    let mut unexpected = Vec::new();
    let mut fixed = Vec::new();
    let mut agree = 0;
    for (id, expected, actual, detail) in &results {
        let listed = expected_fail.iter().find(|(v, _)| v == id);
        match (expected == actual, listed) {
            (true, None) => agree += 1,
            (true, Some((_, finding))) => fixed.push(format!("{id} ({finding}) now agrees with the spec — remove it from EXPECTED_FAIL")),
            (false, Some(_)) => {}
            (false, None) => unexpected.push(format!("{id}: spec {expected}, impl {actual} — {detail}")),
        }
    }
    eprintln!("{suite}: {agree} agree, {} expected-fail, {} unexpected", expected_fail.len(), unexpected.len());
    assert!(unexpected.is_empty(), "{suite}: unexpected disagreements:\n{}", unexpected.join("\n"));
    assert!(fixed.is_empty(), "{suite}:\n{}", fixed.join("\n"));
}

/// Empty since Q36 (audit 2026-11): sbo-types IS the grammar.
const EXPECTED_FAIL: &[(&str, &str)] = &[];

#[test]
fn identifier_vectors_sbo_types_grammar() {
    let doc = load("identifiers.json");
    let mut results = Vec::new();
    for v in doc["ids"].as_array().unwrap() {
        let s = v["value"].as_str().unwrap();
        results.push((v["id"].as_str().unwrap().into(), v["valid"].as_bool().unwrap(), Id::new(s).is_ok(), format!("Id::new({s:?})")));
    }
    for v in doc["paths"].as_array().unwrap() {
        let s = v["value"].as_str().unwrap();
        results.push((v["id"].as_str().unwrap().into(), v["valid"].as_bool().unwrap(), Path::parse(s).is_ok(), format!("Path::parse({s:?})")));
    }
    for v in doc["actions"].as_array().unwrap() {
        let s = v["value"].as_str().unwrap();
        results.push((v["id"].as_str().unwrap().into(), v["valid"].as_bool().unwrap(), Action::parse(s).is_ok(), format!("Action::parse({s:?})")));
    }
    judge("identifiers/sbo-types", results, EXPECTED_FAIL);
}
