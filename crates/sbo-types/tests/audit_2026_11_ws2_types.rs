//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-types`.
//!
//! `sbo-types` carries a second `Id` / `Path` / `Action` grammar (re-exported
//! by sbo-core as `sbo_core::Id` etc. and used by the zkVM guest) next to the
//! one in `sbo-core::message`. Both must agree with the spec grammar in
//! `conformance/identifiers.json`.

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

const EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 W2-1: sbo-types' grammar predates `@`, `+` and `:`; it
    // rejects every email-rooted identity, agent identity and namespaced id
    // that sbo-core::message accepts (D30).
    ("ID-OK-03", "W2-1"),
    ("ID-OK-04", "W2-1"),
    ("ID-OK-05", "W2-1"),
    ("ID-OK-06", "W2-1"),
    ("PATH-OK-03", "W2-1"),
    // AUDIT-2026-11 D21: `.` / `..` accepted.
    ("ID-REJ-07", "D21"),
    ("ID-REJ-08", "D21"),
    ("PATH-REJ-04", "D21"),
    ("PATH-REJ-05", "D21"),
    // AUDIT-2026-11 W2-1: sbo-types' `Action::parse` lowercases its input and
    // admits `create` / `update`, which are not wire actions.
    ("ACT-REJ-01", "W2-1"),
    ("ACT-REJ-02", "W2-1"),
    ("ACT-REJ-03", "W2-1"),
    ("ACT-REJ-04", "W2-1"),
];

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
