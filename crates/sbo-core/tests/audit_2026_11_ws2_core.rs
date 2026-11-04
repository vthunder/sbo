//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-core`
//! (wire parser + signature verification, batch splitter, identifier grammar,
//! identity resolution, ed25519 wrapper, the daemon's object_hash rule).
//!
//! Reads `conformance/*.json` and judges every vector with sbo-core. Vectors
//! that disagree with the spec's verdict today are listed in an
//! `EXPECTED_FAIL` table with the audit id that owns the gap
//! (`AUDIT-2026-11 <id>`); the test fails if any OTHER vector disagrees, and
//! ALSO if a listed vector starts agreeing — removing it from the table is the
//! acceptance test for the fix.
//!
//! Report: docs/security-audit-2026-11-ws2-conformance.md.

use sbo_core::crypto::{sha256, PublicKey, Signature};
use sbo_core::message::{verify_message, Action, Id, Path};
use sbo_core::resolve::{resolve_controller, Controller, NameRecord};
use sbo_core::wire;
use serde_json::Value;
use std::path::PathBuf;

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

/// Compare per-vector verdicts against the spec, honouring an expected-fail table.
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

// ---------------------------------------------------------------- wire ----

/// Wire vectors sbo-core gets wrong today.
const WIRE_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D3: import headers are dropped by the parser and absent
    // from the rebuilt signing content, so a correctly signed message that
    // carries one cannot be verified.
    ("W-OK-05", "D3"),
    // AUDIT-2026-11 D1: Content-Hash is never checked against the payload.
    ("W-CH-01", "D1"),
    // AUDIT-2026-11 D2: the signature is verified over a reconstruction, so
    // reordered, duplicated, injected and non-canonically encoded headers
    // verify as long as they parse to the same fields.
    ("W-ORD-01", "D2"),
    ("W-DUP-01", "D2"),
    ("W-DUP-02", "D2"),
    ("W-CL-01", "D2"),
    ("W-CL-02", "D2"),
    ("W-HEX-01", "D2"),
    ("W-HEX-02", "D2"),
    ("W-INJ-01", "D2"),
    ("W-INJ-02", "D2"),
    // AUDIT-2026-11 D21: `.` / `..` are accepted as ids and path segments.
    ("W-ID-01", "D21"),
    ("W-ID-02", "D21"),
    // AUDIT-2026-11 D13 / D54 / Q5: no identity grammar beyond the id charset.
    ("W-ID-03", "D54"),
    ("W-ID-04", "D13"),
];

#[test]
fn wire_vectors_core_parser_and_verifier() {
    let doc = load("wire.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let bytes = v["wire"].as_str().unwrap().as_bytes();
        let expected = v["spec"]["valid"].as_bool().unwrap();
        let (actual, detail) = match wire::parse(bytes) {
            Err(e) => (false, format!("parse: {e:?}")),
            Ok(m) => match verify_message(&m) {
                Ok(()) => (true, "parsed and signature verified".into()),
                Err(e) => (false, format!("signature: {e:?}")),
            },
        };
        results.push((id, expected, actual, detail));
    }
    judge("wire/core", results, WIRE_EXPECTED_FAIL);
}

/// Object-hash vectors where the daemon's rule (`sha256(serialize(parse(b)))`,
/// sync.rs:1122) differs from the spec's `sha256(raw bytes)`.
const OBJECT_HASH_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D3: for every non-canonical-but-accepted encoding (D2) the
    // re-serialized bytes differ from the received bytes, so two nodes that
    // disagree on acceptance already disagree on the root, and a node that
    // accepts them commits to bytes that were never on chain.
    ("W-DUP-01", "D3"),
    ("W-DUP-02", "D3"),
    ("W-ORD-01", "D3"),
    ("W-CL-01", "D3"),
    ("W-CL-02", "D3"),
    ("W-HEX-01", "D3"),
    ("W-HEX-02", "D3"),
    ("W-INJ-01", "D3"),
    ("W-INJ-02", "D3"),
];

/// I4: for every vector the parser accepts (whatever the spec says), the
/// object_hash the daemon would store must equal sha256 of the received bytes.
#[test]
fn object_hash_is_over_the_received_bytes() {
    let doc = load("wire.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let bytes = v["wire"].as_str().unwrap().as_bytes();
        let Ok(m) = wire::parse(bytes) else { continue };
        if verify_message(&m).is_err() {
            continue;
        }
        let raw = v["object_hash_raw"].as_str().unwrap();
        let daemon_rule = hex::encode(sha256(&wire::serialize(&m)));
        results.push((id, true, daemon_rule == raw, format!("raw {raw} vs re-serialized {daemon_rule}")));
    }
    judge("object_hash/core", results, OBJECT_HASH_EXPECTED_FAIL);
}

// --------------------------------------------------------------- batch ----

#[test]
fn batch_vectors_core_splitter() {
    let doc = load("batch.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let bytes = v["wire"].as_str().unwrap().as_bytes();
        let expected = v["parse"].as_str().unwrap() == "accept";
        let (actual, detail) = match wire::parse_batch(bytes) {
            Ok(ms) => {
                let n = v["count"].as_u64().unwrap() as usize;
                (true && ms.len() == n, format!("parsed {} messages (spec {n})", ms.len()))
            }
            Err(e) => (false, format!("{e:?}")),
        };
        results.push((id, expected, actual, detail));
    }
    // Rule 1 (a submission that fails to parse is ignored whole) is what
    // `parse_batch` does today; nothing expected to fail.
    judge("batch-parse/core", results, &[]);
}

// --------------------------------------------------------- identifiers ----

const ID_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D21: `.` and `..` accepted.
    ("ID-REJ-07", "D21"),
    ("ID-REJ-08", "D21"),
    ("PATH-REJ-04", "D21"),
    ("PATH-REJ-05", "D21"),
    // AUDIT-2026-11 D54 / D13 (Q5): the id grammar has no identity rule.
    ("ID-REJ-09", "D54"),
    ("ID-REJ-10", "D13"),
    ("ID-REJ-11", "D13"),
    ("ID-REJ-12", "D13"),
];

#[test]
fn identifier_vectors_core_message_grammar() {
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
        results.push((v["id"].as_str().unwrap().into(), v["valid"].as_bool().unwrap(), Action::parse(s).is_ok(), format!("message::Action::parse({s:?})")));
    }
    judge("identifiers/core-message", results, ID_EXPECTED_FAIL);
}

// ------------------------------------------------------------ identity ----

const IDENTITY_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D13 (Q5): domains are compared byte-exact everywhere.
    ("IDC-02", "D13"),
    ("IDC-06", "D13"),
    ("IDD-02", "D13"),
    ("IDR-02", "D13"),
    // AUDIT-2026-11 D54: `parse_email` splits at the first `@` and keeps the rest.
    ("IDD-04", "D54"),
];

#[test]
fn identity_vectors_core_resolution_and_email_split() {
    let doc = load("identity.json");
    let pd = doc["primary_domain"].as_str().unwrap();
    let no_names = |_: &str| -> Option<NameRecord> { None };
    let mut results = Vec::new();

    // Pairs: the same identity iff both references resolve to the same controller.
    for v in doc["pairs"].as_array().unwrap() {
        let (a, b) = (v["a"].as_str().unwrap(), v["b"].as_str().unwrap());
        let ca = resolve_controller(a, &no_names, 8, None);
        let cb = resolve_controller(b, &no_names, 8, None);
        results.push((v["id"].as_str().unwrap().into(), v["equal"].as_bool().unwrap(), ca == cb, format!("{ca:?} vs {cb:?}")));
    }

    // Domain extraction (`dns::parse_email`): expected lowercase A-label or None.
    for v in doc["domain_of"].as_array().unwrap() {
        let ident = v["identity"].as_str().unwrap();
        let expected = v["domain"].as_str().map(|s| s.to_string());
        let got = sbo_core::dns::parse_email(ident).map(|(_, d)| d.to_string());
        let ok = got == expected;
        results.push((v["id"].as_str().unwrap().into(), true, ok, format!("parse_email({ident:?}) = {got:?}, spec {expected:?}")));
    }

    // Primary-domain resolution: `alice@<pd>` resolves through `/sys/names/alice`.
    for v in doc["resolve_through_primary_domain"].as_array().unwrap() {
        let reference = v["reference"].as_str().unwrap();
        let name = v["name_record_for"].as_str().unwrap().to_string();
        let lookup = move |n: &str| -> Option<NameRecord> {
            if n == name { Some(NameRecord::KeyRooted("ed25519:aa".into())) } else { None }
        };
        let c = resolve_controller(reference, &lookup, 8, Some(pd));
        let via_record = matches!(c, Controller::Key(_));
        results.push((v["id"].as_str().unwrap().into(), v["resolves_to_name_record"].as_bool().unwrap(), via_record, format!("resolve_controller({reference:?}) = {c:?}")));
    }
    judge("identity/core", results, IDENTITY_EXPECTED_FAIL);
}

// ------------------------------------------------------------- ed25519 ----

const ED_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D30: both wrappers use dalek's non-strict `verify`, which
    // admits small-order keys (a non-canonical S is rejected by dalek itself).
    ("ED-REJ-04", "D30"),
];

#[test]
fn ed25519_vectors_core_wrapper() {
    let doc = load("ed25519.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let expected = v["valid"].as_bool().unwrap();
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let pk = PublicKey::parse(&format!("ed25519:{}", v["public_key"].as_str().unwrap()));
        let sig = Signature::parse(v["signature"].as_str().unwrap());
        let (actual, detail) = match (pk, sig) {
            (Ok(pk), Ok(sig)) => match sbo_core::crypto::verify(&pk, &msg, &sig) {
                Ok(()) => (true, "verified".to_string()),
                Err(e) => (false, format!("{e:?}")),
            },
            (pk, sig) => (false, format!("parse: pk {} sig {}", pk.is_ok(), sig.is_ok())),
        };
        results.push((id, expected, actual, detail));
    }
    judge("ed25519/core", results, ED_EXPECTED_FAIL);
}
