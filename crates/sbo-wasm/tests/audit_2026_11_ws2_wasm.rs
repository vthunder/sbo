//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-wasm`.
//!
//! `sbo-wasm` `#[path]`-includes the wire/message/crypto sources of sbo-core
//! and compiles them separately (the browser client's signing kit). This
//! runner judges the same `conformance/*.json` vectors through the sbo-wasm
//! copy and through the kit builder, so any drift between the two compilations
//! or between the kit's assembled bytes and the native serializer shows up
//! here. Expected-fail tables mirror the sbo-core runner: the two MUST stay
//! identical (same source), and that identity is itself asserted by the
//! cross-implementation test in the report.

use sbo_wasm::crypto::{PublicKey, Signature};
use sbo_wasm::kit::{self, EnvelopeSpec};
use sbo_wasm::message::{verify_message, Action, Id, Path};
use sbo_wasm::wire;
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

/// Same table as `sbo-core/tests/audit_2026_11_ws2_core.rs` — same source.
const WIRE_EXPECTED_FAIL: &[(&str, &str)] = &[
    ("W-OK-05", "D3"),
    ("W-CH-01", "D1"),
    ("W-ORD-01", "D2"),
    ("W-DUP-01", "D2"),
    ("W-DUP-02", "D2"),
    ("W-CL-01", "D2"),
    ("W-CL-02", "D2"),
    ("W-HEX-01", "D2"),
    ("W-HEX-02", "D2"),
    ("W-INJ-01", "D2"),
    ("W-INJ-02", "D2"),
    ("W-ID-01", "D21"),
    ("W-ID-02", "D21"),
    ("W-ID-03", "D54"),
    ("W-ID-04", "D13"),
];

#[test]
fn wire_vectors_wasm_parser_and_verifier() {
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
    judge("wire/wasm", results, WIRE_EXPECTED_FAIL);
}

/// The kit's `object_hash` is sha256 of the bytes it is given, i.e. the spec's
/// rule by construction; and the kit, fed the base vector's fields, must
/// assemble byte-identical wire to the native serializer (signing-byte parity).
#[test]
fn kit_reproduces_the_canonical_vector_and_hashes_raw_bytes() {
    let doc = load("wire.json");
    let base = doc["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "W-OK-01").unwrap();
    let wire_text = base["wire"].as_str().unwrap();
    let sig_hex = wire_text.lines().find_map(|l| l.strip_prefix("Signature: ")).unwrap();
    let spec = EnvelopeSpec {
        action: "post".into(),
        path: "/communities/cooks/spaces/general/".into(),
        id: "p1".into(),
        public_key: doc["key"]["public_key"].as_str().unwrap().into(),
        content_type: None,
        content_schema: Some("post.v1".into()),
        owner: Some("alice@example.com".into()),
        payload: br#"{"body":"hello"}"#.to_vec(),
        hlc: Some("1703001234567.0".into()),
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None,
    };
    let assembled = kit::assemble_wire(&spec, sig_hex).unwrap();
    assert_eq!(String::from_utf8(assembled.clone()).unwrap(), wire_text, "kit must assemble the exact canonical bytes");
    assert_eq!(hex::encode(kit::object_hash(&assembled)), base["object_hash_raw"].as_str().unwrap());
    // The signing bytes the kit hands the signer verify under the vector key.
    let m = wire::parse(&assembled).unwrap();
    assert!(verify_message(&m).is_ok());
    assert_eq!(kit::signing_bytes(&spec).unwrap(), m.canonical_signing_content());
}

const ID_EXPECTED_FAIL: &[(&str, &str)] = &[
    ("ID-REJ-07", "D21"),
    ("ID-REJ-08", "D21"),
    ("PATH-REJ-04", "D21"),
    ("PATH-REJ-05", "D21"),
    ("ID-REJ-09", "D54"),
    ("ID-REJ-10", "D13"),
    ("ID-REJ-11", "D13"),
    ("ID-REJ-12", "D13"),
];

#[test]
fn identifier_vectors_wasm_grammar() {
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
    judge("identifiers/wasm", results, ID_EXPECTED_FAIL);
}

const ED_EXPECTED_FAIL: &[(&str, &str)] = &[("ED-REJ-04", "D30")];

#[test]
fn ed25519_vectors_wasm_wrapper() {
    let doc = load("ed25519.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let expected = v["valid"].as_bool().unwrap();
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let pk = PublicKey::parse(&format!("ed25519:{}", v["public_key"].as_str().unwrap()));
        let sig = Signature::parse(v["signature"].as_str().unwrap());
        let (actual, detail) = match (pk, sig) {
            (Ok(pk), Ok(sig)) => match sbo_wasm::crypto::verify(&pk, &msg, &sig) {
                Ok(()) => (true, "verified".to_string()),
                Err(e) => (false, format!("{e:?}")),
            },
            (pk, sig) => (false, format!("parse: pk {} sig {}", pk.is_ok(), sig.is_ok())),
        };
        results.push((id, expected, actual, detail));
    }
    judge("ed25519/wasm", results, ED_EXPECTED_FAIL);
}
