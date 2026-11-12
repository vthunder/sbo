//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-crypto`
//! (the no_std ed25519 wrapper the zkVM guest uses; the two trie hashers:
//! `SparseTrie` (builder) and `PartialTrie` (verifier, also the guest's
//! `verify_state_transition` path)).

use sbo_crypto::ed25519::{PublicKey, Signature};
use sbo_crypto::trie::{compute_trie_root, PartialTrie, SparseTrie};
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

/// `verify_strict` since sbo-cusw: nothing expected to fail.
const ED_EXPECTED_FAIL: &[(&str, &str)] = &[];

#[test]
fn ed25519_vectors_sbo_crypto_wrapper() {
    let doc = load("ed25519.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let expected = v["valid"].as_bool().unwrap();
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let pk = PublicKey::parse(&format!("ed25519:{}", v["public_key"].as_str().unwrap()));
        let sig = Signature::parse(v["signature"].as_str().unwrap());
        let (actual, detail) = match (pk, sig) {
            (Ok(pk), Ok(sig)) => match sbo_crypto::ed25519::verify(&pk, &msg, &sig) {
                Ok(()) => (true, "verified".to_string()),
                Err(e) => (false, format!("{e:?}")),
            },
            (pk, sig) => (false, format!("parse: pk {} sig {}", pk.is_ok(), sig.is_ok())),
        };
        results.push((id, expected, actual, detail));
    }
    judge("ed25519/sbo-crypto", results, ED_EXPECTED_FAIL);
}

fn objects_of(v: &Value) -> Vec<(Vec<String>, [u8; 32])> {
    v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let segs = o["segments"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
            let h: [u8; 32] = hex::decode(o["object_hash"].as_str().unwrap()).unwrap().try_into().unwrap();
            (segs, h)
        })
        .collect()
}

/// Every trie implementation reproduces the recorded root (agreement), and
/// roots the spec requires to be distinct are distinct (I30).
const TRIE_EXPECTED_FAIL: &[(&str, &str)] = &[];

#[test]
fn trie_vectors_builder_verifier_and_helper_agree() {
    let doc = load("trie.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let mut results = Vec::new();
    let mut roots = std::collections::HashMap::new();
    for v in vectors {
        let id = v["id"].as_str().unwrap().to_string();
        let objs = objects_of(v);
        let expected_root = v["root"].as_str().unwrap().to_string();

        let mut sparse = SparseTrie::new();
        for (s, h) in &objs {
            sparse.insert(s.clone(), *h);
        }
        let r_sparse = hex::encode(sparse.root_hash());

        let r_helper = hex::encode(compute_trie_root(&objs));

        let mut partial = PartialTrie::new(sbo_crypto::trie::empty_root());
        for (s, h) in &objs {
            partial.insert(s, *h);
        }
        let r_partial = hex::encode(partial.root_hash());

        results.push((format!("{id}/SparseTrie"), true, r_sparse == expected_root, format!("{r_sparse} vs {expected_root}")));
        results.push((format!("{id}/compute_trie_root"), true, r_helper == expected_root, format!("{r_helper} vs {expected_root}")));
        results.push((format!("{id}/PartialTrie"), true, r_partial == expected_root, format!("{r_partial} vs {expected_root}")));
        roots.insert(id, expected_root);
    }
    for v in vectors {
        if let Some(other) = v["distinct_from"].as_str() {
            let id = v["id"].as_str().unwrap();
            let (a, b) = (&roots[id], &roots[other]);
            results.push((format!("{id}/distinct"), true, a != b, format!("root of {id} ({a}) equals root of {other}")));
        }
    }
    judge("trie/sbo-crypto", results, TRIE_EXPECTED_FAIL);
}
