//! Write the seed corpus for every target (`cargo run --release --bin gen_seeds`
//! from `fuzz/`). Seeds are committed under `fuzz/seeds/<target>/`; libFuzzer
//! reads them read-only and writes new findings to `fuzz/corpus/<target>/`.

use std::fs;
use std::path::Path;

use sbo_fuzz as fx;

fn put(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");

    let m = fx::envelope("/u/alice/posts/", "p1", br#"{"body":"hi"}"#.to_vec(), 1);
    let w = sbo_core::wire::serialize(&m);
    let d = root.join("wire_parse");
    put(&d, "post", &w);
    let mut batch = w.clone();
    batch.extend_from_slice(&sbo_core::wire::serialize(&fx::envelope("/u/bob/", "x", vec![], 2)));
    put(&d, "batch", &batch);
    put(&d, "delete", b"SBO-Version: 0.5\nAction: delete\nPath: /u/alice/posts/\nID: p1\nType: object\nPublic-Key: ed25519:0000000000000000000000000000000000000000000000000000000000000000\nSignature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n\n");
    put(&root.join("wire_build"), "zero", &[0u8; 16]);

    let d = root.join("uri_dns");
    put(&d, "bare", b"sbo+raw://avail:turing:506/");
    put(&d, "anchored", b"sbo+raw://avail:turing:506@3545910/communities/cooks/community?genesis=sha256:ab&as_of=12");
    put(&d, "txt", b"v=sbo1 repo=sbo+raw://avail:turing:506@3545910/ genesis=sha256:abcd node=https://da.sandmill.org");
    put(&d, "dns", b"sbo://sandmill.org/sys/names/alice");

    let d = root.join("policy_json");
    put(&d, "root", br#"{"roles":{"admin":["sys",{"role":"mods"}],"mods":[{"attested":{"type":"role:moderator","by":"sys"}}]},"deny":["/sys/trust/**"],"grants":[{"to":"*","can":["post"],"on":"/u/$user/**"},{"to":{"role":"admin"},"can":["govern"],"on":"/**"}],"restrictions":[{"on":"/u/**","require":{"max_size":65536,"not_attested":{"type":"ban"},"fields":[{"pointer":"/v","min":0}]}}],"descendant_constraint":{"allowed_grants":[{"to":"*","can":["create"],"on":"/c/**","id":"ev_*"}],"forbid_pinning":true}}"#);
    put(&root.join("path_glob"), "a", b"/a/**/b/*/\x00/a/x/b/c/\x00ev_*\x00ev_1\x00path:/u/**");

    let d = root.join("proof_parse");
    let sbop = sbo_core::proof::serialize_sbop(&sbo_core::proof::SbopMessage { version: "0.1".into(), block_from: 1, block_to: 9, receipt_kind: "succinct".into(), receipt_bytes: vec![1, 2, 3] });
    put(&d, "sbop", &sbop);
    let mut t = sbo_crypto::SparseTrie::new();
    t.insert(vec!["a".into(), "b".into()], [7u8; 32]);
    let proof = t.generate_proof(&["a".to_string(), "b".to_string()]).unwrap();
    let sboq = sbo_core::proof::serialize_sboq(&sbo_core::proof::SboqMessage { version: "0.2".into(), path: "/a/".into(), id: "b".into(), creator: "c".into(), block: 1, state_root: proof.state_root, object_hash: proof.object_hash, trie_proof: proof, object: Some(b"obj".to_vec()) });
    put(&d, "sboq", &sboq);

    put(&root.join("hlc_lww"), "a", b"1703001234567.0\x001703001234567.1");
    put(&root.join("trie_proof"), "zero", &[0u8; 32]);
    let d = root.join("schema_json");
    put(&d, "attestation", br#"attestation.v1\x00{"subject":"alice@example.com","type":"role:moderator","value":true,"issued_at":1700000000,"expires":1800000000}"#);
    put(&d, "collection", br#"collection.v1\x00{"durability":"batched","batch_interval_s":5,"max_authoring_lag_s":3600}"#);
    put(&d, "post", br#"post.v1\x00{"body":"hi","created_at":1700000000}"#);

    put(&root.join("presentation"), "valid", fx::fixture().presentation.as_bytes());
    put(&root.join("dnssec_rr"), "zero", &[0u8; 8]);
    let d = root.join("jwt");
    put(&d, "self", sbo_core::jwt::create_self_signed_identity(&fx::key(1), "alice", None).unwrap().as_bytes());
    put(&d, "domain", sbo_core::jwt::create_domain(&fx::key(2), "example.com").unwrap().as_bytes());
}
