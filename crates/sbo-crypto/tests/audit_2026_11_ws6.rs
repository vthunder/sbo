//! Security audit 2026-11, WS6 — sbo-crypto side (trie domain separation,
//! Ed25519 wrapper, KZG stub). `#[ignore]`d tests fail today and are the
//! acceptance tests for their fix. No production code changed.

use sbo_crypto::trie::{compute_trie_root, verify_trie_proof, SparseTrie, TrieNode};

fn seg(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// State Commitment spec, "State Tree Structure": leaves and internal nodes
/// must be distinguishable. Today a leaf hashes to the bare object hash and
/// an internal node to `sha256(canonical_json)`, so an object whose
/// `object_hash` equals a subtree's node hash yields the same root as that
/// subtree: a second preimage of the state root.
#[test]
#[ignore] // AUDIT-2026-11 D4: fails today — no leaf/internal domain separation (July sbo-hedq)
fn d4_leaf_and_internal_node_hashes_are_domain_separated() {
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];
    // State 1: two objects under /x/.
    let r1 = compute_trie_root(&[(seg(&["x", "a"]), h1), (seg(&["x", "b"]), h2)]);
    // The internal node for /x/ in state 1.
    let mut node = TrieNode::new();
    node.children.insert("a".into(), h1);
    node.children.insert("b".into(), h2);
    let n = node.hash();
    // State 2: one object at /x whose object_hash is that node hash.
    let r2 = compute_trie_root(&[(seg(&["x"]), n)]);
    assert_ne!(r1, r2, "a leaf carrying a subtree's node hash collides with the subtree");
}

#[test]
fn inclusion_proof_verifies_and_tampering_is_detected() {
    let mut trie = SparseTrie::new();
    trie.insert(seg(&["x", "a"]), [1u8; 32]);
    trie.insert(seg(&["x", "b"]), [2u8; 32]);
    trie.insert(seg(&["y"]), [3u8; 32]);
    let proof = trie.generate_proof(&seg(&["x", "a"])).unwrap();
    assert_eq!(proof.state_root, trie.root_hash());
    assert_eq!(verify_trie_proof(&proof), Ok(true));
    let mut bad = proof.clone();
    bad.object_hash = Some([9u8; 32]);
    assert_ne!(verify_trie_proof(&bad), Ok(true));
    let mut bad = proof.clone();
    bad.state_root = [7u8; 32];
    assert_ne!(verify_trie_proof(&bad), Ok(true));
    let absent = trie.generate_nonexistence_proof(&seg(&["x", "c"])).unwrap();
    assert_eq!(verify_trie_proof(&absent), Ok(true));
}

/// The Ed25519 wrapper pins key and signature lengths. (Strictness is tested
/// in sbo-core's `audit_2026_11_ws6.rs`, where both wrappers are reachable.)
#[test]
fn ed25519_wrapper_pins_lengths() {
    use sbo_crypto::ed25519::{PublicKey, Signature};
    assert!(PublicKey::parse(&format!("ed25519:{}", "ab".repeat(31))).is_err());
    assert!(PublicKey::parse(&format!("ed25519:{}", "ab".repeat(33))).is_err());
    assert!(PublicKey::parse(&format!("secp256k1:{}", "ab".repeat(32))).is_err());
    assert!(Signature::parse(&"ab".repeat(63)).is_err());
    assert!(Signature::parse(&"ab".repeat(65)).is_err());
}

/// `verify_kzg_proof` returns `Ok(true)` for any pair of valid G1 points: it
/// never performs the pairing check. Compile with `--features kzg`.
#[cfg(feature = "kzg")]
#[test]
fn d9_kzg_verify_rejects_a_proof_that_does_not_open_the_commitment() {
    use sbo_crypto::kzg::{verify_kzg_proof, KzgCommitment, KzgProof};
    // The BLS12-381 G1 generator, compressed.
    let g1 = hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap();
    let c = KzgCommitment::from_bytes(&g1).unwrap();
    let p = KzgProof::from_bytes(&g1).unwrap();
    let x = [1u8; 32];
    let y = [2u8; 32];
    let r = verify_kzg_proof(&c, &x, &y, &p);
    assert_ne!(r, Ok(true), "the generator 'proves' an arbitrary opening of itself");
}
