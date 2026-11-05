//! Security audit 2026-11, WS3: property tests over the sparse path-segment
//! trie (inclusion / non-existence proofs, state-transition witnesses) and the
//! (threat model I4; WS1 leads D4, D21; July `sbo-hedq`). The dead `merkle.rs`
//! this crate once carried (never a declared module) was deleted under W3-5.

use proptest::prelude::*;
use sbo_crypto::trie::{
    compute_trie_root, verify_state_transition, verify_trie_proof, ObjectWitness, SparseTrie,
    StateTransitionWitness, TrieNode, TrieProofStep,
};
use std::collections::{BTreeMap, BTreeSet};

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 128, ..ProptestConfig::default() }
}

fn seg() -> impl Strategy<Value = String> {
    "[ab][a-c]{0,2}"
}

/// A set of objects keyed by segment vectors, no key a prefix of another
/// (the shape the daemon's `(path, id)` → segments mapping is meant to give).
fn prefix_free_objects() -> impl Strategy<Value = Vec<(Vec<String>, [u8; 32])>> {
    prop::collection::vec((prop::collection::vec(seg(), 1..4), any::<[u8; 32]>()), 1..8).prop_map(|v| {
        let mut out: Vec<(Vec<String>, [u8; 32])> = Vec::new();
        'outer: for (k, h) in v {
            for (o, _) in &out {
                if o.starts_with(&k) || k.starts_with(o) { continue 'outer; }
            }
            out.push((k, h));
        }
        out
    }).prop_filter("non-empty", |v| !v.is_empty())
}

fn build(objs: &[(Vec<String>, [u8; 32])]) -> SparseTrie {
    let mut t = SparseTrie::new();
    for (k, h) in objs { t.insert(k.clone(), *h); }
    t
}

proptest! {
    #![proptest_config(cfg())]

    /// The root is a pure function of the object SET: insertion order does not
    /// matter, and `compute_trie_root` agrees with incremental building.
    #[test]
    fn trie_root_is_order_independent(objs in prefix_free_objects(), seed in any::<u64>()) {
        let a = build(&objs).root_hash();
        let mut shuffled = objs.clone();
        // deterministic shuffle
        let mut s = seed;
        for i in (1..shuffled.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            shuffled.swap(i, (s as usize) % (i + 1));
        }
        prop_assert_eq!(build(&shuffled).root_hash(), a);
        prop_assert_eq!(compute_trie_root(&objs), a);
    }

    /// Every object has an inclusion proof that verifies; every absent path
    /// has a non-existence proof that verifies; a proof against a different
    /// root does not verify; tampering with any sibling hash breaks the proof.
    #[test]
    fn trie_proofs_are_sound_and_complete(objs in prefix_free_objects(), absent in prop::collection::vec(seg(), 1..4), bit in 0usize..256) {
        let t = build(&objs);
        let root = t.root_hash();
        for (k, h) in &objs {
            let p = t.generate_proof(k).unwrap();
            prop_assert_eq!(p.object_hash, Some(*h));
            prop_assert_eq!(p.state_root, root);
            prop_assert!(verify_trie_proof(&p).unwrap());
            // Wrong root.
            let mut bad = p.clone();
            bad.state_root[0] ^= 1;
            prop_assert!(!verify_trie_proof(&bad).unwrap());
            // Tampered sibling (if any).
            let mut tampered = p.clone();
            let nsib: usize = tampered.proof.iter().map(|s| s.siblings.len()).sum();
            if nsib > 0 {
                let mut i = bit % nsib;
                'find: for step in tampered.proof.iter_mut() {
                    for (_, hsh) in step.siblings.iter_mut() {
                        if i == 0 { hsh[0] ^= 1; break 'find; }
                        i -= 1;
                    }
                }
                prop_assert!(!verify_trie_proof(&tampered).unwrap());
            }
            // Wrong object hash for the same path.
            let mut wrong = p.clone();
            wrong.object_hash = Some([h[0] ^ 1, h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]]);
            prop_assert!(!verify_trie_proof(&wrong).unwrap());
        }
        let present: BTreeSet<&Vec<String>> = objs.iter().map(|(k, _)| k).collect();
        if !present.contains(&absent) && !objs.iter().any(|(k, _)| k.starts_with(&absent) || absent.starts_with(k)) {
            let np = t.generate_nonexistence_proof(&absent).unwrap();
            prop_assert_eq!(np.object_hash, None);
            prop_assert!(verify_trie_proof(&np).unwrap(), "non-existence proof for {:?}", absent);
            prop_assert!(!t.contains(&absent));
        }
    }

    /// A state transition witness built from real proofs yields exactly the
    /// root of the trie after applying the same changes (create, update,
    /// delete).
    #[test]
    fn state_transition_witness_matches_rebuilt_root(objs in prefix_free_objects(), new_seg in prop::collection::vec(seg(), 1..3), new_hash in any::<[u8; 32]>(), upd_hash in any::<[u8; 32]>()) {
        let t = build(&objs);
        let prev = t.root_hash();
        let mut witnesses = Vec::new();
        let mut after = objs.clone();
        // Update the first object, delete the last (if distinct), create a new one.
        let (k0, _) = objs[0].clone();
        witnesses.push(ObjectWitness::Update { path_segments: k0.clone(), old_object_hash: objs[0].1, new_object_hash: upd_hash, inclusion_proof: t.generate_proof(&k0).unwrap() });
        after[0].1 = upd_hash;
        if objs.len() > 1 {
            let (kl, hl) = objs[objs.len() - 1].clone();
            witnesses.push(ObjectWitness::Delete { path_segments: kl.clone(), old_object_hash: hl, inclusion_proof: t.generate_proof(&kl).unwrap() });
            after.pop();
        }
        let fresh = !objs.iter().any(|(k, _)| k == &new_seg || k.starts_with(&new_seg) || new_seg.starts_with(k));
        if fresh {
            witnesses.push(ObjectWitness::Create { path_segments: new_seg.clone(), new_object_hash: new_hash, nonexistence_proof: t.generate_nonexistence_proof(&new_seg).unwrap() });
            after.push((new_seg.clone(), new_hash));
        }
        let w = StateTransitionWitness { prev_state_root: prev, witnesses, sibling_hints: vec![] };
        let got = verify_state_transition(&w).unwrap();
        prop_assert_eq!(got, build(&after).root_hash());
        // A witness against the wrong previous root is rejected.
        let mut bad = StateTransitionWitness { prev_state_root: prev, witnesses: vec![], sibling_hints: vec![] };
        bad.prev_state_root[0] ^= 1;
        bad.witnesses.push(ObjectWitness::Update { path_segments: k0.clone(), old_object_hash: objs[0].1, new_object_hash: upd_hash, inclusion_proof: t.generate_proof(&k0).unwrap() });
        prop_assert!(verify_state_transition(&bad).is_err());
    }

    /// Arbitrary (unstructured) proofs never panic the verifier — for proofs
    /// whose `path_segments` is at least as long as the step list. The shorter
    /// case panics today (W3-8 below).
    #[test]
    fn trie_verifier_is_total(root in any::<[u8; 32]>(), oh in prop::option::of(any::<[u8; 32]>()), segs in prop::collection::vec(seg(), 0..4), steps in prop::collection::vec((prop::option::of(seg()), prop::collection::btree_map(seg(), any::<[u8; 32]>(), 0..3)), 0..5)) {
        let steps: Vec<TrieProofStep> = steps.into_iter().map(|(segment, siblings)| TrieProofStep { segment, siblings }).collect();
        prop_assume!(segs.len() >= steps.len());
        let proof = sbo_crypto::trie::TrieProof { state_root: root, path_segments: segs, object_hash: oh, proof: steps };
        let _ = verify_trie_proof(&proof);
    }

}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// D4 (High, July `sbo-hedq`): node hashing has no leaf/internal domain
/// separation — a leaf contributes its bare `object_hash`, an internal node
/// `sha256(canonical_json)`. So a single object whose `object_hash` equals
/// the hash of some internal node commits to the same root as that whole
/// subtree: the commitment cannot tell "object at /a" from "subtree under
/// /a", which is the second-preimage property the State Commitment spec
/// claims. Expected after the fix: the two roots differ.
#[test]
#[ignore] // AUDIT-2026-11 D4: fails today — trie leaf and internal node hashes share one domain
fn d4_leaf_and_subtree_commit_to_different_roots() {
    // Subtree: /a/b → X.
    let x = [7u8; 32];
    let mut sub = TrieNode::new();
    sub.children.insert("b".to_string(), x);
    let subtree_hash = sub.hash();
    // Trie 1: object at /a/b with hash X.
    let t1 = compute_trie_root(&[(vec!["a".into(), "b".into()], x)]);
    // Trie 2: ONE object at /a whose object_hash happens to equal hash(subtree).
    let t2 = compute_trie_root(&[(vec!["a".into()], subtree_hash)]);
    assert_ne!(t1, t2, "an object at /a with object_hash == H(subtree) is indistinguishable from the subtree");
}

/// W3-4 (Medium): the trie cannot hold an object at a path that is a strict
/// prefix of another object's path. `insert([a], h1)` after `insert([a,b],
/// h2)` REPLACES the branch with a leaf (the /a/b object vanishes from the
/// commitment); the opposite order replaces the leaf with a branch. Under
/// the daemon's `segments = path ++ [id]` mapping both writes are legal (an
/// object `a` at `/x/` and an object `b` at `/x/a/`), so one of them is
/// silently dropped from every state root and can never be proven — and
/// which one depends on insertion order (D21 collision class).
#[test]
#[ignore] // AUDIT-2026-11 W3-4: fails today — an object at a prefix path evicts (or is evicted by) the subtree beneath it
fn w3_4_prefix_paths_coexist_in_the_commitment() {
    let (h1, h2) = ([1u8; 32], [2u8; 32]);
    let a = vec!["x".to_string(), "a".to_string()];
    let ab = vec!["x".to_string(), "a".to_string(), "b".to_string()];
    let mut t = SparseTrie::new();
    t.insert(ab.clone(), h2);
    t.insert(a.clone(), h1);
    assert!(t.contains(&a) && t.contains(&ab), "inserting the prefix evicted the deeper object");
    let mut u = SparseTrie::new();
    u.insert(a.clone(), h1);
    u.insert(ab.clone(), h2);
    assert!(u.contains(&a) && u.contains(&ab), "inserting beneath a leaf evicted it");
    assert_eq!(t.root_hash(), u.root_hash());
}

/// Pinned: the empty-trie root is the zero hash and an empty non-existence
/// proof against it verifies (the daemon's empty-state convention).
#[test]
fn empty_trie_conventions() {
    let t = SparseTrie::new();
    assert_eq!(t.root_hash(), [0u8; 32]);
    let np = t.generate_nonexistence_proof(&["a".to_string()]).unwrap();
    assert!(verify_trie_proof(&np).unwrap());
    let _ = BTreeMap::<String, [u8; 32]>::new();
}

/// W3-8 (Medium): `verify_nonexistence_proof` indexes `path_segments[idx]`
/// at the divergence step without checking the length, so a non-existence
/// proof with fewer path segments than steps panics the verifier. The SBOQ
/// parser derives `path_segments` from the steps' `segment` fields, so a
/// proof whose first step has `"segment": null` — exactly what an untrusted
/// indexer returns for a missing object — reaches this with an empty
/// segment list and crashes the client verifying it. Expected: a malformed
/// proof is `Err(InvalidProof)`.
#[test]
fn w3_8_nonexistence_verifier_rejects_short_path_segments() {
    let proof = sbo_crypto::trie::TrieProof {
        state_root: [1u8; 32],
        path_segments: vec![],
        object_hash: None,
        proof: vec![TrieProofStep { segment: None, siblings: BTreeMap::new() }],
    };
    let r = std::panic::catch_unwind(|| verify_trie_proof(&proof));
    match r {
        Err(_) => panic!("verify_trie_proof panicked on a short path_segments"),
        Ok(v) => assert!(matches!(v, Err(_)) || v == Ok(false), "malformed proof verified: {v:?}"),
    }
}
