#![no_main]
//! WS3: the sparse trie's proofs are sound and complete for arbitrary
//! prefix-free object sets, the root is insertion-order independent, state
//! transition witnesses agree with a rebuilt trie, and the verifier is total
//! on arbitrary proofs.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sbo_crypto::trie::{verify_state_transition, verify_trie_proof, ObjectWitness, SparseTrie, StateTransitionWitness, TrieProof, TrieProofStep};
use std::collections::BTreeMap;

#[derive(Arbitrary, Debug)]
struct Input {
    objects: Vec<(Vec<u8>, [u8; 32])>,
    absent: Vec<u8>,
    update: [u8; 32],
    raw_root: [u8; 32],
    raw_oh: Option<[u8; 32]>,
    raw_steps: Vec<(Option<u8>, Vec<(u8, [u8; 32])>)>,
}

fn segs(bytes: &[u8]) -> Vec<String> {
    bytes.iter().take(4).map(|b| format!("s{}", b % 5)).collect()
}

fuzz_target!(|input: Input| {
    // Prefix-free object set (the daemon's (path,id) mapping is meant to be).
    let mut objs: Vec<(Vec<String>, [u8; 32])> = Vec::new();
    'outer: for (k, h) in input.objects.iter().take(8) {
        let k = segs(k);
        if k.is_empty() { continue; }
        for (o, _) in &objs { if o.starts_with(&k) || k.starts_with(o) { continue 'outer; } }
        objs.push((k, *h));
    }
    let mut t = SparseTrie::new();
    for (k, h) in &objs { t.insert(k.clone(), *h); }
    let root = t.root_hash();
    let mut rev = SparseTrie::new();
    for (k, h) in objs.iter().rev() { rev.insert(k.clone(), *h); }
    assert_eq!(rev.root_hash(), root, "root depends on insertion order");
    for (k, h) in &objs {
        let p = t.generate_proof(k).expect("inclusion proof");
        assert_eq!(p.object_hash, Some(*h));
        assert!(verify_trie_proof(&p).unwrap(), "inclusion proof does not verify");
        let mut bad = p.clone();
        bad.state_root[0] ^= 1;
        assert!(!verify_trie_proof(&bad).unwrap());
    }
    let absent = segs(&input.absent);
    if !absent.is_empty() && !objs.iter().any(|(k, _)| k.starts_with(&absent) || absent.starts_with(k)) {
        let np = t.generate_nonexistence_proof(&absent).expect("non-existence proof");
        assert!(verify_trie_proof(&np).unwrap(), "non-existence proof does not verify");
        assert!(!t.contains(&absent));
        // Witness: create at `absent`, update object 0 (if any).
        let mut witnesses = vec![ObjectWitness::Create { path_segments: absent.clone(), new_object_hash: input.update, nonexistence_proof: np }];
        let mut after = objs.clone();
        after.push((absent.clone(), input.update));
        if let Some((k0, h0)) = objs.first().cloned() {
            witnesses.push(ObjectWitness::Update { path_segments: k0.clone(), old_object_hash: h0, new_object_hash: input.raw_root, inclusion_proof: t.generate_proof(&k0).unwrap() });
            after[0].1 = input.raw_root;
        }
        let w = StateTransitionWitness { prev_state_root: root, witnesses, sibling_hints: vec![] };
        let got = verify_state_transition(&w).expect("witness verifies");
        let mut u = SparseTrie::new();
        for (k, h) in &after { u.insert(k.clone(), *h); }
        assert_eq!(got, u.root_hash(), "witness root != rebuilt root");
    }
    // Totality on unstructured proofs, including a path shorter than the
    // steps (W3-8 fixed by sbo-ch88: the verifier answers Err, never panics).
    let path_segments = segs(&input.absent);
    let proof = TrieProof {
        state_root: input.raw_root,
        path_segments,
        object_hash: input.raw_oh,
        proof: input.raw_steps.iter().take(6).map(|(s, sibs)| TrieProofStep {
            segment: s.map(|b| format!("s{}", b % 5)),
            siblings: sibs.iter().take(4).map(|(k, h)| (format!("s{}", k % 5), *h)).collect::<BTreeMap<_, _>>(),
        }).collect(),
    };
    let _ = verify_trie_proof(&proof);
});
