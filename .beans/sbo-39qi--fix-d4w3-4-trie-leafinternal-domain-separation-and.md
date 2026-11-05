---
# sbo-39qi
title: 'Fix D4/W3-4: trie leaf/internal domain separation and the object-versus-container rule'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T10:54:47Z
parent: sbo-ax7t
---

**High.** `sbo-crypto/src/trie.rs` hashes a leaf to its bare `object_hash` and an internal node to `sha256(json)`; an object whose hash equals a subtree hash commits to the same root (WS6 `d4_*`, WS2 TRIE-03 across all four trie implementations). W3-4: an object at a strict prefix of another's segments evicts it from every root and proof. July `sbo-hedq`.

Blocked by: state-commitment v2 bundle (Q18 (a), root change). No open decision.

- [x] Prefix leaf and internal preimages (`0x00`/`0x01`) in `SparseTrie`, `PartialTrie::compute_node_hash`, `compute_trie_root`
- [x] One rule for object-vs-container collisions (forbid at validation or key leaves distinctly); state it in the State Commitment spec
- [x] Acceptance (un-ignore): `crates/sbo-crypto/tests/audit_2026_11_ws6.rs` `d4_leaf_and_internal_node_hashes_are_domain_separated`; `audit_2026_11_ws3_trie.rs` `d4_leaf_and_subtree_commit_to_different_roots`, `w3_4_prefix_paths_coexist_in_the_commitment`; WS2 TRIE-03 out of `EXPECTED_FAIL` (crypto, daemon)

## Summary of Changes

Implements State Commitment spec v2 (`state-commitment/v2`) in the one place
that hashes trie nodes, `crates/sbo-crypto/src/trie.rs`; sbo-core proofs,
the daemon state root, snapshots, sync witnesses and the zkVM guest all go
through it.

- Domain separation: `leaf_hash(h) = sha256(0x00 || h)`, `TrieNode::hash() =
  sha256(0x01 || canonical_json)`; `TrieNode::commitment()` picks the form
  (an object with no children is a leaf). `leaf_hash` is exported.
- Object-versus-container: `TrieNode` gains `object: Option<[u8;32]>`
  (serialized after `children`); `SparseTrie` / `PartialTrie` nodes carry an
  object beside their children, nothing is evicted, roots are order
  independent, deleting the last child collapses the node to a leaf.
- Proofs: `TrieProofStep` gains `object` (object at that level's node) and
  `children` (final step of an inclusion proof whose target is a container),
  both optional and omitted on the wire when absent; `TrieProofStep::new`
  for the plain form. Non-existence of a container without an object is a
  trailing `segment: null` step listing its children. Verifier checks
  segment/path agreement on every step, rejects an empty path, a followed
  segment that is also a sibling, and `children` on a non-final step.
- SBOQ (`sbo-core/src/proof/sboq.rs`) parses and emits the two new members.
- Conformance: `conformance/trie.json` regenerated (all roots change; new
  TRIE-05 object-and-container vector); `TRIE-03/distinct` removed from
  `EXPECTED_FAIL` in sbo-crypto (daemon runner had none). Un-ignored:
  `d4_leaf_and_internal_node_hashes_are_domain_separated`,
  `d4_leaf_and_subtree_commit_to_different_roots`,
  `w3_4_prefix_paths_coexist_in_the_commitment`.
- Kept: zero empty-root convention (`[0u8;32]`), pinned by
  `empty_trie_conventions`, TRIE-04 and the daemon/zkVM genesis path. The v2
  spec text says the empty root is `node_hash({"children":{}})`; aligning
  that is a separate root-changing decision, noted in the migration note.

