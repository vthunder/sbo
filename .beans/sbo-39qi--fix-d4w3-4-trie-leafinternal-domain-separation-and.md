---
# sbo-39qi
title: 'Fix D4/W3-4: trie leaf/internal domain separation and the object-versus-container rule'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-04T21:31:36Z
parent: sbo-ax7t
---

**High.** `sbo-crypto/src/trie.rs` hashes a leaf to its bare `object_hash` and an internal node to `sha256(json)`; an object whose hash equals a subtree hash commits to the same root (WS6 `d4_*`, WS2 TRIE-03 across all four trie implementations). W3-4: an object at a strict prefix of another's segments evicts it from every root and proof. July `sbo-hedq`.

Blocked by: state-commitment v2 bundle (Q18 (a), root change). No open decision.

- [ ] Prefix leaf and internal preimages (`0x00`/`0x01`) in `SparseTrie`, `PartialTrie::compute_node_hash`, `compute_trie_root`
- [ ] One rule for object-vs-container collisions (forbid at validation or key leaves distinctly); state it in the State Commitment spec
- [ ] Acceptance (un-ignore): `crates/sbo-crypto/tests/audit_2026_11_ws6.rs` `d4_leaf_and_internal_node_hashes_are_domain_separated`; `audit_2026_11_ws3_trie.rs` `d4_leaf_and_subtree_commit_to_different_roots`, `w3_4_prefix_paths_coexist_in_the_commitment`; WS2 TRIE-03 out of `EXPECTED_FAIL` (crypto, daemon)
