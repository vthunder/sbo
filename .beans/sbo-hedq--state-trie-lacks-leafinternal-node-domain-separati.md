---
# sbo-hedq
title: State trie lacks leaf/internal node domain separation
status: todo
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-07-08T15:48:57Z
parent: sbo-f5wn
---

trie.rs SparseTrie::compute_hash returns the bare object_hash for a Leaf with no prefix, so a 32-byte value is indistinguishable as a leaf-object vs a subtree hash — second-preimage resistance goal (State Commitment spec) not met.
- [ ] Add 0x00/0x01 (leaf/internal) domain-separation tags to node hashing
- [ ] Migration/version note since it changes the root
