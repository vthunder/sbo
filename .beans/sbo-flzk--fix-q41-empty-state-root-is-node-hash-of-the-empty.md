---
# sbo-flzk
title: 'Fix Q41: empty-state root is node_hash of the empty node, not the zero sentinel'
status: completed
type: task
priority: high
created_at: 2026-11-05T11:12:24Z
updated_at: 2026-11-05T11:12:45Z
parent: sbo-ax7t
blocked_by:
    - sbo-39qi
---

Decided 2026-11-05 (Dan): Q41 (a), code follows the State Commitment spec v2. The empty-state root becomes node_hash({"children":{}}) (sha256(0x01 || json)) everywhere the all-zero 32-byte sentinel is used today: sbo-crypto trie (SparseTrie/PartialTrie root of an empty trie), the pinned test empty_trie_conventions, conformance vector TRIE-04, the daemon genesis/sync path, snapshots, and the zkVM guest. Root-changing; part of the regenesis bundle sbo-eefz. See docs/state-commitment-v2-migration.md and Q41 in docs/security-audit-2026-11-decisions.md.

- [x] Trie: empty root = hash of the empty node; remove the sentinel special case
- [x] Daemon genesis/sync/snapshot paths and zkVM guest use the same rule
- [x] empty_trie_conventions re-pinned; TRIE-04 regenerated; migration note updated
- [x] cargo test --workspace green on localtest

## Summary of Changes

- `sbo_crypto::trie::empty_root()` = `TrieNode::new().hash()` =
  `sha256(0x01 || {"children":{}})` (6f2225cc...3d8c); re-exported from
  sbo-crypto and sbo-core. SparseTrie/PartialTrie empty root, the
  `PartialTrie::new` "no root known" case, `StateTransitionWitness::default`
  and both empty-state branches of `verify_trie_proof` use it; the zero
  sentinel is gone from trie.rs.
- Daemon: `StateDb::compute_trie_state_root` and `compute_snapshot_root`
  drop their empty-set early return (the trie gives the same answer);
  `sync.rs` genesis pre-root, bootstrap-proof check, no-repo result and
  post-root fallback; `main.rs` state-root/sync-points views and the prover
  pre-root fallback.
- zkVM: `BlockProofOutput::EMPTY_STATE_ROOT` pinned to the new constant
  (unit test asserts it equals `empty_root()`); `BlockProofInput::default`,
  `prove_genesis*`, the guest genesis check and the recursion test use it.
- Tests/vectors: `empty_trie_conventions` re-pinned (hash of the empty node,
  not zero); ws2 crypto runner seeds `PartialTrie` with `empty_root()`;
  ws3 daemon snapshot property updated; TRIE-04 regenerated.
- `docs/state-commitment-v2-migration.md` updated (Q41 row and paragraph).
- `cargo test --workspace`: 645 pass / 0 fail / 17 ignored.

