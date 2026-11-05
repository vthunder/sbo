---
# sbo-flzk
title: 'Fix Q41: empty-state root is node_hash of the empty node, not the zero sentinel'
status: todo
type: task
priority: high
created_at: 2026-11-05T11:12:24Z
updated_at: 2026-11-05T11:12:24Z
parent: sbo-ax7t
blocked_by:
    - sbo-39qi
---

Decided 2026-11-05 (Dan): Q41 (a), code follows the State Commitment spec v2. The empty-state root becomes node_hash({"children":{}}) (sha256(0x01 || json)) everywhere the all-zero 32-byte sentinel is used today: sbo-crypto trie (SparseTrie/PartialTrie root of an empty trie), the pinned test empty_trie_conventions, conformance vector TRIE-04, the daemon genesis/sync path, snapshots, and the zkVM guest. Root-changing; part of the regenesis bundle sbo-eefz. See docs/state-commitment-v2-migration.md and Q41 in docs/security-audit-2026-11-decisions.md.

- [ ] Trie: empty root = hash of the empty node; remove the sentinel special case
- [ ] Daemon genesis/sync/snapshot paths and zkVM guest use the same rule
- [ ] empty_trie_conventions re-pinned; TRIE-04 regenerated; migration note updated
- [ ] cargo test --workspace green on localtest
