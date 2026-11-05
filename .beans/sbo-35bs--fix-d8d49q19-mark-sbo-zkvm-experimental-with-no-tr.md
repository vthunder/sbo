---
# sbo-35bs
title: 'Fix D8/D49/Q19: mark sbo-zkvm experimental with no trust claim'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:40:00Z
parent: sbo-ax7t
---

**Info this round** (Critical as a trust claim). The guest proves a trie transition over some data: `_actions_hash` discarded, witnesses never derived from `actions_data`, `header_data: None` yields a zero data root, any `prev_state_root` trusted on a first proof (D8, July `sbo-5rww`); unchecked arithmetic in `verify_app_completeness` (D49). Q19 (a).

- [x] README, crates/README and the ZK design doc / State Commitment spec: experimental, feature-gated, carries no validity claim
- [x] Keep `sbo-5rww` as the deferred tracker for real remediation

Pairs with the ZK doc-edit bean (see the SPEC_ZK bean under sbo-ax7t).

## Summary of Changes

specs/SBO State Commitment Specification.md: T1-zk tier row marked as a design slot only (no client may place itself in it today). crates/sbo-zkvm/src/lib.rs: crate-level doc comment (Experimental, no validity claim; D8/D49/Q19; sbo-5rww) - comment only, no behaviour change. README/crates/README/ZK design doc edits landed under sbo-a90r. sbo-5rww stays open as the deferred remediation tracker (bind witness to actions_data, SBO validation in the guest, assert the data root, pin the genesis root, checked arithmetic in verify_app_completeness).
