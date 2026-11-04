---
# sbo-35bs
title: 'Fix D8/D49/Q19: mark sbo-zkvm experimental with no trust claim'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:36:02Z
parent: sbo-ax7t
---

**Info this round** (Critical as a trust claim). The guest proves a trie transition over some data: `_actions_hash` discarded, witnesses never derived from `actions_data`, `header_data: None` yields a zero data root, any `prev_state_root` trusted on a first proof (D8, July `sbo-5rww`); unchecked arithmetic in `verify_app_completeness` (D49). Q19 (a).

- [ ] README, crates/README and the ZK design doc / State Commitment spec: experimental, feature-gated, carries no validity claim
- [ ] Keep `sbo-5rww` as the deferred tracker for real remediation

Pairs with the ZK doc-edit bean (see the SPEC_ZK bean under sbo-ax7t).
