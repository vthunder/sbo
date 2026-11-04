---
# sbo-syib
title: 'Fix D26/D27/D34/W4-2: fast-sync trusts only signed checkpoints by pinned keys; verify snapshot policy_versions'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**High.** `bootstrap.rs:62-66` counts `sys-checkpointer` as a backer with no claim read; `:252-262` adopts the manifest's root (`RootTrust::ServingNode`); `:128-135` loads `policy_versions` unverified while the doc comment claims a hash check (W4-2). `bootstrap.rs:24` names the authority while `trust.rs` pins keys (D34). WS8 P5: a hostile serving node chooses the client's state and its frozen governance. Q12 (a).

No open decision.

- [ ] A root counts only with a `checkpoint.v1` signed by a pinned key (from chain or manifest, re-verified); `sys-checkpointer` becomes a pinned key
- [ ] Remove `bootstrap_provisional` or gate it behind `--trust-serving-node`
- [ ] Reconstruct `policy_versions` from covered objects or verify each against its content hash; fix the comment
- [ ] Acceptance (un-ignore): ws4 `d26_authority_does_not_back_a_root_without_a_signed_checkpoint`, `d27_snapshot_policy_versions_are_verified_against_their_hash`; invert WS8 `poc_d26_*`, `poc_d27_*`
