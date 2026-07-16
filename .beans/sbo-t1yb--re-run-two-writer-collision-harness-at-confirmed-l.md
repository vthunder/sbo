---
# sbo-t1yb
title: Re-run two_writer_collision harness at confirmed level once mempool ordering is fixed
status: todo
type: task
priority: normal
created_at: 2026-07-16T19:33:41Z
updated_at: 2026-07-16T19:33:41Z
blocked_by:
    - sbo-hy4r
---

Once the single-node mempool/DA ordering divergence (sbo-hy4r) is resolved, re-run the two_writer_collision production harness and verify a CLEAN confirmed-level pass.

## Why
The current harness (mingo-app/examples/two_writer_collision.rs) proved the CORE result — a member's write to another member's slot is rejected ('policy: No matching grant') — at submit AND apply time, so that stands. But steps 3/5 ('member can CREATE its own post') only proved OPTIMISTIC acceptance: A's and B's posts were disregarded at apply because they were ordered before their membership in the same block (sbo-hy4r). So the create path was never confirmed on-chain in that run.

## Scope
- Harden the harness to WAIT for each member's membership to CONFIRM (not just go pending) before posting — so the create steps confirm cleanly and the whole test is airtight end-to-end at the confirmed level.
- Re-run against prod; assert: A's post CONFIRMS (owner=A on-chain), B's overwrite rejected, B's own control post CONFIRMS, read-back occupant = A (confirmed).
- Clean up test objects (sys-delete) and note test handles (mingo-ii01).

## Blocked by
sbo-hy4r (the ordering fix). Until then, the confirmed-level create assertions will remain racy. If sbo-hy4r is deferred, the interim harness fix (wait-for-membership-confirmation) alone makes the re-test pass, but that only masks the underlying divergence.
