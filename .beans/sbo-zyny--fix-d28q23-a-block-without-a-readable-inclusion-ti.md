---
# sbo-zyny
title: 'Fix D28/Q23: a block without a readable inclusion time is a fetch failure, never processed'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:38:34Z
parent: sbo-ax7t
---

**Medium.** `rpc.rs:399-410` treats a missing timestamp as non-fatal; `validate.rs:2085` then evaluates attestations at `t = 0` (bans lift) and skips the HLC bound. WS2 TIME-01: two nodes on the same chain data disagree about a banned writer.

Depends on: **Q23 (open)**; recommendation (a).

- [x] Missing timestamp → retry like 'block not available'
- [x] Acceptance (un-ignore): ws4 `d28_unknown_inclusion_time_does_not_lift_a_ban`, `d28_unknown_inclusion_time_does_not_skip_the_hlc_bound`; WS2 TIME-01 out of the daemon runner's `EXPECTED_FAIL`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `rpc.rs::fetch_block_data_for_app_ids`: a block whose `timestamp.set` inherent cannot be read returns `DaemonError::Rpc` instead of `timestamp: None`; `process_block` propagates it and the sync loop's existing error branch leaves the head unchanged and retries next cycle, exactly like "block not available". The block is never processed without its inclusion time.
- Defence in depth for any caller that still builds an `L2Context` with `inclusion_time: None`: `check_hlc_bound` rejects an HLC-bearing write (Ordering) and `attested_subject_matches` returns a state error (`ValidationStage::State`) instead of evaluating at `t = 0`; email-rooted attribution already failed closed.
- Tests that pinned the old fail-open behaviour were changed (decision Q23 (a)): `l2_authorization.rs` `ctx()` now carries a fixed inclusion time, and `hlc_bound_gates_writes` expects an Ordering reject without a timestamp.
- Un-ignored `d28_unknown_inclusion_time_does_not_lift_a_ban`, `d28_unknown_inclusion_time_does_not_skip_the_hlc_bound`; `TIME-01/no-timestamp` removed from the ws2 daemon runner's `EXPECTED_FAIL`.
