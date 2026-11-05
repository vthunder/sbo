---
# sbo-5fja
title: 'Fix D17/W2-2/W2-3/Q25: overlay reads agree with reconcile on a missing HLC; tip validation sees pending policies'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:38:38Z
parent: sbo-ax7t
---

**Medium.** `pending.rs:246` `overlay_wins` lets an HLC-less pending write shadow a confirmed one that `pending_still_wins` (`:142`) then drops (W2-2); `state_view.rs:170-180` `Overlay::resolve_policy` reads the confirmed DB while `get_object` serves the pending policy, so the tip shows a policy the tip does not enforce (W2-3 = `sbo-y757`). The on-chain ordering half stays `sbo-hy4r`.

Depends on: **Q25 (open)**; recommendation (a).

- [x] Align `overlay_wins` with `pending_still_wins`
- [x] `Overlay::resolve_policy` resolves through the overlay (or documents that tip validation is confirmed-only and the read says so)
- [x] Acceptance: WS2 LWW-06..08 and POL-01 out of the daemon runner's `EXPECTED_FAIL`; ws4 `d17_overlay_and_reconcile_disagree_on_missing_hlc` inverts

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `pending::overlay_wins` is now the same rule as `pending_still_wins` (Q25 (a)): the pending side wins only when both carry a parseable HLC and it wins the LWW order; on a missing or unparseable HLC the confirmed value is authoritative for reads as it is for reconciliation. The tip never shows a value reconciliation is about to drop.
- `Overlay::resolve_policy` / `resolve_policy_entry` resolve THROUGH the overlay: the same ancestor walk as `StateDb::resolve_policy_entry` (nearest ancestor, then `/sys/policies/`), preferring at each level a pending `policy.v2` object that wins the read merge for its slot over the confirmed index entry (`StateDb::get_policy_entry_at`, new exact-level lookup). Tip validation now enforces the policy the tip shows (W2-3 / `sbo-y757`).
- ws2 runner: LWW-06..08 and POL-01 removed from `EXPECTED_FAIL`. The POL-01 fixture's confirmed root now carries an HLC, since under LWW-07 a pending shadow never beats an HLC-less on-chain value. ws4 `d17_overlay_and_reconcile_disagree_on_missing_hlc` inverted (asserts agreement). Two new unit tests in `state_view.rs`.
- The on-chain ordering half stays `sbo-hy4r`.
