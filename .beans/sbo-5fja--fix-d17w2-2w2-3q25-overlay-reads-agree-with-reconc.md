---
# sbo-5fja
title: 'Fix D17/W2-2/W2-3/Q25: overlay reads agree with reconcile on a missing HLC; tip validation sees pending policies'
status: draft
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `pending.rs:246` `overlay_wins` lets an HLC-less pending write shadow a confirmed one that `pending_still_wins` (`:142`) then drops (W2-2); `state_view.rs:170-180` `Overlay::resolve_policy` reads the confirmed DB while `get_object` serves the pending policy, so the tip shows a policy the tip does not enforce (W2-3 = `sbo-y757`). The on-chain ordering half stays `sbo-hy4r`.

Depends on: **Q25 (open)**; recommendation (a).

- [ ] Align `overlay_wins` with `pending_still_wins`
- [ ] `Overlay::resolve_policy` resolves through the overlay (or documents that tip validation is confirmed-only and the read says so)
- [ ] Acceptance: WS2 LWW-06..08 and POL-01 out of the daemon runner's `EXPECTED_FAIL`; ws4 `d17_overlay_and_reconcile_disagree_on_missing_hlc` inverts
