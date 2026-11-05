---
# sbo-prqd
title: 'Fix D15: trust gate degrade fallback after the bounded wait'
status: completed
type: bug
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:38:44Z
parent: sbo-ax7t
---

**Low.** `trust.rs` / `main.rs:1690-1700`: `timeout_blocks` bounds the wait but stops sync and keeps reads refused; the spec's degrade fallback is unimplemented. July `sbo-zocd`.

- [x] Implement the spec's bounded-wait/degrade rule (or document the stop as the chosen behaviour)
- [x] Extend `d15_enforcing_gate_stays_gated_without_claims`

## Summary of Changes

- Chosen behaviour, now documented in code and config: on exhaustion of the bounded wait (`trust.timeout_blocks`) the daemon REPORTS trust not established — sync stops and the gate stays closed. It does not degrade to a weaker policy or fall back to an older checkpoint (the spec leaves the choice to the deployment; a fast-synced node that cannot verify its anchor serves nothing rather than something it cannot vouch for).
- `TrustGate::wait_exhausted(block, timeout_blocks)` encodes the rule (gated, timeout > 0, block > anchor + timeout; saturating) and `main.rs` uses it instead of the inline arithmetic; the error log tells the operator what to do (new anchor or full replay). `TrustConfig::timeout_blocks` doc updated.
- `d15_enforcing_gate_stays_gated_without_claims` extended: exhaustion boundaries, a wrong-root claim does not count, exhaustion never opens the gate or invents backers, only the pinned attestor's claim for the anchor root promotes.
