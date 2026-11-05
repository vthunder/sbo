---
# sbo-mux6
title: 'Fix W2-4/S18/Q34: checkpoint state_root accepts and emits the sha256:-prefixed form'
status: completed
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:40:22Z
parent: sbo-ax7t
---

**Low.** `trust.rs:91-103` decodes bare hex only; spec examples are `sha256:<hex>`, so a spec-shaped `checkpoint.v1` never counts as a backer.

Depends on: **Q34 (open)**; recommendation (a).

- [x] Accept both during migration, emit the prefixed form
- [x] Acceptance: WS2 CP-01, CP-03 out of `audit_2026_11_ws2_daemon.rs` `EXPECTED_FAIL`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).



## Summary of Changes

Decided Q34 (a). `trust.rs`: new `parse_state_root` accepts `sha256:<hex>` (spec) and bare hex (migration; any other prefix is `None`) and `format_state_root` emits `sha256:<hex>`; `claim_from_message` and `PendingAnchor::root_bytes` use the parser. `main.rs` emits the prefixed form in both `checkpoint.v1` (`build_checkpoint_wire`) and `checkpoint-attestation.v1` (`build_attestation_wire`), and the attestor's divergence check compares roots by value so it keeps attesting pre-Q34 bare-hex checkpoints. `bootstrap.rs`: `hex_to_32` parses either form; `evaluate_trust` compares attestation and checkpoint roots by value (`roots_equal`), so mixed-form backers still count. `/v1/sync-points` passes checkpoint / attestation roots through as found on chain (clients already parse both via `hex_to_32`).

Tests: WS2 `CP_EXPECTED_FAIL` emptied (CP-01, CP-03 now agree with the spec); new bootstrap unit test `prefixed_and_bare_roots_agree`; trust.rs test fixture emits the prefixed form.
