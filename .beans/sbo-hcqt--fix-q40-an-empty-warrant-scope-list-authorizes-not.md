---
# sbo-hcqt
title: 'Fix Q40: an empty warrant scope list authorizes nothing'
status: completed
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:36:09Z
parent: sbo-ax7t
---

**Info/Low.** `scopes_authorize([])` is `true`. Nothing emits an empty list today (ledger warrants carry `sign:sbo:*`).

Depends on: **Q40 (open)**; recommendation (b).

- [x] Code: empty list → unauthorized; Authorization spec sentence
- [x] Acceptance: `empty_scopes_authorize_everything_today` inverts

## Decision

Q40 decided (b): an empty scope list authorizes nothing (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `crates/sbo-core/src/authorize.rs`: `scopes_authorize` returns false for an empty scope list (doc comment states Q40 (b)); the Authorization spec sentence is carried by sbo-xs2u (specs agent informed).
- Tests changed because the decision changed the pinned behaviour: `empty_scopes_authorize_everything_today` → `empty_scopes_authorize_nothing` (inverted); `reference_scopes` oracle and `adding_a_scope_never_widens` (base list now non-empty) in `audit_2026_11_ws3_time_scopes.rs`; `plain_user_write_with_empty_scopes_is_unconstrained` → `..._is_unauthorized` in `tests/agent_write.rs` (also asserts the same write passes under `sign:sbo:post`); the empty-scope case in the `authorize.rs` unit test.
