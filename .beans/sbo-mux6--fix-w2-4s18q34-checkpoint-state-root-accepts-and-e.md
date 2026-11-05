---
# sbo-mux6
title: 'Fix W2-4/S18/Q34: checkpoint state_root accepts and emits the sha256:-prefixed form'
status: todo
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Low.** `trust.rs:91-103` decodes bare hex only; spec examples are `sha256:<hex>`, so a spec-shaped `checkpoint.v1` never counts as a backer.

Depends on: **Q34 (open)**; recommendation (a).

- [ ] Accept both during migration, emit the prefixed form
- [ ] Acceptance: WS2 CP-01, CP-03 out of `audit_2026_11_ws2_daemon.rs` `EXPECTED_FAIL`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
