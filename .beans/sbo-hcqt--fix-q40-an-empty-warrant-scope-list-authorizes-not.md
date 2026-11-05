---
# sbo-hcqt
title: 'Fix Q40: an empty warrant scope list authorizes nothing'
status: todo
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Info/Low.** `scopes_authorize([])` is `true`. Nothing emits an empty list today (ledger warrants carry `sign:sbo:*`).

Depends on: **Q40 (open)**; recommendation (b).

- [ ] Code: empty list → unauthorized; Authorization spec sentence
- [ ] Acceptance: `empty_scopes_authorize_everything_today` inverts

## Decision

Q40 decided (b): an empty scope list authorizes nothing (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
