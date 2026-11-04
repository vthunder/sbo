---
# sbo-x2a5
title: 'Spec edit (Core): owner is a principal, dot segments invalid, ASCII-only ids, submit gates are advisory (Q13, Q24, Q37, S20)'
status: draft
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-04T21:36:02Z
parent: sbo-ax7t
---

`specs/SBO Specification.md`: owner updates are policy-evaluated like any principal, with the explicit default grant (Q13); `.` and `..` are not valid ids / segments (Q24, open); drop the percent-encoding sentence (Q37, open); add the §Validity Layers paragraph that submit-time gates are advisory and replay validation is the only boundary (S20).

- [ ] Q13, S20
- [ ] Q24, Q37 (after decisions)
