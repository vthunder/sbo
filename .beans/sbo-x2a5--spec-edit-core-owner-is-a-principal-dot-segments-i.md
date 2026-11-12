---
# sbo-x2a5
title: 'Spec edit (Core): owner is a principal, dot segments invalid, ASCII-only ids, submit gates are advisory (Q13, Q24, Q37, S20)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:34:04Z
parent: sbo-ax7t
---

`specs/SBO Specification.md`: owner updates are policy-evaluated like any principal, with the explicit default grant (Q13); `.` and `..` are not valid ids / segments (Q24, open); drop the percent-encoding sentence (Q37, open); add the §Validity Layers paragraph that submit-time gates are advisory and replay validation is the only boundary (S20).

- [x] Q13, S20
- [x] Q24, Q37 (after decisions)

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

specs/SBO Specification.md: changelog; Identifier Syntax: ASCII-only paragraph replaces the percent-encoding sentence (Q37 (a)), dot-segment rule (. and .. invalid; Q24 (a)) in prose and ABNF, object-vs-container coexistence note pointing at State Commitment v2 and the collision-free mirror layout; Validity Layers gains the submit-time-gates-are-advisory paragraph (S20); Object Ownership and Authorization states the owner is a principal with an explicit default grant and post/transfer/delete rules say the owner's own action is policy-evaluated (Q13 (a)); Public-Key example moved to ed25519.
