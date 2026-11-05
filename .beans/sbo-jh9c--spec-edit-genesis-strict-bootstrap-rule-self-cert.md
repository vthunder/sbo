---
# sbo-jh9c
title: 'Spec edit (Genesis): strict bootstrap rule, self-cert required for Mode B, batch order, genesisHash bytes, brokers.v1 shape, one genesis per anchor (Q7, Q8, Q33, Q35, Q2, S8, S19)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:22:43Z
parent: sbo-ax7t
---

`specs/SBO Genesis Specification.md` (+ the URI spec's anchor sentence): precise bootstrap window (Q7 (a), S8); self-certification required for Mode B (Q8 (a)); mode objects first and everything after the root policy validated normally (Q33, open); `genesisHash` over the bytes as included on chain, equal to the canonical serialization because non-canonical messages are invalid (Q35, open); `brokers.v1` object form (Q2 (a), S3); >1 genesis at the anchor halts (S19).

- [x] Q7, Q8, Q2, S19
- [x] Q33, Q35 (after decisions)

## Decision

Q33 decided (b), Q35 decided (a) (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

specs/SBO Genesis Specification.md: changelog; fail-closed overview sentence; Mode B is self-certifying REQUIRED (dnssec.v1 first, key must match the proven _browserid key; Q8 (a)); new §Bootstrap Window (Q7 (a)/S8: one submission at the anchor, mode objects first in order validated structurally, root policy closes the window, everything after it validated normally per Q33 (b), genesis is not an atomic exception); Mode A/B validation lists rewritten with message positions and the post-root rule; new §Failure (halting on missing/invalid prefix, genesisHash mismatch, >1 genesis at the anchor without a hash: S19; scan rule for an unanchored follow); Genesis Detection rewritten per submission with the halt rule; brokers.v1 object form and after-root placement (Q2 (a)); §genesisHash bytes redefined over the submission bytes as included on chain, equal to the canonical serialization because non-canonical messages are invalid, readers never reserialize (Q35 (a)); bootstrapping and compatibility lines updated. specs/SBO URI Specification.md: Resolution Semantics anchor sentence now says a >1-genesis anchor or hash mismatch halts (links to Genesis §Failure).
