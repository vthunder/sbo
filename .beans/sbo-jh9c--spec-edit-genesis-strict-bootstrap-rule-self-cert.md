---
# sbo-jh9c
title: 'Spec edit (Genesis): strict bootstrap rule, self-cert required for Mode B, batch order, genesisHash bytes, brokers.v1 shape, one genesis per anchor (Q7, Q8, Q33, Q35, Q2, S8, S19)'
status: draft
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-04T21:36:02Z
parent: sbo-ax7t
---

`specs/SBO Genesis Specification.md` (+ the URI spec's anchor sentence): precise bootstrap window (Q7 (a), S8); self-certification required for Mode B (Q8 (a)); mode objects first and everything after the root policy validated normally (Q33, open); `genesisHash` over the bytes as included on chain, equal to the canonical serialization because non-canonical messages are invalid (Q35, open); `brokers.v1` object form (Q2 (a), S3); >1 genesis at the anchor halts (S19).

- [ ] Q7, Q8, Q2, S19
- [ ] Q33, Q35 (after decisions)
