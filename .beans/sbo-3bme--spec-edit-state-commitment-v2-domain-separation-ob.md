---
# sbo-3bme
title: 'Spec edit (State Commitment): v2 — domain separation, object-vs-container rule, raw bytes, state_root form (Q18, D4, W3-4, Q34)'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

`specs/SBO State Commitment Specification.md`: version bump to v2 with migration note (Q18); leaf/internal domain separation (D4); one rule for an object at a prefix of another's segments (W3-4); `object_hash` over the bytes as included (with Q32/Q35); `state_root` wire form `sha256:<hex>` (Q34, open).

- [ ] D4, W3-4, Q18 text
- [ ] Q34 (after decision)

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
