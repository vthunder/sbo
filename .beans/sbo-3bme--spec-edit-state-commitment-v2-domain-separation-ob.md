---
# sbo-3bme
title: 'Spec edit (State Commitment): v2 — domain separation, object-vs-container rule, raw bytes, state_root form (Q18, D4, W3-4, Q34)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:25:10Z
parent: sbo-ax7t
---

`specs/SBO State Commitment Specification.md`: version bump to v2 with migration note (Q18); leaf/internal domain separation (D4); one rule for an object at a prefix of another's segments (W3-4); `object_hash` over the bytes as included (with Q32/Q35); `state_root` wire form `sha256:<hex>` (Q34, open).

- [x] D4, W3-4, Q18 text
- [x] Q34 (after decision)

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

specs/SBO State Commitment Specification.md: changelog entry for state-commitment/v2 (root-changing) with the earlier entries marked as v1; object_hash defined over the bytes as included on chain with a Never-a-reserialization paragraph tied to Wire Q32 (c) and Genesis Q35; node format gains an optional object member; new §Domain Separation (leaf = sha256(0x00 || object_hash), node = sha256(0x01 || json)); new §Object Versus Container (both coexist, order-independent root, collapse rule); node serialization and examples updated; new §Wire Form (state_root and every hash on the wire is sha256:<hex>, bare hex is not a claim; Q34 (a)) and checkpoint field row; post/delete update algorithms and inclusion/subtree verification rewritten for v2 with bounds-checking note; new §Migration from v1 (regenesis, no cross-version acceptance). Docs only; the code change is sbo-39qi/sbo-xypz/sbo-mux6 under sbo-eefz.
