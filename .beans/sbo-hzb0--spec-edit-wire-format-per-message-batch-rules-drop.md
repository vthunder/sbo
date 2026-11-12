---
# sbo-hzb0
title: 'Spec edit (Wire Format): per-message batch rules, drop Auth-Warrant from canonical order, unknown headers reject, ed25519/sha256 REQUIRED, bounds (Q4, S2, Q32, S21, S22, W3-10)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:20:43Z
parent: sbo-ax7t
---

`specs/SBO Wire Format Specification.md`: replace §Batch Submissions atomicity with the eight Q4 rules (parse-as-unit, strict order with state threading, rejected message invisible, LWW loser is valid, index tiebreak, per-block root, genesis not an exception, submit-time validation for all-or-nothing); remove `Auth-Warrant` from the canonical order (S2); unknown headers are valid iff signed and placed after the modelled headers, consumers never reserialize, `Critical` header, `X-` experimental prefix (Q32 (c)); mark `ed25519`/`sha256` REQUIRED and `secp256k1`/`keccak256` reserved (S21); restate encoding rules as MUST-reject (S22); bound `Content-Length` and the batch size (W3-10).

- [x] Q4 rules
- [x] S2, S21, S22
- [x] Q32 sentence (after decision)

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05).

## Summary of Changes

specs/SBO Wire Format Specification.md: §Atomicity replaced by §Per-Message Validation and Ordering (the eight Q4 rules); new §Size Bounds (MAX_MESSAGE_BYTES 2 MiB, MAX_SUBMISSION_BYTES 4 MiB, MAX_HEADER_BLOCK_BYTES 64 KiB, checked arithmetic, W3-10) and the parse pseudocode bounds-checks Content-Length; Auth-Warrant stated as not a header and absent from the canonical order (S2); new §Unknown Headers (Q32 (c): valid iff signed and after the modelled headers, Critical header, X- prefix), canonical order gains Critical and the unknown-header slot; §Signed Content redefined as the received header block minus the Signature line, verification pseudocode no longer reconstructs, new §Consumers Never Reserialize; ed25519/sha256 REQUIRED and secp256k1/keccak256 reserved (S21), examples moved to ed25519; encoding rules restated as MUST-reject with canonical-integer and lowercase-hex rows (S22); Validation Rules 10-16 added/updated; changelog entry. Docs only, no code.
