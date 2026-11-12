---
# sbo-cusw
title: 'Fix D2/S22/W6-1/D30: reject non-canonical wire (order, duplicates, Content-Length, hex) and use verify_strict'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T10:35:50Z
parent: sbo-ax7t
---

**High.** `parser.rs:123-130` drops header order and takes the last duplicate; `:159` accepts `+2`/`002`; uppercase hex accepted; both ed25519 wrappers use non-strict `verify` (small-order key = universal forgery, W6-1). A duplicate `Path:` is read differently by first-wins and last-wins parsers (WS2 W-DUP). July `sbo-h75z`.

Blocked by: the canonical-bytes helper bean (Q32 open). Decision: Q32.

- [x] Enforce canonical header order and uniqueness on parse (reject, do not reorder)
- [x] `Content-Length` as canonical decimal; lowercase hex only in `Public-Key`, `Signature`, `Content-Hash`
- [x] `verify_strict` in `sbo-core/src/crypto/ed25519.rs` and `sbo-crypto/src/ed25519.rs` (or one wrapper)
- [x] Acceptance (un-ignore): ws6 `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected`, `d2_uppercase_hex_is_rejected`, `w6_1_small_order_public_key_universal_signature_is_rejected`; ws3_wire `d2_*` (3); WS2 W-ORD-01, W-DUP-01/02, W-CL-01/02, W-HEX-01/02, ED-REJ-04 out of `EXPECTED_FAIL`

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `wire/parser.rs` `check_canonical_form`: a repeated header name is `ParseError::DuplicateHeader`; headers out of the canonical order (listed headers by list position, unknown headers in slot 27 in byte order) are `ParseError::HeaderOrder`. The parser never reorders.
- `Content-Length` must be a canonical decimal (digits only, no sign, no leading zero, ≤ 19 digits) — Validation Rule 12; `+2`, `002`, ` 5` and empty reject.
- Hex in `Public-Key`, `Signature` and `Content-Hash` must be lowercase (Rule 10); reserved `secp256k1`/`keccak256` prefixes reject as unknown algorithms (Rule 11).
- `verify_strict` in both `sbo-core/src/crypto/ed25519.rs` and `sbo-crypto/src/ed25519.rs` (W6-1: small-order keys/R rejected).
- Un-ignored: ws6 `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected`, `d2_uppercase_hex_is_rejected`, `w6_1_small_order_public_key_universal_signature_is_rejected`; ws3_wire `d2_*` (3). W-ORD-01, W-DUP-01/02, W-CL-01/02, W-HEX-01/02 and ED-REJ-04 out of `EXPECTED_FAIL` in the core, wasm and sbo-crypto runners.
