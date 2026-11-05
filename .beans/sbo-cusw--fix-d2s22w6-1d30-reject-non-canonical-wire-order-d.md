---
# sbo-cusw
title: 'Fix D2/S22/W6-1/D30: reject non-canonical wire (order, duplicates, Content-Length, hex) and use verify_strict'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**High.** `parser.rs:123-130` drops header order and takes the last duplicate; `:159` accepts `+2`/`002`; uppercase hex accepted; both ed25519 wrappers use non-strict `verify` (small-order key = universal forgery, W6-1). A duplicate `Path:` is read differently by first-wins and last-wins parsers (WS2 W-DUP). July `sbo-h75z`.

Blocked by: the canonical-bytes helper bean (Q32 open). Decision: Q32.

- [ ] Enforce canonical header order and uniqueness on parse (reject, do not reorder)
- [ ] `Content-Length` as canonical decimal; lowercase hex only in `Public-Key`, `Signature`, `Content-Hash`
- [ ] `verify_strict` in `sbo-core/src/crypto/ed25519.rs` and `sbo-crypto/src/ed25519.rs` (or one wrapper)
- [ ] Acceptance (un-ignore): ws6 `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected`, `d2_uppercase_hex_is_rejected`, `w6_1_small_order_public_key_universal_signature_is_rejected`; ws3_wire `d2_*` (3); WS2 W-ORD-01, W-DUP-01/02, W-CL-01/02, W-HEX-01/02, ED-REJ-04 out of `EXPECTED_FAIL`

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
