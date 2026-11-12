---
# sbo-zom8
title: 'Fix D2/D3/Q32: canonical wire bytes helper (signing content = received header block; unknown headers reject)'
status: completed
type: task
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T10:35:50Z
parent: sbo-ax7t
blocking:
    - sbo-cusw
    - sbo-xypz
---

Shared helper for the wire-integrity group. Today the parser collects headers into a HashMap and the signature is verified over a reconstruction (`wire/parser.rs:123`, `message/validate.rs`), so any byte string that parses to the same fields verifies, and `object_hash` is taken over `wire::serialize(parsed)` instead of the received bytes. Under Q32 (a) the parser rejects any header it does not model and the signing content is the received header block minus the `Signature` line, so every accepted message is canonical and raw == reserialized.

Depends on: **Q32 (open)**. Blocks: the D2, D3 and W3-10 beans.

- [x] One helper in `sbo-core/src/wire` that returns the received header block and rejects unknown headers (Q32 (a))
- [x] `verify_message` signs/verifies that block, not a reconstruction
- [x] Acceptance: `crates/sbo-core/tests/audit_2026_11_ws6.rs` `d2_unsigned_unknown_header_is_rejected`, `d3_every_accepted_message_is_canonical`; WS2 `conformance/wire.json` W-INJ-01/02 removed from `EXPECTED_FAIL` in core + wasm runners

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

Implemented Q32 (c) as merged into the Wire Format spec (§Unknown Headers, §Canonical Header Order slots 26/27, Validation Rules 14–16):

- `wire::signing_content(bytes)`: the received header block minus the `Signature` line (which must be last), plus the blank line. `message::verify_received(msg, raw)` verifies that; nothing is reserialized. `verify_message` stays for in-memory (producer) messages and now builds its content from the same `wire::serializer::header_lines` the serializer uses, so for a parsed message the two are byte-equal.
- `Message::extra_headers: Vec<(String, String)>`: headers this implementation does not model (listed-but-unmodelled `Attestation`/`Origin`/`Proof`/…, `Critical`, `X-…`) are kept verbatim in canonical order and reserialize to their received position. Every `Message` literal in the workspace gained `extra_headers: Vec::new()`.
- `wire/headers.rs`: `HEADER_ORDER` (spec order; `Critical` at slot 26; unknown headers at slot 27 between `Critical` and `Auth-Cert`, byte-ordered among themselves), `MODELLED_HEADERS`, `header_rank`. `Auth-Warrant` stays in the order after `Auth-Evidence` until the Q1 bean removes the field.
- Parser: an unknown header before a modelled one, or out of byte order, is `ParseError::HeaderOrder`; a `Critical` header naming a header not in `MODELLED_HEADERS` is `ParseError::UnknownCriticalHeader`. Unsigned injected headers fail signature verification (they change the received block).
- `wire::serialize` is documented as producer-only; `parse_batch_raw` gives consumers the received bytes per message.
- Un-ignored: ws6 `d2_unsigned_unknown_header_is_rejected`, `d3_every_accepted_message_is_canonical`; ws3_wire `d3_unknown_header_survives_or_rejects`. W-INJ-01/02 and W-OK-05 out of `EXPECTED_FAIL` (core, wasm). New tests: `critical_header_rejects_unknown_names_and_x_headers_are_carried`, `signing_content_of_received_bytes_equals_what_the_signer_signed`, `size_bounds_reject_before_any_slice`.
- Test changed by the decision: ws6 `signature_covers_every_modelled_header` asserted that a *signed* listed-but-unmodelled `Origin` header is rejected (it was dropped at parse). Under (c) it is kept and verifies; the assertion is flipped and the unsigned variant still rejects.
