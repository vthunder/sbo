---
# sbo-zom8
title: 'Fix D2/D3/Q32: canonical wire bytes helper (signing content = received header block; unknown headers reject)'
status: draft
type: task
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-ax7t
blocking:
    - sbo-cusw
    - sbo-xypz
---

Shared helper for the wire-integrity group. Today the parser collects headers into a HashMap and the signature is verified over a reconstruction (`wire/parser.rs:123`, `message/validate.rs`), so any byte string that parses to the same fields verifies, and `object_hash` is taken over `wire::serialize(parsed)` instead of the received bytes. Under Q32 (a) the parser rejects any header it does not model and the signing content is the received header block minus the `Signature` line, so every accepted message is canonical and raw == reserialized.

Depends on: **Q32 (open)**. Blocks: the D2, D3 and W3-10 beans.

- [ ] One helper in `sbo-core/src/wire` that returns the received header block and rejects unknown headers (Q32 (a))
- [ ] `verify_message` signs/verifies that block, not a reconstruction
- [ ] Acceptance: `crates/sbo-core/tests/audit_2026_11_ws6.rs` `d2_unsigned_unknown_header_is_rejected`, `d3_every_accepted_message_is_canonical`; WS2 `conformance/wire.json` W-INJ-01/02 removed from `EXPECTED_FAIL` in core + wasm runners
