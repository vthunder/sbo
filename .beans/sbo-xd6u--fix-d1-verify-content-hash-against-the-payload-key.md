---
# sbo-xd6u
title: 'Fix D1: verify Content-Hash against the payload; key P2 policy versions by the verified hash'
status: todo
type: bug
priority: critical
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-04T21:31:36Z
parent: sbo-ax7t
---

**Critical.** `wire/parser.rs:169` skips Content-Hash validation; `ContentHashMismatch` is never raised; no stage of the daemon's `validate_message` recomputes it. Any relay swaps a signed write's payload (same length) and every replayer accepts it (WS8 P1). `sync.rs:1240` keys P2 policy versions by the *claimed* header hash, so a hostile policy body is filed under a benign policy's hash (WS8 P1b). July `sbo-d5nm`.

Depends on: Q11 (b) satisfied by WS8 P1/P1b. No open decision.

- [ ] In `parse_at`, when a payload is present require `Content-Hash` and reject on `sha256(payload) != header` (wire up `ParseError::ContentHashMismatch`)
- [ ] Require the content headers for `Type: object`; reject missing/extra content headers (July checklist)
- [ ] Key policy versions by the hash computed over the body, never the header
- [ ] Acceptance (un-ignore): `crates/sbo-core/tests/audit_2026_11_ws6.rs` `d1_payload_swap_on_a_signature_valid_envelope_is_rejected`, `d1_payload_without_content_hash_is_rejected`; `crates/sbo-daemon/tests/audit_2026_11_ws6.rs` `d1_daemon_rejects_a_payload_that_does_not_match_content_hash`; `audit_2026_11_ws3_wire.rs` `d1_swapped_payload_is_rejected`; WS2 W-CH-01 out of `EXPECTED_FAIL` (core, wasm)
- [ ] Invert WS8 `audit_2026_11_poc_core.rs` `poc_d1_*` to assert rejection
