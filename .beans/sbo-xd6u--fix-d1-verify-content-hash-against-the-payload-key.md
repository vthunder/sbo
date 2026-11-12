---
# sbo-xd6u
title: 'Fix D1: verify Content-Hash against the payload; key P2 policy versions by the verified hash'
status: completed
type: bug
priority: critical
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T10:35:50Z
parent: sbo-ax7t
---

**Critical.** `wire/parser.rs:169` skips Content-Hash validation; `ContentHashMismatch` is never raised; no stage of the daemon's `validate_message` recomputes it. Any relay swaps a signed write's payload (same length) and every replayer accepts it (WS8 P1). `sync.rs:1240` keys P2 policy versions by the *claimed* header hash, so a hostile policy body is filed under a benign policy's hash (WS8 P1b). July `sbo-d5nm`.

Depends on: Q11 (b) satisfied by WS8 P1/P1b. No open decision.

- [x] In `parse_at`, when a payload is present require `Content-Hash` and reject on `sha256(payload) != header` (wire up `ParseError::ContentHashMismatch`)
- [x] Require the content headers for `Type: object`; reject missing/extra content headers (July checklist)
- [x] Key policy versions by the hash computed over the body, never the header
- [x] Acceptance (un-ignore): `crates/sbo-core/tests/audit_2026_11_ws6.rs` `d1_payload_swap_on_a_signature_valid_envelope_is_rejected`, `d1_payload_without_content_hash_is_rejected`; `crates/sbo-daemon/tests/audit_2026_11_ws6.rs` `d1_daemon_rejects_a_payload_that_does_not_match_content_hash`; `audit_2026_11_ws3_wire.rs` `d1_swapped_payload_is_rejected`; WS2 W-CH-01 out of `EXPECTED_FAIL` (core, wasm)
- [x] Invert WS8 `audit_2026_11_poc_core.rs` `poc_d1_*` to assert rejection

## Summary of Changes

- `sbo-core/src/wire/parser.rs`: with a payload (`Content-Length` present) `Content-Hash` is required and `sha256(payload)` must equal it (`ParseError::ContentHashMismatch`); `Content-Hash`, `Content-Type` or `Content-Encoding` without `Content-Length` reject; `post` + `Type: object` requires `Content-Length`.
- `sbo-daemon/src/validate.rs` `validate_message`: recomputes `Content-Hash` after the signature check (step 1.5), so an in-memory message with a swapped payload is `Invalid` even without going through the parser.
- `sbo-daemon/src/sync.rs`: P2 policy versions are indexed under `sha256(body)`, never the header value.
- Un-ignored: core ws6 `d1_payload_swap_on_a_signature_valid_envelope_is_rejected`, `d1_payload_without_content_hash_is_rejected`; ws3_wire `d1_swapped_payload_is_rejected`; daemon ws6 `d1_daemon_rejects_a_payload_that_does_not_match_content_hash`. W-CH-01 out of `EXPECTED_FAIL` (core, wasm). WS8 PoCs inverted: `poc_d1_payload_swap_is_rejected_by_the_daemon_gate`, `poc_d1_policy_version_with_a_mismatched_hash_is_rejected`.
- Fixtures that carried dummy hashes now carry real ones: `tests/wire_parser_test.rs`, `wire/mod.rs` related tests, daemon `submit_queue.rs` tests.
