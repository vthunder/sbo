---
# sbo-c46r
title: 'Fix D7: reject a domain.v1 whose DNSSEC self-certification fails, at validation time'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T10:19:55Z
parent: sbo-ax7t
---

**High.** `sync.rs:1294-1312` evaluates the self-cert after the write is applied and only `warn!`s; `validate_message` never reads the evidence, so the submit gate never sees it either. WS8 P3: garbage evidence + domain.v1 accepted, able to certify sys. Identity spec Rule 4 is a MUST. July `sbo-3gqo` (the shadowing half is closed by global uniqueness).

No open decision.

- [x] Move the check into `validate_message`: fetch the referenced `dnssec.v1`, `verify_domain_self_cert` at inclusion time, reject on error
- [x] Acceptance (un-ignore): `crates/sbo-daemon/tests/audit_2026_11_ws4.rs` `d7_domain_with_failing_self_cert_is_invalid`; invert WS8 `poc_d7_*`

## Summary of Changes

- `validate.rs`: new step 2.7 `check_domain_self_cert` runs for every `domain.v1` Post: resolves the evidence from the message `Auth-Evidence` (`inline:`/`ref:`), else the conventional `/sys/dnssec/<domain>` as-of this block; absent evidence = plain self-signed; present evidence must pass `verify_domain_self_cert` at inclusion time or the write is `Invalid(Attribution)`. Evidence present but no inclusion time = reject (fail closed). Submit gate and apply path both go through this.
- `sync.rs`: the warn-only post-apply check is removed (info log only).
- Tests: `d7_domain_with_failing_self_cert_is_invalid` un-ignored; WS8 `poc_d7_*` inverted to `poc_d7_failing_self_cert_domain_is_rejected` (plants the garbage evidence directly in state since the write gate already refuses it).
