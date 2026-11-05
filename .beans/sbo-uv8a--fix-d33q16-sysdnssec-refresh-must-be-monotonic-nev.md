---
# sbo-uv8a
title: 'Fix D33/Q16: /sys/dnssec refresh must be monotonic (never lower the incumbent''s RRSIG expiration or DNSKEY set)'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:44:23Z
parent: sbo-ax7t
---

**Medium.** `policy/evaluate.rs:224-250` checks validity only; any party can replace the proof with an older valid chain or a pre-rotation key still inside its window. Q16 (a).

Blocked by: the W6-5 fixture bean (needs an offline chain to test).

- [x] Compare the new proof's RRSIG expiration and DNSKEY set against the incumbent's in the dnssec policy path
- [x] Acceptance: new test `AUDIT-2026-11 D33` over the fixture

## Summary of Changes

- `attribution::dnssec_proof_freshness` reports a validated proof's RRSIG window and the `<domain>.` DNSKEY RRset's RRSIG inception + key tags; `check_dnssec_refresh_monotonic` rejects a replacement whose expiration is older than the incumbent's or whose DNSKEY set was signed earlier (a pre-rotation set still inside its window). Equal values pass (idempotent re-post).
- `sbo-daemon/validate.rs` step 2.8 `check_dnssec_refresh_monotonic`: for a `dnssec.v1` Post onto an existing `(path, id)` both proofs are validated against the pinned anchors at the block's inclusion time and compared; rejection is `Invalid(Policy)` with a `rollback` reason. An incumbent that no longer validates (e.g. after a root rollover) does not block the refresh; a first write has no rule. Kept in the daemon (which has state) rather than in `policy/evaluate.rs`, which only sees the message.
- Acceptance `AUDIT-2026-11 D33`: `sbo-core/tests/audit_2026_11_dnssec.rs` `d33_*` (verifier level) and `sbo-daemon/tests/audit_2026_11_dnssec_refresh.rs` `d33_*` (through `validate_message`, over synthetic chains).
