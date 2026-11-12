---
# sbo-evne
title: 'Fix D6/S4: make /sys/trust/dns-root the DNSSEC trust anchor (patch dnssec-prover to take anchors)'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T10:44:23Z
parent: sbo-ax7t
---

**High.** `dnssec-prover 0.6.8` validates against compiled-in `root_hints()` and `verify_rr_stream` takes no anchors; `load_trust_anchors` never reads `/sys/trust/dns-root`. A governance rollover changes nothing and replay diverges across library versions. July `sbo-y5ek`. Q3 (a).

Blocked by: the W6-5 fixture bean. No open decision.

- [x] Fork/patch `dnssec-prover` to accept trust anchors (and note alg 15 absence, W6-2)
- [x] Read `/sys/trust/dns-root` history at inclusion time; verify `valid_from`/`valid_until` against inclusion time
- [x] Acceptance: new test `AUDIT-2026-11 D6` — a chain rooted at a non-IANA key validates when pinned and rejects when not; rollover history spans old+new evidence

## Summary of Changes

- Patched validator: see `sbo-ospt` (vendored `dnssec-prover` with `verify_rr_stream_with_anchors`; alg 15 still absent, W6-2).
- `sbo-daemon/validate.rs` `load_trust_anchors` reads `/sys/trust/dns-root` (`dns-root.v1`) as of the block into `L2Context.anchors`; the verifier selects the key(s) whose `valid_from`/`valid_until` contain the inclusion time (`TrustAnchors::root_anchors_at`). A pinned history with no active key fails closed (`NoActiveRootAnchor`); an unparseable object pins an empty history (fail closed). **Fallback:** a repository with no `/sys/trust/dns-root` at all keeps validating against the library's compiled-in IANA anchors (documented on `TrustAnchors::root_keys`) — the mingo genesis does not yet carry the object, so this keeps it working; once governance posts it, it is used exclusively and a rollover is a governance write.
- Threaded through every DNSSEC consumer: user attribution (`device_attribution::verify_device_attribution` now passes anchors + inclusion time), domain self-certification (D7 gate), and the `dnssec_proof` policy restriction via the additive `policy::evaluate_with_dnssec(..., Option<&DnssecContext>)` (`evaluate` forwards `None`, so no existing caller changed).
- Acceptance `AUDIT-2026-11 D6`: `sbo-core/tests/audit_2026_11_dnssec.rs` (`d6_*`: non-IANA root validates when pinned / rejects when not; rollover history spans old+new evidence; self-cert) and `sbo-daemon/tests/audit_2026_11_dnssec.rs` (`d6_*`: `/sys/dnssec` write and `domain.v1` self-cert end to end through `validate_message`, history window checked at inclusion time).
