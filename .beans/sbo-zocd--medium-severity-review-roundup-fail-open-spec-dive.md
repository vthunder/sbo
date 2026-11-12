---
# sbo-zocd
title: Medium-severity review roundup (fail-open + spec divergences)
status: scrapped
type: task
priority: normal
created_at: 2026-07-08T15:49:22Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

Medium items from the 2026-07-08 SBO review, grouped so none are lost.

- [ ] Policy-Ref set/update ownership restriction unenforced: spec (post) says may only set/update Policy-Ref if owned by the object's creator; validate.rs:1204 just copies msg.policy_ref. Any authorized updater can repoint to an arbitrary policy.
- [ ] Negative attestation checks fail open on DB error: validate.rs:1136 unwrap_or_default() — a state-read error makes not_attested:{type:'ban'} treat a banned user as un-banned, while the rest of the daemon fails closed.
- [ ] No email/name normalization: Alice@X vs alice@x are distinct identities; /sys/names/Alice vs alice separately squattable (resolve.rs:88, envelope.rs:60). Add case-folding + Unicode/percent handling; homograph/case-variant squatting.
- [ ] Bootstrap-proof trust hole: a single proof can start at an arbitrary block with unproven prev_state_root (guest/main.rs:184); only verify_proof_chain forces genesis, so a light client verifying one proof trusts an unproven anchor.
- [ ] URI percent-decoding missing (uri.rs:239-290); an id containing ':' is mis-split with no escaping path (uri.rs:322).
- [ ] No liveness fallback in the trust gate: TrustGate stays gated forever if threshold never met (trust.rs); spec's bounded-wait/degrade fallback unimplemented.
- [ ] Legacy owner_ref fallback to ephemeral signer key (validate.rs:871) — post-rotation mismatch; only legacy objects.
- [ ] verify_kzg_proof stub (kzg.rs:154) — tracked under sbo-7bl8 too.

## Reasons for Scrapping

Every item re-verified and re-filed by the 2026-11 audit: Policy-Ref → sbo-mlyp (D12); not_attested fail-open → sbo-slsm (D11); email/name normalization → sbo-lv2x + sbo-3ao9 (D13/Q5); bootstrap-proof trust hole → sbo-35bs (D8/Q19) and sbo-syib (D26); URI percent-decoding / ':' → sbo-jijr (D14/Q37); trust-gate liveness → sbo-prqd (D15); legacy owner fallback → sbo-yd72 (Q6); KZG stub → sbo-db6p (D9).
