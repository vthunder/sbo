---
# sbo-mwz9
title: 'Spec edit (Attribution): align §3/§4a with the device model; on-chain anchors are the trust root; monotonic evidence refresh (Q1, Q3, Q16)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:37:15Z
parent: sbo-ax7t
---

`specs/SBO Attribution Specification.md`: make §3/§4a consistent with the Authorization rewrite (Q1); state that `/sys/trust/dns-root` history is the anchor used at inclusion time (Q3); state the monotonic-freshness rule for `/sys/dnssec/<domain>` refreshes (Q16).

- [x] Q1 alignment, Q3, Q16

## Summary of Changes

specs/SBO Attribution Specification.md: changelog; §2 agent paragraph and §3 rewritten for the device presentation (access cert / assertion / warrant / config cert, one DNSSEC proof per distinct issuer, grantor/grantee effective author, no Auth-Warrant, bare keys are not owners); old §3a replaced by §3a Trust root: the /sys/trust/dns-root history entry in force at inclusion time anchors every proof, never a library-compiled root (Q3 (a)); §4 algorithm rewritten to the device verifier (per-issuer proofs, authority for grantor and grantee, join via verify_at, assertion at the authoring instant); §4a is now the SBO-side authorization (audience, scopes incl. sign:sbo and empty-list rule, effective author, status refs only at submit); §5 gains Monotonic freshness (RRSIG expiration never lowered, DNSKEY set same or newer; Q16 (a)); §6 lists dns-root first and the brokers object form.
