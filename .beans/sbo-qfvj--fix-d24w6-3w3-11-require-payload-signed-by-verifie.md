---
# sbo-qfvj
title: 'Fix D24/W6-3/W3-11: require_payload_signed_by verifies the JWT against the domain key; JWT kind claim'
status: completed
type: bug
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:36:48Z
parent: sbo-ax7t
---

**Low** today (fails closed), Medium once the path bug is fixed. `policy/evaluate.rs:253-300`: `issuer_to_path` yields `/sys/domains/<d>` without a trailing slash so every payload is denied (W6-3); behind that, only the issuer string is matched, the JWT signature is never verified. W3-11: identity and domain JWT claim types are mutually decodable.

- [x] Fix the path; load the issuer object; verify the JWT signature against its key
- [x] Add a kind/typ claim to identity and domain JWTs
- [x] Acceptance (un-ignore): ws6 core `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer`

## Summary of Changes

- `policy/evaluate.rs`: new `evaluate_with(..., signer_key: &SignerKeyLookup, ...)` (`Fn(&Path, &Id) -> Option<PublicKey>`); `evaluate` is a wrapper with a lookup that always answers `None`, so without state every `require_payload_signed_by` still denies (fail closed). `check_payload_signed_by` now maps `iss: domain:<d>` to (`/sys/domains/`, `<d>`), matches the restriction pattern against `/sys/domains/<d>/` (the W6-3 trailing-slash bug), loads the issuer key through the lookup and verifies the JWT with `verify_domain_certified_identity`; `iss: self`/unknown, a missing issuer object, or a bad signature all deny.
- Daemon `validate.rs::evaluate_policy_for` passes a lookup that reads the `/sys/domains/<d>` object, verifies its self-signed `domain.v1` JWT and returns its `public_key` (one closure + the `evaluate_with` import; the only daemon change).
- `jwt.rs` (W3-11): header `typ` is now the object kind — `identity.v1` for identity JWTs, `domain.v1` for domain JWTs (`IDENTITY_TYP`/`DOMAIN_TYP`) — and every decode/verify checks it, so the two claim sets are no longer mutually decodable and a legacy `typ: JWT` token is rejected. Consensus note: identity/domain JWTs already on a live chain lack the typ and would stop decoding on replay; this rides the Q18 regenesis like the other root-changing fixes. New unit test `identity_and_domain_tokens_are_not_mutually_decodable`.
- Un-ignored ws6 `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer` (now calls `evaluate_with` with a one-entry lookup for `/sys/domains/mingo.place`).
