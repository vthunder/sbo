---
# sbo-4tka
title: by-qualified attested lookup blind to /u/ namespace — moderator roles + bans never resolved
status: completed
type: bug
priority: high
created_at: 2026-07-17T08:44:56Z
updated_at: 2026-07-17T08:44:56Z
---

Found by the mingo live-test runner (S6 moderator-delete failing live despite a confirmed attestation).

## Cause
`attested_subject_matches` (crates/sbo-daemon/src/validate.rs) narrowed candidates for a `by`-qualified attested source by prefix-scanning `/<by>/attestations/`. But the per-candidate check already verifies the issuer resolves to `by` (owner_ref), so the prefix was only an optimization — and it silently missed issuers whose attestations live elsewhere. mingo stores attestations at `/u/<issuer>/attestations/` (genesis grants owner `/u/$owner/**`), so every `by`-qualified role (moderator: `by: <commId>@mingo.place`) and every `not_attested{by}` ban never resolved. `by`-less roles (membership) use a path-independent schema scan, which masked the bug.

## Impact (was LIVE)
Moderator-delete (mingo-n268) was denied on the live chain despite a valid, confirmed moderator attestation. Bans equally broken.

## Fix
Gather candidates by schema scan (`list_objects_by_schema("attestation.v1")`) for both the `by` and `by`-less cases; the existing per-candidate issuer filter (resolve owner_ref == by) enforces correctness regardless of storage layout. Regression test `by_qualified_attested_resolves_under_u_namespace` added. Full workspace suite green (361). Committed b6ac8ba, deployed to da.sandmill.org (SBO_REV b6ac8ba).

## Summary of Changes
crates/sbo-daemon/src/validate.rs attested_subject_matches — layout-independent candidate gathering + regression test.
