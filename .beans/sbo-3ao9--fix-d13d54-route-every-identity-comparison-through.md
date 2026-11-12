---
# sbo-3ao9
title: 'Fix D13/D54: route every identity comparison through the shared helper'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:20:48Z
parent: sbo-ax7t
---

**Medium.** No normalization anywhere; `a@mingo.place@evil` is in domain `mingo.place` for `check_authority` and `mingo.place@evil` for `resolve_controller`; `/u/alice@Example.com/` aliases. July `sbo-zocd` normalization item.

Blocked by: the identity helper bean. Decision Q5 settled.

- [x] `resolve_controller`, `check_authority`, `parse_email`, `canonical_name_ref`, `Id` validation use the helper
- [x] Acceptance: WS2 `conformance/identity.json` W-ID-03/04, ID-REJ-09..12, IDC-02/06, IDD-02/04, IDR-02 out of `EXPECTED_FAIL` (core, wasm, daemon)

## Summary of Changes

- `resolve_controller`: canonicalizes an email reference (lowercase domain) before resolution, returns `Unresolved` for a malformed one, compares the primary domain and the self-affirming `EmailRooted` record with `identity::in_domain` / `identity_eq`; `is_authorized` compares the attributed email with `identity_eq`.
- `dns::parse_email` returns `(local, String domain)` via the helper (domain lowercased; two `@` → `None`). CLI caller adjusted.
- `device_attribution::check_authority` uses `identity::in_domain` (a two-`@` identity is in no domain).
- policy `canonical_name_ref` canonicalizes an `@` reference; `grant_name_matches` compares with `identity_eq`.
- EXPECTED_FAIL: W-ID-03/04, ID-REJ-09..12, IDC-02/06, IDD-02/04, IDR-02 removed from the core and wasm runners (the daemon runner carries no identity vectors).
