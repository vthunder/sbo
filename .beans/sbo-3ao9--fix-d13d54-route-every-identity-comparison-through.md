---
# sbo-3ao9
title: 'Fix D13/D54: route every identity comparison through the shared helper'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** No normalization anywhere; `a@mingo.place@evil` is in domain `mingo.place` for `check_authority` and `mingo.place@evil` for `resolve_controller`; `/u/alice@Example.com/` aliases. July `sbo-zocd` normalization item.

Blocked by: the identity helper bean. Decision Q5 settled.

- [ ] `resolve_controller`, `check_authority`, `parse_email`, `canonical_name_ref`, `Id` validation use the helper
- [ ] Acceptance: WS2 `conformance/identity.json` W-ID-03/04, ID-REJ-09..12, IDC-02/06, IDD-02/04, IDR-02 out of `EXPECTED_FAIL` (core, wasm, daemon)
