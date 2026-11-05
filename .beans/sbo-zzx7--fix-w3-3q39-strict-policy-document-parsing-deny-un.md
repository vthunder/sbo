---
# sbo-zzx7
title: 'Fix W3-3/Q39: strict policy document parsing (deny_unknown_fields)'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Medium.** `policy/types.rs`: `Policy`, `Grant`, `Restriction`, `Requirements` accept unknown keys; `{"max_sise":5}` is an empty requirement that fails open (I11). Consensus-changing for any on-chain policy with a stray key.

Depends on: **Q39 (open)**; recommendation (a) from the regenesis. Blocked by: state-commitment v2 bundle.

- [ ] `deny_unknown_fields` on all four structs; survey app 506 policies first
- [ ] Acceptance (un-ignore): `audit_2026_11_ws3_policy.rs` `w3_3_unknown_policy_keys_are_rejected`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
