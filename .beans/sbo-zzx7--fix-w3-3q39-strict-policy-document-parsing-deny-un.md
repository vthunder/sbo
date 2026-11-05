---
# sbo-zzx7
title: 'Fix W3-3/Q39: strict policy document parsing (deny_unknown_fields)'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T11:26:02Z
parent: sbo-ax7t
---

**Medium.** `policy/types.rs`: `Policy`, `Grant`, `Restriction`, `Requirements` accept unknown keys; `{"max_sise":5}` is an empty requirement that fails open (I11). Consensus-changing for any on-chain policy with a stray key.

Depends on: **Q39 (open)**; recommendation (a) from the regenesis. Blocked by: state-commitment v2 bundle.

- [x] `deny_unknown_fields` on all four structs; survey app 506 policies first
- [x] Acceptance (un-ignore): `audit_2026_11_ws3_policy.rs` `w3_3_unknown_policy_keys_are_rejected`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `crates/sbo-core/src/policy/types.rs`: `#[serde(deny_unknown_fields)]` on `Policy` (through its `remote = "Self"` derive, so the existing `validate.rs` pass still runs from `Deserialize`), `Grant`, `Restriction`, `Requirements`, and also `PolicyPin`, `DescendantConstraint`, `AttestedSource`, `RequirePayloadSignedBy`, `FieldCondition` and the untagged `Identity` enum, so no sub-document of a policy accepts a stray key. Nothing duplicated: the structural pass in `policy/validate.rs` is unchanged.
- Survey: the four policies in the pre-regenesis genesis fixture (`mingo-genesis-v5.wire`: root, cooks, woodworking, homelab) carry only known keys, so they parse under the strict rule; the v6 fixture (sbo-3q6x) re-signs the same documents. Policies written later on app 506 are not in this repo (mingo-side check before the regenesis).
- Un-ignored `w3_3_unknown_policy_keys_are_rejected` (ws3 policy); `unknown_action_name_rejects` still pins the `can` enum.
- Consensus-changing: part of the regenesis bundle sbo-eefz (a chain with a stray-key policy would replay differently).
