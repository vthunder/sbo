---
# sbo-hw7b
title: 'Fix D56/S14: /sys/names claims evaluate the governing policy'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:23:31Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:692-704` routes every `/sys/names/` write to `validate_name_claim`, which never calls `check_policy`: root-policy grants, `deny` and `not_attested` bans on names are dead text. Q14 (a).

- [x] Run `check_policy` (Create/Update) after the anti-hijack check
- [x] Acceptance (un-ignore): ws4 `d56_name_claim_evaluates_root_policy`

## Summary of Changes

- `validate_name_claim` now calls `check_policy` after the anti-hijack check: `Create` (no owner) for a new claim, `Update` (owner = the stored controller) for a controller update. Genesis mode (no root policy) stays policy-free.
- The shipped root-policy presets (`crates/sbo-core/src/presets.rs`) and the `policy_vars` test fixture granted `on: "/sys/names/*"`, which under the Policy spec (`on` matches the container path, never the id) matches nothing; changed to `on: "/sys/names/"`. The `genesis_with_domain_and_restriction` restriction on `/sys/names/` is live as a consequence.
- Deployment note: the live mingo genesis (`crates/sbo-core/tests/fixtures/mingo-genesis-v5.wire`) grants `/sys/names/*`, so once this daemon is deployed new name claims there are denied until the root policy is amended (govern) to `/sys/names/`. The Genesis spec example has the same pattern; reported to the spec agent.
- Un-ignored `d56_name_claim_evaluates_root_policy`.
