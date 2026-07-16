---
# sbo-whfw
title: 'P1: govern is a distinct capability; policy objects governed by parent'
status: completed
type: feature
priority: normal
created_at: 2026-07-16T23:39:50Z
updated_at: 2026-07-16T23:59:53Z
parent: sbo-orvt
---

Part of sbo-orvt. Closes the sbo-vos1 capture bug.

- Add a `govern` permission, NOT implied by `create`/`post`/`*` (governance is meta-authority, outside the content action set — lean: a permission string the wildcard never covers, decide vs new ActionType).
- Writing/updating a `policy.v2` object requires `govern` on the target path, resolved against the nearest policy STRICTLY ABOVE the target (parent), never the target's own policy.
- Removes self-governing lock-in: an ancestor can always replace/delete a descendant policy (absent a pin — see P2).

## Todos
- [x] Introduce `govern` permission in policy types + evaluate
- [x] Gate policy.v2 writes in validate: require govern, resolve at parent
- [x] Ensure `*` / post / create do NOT confer govern
- [x] Tests: member with create cannot install a policy; parent-govern can; self-lock-in gone

## Summary of Changes

- `ActionType::Govern` added (sbo-core policy/types.rs); `action_covered_by` makes govern matchable ONLY by an explicit `govern` grant — `*`/`post`/`create` never confer it (evaluate.rs).
- Daemon (validate.rs): `is_policy_write`/`is_policy_object` (content_schema==policy.v2); `require_govern` resolves the policy at the PARENT container (`parent_container_path`) and requires a `govern` grant matching the policy object own path (owner fast-path bypassed). Wired into validate_post (create+update of a policy) and validate_transfer/delete (delete/relocate of a policy object → reversibility for an ancestor with govern).
- Tests: govern coverage (evaluate.rs); daemon capture-attack blocked (`member_create_grant_cannot_install_shadowing_policy`), admin-govern authorizes + stranger denied (`admin_govern_authorizes_community_policy_write_stranger_denied`). Full workspace suite green.
- Closes sbo-vos1. NOTE: deploying this daemon requires a matched regenesis — the existing chain has post-genesis sys policy updates that the new govern rule would reject on replay.
