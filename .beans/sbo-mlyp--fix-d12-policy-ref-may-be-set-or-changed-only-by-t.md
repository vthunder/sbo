---
# sbo-mlyp
title: 'Fix D12: Policy-Ref may be set or changed only by the object''s creator'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:38:23Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:2165` copies `msg.policy_ref` from any authorized updater. July `sbo-zocd`.

- [x] Enforce the creator restriction in `message_to_stored_object` / `validate_post`
- [x] Acceptance (un-ignore): ws4 `d12_policy_ref_is_not_changed_by_a_non_creator`

## Summary of Changes

- `validate_post`: on an update to an occupied slot, a `Policy-Ref` header that differs from the stored one is `Invalid { stage: Policy }` unless the signer resolves (`resolve_creator`) to the object's immutable creator. The controller/owner fast-path and `update` grants no longer let anyone else repoint it.
- `message_to_stored_object`: for an update by a non-creator the stored `policy_ref` is carried forward unchanged (belt and braces for callers that store without the validator's verdict).
- Un-ignored `d12_policy_ref_is_not_changed_by_a_non_creator`.
