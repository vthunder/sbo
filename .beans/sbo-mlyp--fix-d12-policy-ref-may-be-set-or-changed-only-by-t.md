---
# sbo-mlyp
title: 'Fix D12: Policy-Ref may be set or changed only by the object''s creator'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:2165` copies `msg.policy_ref` from any authorized updater. July `sbo-zocd`.

- [ ] Enforce the creator restriction in `message_to_stored_object` / `validate_post`
- [ ] Acceptance (un-ignore): ws4 `d12_policy_ref_is_not_changed_by_a_non_creator`
