---
# sbo-whfw
title: 'P1: govern is a distinct capability; policy objects governed by parent'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T23:39:50Z
updated_at: 2026-07-16T23:40:25Z
parent: sbo-orvt
---

Part of sbo-orvt. Closes the sbo-vos1 capture bug.

- Add a `govern` permission, NOT implied by `create`/`post`/`*` (governance is meta-authority, outside the content action set — lean: a permission string the wildcard never covers, decide vs new ActionType).
- Writing/updating a `policy.v2` object requires `govern` on the target path, resolved against the nearest policy STRICTLY ABOVE the target (parent), never the target's own policy.
- Removes self-governing lock-in: an ancestor can always replace/delete a descendant policy (absent a pin — see P2).

## Todos
- [ ] Introduce `govern` permission in policy types + evaluate
- [ ] Gate policy.v2 writes in validate: require govern, resolve at parent
- [ ] Ensure `*` / post / create do NOT confer govern
- [ ] Tests: member with create cannot install a policy; parent-govern can; self-lock-in gone
