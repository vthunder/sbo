---
# sbo-vos1
title: 'Policy install is unprivileged: member can plant a shadowing policy and capture a subtree'
status: completed
type: bug
priority: high
created_at: 2026-07-16T21:55:38Z
updated_at: 2026-07-17T00:27:32Z
blocked_by:
    - sbo-orvt
---

Writing a `policy.v2` object is treated as an ordinary object create — there is no gate on WHO may install a policy. Combined with deepest-ancestor policy resolution (winner-take-all, no merge), any principal with a `create` grant on a subtree can install a policy that shadows the governing policy for that subtree, escalate their own rights, escape restrictions (e.g. bans), and lock governance out irreversibly.

## Impact (LIVE on the deployed mingo chain)

The community policy grants `role:member` `create` on `/communities/<id>/spaces/**`. Any member can therefore:
1. Create a `policy.v2` object at e.g. `/communities/cooks/spaces/general/x/` — authorized by the ordinary member `create` grant.
2. `put_policy` indexes it at its own container path; `resolve_policy` now returns it FIRST (deepest ancestor) for that subtree, shadowing the community policy wholesale (no merge, restrictions come only from the resolved policy — so the community `not_attested: ban` restriction disappears in that subtree).
3. Grant themselves `update`/`delete`/`transfer` on other members' objects there.
4. They OWN the planted policy, so the owner fast-path lets them keep amending it; and an admin delete of it resolves against the planted policy itself (self-governing) which grants admin nothing — so the capture is effectively irreversible from within the repo's governance.

Collection `_config` schema does NOT block this: `collection.v1.schema` is descriptive metadata; the only consumer is `collection_max_lag_ms` (reads only `max_authoring_lag_s`). A `policy.v2` payload into a `post.v1` collection is not rejected.

## Evidence (file:line)

- `crates/sbo-core/src/state/db.rs:160` `resolve_policy` — walks `path.ancestors()`, returns FIRST match, no merge; root only as fallback.
- `crates/sbo-core/src/message/envelope.rs:147` `ancestors()` includes self → policies are self-governing.
- `crates/sbo-daemon/src/sync.rs:1197` — unconditional `put_policy(msg.path, policy)` on any successful `policy.v2` apply.
- `crates/sbo-daemon/src/validate.rs` — `validate_post`/`validate_message` have NO special-casing of `policy.v2` writes (the two refs at :1042/:1121 are test fixtures). Create is authorized by the parent policy's ordinary `create` grant.
- `crates/sbo-core/src/policy/evaluate.rs:78` — restrictions iterate only the single resolved policy; ancestor/root restrictions not consulted.
- Spec specified the missing guardrail but it was not implemented: `SBO Specification.md:239` "May only set or update Policy-Ref if the object is owned by the creator of the object." The impl dropped the Policy-Ref-on-collection model for self-indexing policy.v2 objects and the install gate went with it.

## No test coverage

No test exercises member-initiated policy installation or policy-write authorization. `l2_authorization.rs` nested-policy tests install policies out-of-band via `db.put_policy` in test setup, never through a member write.

## Fix direction (to be designed — see brainstorm)

Gate policy installation: a `policy.v2` write must be authorized by the PARENT policy (resolve at parent, not self), and/or require a dedicated policy-write permission that ordinary `create` grants do not confer. Re-introduce the spec's ownership/authority gate at install time. Do NOT change the live chain policy until the install-gate lands.

## Resolution path (2026-07-17)

Superseded by the full delegation design in sbo-orvt (do NOT ship a standalone minimal patch — greenfield, no live users, so we fix it properly). The capture bug is closed by P1 there: `govern` becomes a distinct capability not implied by `create`/`post`/`*`, and a policy object is governed by its PARENT policy rather than itself. Members holding only `create` can no longer install a shadowing policy, and self-governing lock-in is gone. Blocked-by sbo-orvt.

## RESOLVED LIVE (2026-07-17)
Fixed by P1 (sbo-whfw, rev 4b28d8e) and deployed via regenesis v5 (mingo-qjkf) @ block 3623864. The live community policies grant members create+owner-update with NO govern, and `*` no longer confers govern, so the plant-a-shadowing-policy capture is dead on the live chain. Verified by daemon integration test member_create_grant_cannot_install_shadowing_policy.
