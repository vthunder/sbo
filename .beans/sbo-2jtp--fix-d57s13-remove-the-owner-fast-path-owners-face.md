---
# sbo-2jtp
title: 'Fix D57/S13: remove the owner fast-path; owners face deny, restrictions and grants like any principal'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T11:26:02Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:745-758` and `:926-940` skip policy entirely when the signer controls the owner: a `not_attested` ban cannot stop a banned author editing their posts, a `deny` bridge lock does not hold, size caps exempt the author. Q13 (a): spec wins; the implicit owner grant becomes an explicit `to: owner` grant in presets and the root policy.

Blocked by: state-commitment v2 bundle (preset change + regenesis; survey app 506 policies first). Decision Q13 settled.

- [x] Delete the short-circuits; always `check_policy` with `signer_is_owner`
- [x] Presets carry `to: owner` grants for update/transfer/delete
- [x] Acceptance (un-ignore): ws4 `d57_owner_update_under_denied_path_is_invalid`, `d57_owner_update_ignores_restrictions`, `d57_owner_transfer_out_of_denied_path_is_invalid`

## Summary of Changes

- `crates/sbo-daemon/src/validate.rs`: the update path of `validate_post` always runs `check_policy(Update, Some(owner_ref))`; the source-authorization branch of `validate_transfer` always runs `check_policy(Transfer|Delete, Some(owner_ref))` for non-policy objects (policy objects keep the `govern` rule). `evaluate_policy_for` already derives `signer_is_owner` from the signer's control of `owner_ref`, so a `to: owner` grant admits the owner and `deny`/`restrictions` bind it. Name-claim updates keep the controller-only check and also evaluate policy (unchanged).
- Presets (`genesis`, `genesis_with_domain`, `genesis_with_domain_and_restriction`): the root policy carries `{"to": "owner", "can": ["update", "transfer", "delete"], "on": "/**"}` next to the existing `/sys/names/` and `/$owner/**` owner grants; the v6 genesis fixture (sbo-3q6x) adds the same grant to the live root policy.
- Policy resolution is nearest-ancestor (not merged), so a community policy that governs a subtree must carry its own owner grant. The live cooks/woodworking/homelab policies grant owners `update` on their spaces but not `delete`/`transfer` (moderators delete): under this rule owners cannot delete their own posts there unless mingo's policies add it. The Q13 check "every policy on app 506 still admits its owners" is mingo-side.
- Tests: un-ignored ws4 `d57_owner_update_under_denied_path_is_invalid`, `d57_owner_update_ignores_restrictions`, `d57_owner_transfer_out_of_denied_path_is_invalid`. No previously passing test pinned the fast-path.
