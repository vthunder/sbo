---
# sbo-2jtp
title: 'Fix D57/S13: remove the owner fast-path; owners face deny, restrictions and grants like any principal'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:745-758` and `:926-940` skip policy entirely when the signer controls the owner: a `not_attested` ban cannot stop a banned author editing their posts, a `deny` bridge lock does not hold, size caps exempt the author. Q13 (a): spec wins; the implicit owner grant becomes an explicit `to: owner` grant in presets and the root policy.

Blocked by: state-commitment v2 bundle (preset change + regenesis; survey app 506 policies first). Decision Q13 settled.

- [ ] Delete the short-circuits; always `check_policy` with `signer_is_owner`
- [ ] Presets carry `to: owner` grants for update/transfer/delete
- [ ] Acceptance (un-ignore): ws4 `d57_owner_update_under_denied_path_is_invalid`, `d57_owner_update_ignores_restrictions`, `d57_owner_transfer_out_of_denied_path_is_invalid`
