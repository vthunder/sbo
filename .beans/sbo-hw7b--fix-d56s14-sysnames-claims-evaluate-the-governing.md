---
# sbo-hw7b
title: 'Fix D56/S14: /sys/names claims evaluate the governing policy'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:692-704` routes every `/sys/names/` write to `validate_name_claim`, which never calls `check_policy`: root-policy grants, `deny` and `not_attested` bans on names are dead text. Q14 (a).

- [ ] Run `check_policy` (Create/Update) after the anti-hijack check
- [ ] Acceptance (un-ignore): ws4 `d56_name_claim_evaluates_root_policy`
