---
# sbo-sla3
title: 'Fix D10: validate policies on write (cycles, unknown kinds, patterns) and bound role resolution'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-04T21:31:37Z
parent: sbo-ax7t
---

**High.** `policy/evaluate.rs:342-380` recurses through `Role` and `Any` with no visited set or depth bound; no validation pass on write. A cyclic policy on chain crashes every evaluating node (WS8 P6, WS3 200k-deep chain). July `sbo-bynl`. Q17 (a).

No open decision.

- [ ] Policy-validation pass on `policy.v2` write: cycles, unknown identity kinds, bad patterns reject
- [ ] Visited set + depth bound in `identity_matches`
- [ ] Acceptance (un-ignore): ws6 core `d10_cyclic_role_policy_does_not_crash_the_evaluator`, `d10_cyclic_role_policy_is_rejected_at_parse`; `audit_2026_11_ws3_role_cycle.rs` `d10_cyclic_roles_terminate`, `d10_self_referencing_role_terminates`, `d10_role_chain_depth_is_bounded`; invert WS8 `poc_d10_*`
