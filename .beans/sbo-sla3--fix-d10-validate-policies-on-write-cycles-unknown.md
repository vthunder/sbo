---
# sbo-sla3
title: 'Fix D10: validate policies on write (cycles, unknown kinds, patterns) and bound role resolution'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T10:36:48Z
parent: sbo-ax7t
---

**High.** `policy/evaluate.rs:342-380` recurses through `Role` and `Any` with no visited set or depth bound; no validation pass on write. A cyclic policy on chain crashes every evaluating node (WS8 P6, WS3 200k-deep chain). July `sbo-bynl`. Q17 (a).

No open decision.

- [x] Policy-validation pass on `policy.v2` write: cycles, unknown identity kinds, bad patterns reject
- [x] Visited set + depth bound in `identity_matches`
- [x] Acceptance (un-ignore): ws6 core `d10_cyclic_role_policy_does_not_crash_the_evaluator`, `d10_cyclic_role_policy_is_rejected_at_parse`; `audit_2026_11_ws3_role_cycle.rs` `d10_cyclic_roles_terminate`, `d10_self_referencing_role_terminates`, `d10_role_chain_depth_is_bounded`; invert WS8 `poc_d10_*`

## Summary of Changes

- New `crates/sbo-core/src/policy/validate.rs`: `validate(&Policy)` rejects a role cycle (incl. self-reference, through `any` nesting), a `{"role": x}` naming an undefined role, a role chain deeper than `MAX_ROLE_DEPTH = 32`, a non-absolute path pattern, and any pattern over the wildcard cap (sbo-0qqq). Iterative DFS, so the validator itself never recurses. `Policy` now derives with `#[serde(remote = "Self")]` and its `Deserialize` impl runs the pass, so every `policy.v2` write (daemon `sync.rs`/`bootstrap.rs`/`db.rs` all go through serde) rejects at parse. Exported as `policy::validate_policy`, `PolicyError`, `MAX_ROLE_DEPTH`.
- `policy/evaluate.rs::identity_matches`: carries the stack of roles being resolved; a role already on it (cycle) or a depth past `MAX_ROLE_DEPTH` (an `any` level counts) is no match, so a cyclic policy that reaches the evaluator by any route terminates with a denial.
- Tests: un-ignored ws6 `d10_cyclic_role_policy_does_not_crash_the_evaluator` (its child now builds the cyclic policy in code, since the document no longer parses — this is deliberate: the evaluator bound is what it tests) and `d10_cyclic_role_policy_is_rejected_at_parse`; ws3 `d10_cyclic_roles_terminate`, `d10_self_referencing_role_terminates`, `d10_role_chain_depth_is_bounded` (200k chain rejects at parse in ~2s). WS8 `poc_d10_role_cycle_crashes_the_evaluator` inverted (child must exit cleanly; asserts parse rejection + in-code denial). `tests/state_test.rs` fixture gained a `roles.member` definition (it referenced an undefined role, now a parse error).
- Spec statement (Rule 3 cycle rejection + depth bound) is carried by sbo-skvm.
