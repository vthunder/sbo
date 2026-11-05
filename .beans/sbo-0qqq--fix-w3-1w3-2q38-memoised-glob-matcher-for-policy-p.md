---
# sbo-0qqq
title: 'Fix W3-1/W3-2/Q38: memoised glob matcher for policy patterns and warrant path scopes, plus a wildcard cap'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**High.** `policy/path.rs::match_parts`, `IdPattern::glob_match` and `authorize.rs::path_glob_matches` backtrack over every split: O(n^k) in wildcards. Ten `**` against 24 segments never finishes. Policy patterns need a `govern` grant; warrant `path:` scopes need only a wallet and are evaluated at the submit gate and on replay (the externally reachable DoS).

Depends on: **Q38 (open)**; recommendation (c): one O(k·n) matcher shared by core policy and `authorize.rs` plus a spec-stated wildcard cap.

- [ ] One memoised matcher; reference oracle in `audit_2026_11_ws3_policy.rs` `reference_match` and `fuzz/fuzz_targets/path_glob.rs`
- [ ] Wildcard cap enforced at policy write and scope parse; stated in Policy and Authorization specs
- [ ] Lift the wildcard guards in the `policy_json` and `path_glob` fuzz targets
- [ ] Acceptance (un-ignore): `w3_1_path_pattern_matching_is_polynomial`, `w3_1_id_pattern_matching_is_polynomial`, `w3_2_scope_path_glob_is_polynomial`

## Decision

Q38 decided (c): one memoised O(k·n) matcher shared by core policy and authorize.rs, plus a spec-stated wildcard cap (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
