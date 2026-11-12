---
# sbo-0qqq
title: 'Fix W3-1/W3-2/Q38: memoised glob matcher for policy patterns and warrant path scopes, plus a wildcard cap'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T10:36:09Z
parent: sbo-ax7t
---

**High.** `policy/path.rs::match_parts`, `IdPattern::glob_match` and `authorize.rs::path_glob_matches` backtrack over every split: O(n^k) in wildcards. Ten `**` against 24 segments never finishes. Policy patterns need a `govern` grant; warrant `path:` scopes need only a wallet and are evaluated at the submit gate and on replay (the externally reachable DoS).

Depends on: **Q38 (open)**; recommendation (c): one O(k·n) matcher shared by core policy and `authorize.rs` plus a spec-stated wildcard cap.

- [x] One memoised matcher; reference oracle in `audit_2026_11_ws3_policy.rs` `reference_match` and `fuzz/fuzz_targets/path_glob.rs`
- [x] Wildcard cap enforced at policy write and scope parse; stated in Policy and Authorization specs
- [x] Lift the wildcard guards in the `policy_json` and `path_glob` fuzz targets
- [x] Acceptance (un-ignore): `w3_1_path_pattern_matching_is_polynomial`, `w3_1_id_pattern_matching_is_polynomial`, `w3_2_scope_path_glob_is_polynomial`

## Decision

Q38 decided (c): one memoised O(k·n) matcher shared by core policy and authorize.rs, plus a spec-stated wildcard cap (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- New `crates/sbo-core/src/policy/glob.rs`: one memoised O(k·n) matcher for segment globs (`segments_match`, `*`/`**`) and char globs (`chars_match`), plus `MAX_WILDCARDS = 32` and the wildcard counters. `PathPattern`, `IdPattern` (`policy/path.rs`) and `authorize.rs::path_glob_matches` all route through it; the three backtracking matchers are gone. Char matching compares by `char`, so the old byte-slice panic on multi-byte ids is gone too.
- Cap enforcement: a policy pattern (`deny`, grant/restriction `on`, `id`, descendant-constraint templates, `require_payload_signed_by.path`) over 32 wildcard segments / `*` chars rejects at parse (`policy/validate.rs`, shared with sbo-sla3); a warrant `path:` scope over the cap makes `scopes_authorize` return false (fail closed). Spec sentences for the cap are carried by sbo-skvm (Policy) and sbo-xs2u (Authorization); the constants were sent to the specs agent.
- Fuzz: lifted the `<= 3` wildcard guards and the ASCII guard in `fuzz/fuzz_targets/path_glob.rs` (scope assertions run only under the cap, since over-cap scopes fail closed by design); removed the `wild()` skip in `policy_json.rs`.
- Un-ignored `w3_1_path_pattern_matching_is_polynomial`, `w3_1_id_pattern_matching_is_polynomial`, `w3_2_scope_path_glob_is_polynomial`.
