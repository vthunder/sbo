---
# sbo-bynl
title: Circular roles cause unbounded recursion (deterministic crash-DoS)
status: todo
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-07-08T15:48:57Z
parent: sbo-f5wn
---

evaluate.rs:356-362 Role branch recurses over members with no visited-set; no policy-validation pass exists. Policy Spec Rule 3 requires rejecting circular role references. A policy with admin->mod->admin is accepted on write and stack-overflows every client that later evaluates a grant touching it — deterministic chain-wide divergence/DoS.
- [ ] Add a visited-set/cycle guard to role resolution in identity_matches
- [ ] Add a policy-validation pass that rejects circular roles on write
- [ ] Tests: cyclic role policy rejected; deep role chain bounded
