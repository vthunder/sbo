---
# sbo-bynl
title: Circular roles cause unbounded recursion (deterministic crash-DoS)
status: scrapped
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

evaluate.rs:356-362 Role branch recurses over members with no visited-set; no policy-validation pass exists. Policy Spec Rule 3 requires rejecting circular role references. A policy with admin->mod->admin is accepted on write and stack-overflows every client that later evaluates a grant touching it — deterministic chain-wide divergence/DoS.
- [ ] Add a visited-set/cycle guard to role resolution in identity_matches
- [ ] Add a policy-validation pass that rejects circular roles on write
- [ ] Tests: cyclic role policy rejected; deep role chain bounded

## Reasons for Scrapping

Superseded by sbo-sla3 (audit 2026-11 D10). Every unchecked item above is carried in that bean's checklist; the finding was re-verified by the 2026-11 audit and is encoded as an ignored `AUDIT-2026-11` test there.
