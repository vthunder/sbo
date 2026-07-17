---
# sbo-yxm5
title: 'P4: no-pin restriction (force tracking / strict hierarchy)'
status: completed
type: feature
priority: normal
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-17T00:23:01Z
parent: sbo-orvt
blocked_by:
    - sbo-723r
---

Part of sbo-orvt. The strict top-down / unix-fs regime knob.

- A policy may forbid its direct children from pinning, forcing them to always track latest → ancestor (admin) always dominates and can retighten at will.
- mingo does NOT use this; hierarchical-FS-style tenants would.

## Todos
- [ ] policy schema: no-pin flag on descendant-constraint clause
- [ ] validate: reject a pinned child policy where parent forbids pinning
- [ ] tests: forbidden-pin child rejected; tracking child accepted



## Resolution (done, commit db14faf)
Added `descendant_constraint.forbid_pinning` flag. A pinned direct child under a forbidding parent is rejected at the Policy stage (evaluated against the current latest parent, the ancestor's live retightening lever). Tests: forbidden-pin child rejected, tracking child accepted.
