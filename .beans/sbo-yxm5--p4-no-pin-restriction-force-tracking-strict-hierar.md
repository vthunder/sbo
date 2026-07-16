---
# sbo-yxm5
title: 'P4: no-pin restriction (force tracking / strict hierarchy)'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-16T23:40:25Z
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
