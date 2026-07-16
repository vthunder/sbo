---
# sbo-vqzj
title: 'P3: descendant-policy constraint clause (direct children)'
status: todo
type: feature
priority: normal
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-16T23:40:25Z
parent: sbo-orvt
blocked_by:
    - sbo-723r
---

Part of sbo-orvt. The declarative ceiling/template.

- A parent policy may declare allowed grants + mandated restrictions for its DIRECT child policies (decided: direct-children-only; each level re-delegates its own template downward, keeping checks local).
- Validated at child create/update: child grants subset-of template; mandated restrictions present.
- Expresses e.g. "any user under /users/* may grant a,b,c but must carry restriction z".

## Todos
- [ ] policy schema: descendant-constraint clause
- [ ] validate child policy against parent's clause (grants subset, mandated restrictions present)
- [ ] byte-exact freezing semantics for reserved/mandated entries under a pin (coordinate with P2)
- [ ] tests: over-broad child grant rejected; missing mandated restriction rejected; direct-only scoping
