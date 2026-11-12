---
# sbo-8j2t
title: 'Spec note (Core, Identity): internationalized identifiers via IDNA-style A-labels (Q37 route 2)'
status: draft
type: task
priority: deferred
created_at: 2026-11-05T08:40:30Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

Agreed path if internationalized addresses are ever wanted (Dan, 2026-11-05, Q37 zoom-out in docs/security-audit-2026-11-decisions.md). Unicode path segments and identity local parts are carried on chain as xn-- punycode A-labels after UTS #46 mapping and NFC; clients render the U-label; comparison stays byte-exact ASCII; confusable policy (mixed script, skeleton match) is a collection policy rule. No wire change. Not scheduled; open only when a product need appears.

- [ ] Core spec §Identifier Syntax: A-label rule and rendering note
- [ ] Identity spec: extend the Q5 A-label rule from domains to local parts
- [ ] Conformance vectors for A-label round trip
