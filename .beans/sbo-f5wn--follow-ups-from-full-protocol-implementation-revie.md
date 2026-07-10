---
# sbo-f5wn
title: Follow-ups from full protocol + implementation review (2026-07-08)
status: todo
type: epic
priority: high
created_at: 2026-07-08T15:47:59Z
updated_at: 2026-07-08T15:47:59Z
---

Tracked follow-up work from the comprehensive SBO protocol/implementation review. See task sbo-ix77 for the review itself. Children cover critical enforcement holes (Content-Hash, zkVM validity, bare-key ownership, genesis), high-severity spec/impl divergences (pinned root KSK, circular-role DoS, domain self-cert warn-only, object_hash, signature reconstruction, trie domain separation, DA trust), and medium items. Design core is sound; the gap is spec-vs-impl enforcement.
