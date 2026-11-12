---
# sbo-f5wn
title: Follow-ups from full protocol + implementation review (2026-07-08)
status: completed
type: epic
priority: high
created_at: 2026-07-08T15:47:59Z
updated_at: 2026-11-04T21:35:03Z
---

Tracked follow-up work from the comprehensive SBO protocol/implementation review. See task sbo-ix77 for the review itself. Children cover critical enforcement holes (Content-Hash, zkVM validity, bare-key ownership, genesis), high-severity spec/impl divergences (pinned root KSK, circular-role DoS, domain self-cert warn-only, object_hash, signature reconstruction, trie domain separation, DA trust), and medium items. Design core is sound; the gap is spec-vs-impl enforcement.

## Summary of Changes

Closed 2026-11-04 by the security audit epic sbo-ax7t: every child was re-verified (all still open at 30e267c) and re-filed as a remediation bean with an ignored `AUDIT-2026-11` acceptance test; sbo-5rww and sbo-7bl8 moved under sbo-ax7t as deferred trackers (Q19, Q20). Ledger: `docs/security-audit-2026-11.md` §4.
