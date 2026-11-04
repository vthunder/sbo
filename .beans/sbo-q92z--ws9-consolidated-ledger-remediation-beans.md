---
# sbo-q92z
title: 'WS9: consolidated ledger + remediation beans'
status: in-progress
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-04T21:27:26Z
parent: sbo-ax7t
blocked_by:
    - sbo-5t0f
    - sbo-qw0z
    - sbo-f8cj
    - sbo-s4xl
    - sbo-iye5
    - sbo-ip5k
    - sbo-cka2
---

`docs/security-audit-2026-11.md` in the browserid-ng 2026-11 format: scope, method, executive summary (themes), §1 severity ledger (High/Medium/Low/Info + spec-only items, each with ID, finding, where, test, bean), §2 refuted leads with reasons, §3 cross-implementation disagreement (WS2), §4 July 2026 re-verification (Then/Now), §5 remediation order. One remediation bean per fix group (bug or task), blocked-by relations for shared helpers (e.g. one canonical-bytes helper before the hash/signature fixes), infra-side items as separate task beans (mingo deploy / sandmill-infra). Decisions from the decisions doc recorded in the affected beans. Fold the open July beans (sbo-f5wn children) into the new remediation beans or mark them superseded.

- [ ] ledger
- [ ] remediation beans + blocked-by graph
- [ ] July beans reconciled
- [ ] epic checklist closed
