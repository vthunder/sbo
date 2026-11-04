---
# sbo-q92z
title: 'WS9: consolidated ledger + remediation beans'
status: completed
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-04T21:40:43Z
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

- [x] ledger
- [x] remediation beans + blocked-by graph
- [x] July beans reconciled
- [x] epic checklist closed

## Summary of Changes

- `docs/security-audit-2026-11.md`: scope, method, suite tally (518 / 0 / 94 after one WS3 generator fix), executive summary in six themes, §1 ledger (2 Critical, 12 High, 29 Medium, 22 Low, 10 Info; every row with where / acceptance test or vector / PoC / decision / bean), §2 refuted leads, §3 WS2 disagreements, §4 July Then/Now (all 12 open leads still present, 2 fixed), §5 remediation order.
- 48 remediation beans under sbo-ax7t (28 `todo`, 20 `draft` naming the open Q22–Q40 they wait on) plus 12 spec-edit beans (one per spec document); helpers block dependents: canonical-bytes `sbo-zom8` → D2/D3; state-commitment v2 bundle `sbo-eefz` → D3/D4/D5/D57/Q6/W3-3; identity helper `sbo-lv2x` → D13/grammar; DNSSEC fixture `sbo-ospt` → D6/D33; supply chain `sbo-bzp7` → required checks; public mode `sbo-b4cx` → non-root container. Infra items filed here with a note that they execute in mingo / sandmill-infra.
- July: 12 beans scrapped with a successor pointer, sbo-5rww and sbo-7bl8 re-parented as deferred trackers (Q19, Q20), sbo-hy4r annotated, epic sbo-f5wn completed.
- `Cargo.lock` verified `--locked` against the final manifests (OK). One WS3 test generator fixed (`dns_record_parsing`).
