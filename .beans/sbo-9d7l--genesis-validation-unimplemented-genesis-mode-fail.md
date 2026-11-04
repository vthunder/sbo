---
# sbo-9d7l
title: Genesis validation unimplemented + genesis mode fails open + genesis-hash advisory
status: scrapped
type: bug
priority: critical
created_at: 2026-07-08T15:48:22Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

Genesis::validate() is todo!() (genesis.rs:13). Operationally genesis mode = 'no root policy present -> accept every write with zero policy checks' (validate.rs), inverting the spec's 'absence of root policy -> invalid and discarded'. Genesis-hash mismatch only error!-logs and keeps syncing (main.rs:1573). So a forged/ambiguous genesis batch at anchor height is never structurally validated, and a client pointed at a forged DB syncs it anyway.
- [ ] Implement Genesis::validate (Mode A/B object presence, ordering, iss/signature, same-block)
- [ ] Make genesis-hash pinning fail-closed (stop sync on mismatch)
- [ ] Reconcile genesis bootstrap with root-policy-required-else-discard so it doesn't fail open
- [ ] Enforce @firstBlock anchor uniqueness (MUST error if >1 genesis at (chain,appId,firstBlock))

## Reasons for Scrapping

Superseded by sbo-3q6x (audit 2026-11 D5). Every unchecked item above is carried in that bean's checklist; the finding was re-verified by the 2026-11 audit and is encoded as an ignored `AUDIT-2026-11` test there.
