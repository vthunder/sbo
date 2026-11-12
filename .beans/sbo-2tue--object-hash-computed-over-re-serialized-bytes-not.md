---
# sbo-2tue
title: object_hash computed over re-serialized bytes, not raw on-chain bytes
status: scrapped
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

sync.rs:1109 does sha256(wire::serialize(msg)) after parsing; State Commitment spec mandates sha256(raw_sbo_bytes). If wire::serialize isn't byte-identical to the producer's original (header order/casing/optional headers, dropped Related/import headers), the state root diverges cross-implementation and the inclusion-proof re-hash step fails.
- [ ] Hash the raw received message bytes for object_hash (retain original bytes through parse)
- [ ] Cross-impl root-agreement test with non-canonical-but-valid input

## Reasons for Scrapping

Superseded by sbo-xypz and sbo-eefz (audit 2026-11 D3/Q18). Every unchecked item above is carried in that bean's checklist; the finding was re-verified by the 2026-11 audit and is encoded as an ignored `AUDIT-2026-11` test there.
