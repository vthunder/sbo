---
# sbo-d5nm
title: Content-Hash is never verified against the payload (payload swappable)
status: scrapped
type: bug
priority: critical
created_at: 2026-07-08T15:48:22Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

parser.rs:169 explicitly skips Content-Hash validation ('Skip content hash validation for now'); ContentHashMismatch error is defined but never used; validate.rs only checks the signature over reconstructed headers. Payload is bound to signed headers ONLY via Content-Hash, so on a signature-valid message the payload can be swapped for arbitrary bytes and it still validates. Breaks the entire payload-integrity model (master spec Signature Scope / Validation).
- [ ] Recompute and verify Content-Hash over the payload in the parse/validate path
- [ ] Reject on mismatch (wire up ContentHashMismatch)
- [ ] Enforce object/collection payload-presence rules (Type: object MUST have payload + content headers)
- [ ] Tests: swapped payload rejected; missing/extra content headers rejected

## Reasons for Scrapping

Superseded by sbo-xd6u (audit 2026-11 D1). Every unchecked item above is carried in that bean's checklist; the finding was re-verified by the 2026-11 audit and is encoded as an ignored `AUDIT-2026-11` test there.
