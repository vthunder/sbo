---
# sbo-rx1z
title: Bridge/import subsystem is entirely unimplemented (spec is aspirational)
status: scrapped
type: task
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-f5wn
---

Action::Import returns 'not yet implemented' (validate.rs:542); parsed fields hardcoded empty (action.rs:41). No oracle/verifier/quorum/burn-proof/registry-uniqueness logic exists. Every Bridge spec trust claim (attestation verification, replay protection, burn double-unlock) is undelivered.
- [ ] Mark the Bridge spec clearly as unimplemented/aspirational so nobody builds against assumed enforcement
- [ ] Or implement: oracle attestation verify, registry-path uniqueness, burn-proof replay/double-unlock protection

## Reasons for Scrapping

Decision Q10 (a), 2026-11-04: the Bridge spec is marked Aspirational / not implemented; carried by the Bridge spec-edit bean under sbo-ax7t (S11).
