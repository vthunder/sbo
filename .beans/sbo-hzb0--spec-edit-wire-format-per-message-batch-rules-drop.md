---
# sbo-hzb0
title: 'Spec edit (Wire Format): per-message batch rules, drop Auth-Warrant from canonical order, unknown headers reject, ed25519/sha256 REQUIRED, bounds (Q4, S2, Q32, S21, S22, W3-10)'
status: draft
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-04T21:36:02Z
parent: sbo-ax7t
---

`specs/SBO Wire Format Specification.md`: replace §Batch Submissions atomicity with the eight Q4 rules (parse-as-unit, strict order with state threading, rejected message invisible, LWW loser is valid, index tiebreak, per-block root, genesis not an exception, submit-time validation for all-or-nothing); remove `Auth-Warrant` from the canonical order (S2); unknown headers reject (Q32, open); mark `ed25519`/`sha256` REQUIRED and `secp256k1`/`keccak256` reserved (S21); restate encoding rules as MUST-reject (S22); bound `Content-Length` and the batch size (W3-10).

- [ ] Q4 rules
- [ ] S2, S21, S22
- [ ] Q32 sentence (after decision)
