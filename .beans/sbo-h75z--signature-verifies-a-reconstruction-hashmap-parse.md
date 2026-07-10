---
# sbo-h75z
title: Signature verifies a reconstruction (HashMap parse), enabling wire-form malleability
status: todo
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-07-08T15:48:57Z
parent: sbo-f5wn
---

parser.rs:123 collects headers into a HashMap (discards order, silently last-wins on duplicates); canonical_signing_content rebuilds signed bytes from parsed fields. Reordered/duplicate headers, uppercase hex, extra unknown headers all reduce to the same signed bytes -> signature valid for byte-strings the signer never produced. Canonical order not enforced on parse (spec: reject non-canonical). Non-strict ed25519 verify used (S-malleability). Related + all import headers dropped on parse (unsigned/lost).
- [ ] Verify against received bytes OR enforce canonical order + reject duplicates/unknown on parse
- [ ] Use verify_strict
- [ ] Preserve/serialize Related and import (Origin/Registry-Path/Object-Path/Attestation) headers
- [ ] Reject non-lowercase hex / leading-zero Content-Length per Encoding Rules
