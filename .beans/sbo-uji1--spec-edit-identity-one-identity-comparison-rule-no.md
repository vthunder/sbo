---
# sbo-uji1
title: 'Spec edit (Identity): one identity-comparison rule, no bare-key owners, T1-operator impersonation stated plainly (Q5, Q6, S6, S7, sbo-0web)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:35:18Z
parent: sbo-ax7t
---

`specs/SBO Identity Specification.md`: normative comparison rule (exactly one `@`, lowercase A-label domain, byte-exact local part, canonical on-chain form) (Q5 (a), S6); remove the bare-key row from the owner-reference table and `resolve_controller` pseudocode, state the genesis-anchor exception (Q6, S7); say plainly that a T1 community operator can impersonate any member until the sovereignty upgrade (sbo-0web).

- [x] Q5 rule
- [x] Q6 table + pseudocode
- [x] T1 operator sentence

## Summary of Changes

specs/SBO Identity Specification.md: changelog; owner-reference table loses the bare-key row and gains a No-bare-key-owners paragraph (explicit bare key invalid, no signer fallback, every write names a name or an email, genesis anchor the single exception; Q6); new §Identity comparison (exactly one @, lowercase A-label domain, byte-exact local part, canonical lowercase on chain with uppercase-domain headers invalid, names byte-exact; Q5 (a)/S6); resolve_controller pseudocode returns Unresolved for a key-shaped or malformed ref; stored-creator fallback to a key encoding removed; T1 §Properties states plainly that the operator can impersonate any member until the sovereignty upgrade (evident, not preventable; sbo-0web); Security Considerations add T1 operator impersonation and aliasing.
