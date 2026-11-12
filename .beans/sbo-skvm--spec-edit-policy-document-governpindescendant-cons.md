---
# sbo-skvm
title: 'Spec edit (Policy): document govern/pin/descendant_constraint/forbid_pinning/dnssec_proof/require_payload_signed_by; cycles reject; unknown keys reject; wildcard cap (S12, Q17, Q39, Q38)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:28:22Z
parent: sbo-ax7t
---

`specs/SBO Policy Specification.md`: document what shipped in P1–P4 (S12); Rule 3 cycle rejection and the evaluation depth bound (Q17); unknown condition keys reject (Q39, open); wildcard cap on patterns (Q38, open); `require_payload_signed_by` semantics (D24).

- [x] S12, Q17
- [x] Q38, Q39 (after decisions)

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

specs/SBO Policy Specification.md: changelog; payload structure lists pin and descendant_constraint and states the closed key set; new §Where a policy lives and what it governs (resolution walk, parent governs the policy object); owner-is-a-principal paragraph after Evaluation Order (Q13); new §pin (P2 semantics: governance resolves against the pinned version, forward-only, version retention) and §descendant_constraint (allowed_grants coverage rule, mandated_restrictions, forbid_pinning); govern action row and new §govern (parent policy, not covered by *, post, create; example); new §Wildcard cap (8 wildcards per pattern, polynomial matcher required, shared with warrant path: scopes; Q38 (c)); dnssec_proof and require_payload_signed_by rows plus their own sections (self-authorizing rule, monotonic freshness, signature MUST be verified against the issuer object: D24); Role Resolution bounded (visited set, depth 16, fail closed; Q17 (a)); Validation Rules rewritten as consensus write-time validation with strict no-unknown-keys (Q39 (a), consensus-changing note tied to the regenesis). Examples moved off secp256k1. Numbers chosen here (cap 8, depth 16) are the spec values the sbo-0qqq and sbo-sla3 code beans should implement.
