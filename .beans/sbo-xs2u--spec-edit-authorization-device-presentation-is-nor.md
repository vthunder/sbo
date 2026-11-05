---
# sbo-xs2u
title: 'Spec edit (Authorization): device presentation is normative, sign:sbo scopes, wildcard cap, empty scope list (Q1, S1, Q38, Q40)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:32:38Z
parent: sbo-ax7t
---

One bean per spec document. `specs/SBO Authorization Specification.md`: rewrite §Auth-Cert / §Agent Warrant around the four-object device presentation (Q1 (a), S1); delete `Auth-Warrant`; document the `sign:sbo:<action>` scope grammar from the July text; state the wildcard cap for `path:` scopes (Q38, open); state that an empty scope list authorizes nothing (Q40, open); note what the attribution window is (assertion at authoring instant, Q9).

- [x] Q1 rewrite + Auth-Warrant removal
- [x] sign:sbo scope grammar
- [x] Q38 cap, Q40 sentence (after decisions)

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

specs/SBO Authorization Specification.md: changelog; Authorization Modes reduced to Direct and Attributed, the latter being the four-object browserid-ng device presentation in Auth-Cert; legacy single-JWT Auth-Cert and Auth-Warrant retired and MUST be rejected (Q1 (a), S1). New §The Device Presentation: object table (access cert, assertion, warrant, config cert), claims SBO reads, envelope binding, self-grant vs delegated grant, audience rule (kept, assertion aud == warrant audience), §Warrant Scopes with the sign:sbo:<action> grammar (synonym of action:, other sign: kinds fail closed), empty scope list authorizes nothing (Q40 (b)), §Wildcard cap (8, polynomial matcher; Q38 (c)), on-behalf writes reworded to grantor/grantee. DNSSEC evidence intro covers two issuers. Inclusion-Time Clock lists the three chain objects and gains §The authoring instant (assertion only, HLC-derived, W capped; Q9 (a)). Verification Algorithm rewritten for the presentation (seven steps, status refs not consulted on replay). Creator integrity drops the signer fallback (Q6). Security Considerations: replay, scope evaluation as untrusted input, submit-time checks advisory.
