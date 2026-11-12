---
# sbo-4rc3
title: 'Spec edit (Indexer & Client): completeness proofs are a gap; hostile-indexer threats (S17, W3-6, W3-8)'
status: completed
type: task
priority: low
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:40:55Z
parent: sbo-ax7t
---

`specs/SBO Indexer and Client Specification.md`: document that `/v1/list` serves no completeness proof (S17); add the hostile-indexer threat text for proof parsing (SBOQ length arithmetic, non-existence proof shape).

- [x] S17
- [x] threat text

## Summary of Changes

specs/SBO Indexer and Client Specification.md: changelog; new §Completeness proofs are not served (S17: /v1/list serves no subtree proof, what a client must do meanwhile, SHOULDs for indexers and clients); Security Considerations: omission note extended to objective enumerations, new §Hostile-indexer threats (checked and bounded length arithmetic in SBOQ/SBOP incl. the missing blank-line case: W3-6/W3-9; proof-shape validation before indexing incl. the empty path_segments non-existence case: W3-8; total verifiers with fuzzing as acceptance; a verified proof is still only a claim about a root; transport does not help); Client Conformance item 2 names the device presentation and the authoring-instant exception. threat-model.md untouched (bean did not ask).
