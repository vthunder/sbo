---
# sbo-0web
title: Docs & spec-drift reconciliation from review
status: todo
type: task
priority: normal
created_at: 2026-07-08T15:49:22Z
updated_at: 2026-07-08T15:49:22Z
parent: sbo-f5wn
---

Documentation and spec-vs-code drift from the 2026-07-08 review.

- [ ] Spec/impl drift to reconcile (move code OR spec so they agree): bare-key owner form (spec lists it, decision removed — see sbo-h0sr/sbo-4arq); domain self-cert MUST-reject vs warn-only (sbo-3gqo); root-policy required-else-discard vs fail-open genesis (sbo-9d7l); canonical-order-on-parse vs HashMap reconstruction (sbo-h75z). For self-cert + genesis move the CODE to the spec; for bare-key move the SPEC to the decision.
- [ ] Misleading stub public APIs in sbo-core: Genesis::validate (genesis.rs:13) and indexer::process_block (indexer.rs:19) are todo!() while real logic lives in the daemon — wire them up or mark clearly non-authoritative.
- [ ] Identity spec security section: state plainly that a T1 community operator (runs the provider AND is de-anonymizer) can silently impersonate any member until that member does the sovereignty upgrade. Currently alluded to, not explicit.
- [ ] names.rs IdentityClaim appears vestigial vs the content_schema/owner_ref resolver path — dead/stale, confirm and remove.
