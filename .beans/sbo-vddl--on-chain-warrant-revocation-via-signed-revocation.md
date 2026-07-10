---
# sbo-vddl
title: On-chain warrant revocation via signed revocation records
status: draft
type: feature
created_at: 2026-07-10T21:54:00Z
updated_at: 2026-07-10T21:54:00Z
---

Future work, split from sbo-8t4b (design 2026-07-10, vthunder). browserid status lists give instant revocation off-chain, but a validator replaying the ledger offline can't fetch a status list. On-chain revocation needs an on-chain, deterministic artifact.

## Design sketch
- The **delegator signs a revocation record** with their identity key (same key that signs warrants) and it is posted on-chain (e.g. `/sys/revocations/<warrant-id>` or keyed by the revoked agent key / status index).
- On replay, validators honor it deterministically: **any write authorized by the revoked warrant/agent-key with inclusion_time AFTER the revocation record's inclusion is L2-invalid** (disregarded, like any unauthorized write). Fully offline — it's just another on-chain object with an inclusion timestamp, verified against the pinned root like everything else.
- Signed by the delegator's key → authoritative (the same authority that granted the warrant revokes it). The delegator signs client-side (as they do warrants); a submitter posts it.

## The broker's role (why it matters)
The **broker is the natural submitter**: with the warrant registry (jipx) it already knows each warrant's audience. When a user revokes a warrant whose audience is an sbo:// / sbo+raw:// chain, the broker is positioned to submit the revocation record to that chain (it knows which chain, and can hold chain-submit access). **This means the broker must understand sbo audiences in warrants** — parse the audience, recognize it as a ledger, resolve/submit. So: revoke-a-warrant in /account → user signs a revocation record → broker submits it on-chain to the audience's ledger. Ties egr7 (status lists) to on-chain enforcement.

## Open questions
- Record schema + path convention; keyed by warrant id, agent key, or status index?
- Broker chain-submit infrastructure (which chains, credentials, cost).
- Interaction with the audience-matching rule (a bare-authority warrant revoked on chain X — does it revoke everywhere or per-instance?).
- Relationship to key-rooted /sys/names revocation (different mechanism).
