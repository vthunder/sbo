---
# sbo-vddl
title: On-chain warrant revocation via signed revocation records
status: draft
type: feature
priority: normal
created_at: 2026-07-10T21:54:00Z
updated_at: 2026-08-25T12:55:12Z
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

## Update (2026-08-25) — landscape after signing grants + the submit-gate/clock work

**What exists now (off-chain, live):** every browserid-warrant-v2 is REQUIRED to carry a status ref with a registrar-allocated index; /account revokes per grant; and the sbo-daemon /v1/submit gate now checks all three refs fail-closed (crates/sbo-daemon/src/status.rs, sbo cf6df3f) — every honest gateway refuses a revoked grant within one ~5-min cache window. sbo_core::device_attribution::presentation_status_refs() is the parse-only ref projection to build on. Nothing on-chain yet — replay still consults no revocation artifact; this bean is still the missing piece.

**Sharpened threat model:** the own-node bypass this bean closes applies to KEY-HOLDING grantees (agent grants): revoking only the warrant doesn't stop their IdP minting fresh access certs, so they can submit valid writes via their own node until warrant exp (90d). Signing grants' requester holds no keys (the wallet refuses), and revoking the grantee's device cert at its IdP kills fresh mints — the existing partial mitigation.

**Keying answer to the open question:** key the record by the warrant's (status uri, idx) — since 2026-08-25 that pair is 1:1 with the /account revoke lever, stable across reissues (warrant_status_subject), and present on every v2 record by construction. One on-chain record then mirrors one registrar bit.

**Clock semantics resolved:** attribution expiries are now evaluated deterministically at the write's HLC-bounded authoring instant (AccessPresentation::verify_at; wall-clock replay bug fixed 2026-08-25). vddl's rule should deliberately NOT use that instant: revoked ⇔ the revocation record's INCLUSION precedes the write's INCLUSION. Inclusion ordering is unforgeable; authoring time can be back-dated within W, which must not let a write slip under a revocation.
