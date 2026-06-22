---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Indexer and Client Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Abstract

This specification defines the **read side** of SBO: how clients derive trustworthy state, and how they use **indexers** — off-chain services that provide feeds, search, reputation scoring, and other derived views — **without trusting them**.

It is deliberately thin. SBO's design holds that derived views are an **open, competing market**: how an indexer ranks a feed, scores reputation, or orders search results is **not specified** and must not be, or the protocol would re-absorb the subjective, expressive logic it has kept off chain at every layer. What *is* specified is the narrow, interoperable core: the indexer **trust model** (untrusted, outputs verifiable against on-chain state), the **verifiable query** interaction, and **client conformance** (how any correct client computes canonical state). Algorithms are out of scope by design; verifiability is in scope.

## The Trust Model

An indexer is an **acceleration, never an authority**. It exists because replaying the whole chain to answer "all posts in this space" or "this subject's attestations" is expensive, and because useful views (ranking, search, reputation) require computation no validator performs. But an indexer's output is only ever a **claim**, which a client checks against on-chain state.

- **Canonical state is client-derived.** The source of truth is the ordered DA layer replayed under SBO validity (see [Validity Layers](./SBO%20Specification.md#validity-layers)); a client never substitutes an indexer's word for it.
- **Indexer outputs are verifiable, not trusted.** An indexer returns data together with **State Commitment proofs** (see the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md)); the client verifies the proofs against a state root it independently trusts. A lying or buggy indexer is caught, not believed.
- **Indexers are interchangeable and plural.** Because outputs are verifiable and the market is open, a client may use several indexers, cross-check them, or fall back to direct replay. No indexer is privileged by the protocol.

## Verifiable Queries

A verifiable query response carries three things: **results**, **proofs**, and the **state root** they are relative to.

```
results:     the objects (or object references) the query selected
state_root:  the State Commitment root the results are proven against
block:       the block at which state_root holds
proofs:      State Commitment proofs binding each result (and, for completeness, the queried subtree) to state_root
```

A client accepts the response only after:

1. **Authenticity** — each result verifies against `state_root` via a State Commitment **inclusion proof** (the embedded object bytes hash to the proven `object_hash`); see the [verification algorithm](./SBO%20State%20Commitment%20Specification.md#verification-algorithm).
2. **Freshness** — `state_root` is one the client **independently trusts**: it equals the root the client itself computed at `block`, or a [checkpoint](./SBO%20State%20Commitment%20Specification.md#checkpoints) the client accepts. A stale or forged root is rejected here.
3. **Validity** — the client applies SBO validity to the returned objects (signatures, attribution, policy); an indexer cannot launder an invalid object by serving it.

### Confirmed state only

Verifiable queries answer over **confirmed** state (see [Confirmed vs Tip](./SBO%20Content%20Specification.md#confirmed-vs-tip)): only writes that are durable on the DA layer appear in a State Commitment root and can be proven. The optimistic **tip** — locally-authored, not-yet-durable writes — is the client's own overlay and is never served by an indexer as proven state. So indexer results are inherently "as of `block`," and the client composes its own tip on top.

### Completeness and read-censorship resistance

Objective enumerations are **completeness-verifiable**: a **subtree proof** (see the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#subtree-proof)) proves the *full* membership of a path prefix at `state_root`, so a client can confirm an indexer omitted nothing under, e.g., `/spaces/general/`. This is the read-side analogue of the censorship-resistance the DA layer gives writes: an indexer cannot silently hide an object that exists on chain.

This guarantee is **inherently limited to objective queries.** A *subjective* view — a ranked feed, a relevance-ordered search, a reputation leaderboard — selects and orders by criteria no proof can capture, so an indexer **can** omit or down-rank an item undetectably. That is the nature of an open algorithm market, not a defect. The defenses are structural, not cryptographic: use multiple competing indexers, cross-check, or fall back to the objective enumeration the subtree proof *can* verify. A client SHOULD treat any ranked/filtered result as advisory and retain the ability to enumerate the underlying objective set.

## Query Categories (non-normative)

The following are typical indexer products. None is standardized; they illustrate the market the protocol enables.

| Category | Example | Verifiable? |
|----------|---------|-------------|
| Reverse index | subject → attestations about it; target → reactions on it (which the issuer-namespace and author-namespace storage layouts do not provide directly) | inclusion-verifiable per item; completeness only via full enumeration |
| Enumeration | all posts in a space, all members of a community | completeness-verifiable (subtree proof) |
| Aggregation | reaction counts, vote scores, reputation from a vouch graph | not verifiable as a *number*; the inputs are individually verifiable |
| Ranking / feed | "top posts," a personalized timeline | not completeness-verifiable (subjective) |
| Search | full-text or semantic search | not completeness-verifiable (subjective) |

In every case the **inputs** (individual attestations, reactions, posts) are verifiable on chain; only the **derived view** is subjective. This is the same boundary held in the [Attestation](./SBO%20Attestation%20Specification.md#indexing-and-off-chain-scoring) and [Content](./SBO%20Content%20Specification.md#reactionv1) specifications: raw facts on chain, aggregate views off chain.

## Client Conformance

A conforming client computes canonical state deterministically and never delegates that computation. It MUST:

1. **Replay deterministically.** Apply DA blocks in order under SBO validity; given the same chain, all conforming clients reach the same canonical state.
2. **Verify attribution at inclusion time.** Check each write's `Auth-Cert` and DNSSEC evidence to the **pinned DNS root KSK**, valid at the write's block inclusion time (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)). Honor the pinned trust anchors (`/sys/trust/dns-root`, `/sys/trust/brokers`; see the [Genesis Specification](./SBO%20Genesis%20Specification.md)).
3. **Evaluate policy deterministically**, including attestation-defined roles and `attested`/`not_attested` conditions resolved at inclusion time (see the [Policy Specification](./SBO%20Policy%20Specification.md#attestation-defined-roles)).
4. **Resolve references with bounded hops.** Owner/name resolution and attestation in-force checks follow the Identity and Attestation rules, enforcing hop limits; an unresolved owner yields an unauthorized (disregarded) write.
5. **Distinguish tip from confirmed** per the Content Specification, and surface which view a result reflects.
6. **Verify, not trust, indexers.** Treat every indexer response as a claim to be checked against an independently trusted state root, per [Verifiable Queries](#verifiable-queries).

A client MAY rely on checkpoints and indexers for **performance** (to avoid full replay), but only insofar as it can verify their outputs; correctness never rests on an unverified third party.

## Out of Scope (the open market)

The following are **intentionally unspecified** and left to competing implementations:

- ranking, feed curation, and personalization algorithms;
- reputation and trust-graph scoring (weights, decay, path-finding);
- search indexing and relevance;
- recommendation and discovery;
- indexer discovery, transport, and API shape beyond the verifiable-response contract above.

Standardizing any of these would pull subjective, expressive computation back into the protocol — precisely the line (Fork D) the suite has held from policy through content. Their absence from this spec is a design choice, not an omission.

## Reference Architecture (non-normative)

A complete deployment typically comprises:

- a **local-first sync engine** (the `sbo-daemon` lineage) that replays the DA layer, maintains canonical confirmed state and the local tip, queues and batches optimistic writes, verifies attribution and policy, and projects state onto the local filesystem;
- one or more **indexers** offering the views above over verifiable queries;
- a **reference client** (e.g. a community application) wiring **browserid** authentication to SBO reads and writes.

These are implementations of the specifications, not additional protocol, and are described here only to situate the conformance requirements.

## Security Considerations

- **A malicious indexer cannot forge or launder state** — inclusion proofs and client-side validity checks catch fabricated or invalid objects, and a forged state root fails the freshness check against the client's own root or a trusted checkpoint.
- **A malicious indexer can selectively omit from subjective views.** Ranked and filtered results are not completeness-verifiable; mitigate by cross-checking indexers and retaining the objective enumeration path (subtree proofs).
- **Checkpoint trust is inherited, not created here.** A client that accepts a checkpoint root to avoid replay inherits that checkpoint's trust model (ZK proof, committee, optimistic, or trusted indexer; see the State Commitment Specification). Maximum assurance comes from independent replay.
- **Tip is untrusted and local.** Decisions with security weight (acting on a moderation or membership state) should read confirmed, proven state — not the optimistic tip.

## Privacy Considerations

- Indexers see query patterns; a client's reads (what it asks for, follows, or searches) are exposed to whatever indexer it queries. Privacy-sensitive clients should self-host an indexer or replay directly.
- All indexed content is already public on chain (on-chain and batched tiers); indexers add no exposure to the data itself, only to access patterns.

## References

- [SBO Specification](./SBO%20Specification.md) — validity layers, canonical state
- [SBO State Commitment Specification](./SBO%20State%20Commitment%20Specification.md) — inclusion, subtree, non-existence proofs; checkpoints
- [SBO Content Specification](./SBO%20Content%20Specification.md) — confirmed vs tip
- [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) — inclusion-time attribution, pinned anchors
- [SBO Policy Specification](./SBO%20Policy%20Specification.md) — deterministic evaluation, attestation-defined roles
- [SBO Attestation Specification](./SBO%20Attestation%20Specification.md) — off-chain scoring boundary
