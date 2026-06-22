---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Attestation Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Abstract

This specification defines `attestation.v1`: a signed, on-chain claim made by one identity (the **issuer**) about another (the **subject**). Memberships, roles, bans, vouches, badges, and credentials are all instances of the same primitive.

Attestations are the keystone of SBO's reputation fabric. Raw attestations are objective, replayable on-chain facts authorized like any other SBO object. **Reputation scores are not on chain** — they are subjective views computed off chain by indexers from the raw attestations. Holding that line is what keeps attestation declarative (no computed constraints, no on-chain scoring logic) while still supporting web-of-trust and portable credentials.

This document defines the attestation object, where it is stored, how it is authorized, how freshness is handled by expiry and re-issuance, and the boundary between on-chain facts and off-chain scoring.

---

## Concepts

An attestation is a claim of the shape:

> **issuer** asserts that **subject** has **type** = **value**, as of **issued_at**, until **expires**.

| Term | Meaning |
|------|---------|
| **Issuer** | The identity making the claim. The attestation object's `Owner`; the only party who can create, update, or revoke it. |
| **Subject** | The identity the claim is about. An identity reference (see the [Identity Specification](./SBO%20Identity%20Specification.md)). |
| **Type** | A namespaced claim type (e.g. `membership`, `role:moderator`, `vouch`, `badge:early-adopter`, `credential:kyc`). |
| **Value** | The claim's content. Often `true` for a flag, but may be any JSON value (a score, a tier, a structured credential). |

Every richer concept is just a `type` convention over this primitive:

| Concept | `type` | `value` |
|---------|--------|---------|
| Community membership | `membership` | `true`, or a join object |
| Role grant | `role:moderator` | `true` |
| Ban | `ban` | reason string / object |
| Vouch (web-of-trust) | `vouch` | trust weight or `true` |
| Badge | `badge:<name>` | `true` or award metadata |
| Credential | `credential:<kind>` | structured claim |

Because the meaning lives in the `type` string and not in protocol logic, new claim types need no spec change — only an off-chain convention that issuers and indexers agree on.

---

## Object Format

### Envelope

An attestation is an ordinary SBO object stored **in the issuer's namespace** (see [Storage](#storage)):

```
SBO-Version: 0.5
Action: post
Path: /moderators@community.org/attestations/alice/
ID: role:moderator
Type: object
Content-Type: application/json
Content-Schema: attestation.v1
Owner: moderators@community.org
Public-Key: ed25519:<EPHEMERAL_KEY>
Auth-Cert: <browserid certificate binding EPHEMERAL_KEY to moderators@community.org>
Signature: <envelope signature>

{"subject":"alice","type":"role:moderator","value":true,"issued_at":1703001234,"expires":1703606034}
```

The **issuer is the `Owner` header**, not a payload field — exactly as the controller of an identity record is its `Owner` (see the [Identity Specification](./SBO%20Identity%20Specification.md#email-rooted-identity-identityemailv1)). A payload `issuer` field, if present, is advisory and MUST equal the `Owner`; on mismatch the object is invalid.

### Payload

```json
{
  "subject": "alice",
  "type": "role:moderator",
  "value": true,
  "issued_at": 1703001234,
  "expires": 1703606034,
  "evidence": "/moderators@community.org/decisions/2026-06-22"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject` | string | Yes | Identity reference the claim is about (email, name, or cross-repo name/URI). |
| `type` | string | Yes | Namespaced claim type. Lowercase; segments separated by `:`. MUST NOT contain `/` or whitespace. |
| `value` | any | Yes | Claim content. Use `true` for a bare flag. |
| `issued_at` | number | Yes | Unix seconds when the issuer asserts the claim takes effect. |
| `expires` | number | No | Unix seconds after which the claim is stale (see [Freshness](#freshness-expiry-and-re-issuance)). Absent = no self-expiry. |
| `evidence` | string | No | SBO path or URI to supporting material (a moderation decision, an external credential, a vouched interaction). Advisory; not protocol-verified. |

The `value` schema for a given `type` is an off-chain convention. Conforming validators check the envelope and the fields above; they do not interpret `value`.

---

## Storage

An attestation is stored under the **issuer's** namespace, by convention:

```
/<issuer>/attestations/<subject>/<type>
```

with `Path: /<issuer>/attestations/<subject>/` and `ID: <type>`. For example, `moderators@community.org`'s moderator grant to `alice` lives at `/moderators@community.org/attestations/alice/role:moderator`.

> **Decision: issuer namespace, not subject namespace.** An attestation must be controlled by the party who made the claim. If attestations lived in the subject's namespace, a subject could delete or suppress unfavorable claims about themselves — a ban or a revoked credential would be worthless. Storing under the issuer's namespace means the issuer's authorization governs create, update, and revoke; the subject can neither forge nor remove claims about themselves. The cost — that "all attestations about Alice" is not a single on-chain subtree — is borne by indexers, which build the reverse index (see [Indexing](#indexing-and-off-chain-scoring)).

The `<issuer>/<subject>/<type>` path is the attestation's **primary key**: re-issuing the same `(issuer, subject, type)` is a normal SBO `post` that supersedes the prior object under last-writer-wins. This is what makes [re-issuance](#freshness-expiry-and-re-issuance) the natural freshness mechanism.

Issuers MAY use a different layout (e.g. content-addressed IDs) where multiple co-existing attestations of the same type are meaningful (an append-only vouch log). When they do, supersession-by-key no longer applies and consumers see every attestation; the `/<subject>/<type>` convention is recommended wherever a single current claim is intended.

---

## Authorization

An attestation is authorized exactly like any other SBO write: the message must be authorized for its `Owner` (the issuer) per the [Identity Specification](./SBO%20Identity%20Specification.md#authorization) — attributed to the issuer's controlling email via `Auth-Cert`, or signed by the issuer's controlling key.

- **No special issuer privilege exists at the protocol level.** Anyone can issue an attestation about anyone. `alice@gmail.com` asserting `vouch` about `bob@gmail.com` is valid; so is a stranger asserting `role:moderator` about Bob. Validity (the claim is well-formed and genuinely from its issuer) is distinct from **weight** (whether any consumer cares who the issuer is). Weight is an off-chain, subjective judgment (see [Indexing](#indexing-and-off-chain-scoring)).
- **Subject existence is not required.** The subject reference need not resolve to an existing record at issuance time. A claim about an unregistered email is valid; consumers resolve subjects at read time.
- **A repository MAY constrain issuance via [policy](./SBO%20Policy%20Specification.md).** A community can deny `create` on `/<community-issuer>/attestations/**` to all but a role, scoping who may issue *under that repository's authoritative issuer identity*. This does not stop anyone from issuing attestations under their *own* namespace — it only governs claims made in the community's name.

### Choosing a subject

The `subject` is an ordinary identity reference (see the [Identity Specification](./SBO%20Identity%20Specification.md#owner-references-and-resolution)), and **emails are first-class subjects** — both external emails (`alice@gmail.com`, T0) and community-issued, email-shaped names (`alice@community.org`, T1). There is no protocol preference for an on-chain name over an email; an attestation about `alice@gmail.com` is exactly as valid as one about a name.

What an issuer actually chooses is *which identity the claim is about* — and, in particular, **who governs that identity**:

- An **external email** the issuer does not control (`alice@gmail.com`) — appropriate for vouches and claims about people outside the issuer's trust boundary.
- A **community-local identity** the issuer governs (T1) — natural when a community credentials its own members, because the claim then stays inside the trust boundary the community controls. The same identity is addressable as the email form `alice@community.org`, as the bare local name `alice`, or as the `/sys/names/alice` record; these denote one party (see the [Identity Specification](./SBO%20Identity%20Specification.md#community-issued-identities-t1)). A community **MAY** issue credentials to such local identities rather than to members' external emails.

**No durability ranking.** A name is *not* a more recoverable anchor than an email. A name record's controller is itself an email, and the spec's name "recovery" is a `transfer` authorized by that controlling email — so a name is never more durable than the email behind it; it only adds a level of indirection that helps solely in a *planned* migration (transfer before the old email is lost) and adds reputation-hijack risk if a controlling email is recycled. Email providers have their own recovery flows. Choose a subject by who the claim is about and who governs that identity, not by a durability ranking.

Indexers key aggregation off the **resolved subject**, so attestations that denote the same party — written as `alice`, `alice@community.org`, or the name record — aggregate together.

---

## Freshness: Expiry and Re-issuance

SBO attestations use an **expiry-and-re-issuance** model rather than strong revocation infrastructure.

> **Decision: expiry over revocation proofs.** Revocation is fundamentally a *freshness* problem: a consumer must know whether a claim is still in force. Strong revocation — proving that a claim was *not* revoked as of some past time — requires state-proof machinery (revocation lists, non-membership proofs, freshness checkpoints) that is heavy and easy to get wrong. Expiry sidesteps it: a claim carries its own validity window, and the issuer keeps it alive by re-issuing. This mirrors browserid certificates, which are short-lived and re-minted rather than revoked. Strong revocation MAY be layered on later; it is out of scope for this version.

Mechanisms, in order of preference:

1. **Expiry.** Set `expires`. After it passes, the claim is stale and consumers SHOULD disregard it. The issuer keeps a standing claim alive by periodically re-issuing with a fresh window — a normal `post` that supersedes the prior object by primary key. Recommended windows: hours to weeks for revocable authority (roles, memberships), longer or unbounded for durable facts (a badge earned once).
2. **Supersession.** Because the attestation lives in the issuer's namespace under a primary key, the issuer re-issues with new `value`/`expires` to update it, or issues a value that explicitly negates the claim (e.g. `membership` = `false`).
3. **Deletion.** The issuer may `delete` the attestation object (authorized as its `Owner`). On replay, last-writer-wins makes the deletion canonical, so the claim disappears for anyone reading current state.

Note the durability boundary: deletion and supersession govern **current** state. A consumer reading a historical snapshot (or holding a cached copy) sees what was true then. For claims where staleness is dangerous (active moderator authority, unexpired credentials), issuers MUST rely on **`expires`**, not deletion — a short window bounds how long a withdrawn-but-cached claim can be honored. An attestation that grants authority and omits `expires` is honored indefinitely by any consumer who cannot observe a later deletion; issuers SHOULD treat unbounded authority grants as a security smell.

---

## Validation

A conforming validator checks, for an `attestation.v1` object:

1. The envelope is valid and the message is **authorized for `Owner`** (the issuer) per the Identity and [Authorization](./SBO%20Authorization%20Specification.md) specifications.
2. `Content-Schema` is `attestation.v1` and the payload is valid JSON.
3. `subject`, `type`, `value`, and `issued_at` are present; `type` matches `[a-z0-9]+(:[a-z0-9-]+)*` (lowercase, `:`-separated, no `/` or whitespace).
4. If a payload `issuer` field is present, it equals `Owner`.
5. If `expires` is present, it is a number ≥ `issued_at`.

An attestation failing these checks is **invalid** (disregarded on replay, like any malformed object). An attestation that is valid but **stale** (`expires` in the past relative to the consumer's reference time) is *well-formed but not in force* — it remains on chain and is not invalid; consumers simply do not honor it. Whether to honor a claim, and how much weight to give it, is a consumer/indexer decision, not a validity rule.

---

## Indexing and Off-Chain Scoring

This is the line that keeps the attestation fabric declarative and out of expressive (contract-like) territory.

- **On chain:** raw attestations — objective, signed, replayable, individually verifiable. Each is a single issuer's single claim.
- **Off chain:** **reputation** — the aggregation of many attestations into scores, rankings, trust paths, or membership views. This is computed by **indexers**, each free to weight issuers differently, walk vouch graphs to any depth, apply decay, or ignore issuers it distrusts.

Two indexers may legitimately compute **different** reputations from the **same** attestations — that is the point. Reputation is subjective; the chain provides the shared, verifiable substrate of facts, not a canonical score. Concretely, indexers:

- Build the **reverse index** (subject → attestations about it) that the issuer-namespace storage layout does not provide directly.
- Resolve subjects to controllers/names so claims about the same party aggregate.
- Apply **freshness** (drop stale or superseded claims) and **issuer weighting** (a moderator's `ban` counts; a stranger's does not).
- Compute derived views: web-of-trust paths from a vouch graph, role membership for a community, credential portfolios for a subject.

No scoring logic, weighting table, or graph traversal belongs in the protocol or in policy objects. A repository that wants a *canonical* membership or role view publishes the issuer identity whose attestations are authoritative for it (e.g. the community's own issuer); consumers then read that single issuer's claims directly, no scoring required. This is how [community membership and roles](./SBO%20Policy%20Specification.md) are expected to build on attestation (see the forthcoming Community Specification) without on-chain governance computation.

---

## Worked Examples

### Web-of-trust vouch

`alice` vouches for `bob`, weight 0.8:

```
Path: /alice/attestations/bob/
ID: vouch
Owner: alice@gmail.com
Content-Schema: attestation.v1

{"subject":"bob","type":"vouch","value":0.8,"issued_at":1703001234,"expires":1718553234}
```

Any indexer can walk these to compute trust paths; the protocol stores only the edges.

### Portable credential

A community certifies a skill for one of its own members (a community-governed local identity, here written in bare form):

```
Path: /community@example.org/attestations/bob/
ID: credential:maintainer
Owner: community@example.org

{"subject":"bob","type":"credential:maintainer","value":{"repo":"core","since":2025},"issued_at":1703001234}
```

Bob carries this credential across communities: any consumer that recognizes `community@example.org` as an issuer reads it directly.

### Ban (issuer-controlled, expiring)

```
Path: /community@example.org/attestations/spammer/
ID: ban
Owner: community@example.org

{"subject":"spammer","type":"ban","value":{"reason":"spam"},"issued_at":1703001234,"expires":1734537234}
```

The subject cannot delete this — it lives in the community's namespace. The `expires` bounds how long a lifted ban could linger in caches; the community re-issues to extend it.

---

## Security Considerations

- **Issuer authority is not protocol-conferred.** Validity proves only *who* made a claim, never that the claim is *true* or that the issuer is *entitled* to make it. Consumers MUST decide which issuers they trust for which `type`s. Treating any valid attestation as authoritative is a vulnerability.
- **Subject recycling.** Any identifier can change hands: a recycled email re-targets a claim to a new party, and a recycled name (whose controlling email was recycled) silently re-targets accumulated reputation — names do not fix this, and the indirection can make it worse. This is an inherent hazard of mutable, recoverable identifiers (the accepted v1 trust level); claims that grant authority SHOULD use `expires` to bound exposure, and consumers SHOULD weigh issuer trust accordingly.
- **Stale authority.** An authority-granting attestation without `expires` is honored indefinitely by consumers who cannot see a later deletion (offline, cached, or historical readers). Always bound authority grants with `expires`.
- **Issuer-key compromise** lets an attacker mint claims in the issuer's name until the compromise is resolved; short expiry windows bound the blast radius. The issuer's identity-trust assumptions are those of the [Identity Specification](./SBO%20Identity%20Specification.md#security-considerations).

## Privacy Considerations

- Attestations are public on chain. Issuing a claim about a subject publicly links issuer and subject (a vouch reveals a relationship; a credential reveals an affiliation).
- A `ban` or negative claim publishes a judgment about an identity; deployments should weigh this against the subject's pseudonymity tier.
- Zero-knowledge attestations (proving a credential without revealing issuer or subject) are a roadmap item, enabled by the same ZK machinery as identity tier T2; they are not specified in this version.

## References

- [SBO Specification](./SBO%20Specification.md) — object model, validity layers, last-writer-wins
- [SBO Identity Specification](./SBO%20Identity%20Specification.md) — identity references, `/sys/names/`, authorization, community-issued identities
- [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) — how a write is attributed to an issuer
- [SBO Policy Specification](./SBO%20Policy%20Specification.md) — constraining who may issue under a repository's identity
- [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) — envelope and signatures
