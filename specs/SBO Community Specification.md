---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Community Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Abstract

This specification defines `community.v1`: a self-owned community — a governed namespace whose members and moderators are defined by attestations and whose rules are enforced by policy. It is the flagship composition of the SBO stack: a "Discord/Reddit where the community owns itself, and members carry portable reputation across communities."

A community introduces almost no new machinery. Membership, roles, and bans are [attestations](./SBO%20Attestation%20Specification.md); access control is [policy](./SBO%20Policy%20Specification.md) (extended with attestation-defined roles); identities are [email-rooted](./SBO%20Identity%20Specification.md), optionally community-issued (T1). The only new schema is `community.v1`, a thin descriptor that names the community's authoritative issuer and points at its policy and namespace. Governance is **declarative, not computed**: admins are an attestation-defined role plus policy — there is no on-chain voting or contract logic.

## How a Community Is Composed

| Concern | Mechanism | Spec |
|---------|-----------|------|
| Who members/mods/admins are | `membership` and `role:*` attestations | [Attestation](./SBO%20Attestation%20Specification.md) |
| Who may do what | Policy grants to attestation-defined roles | [Policy](./SBO%20Policy%20Specification.md) |
| Banning / moderation | `ban` and `mod:*` attestations + policy `not_attested` | [Attestation](./SBO%20Attestation%20Specification.md), [Policy](./SBO%20Policy%20Specification.md) |
| Member identities | Email-rooted, optionally community-issued (T1) | [Identity](./SBO%20Identity%20Specification.md) |
| The community itself | `community.v1` descriptor | this document |

The descriptor is the only addition; everything else is convention over existing primitives.

## Granularity: Repository or Object

A `community.v1` is an **object**, so a community can exist either as its own repository or as one entry among many in a host repository.

- **Repository-per-community (recommended).** The community is its own SBO repository: its own genesis and root policy, its own `/sys/names/` namespace, and — for T1 — its own browserid provider for `@<community-domain>` identities. This gives the community full sovereignty over its rules and namespace, and makes it forkable (see [Forking and Liveness](#forking-and-liveness)). The descriptor lives at `/sys/community`.
- **Aggregated (permitted).** Many communities share a host repository, each a `community.v1` at `/communities/<id>` with its own subtree. Cheaper to operate and better for cross-community discovery, at the cost of sharing the host's genesis and root policy. Suitable for a hosting platform offering many small spaces.

Under global `(path, id)` uniqueness, the descriptor slot `(/communities/, <id>)` (and the repository-per-community `/sys/community`) holds **exactly one** `community.v1` — the single-canonical-descriptor guarantee is now **native**, not a convention. The first valid writer owns the community's descriptor slot; a competing creator cannot fork it. This resolves the board/descriptor case (a board is a singleton descriptor object per community id).

Within either layout, a community subdivides into **spaces** (channels, subforums) as nested objects/paths — these need no new genesis (see [Spaces](#spaces)).

Deployments SHOULD prefer repository-per-community where self-ownership matters; aggregation is an explicit trade of sovereignty for shared operation.

The two layouts **may coexist in one repository**: a `/sys/community` descriptor (the repo is itself a community, with members and spaces) alongside `/communities/<id>` hosted sub-communities. This models a top-level community that also hosts others. Their subtrees are disjoint, so every object's governing community is unambiguous — whichever descriptor's subtree contains it — provided the repo-level community's `members`/`spaces` paths do not overlap `/communities/` (the defaults do not). A hosted sub-community is **not sovereign**: because [policies cascade](./SBO%20Policy%20Specification.md) down the hierarchy, its policy operates under the repository's root policy, which can override or lock its paths. Full sovereignty requires repository-per-community.

## The `community.v1` Object

### Envelope

```
SBO-Version: 0.5
Action: post
Path: /sys/
ID: community
Type: object
Content-Type: application/json
Content-Schema: community.v1
Owner: sys
Public-Key: ...
Signature: ...
```

### Payload

```json
{
  "name": "Cooks",
  "description": "A community for home cooks.",
  "issuer": "cooks@example.org",
  "policy": "/sys/policies/root",
  "members": "/members/",
  "spaces": "/spaces/",
  "open": true,
  "created_at": 1703001234
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable community name |
| `description` | string | No | Short description |
| `issuer` | string | Yes | The **authoritative issuer** identity: the identity whose `membership`/`role:*`/`ban` attestations the community treats as canonical (see [Authoritative Issuer](#the-authoritative-issuer)). |
| `policy` | string | Yes | Path or URI to the community's root policy |
| `members` | string | No | Path prefix under which membership is recorded (default `/members/`) |
| `spaces` | string | No | Path prefix for spaces (default `/spaces/`) |
| `open` | boolean | No | Advisory hint that membership is self-service; the **actual** gate is the policy (see [Membership](#membership)). |
| `created_at` | number | No | Unix seconds |

The descriptor carries **no logic** — it is a pointer to the community's issuer and policy. Changing governance means updating those objects, each under its own authorization.

### The authoritative issuer

`issuer` names the identity whose attestations are canonical for this community. It is typically the community's own T1 identity (`cooks@example.org`, certified by the community's browserid provider) or a key-rooted `sys`-scoped identity in a dedicated repository. Consumers that recognize the community read its membership and role state by reading attestations from this issuer — there is no scoring step, because the community has named a single authoritative source (consistent with the [Attestation Specification](./SBO%20Attestation%20Specification.md#indexing-and-off-chain-scoring): canonical views come from naming an issuer, not from on-chain aggregation).

## Namespace Layout

A typical community repository:

```
/
├── sys/
│   ├── community                       community.v1 descriptor
│   ├── policies/root                   root policy
│   └── names/<name>                    member names (T1, optional)
├── cooks@example.org/
│   └── attestations/<subject>/<type>   membership, role:*, ban, mod:* (issuer-owned)
├── members/<member>/...                self-issued membership (open mode)
└── spaces/
    └── <space>/...                     channels / subforums (content lives here, see L5)
```

The community's own attestations live in **its issuer's namespace** (per the attestation storage rule); member-owned records (open-mode self-membership, authored content) live in member or space namespaces governed by policy.

## Membership

Membership is a `membership` attestation (see [Attestation](./SBO%20Attestation%20Specification.md)) whose `subject` is the member. The open/curated distinction is a **policy choice**, not a schema difference:

- **Open community** — members self-issue membership in their own namespace (`/<member>/attestations/<member>/membership`). The community recognizes any in-force self-membership via a policy role `{"attested": {"type": "membership"}}` (no `by`). Joining is permissionless and needs no community signature.
- **Curated community** — only the community's issuer (or an admin role) may issue membership, gated by a policy `create` grant on `/<issuer>/attestations/**`. Membership is then `{"attested": {"type": "membership", "by": "<issuer>"}}`. The community signs each admission.

Either way:

- **Leaving** is letting the membership expire, superseding it with a withdrawn value, or deleting it (the member can delete their own self-membership; the community can delete a curated one).
- **Kicking / banning** is a **`ban` attestation issued by the community** (in the community's namespace, which the member cannot remove). Policy denies banned subjects via `not_attested` (see [Moderation](#moderation)). A ban overrides membership regardless of join mode, because it lives in the community's namespace and is checked independently.

Recommended: membership attestations carry `expires` so the roster stays fresh and lapsed members fall out without an explicit removal.

## Roles and Governance

Roles (moderator, admin, or any community-defined capability) are `role:*` attestations issued by the community or its admins, and bound to capabilities by [attestation-defined policy roles](./SBO%20Policy%20Specification.md#attestation-defined-roles):

```json
{
  "roles": {
    "admin": [{"attested": {"type": "role:admin", "by": "cooks@example.org"}}],
    "moderator": [{"attested": {"type": "role:moderator", "by": "cooks@example.org"}}, {"role": "admin"}]
  },
  "grants": [
    {"to": {"role": "admin"}, "can": ["post", "delete"], "on": "/spaces/**"},
    {"to": {"role": "moderator"}, "can": ["delete"], "on": "/spaces/**"},
    {"to": {"role": "admin"}, "can": ["create"], "on": "/cooks@example.org/attestations/**"}
  ]
}
```

This is the load-bearing move: **an admin appoints a moderator by issuing a `role:moderator` attestation**, not by editing the root policy. Revoking a role is letting it expire or deleting the attestation. Because the policy references the role by attestation, the roster is live and expiry-aware, yet evaluation stays deterministic (resolved at the message's inclusion time).

**Governance is non-expressive by design.** There is no on-chain vote tally, quorum, or reducer. "Who governs" is exactly "who holds an in-force `role:admin` attestation from the issuer," and what they can do is exactly what the policy grants. A community that wants richer decision-making runs it **off chain** and records the outcome as attestations (the admins issue the roles the decision produced). This keeps communities clear of expressive/contract-like validation (Fork D).

## Moderation

Moderation actions are attestations issued by mods/admins:

- **Ban** — `ban` attestation about the offending subject. Policy excludes banned users from acting:

  ```json
  {"restrictions": [
    {"on": "/spaces/**", "require": {"not_attested": {"type": "ban", "by": "cooks@example.org"}}}
  ]}
  ```

- **Content removal** — moderators delete an offending object directly, which requires a policy `delete` grant to the moderator role on the content path (posts are author-owned; removal is a delegated capability). To record *why*, the mod issues a `mod:remove` attestation whose `subject` is the removed object's path/URI and whose `value` carries the reason.

- **Other actions** (lock, pin, warn) follow the same pattern: a `mod:*` attestation captures the action; policy enforces any capability it implies.

The **moderation log** is the indexer's reverse view over these `ban`/`mod:*` attestations — an audit trail assembled off chain, not a distinct on-chain object. Because each action is a signed, in-force attestation by a known mod, the log is independently verifiable.

## Spaces

A community subdivides into **spaces** (channels, subforums, threads) as nested paths under `spaces` (default `/spaces/<space>/`). A space is an organizational container, not a new community: it shares the community's issuer, members, and roles, and is governed by the same root policy (which MAY scope grants per space, e.g. a `moderator` of `/spaces/announcements/**` only). Content objects (posts, comments, reactions) live inside spaces and are defined in the forthcoming Content specification (L5); this document defines only the path convention.

A space that needs its own sovereignty (separate issuer, separate policy, separate namespace) is not a space — it is its own community, referenced across repositories.

## Cross-Community Reputation

Portable reputation is **emergent**, requiring no new mechanism. A member is an identity (`alice@gmail.com`, or a cross-repo name); attestations about that identity issued in community A are readable from community B via [cross-repo references](./SBO%20URI%20Specification.md). A vouch earned in one community, a credential issued by another, a role held in a third — all attach to the same identity and travel with it.

Whether community B *honors* community A's attestations is a **subjective, off-chain decision** — B's policy may name A's issuer as authoritative for some `type` (recognizing A's credentials), or B's indexers may weight A's vouches — but recognition is never protocol-enforced. The chain provides the portable, verifiable claims; each community decides what to trust, exactly as the [Attestation Specification](./SBO%20Attestation%20Specification.md#indexing-and-off-chain-scoring) keeps scoring off chain.

## Forking and Liveness

A community **is** an SBO repository (in the recommended layout), so its existence is coupled to that repository's liveness: if the community's domain or provider goes away, its T1 identities and live attribution degrade. This coupling is **accepted** — the community and its namespace share a fate.

The escape hatch is **forking**: because all state is on chain (or restorable from a DA backup), a community can be re-established at a new domain. Members re-anchor under the new repository's issuer, and prior attestations remain readable cross-repo for continuity. Self-ownership means the community is not captive to any single operator.

## Worked Example

A small open community, `cooks@example.org`, in its own repository.

Descriptor (`/sys/community`):

```json
{
  "name": "Cooks",
  "issuer": "cooks@example.org",
  "policy": "/sys/policies/root",
  "open": true,
  "created_at": 1703001234
}
```

Root policy (`/sys/policies/root`), abbreviated:

```json
{
  "roles": {
    "admin": [{"attested": {"type": "role:admin", "by": "cooks@example.org"}}],
    "moderator": [{"attested": {"type": "role:moderator", "by": "cooks@example.org"}}, {"role": "admin"}],
    "member": [{"attested": {"type": "membership"}}]
  },
  "grants": [
    {"to": {"role": "member"}, "can": ["create"], "on": "/spaces/**"},
    {"to": "owner", "can": ["post", "delete"], "on": "/spaces/**/$owner/**"},
    {"to": {"role": "moderator"}, "can": ["delete"], "on": "/spaces/**"},
    {"to": {"role": "admin"}, "can": ["create"], "on": "/cooks@example.org/attestations/**"},
    {"to": "*", "can": ["create"], "on": "/sys/names/*"}
  ],
  "restrictions": [
    {"on": "/spaces/**", "require": {"not_attested": {"type": "ban", "by": "cooks@example.org"}}}
  ]
}
```

Flows:
- **Join.** Alice self-issues `{"subject":"alice@gmail.com","type":"membership","issued_at":...,"expires":...}` in her namespace. She now matches the `member` role and may post in spaces.
- **Appoint a mod.** An admin issues `role:moderator` about Bob from `cooks@example.org`. Bob now matches the `moderator` role — no policy change.
- **Ban.** An admin (moderators lack issue rights on `/cooks@example.org/attestations/**` in this policy) issues a `ban` about a spammer. The `not_attested` restriction now blocks the spammer from posting; the ban also serves as the public moderation record.

## Security Considerations

- **Issuer compromise is community compromise.** Whoever controls the authoritative `issuer` identity can mint memberships, roles, and bans in the community's name. Protect it accordingly (its trust assumptions are those of the [Identity Specification](./SBO%20Identity%20Specification.md#security-considerations)); short `expires` windows on roles bound the blast radius of a temporary compromise.
- **Self-membership is cheap.** In open communities anyone can self-issue membership; the `member` role therefore confers only what an open community intends. Gate sensitive capabilities behind community-issued roles, not bare membership.
- **Ban evasion.** A banned user can create a new external email and rejoin an open community. T1 community-issued identities (which let the provider ban the *person*, not the pseudonym — see [Identity](./SBO%20Identity%20Specification.md#community-issued-identities-t1)) are the mitigation when this matters.
- **Stale roles.** A role attestation without `expires` is honored until explicitly deleted, and deletion is invisible to offline/historical readers; bound governance-bearing roles with `expires`.

## Privacy Considerations

- Membership, roles, and moderation actions are public on chain — joining a community is a public act, and a ban publicly names its subject.
- T0 members expose their email; T1 members expose only the community-issued name (backing known to the community); T2 (roadmap) exposes neither.
- Communities concerned with member privacy SHOULD run a T1 provider rather than admitting members by external email.

## References

- [SBO Attestation Specification](./SBO%20Attestation%20Specification.md) — membership, roles, bans; off-chain reputation
- [SBO Policy Specification](./SBO%20Policy%20Specification.md) — attestation-defined roles, `attested`/`not_attested` conditions
- [SBO Identity Specification](./SBO%20Identity%20Specification.md) — email-rooted and community-issued (T1) identities
- [SBO Genesis Specification](./SBO%20Genesis%20Specification.md) — per-community genesis and root policy
- [SBO URI Specification](./SBO%20URI%20Specification.md) — cross-community references
