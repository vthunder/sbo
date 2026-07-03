---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Identity Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Abstract

This specification defines how identities are established, resolved, and controlled in SBO, and how `Owner`, `Creator`, and `New-Owner` references resolve to a controlling party.

The **default identity is an email address**, whose control is proven by DNSSEC-anchored attribution (see [Attribution Capture](./SBO%20Specification.md#attribution-capture) in the Core Specification and the [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) for the mechanism and formats). **Key-rooted** identities (`identity.v1`) are retained for genesis roots and self-sovereign users. The document also defines domain objects (`domain.v1`), profiles (`profile.v1`), the `/sys/names/` namespace, resolution and grounding rules, and the identity tiers.

## Identity Kinds

SBO has two kinds of identity, distinguished by how control is proven:

| Kind | Control proven by | Used for |
|------|-------------------|----------|
| **Email-rooted** (default) | Attribution: a browserid certificate + DNSSEC chain to the pinned DNS root KSK | Ordinary users and applications |
| **Key-rooted** (`identity.v1`) | A direct signature by the identity's `public_key` | Genesis roots (`sys`, domains); self-sovereign users |

Email-rooted identities store **no durable key** on chain. Control is proven per message by attribution and may rotate across providers without changing the identity — there is no user key to lose, and recovery is the provider's responsibility (regain control of the email, regain the identity). Key-rooted identities are authorized by a direct signature from a key the holder must keep; they are the root of trust for a repository (see the [Genesis Specification](./SBO%20Genesis%20Specification.md)) and the basis for the future self-sovereign tier.

User identities SHOULD be email-rooted (browserid-resolvable); key-rooted identities are the explicit exception, reserved for genesis roots and self-sovereign users. This is achievable even in a repository that has no domain of its own, because an email carries its own provider domain — `alice@gmail.com` is browserid-resolvable regardless of where the repository lives.

## Identity Tiers

Email-rooted identity spans a gradient from simplest to most private. **T0 and T1 are normative in this version; T2 is roadmap.**

- **T0 — Direct email (default).** The identity *is* an email the user controls directly (e.g. `alice@gmail.com`), attributed via that domain's DNSSEC-secured browserid provider, or via the recognized broker when the domain runs no provider. The email is public.

- **T1 — Community-issued.** A repository runs its **own** browserid primary identity provider and issues email-shaped names in its domain (e.g. `alice@community.org`, which need not be an SMTP address). Before issuing, it authenticates the user by consuming the user's *other* browserid identities. To the public the name is a pseudonym; the issuing repository knows the backing identity (a trusted de-anonymizer), which enables banning the person without revealing them. See [Community-Issued Identities](#community-issued-identities-t1).

- **T2 — Pseudonymous multi-factor (roadmap).** A zero-knowledge proof asserts that an identity is backed by one or more recognized providers — plus a nullifier for sybil-resistance — without revealing the backing identities, so the identity is pseudonymous even to the issuer, with no trusted de-anonymizer. Not specified in this version; see [Roadmap](#pseudonymous-identities-t2--roadmap).

All tiers attribute through DNSSEC to the same pinned DNS root KSK, so they share one verification path and one trust assumption.

A repository **without its own domain** (addressed only by a chain URI) cannot run a provider and therefore cannot issue T1 identities; its users authenticate with external emails (T0). Because a locally registered name is owned by — and so publicly reveals — that external email, **pseudonymous, repo-scoped handles require a domain (T1).** Domains are inexpensive, so a community that cares about member privacy should obtain one and run a provider.

## Owner References and Resolution

`Owner`, `Creator`, and `New-Owner` headers carry an **identity reference**, which is one of:

| Form | Example | Meaning |
|------|---------|---------|
| Bare email | `alice@gmail.com` | An email-rooted identity, attributed directly |
| Bare key | `ed25519:<hex>` | A key-rooted identity, authorized by direct signature |
| Local name | `alice` | The record at `/sys/names/alice` in the current repository |
| Cross-repo name | `avail:mainnet:13/alice` or an [SBO URI](./SBO%20URI%20Specification.md) | A name in another repository |
| Null (delete) | `null:` | No owner (see the Core Specification) |

The bare-key form is what `effective_owner` (see the [Authorization Specification](./SBO%20Authorization%20Specification.md#verification-algorithm)) yields when a message carries neither `Owner` nor `Creator`: the effective owner is the signing key, which resolves directly to a key controller.

The canonical reference for an email-rooted identity is its **email**, which is globally unambiguous and browserid-resolvable from anywhere. Compact handle forms:

| Context | Handle | Notes |
|---------|--------|-------|
| Email-rooted identity (preferred) | `alice@gmail.com`, `alice@community.org` | Browserid-resolvable; `@` always denotes a browserid-attributable domain |
| Name in a chain-addressed repo (no domain) | `avail:mainnet:13/alice` | Compact cross-repo reference to the name record |
| Within the current repository | `alice` | Resolves to `/sys/names/alice` |

The `@` form is **reserved for browserid-attributable domains**. It MUST NOT be used to address a name by its repository — use the chain/URI form for that — otherwise `x@y` would be ambiguous between "attributed by `y`'s provider" and "the name `x` in repository `y`".

A repository that runs its own provider issues identities as `<name>@<repo-domain>` (see [Community-Issued Identities](#community-issued-identities-t1)); for those, the local name `alice` and the global `alice@<repo-domain>` are the **same identity**. A local name that merely points to an *external* email (via its `Owner`) is a handle, not a `<name>@<repo-domain>` identity: its canonical reference is the controlling email, and its cross-repo address is the chain/URI form.

### Resolution to a controller

To authorize a message, a reference is resolved to a **controller** — either a key (direct-signature) or an email (attribution):

```
resolve_controller(ref, seen = {}):
    if ref is "null:":
        return NoController

    if ref is a bare email:
        return EmailController(ref)            # proven via attribution

    if ref is a bare key (algorithm-prefixed, e.g. ed25519:<hex>):
        return KeyController(ref)              # direct signature; the signer-fallback owner

    # ref names a record under /sys/names/
    if ref in seen:                            # cycle
        return Unresolved
    seen.add(ref)
    rec = fetch_name_record(ref)
    if rec is None:
        return Unresolved
    if rec is key-rooted (identity.v1 with public_key):
        return KeyController(rec.public_key)
    else:                                       # email-rooted name record
        return resolve_controller(rec.Owner, seen)   # indirect; recurse
```

### Grounding rules

- Resolution MUST terminate at an `EmailController` or a `KeyController` within a bounded number of hops (implementations MUST enforce a hop limit).
- A cycle, a missing record, or exceeding the hop limit yields `Unresolved`; a message whose owner is `Unresolved` is not authorized (it is disregarded on replay, per the Core Specification).
- An email controller MUST be groundable to the DNS root KSK via DNSSEC at the message's inclusion time (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)). An email that is not DNSSEC-groundable cannot control objects.

### Authorization

A message signed by key `E` is authorized for an object owned by `O` when `resolve_controller(O)` yields:

- `KeyController(K)` and `E == K` (direct signature); or
- `EmailController(addr)` and the message's `Auth-Cert` attributes `E` to `addr`, valid at the inclusion time (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)).

Because every step is deterministic given the message, on-chain state, and the pinned DNS root KSK, all correct clients reach the same decision (see [Validity Layers](./SBO%20Specification.md#validity-layers)).

### The stored creator

An object's durable **creator** — the author identity recorded in the state trie (see the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#creator-as-path-segment)) — is the author's *resolved controller*, not the (possibly ephemeral) signing key: the explicit `Creator` header, else the **attributed email** when the signer carries a valid attribution, else the signer's claimed name, else a stable encoding of the signing key. For an email-rooted author this keeps a single, stable creator across browserid key rotation; like authorization, it is pinned to the inclusion-time clock and so is deterministic on replay.

## The `/sys/names/` Namespace

`/sys/names/<name>` records register names. A name record provides a stable, human-friendly handle, optionally points to a profile, and — for email-rooted names — anchors reputation and other claims to a stable subject even as the controlling email changes.

A name record is an ordinary SBO object: its **controller is its `Owner`**, and updating or transferring it follows the normal authorization rules. Creating names is governed by the repository's policy (the default root policy grants `create` on `/sys/names/*` to everyone — first-come-first-served — and `update`/`delete` to the owner; see the [Genesis Specification](./SBO%20Genesis%20Specification.md)).

A name is **not required** to own objects: a bare email may be used as an owner directly. Register a name when you want a friendly handle, a profile, or a stable anchor independent of which email backs it.

## Email-Rooted Identity (`identity.email.v1`)

A name controlled by an email uses `Content-Schema: identity.email.v1` with `Content-Type: application/json`.

### Payload

```json
{
  "profile": "/alice/profile",
  "iat": 1703001234
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `profile` | string | No | Path or URI to a profile object |
| `iat` | number | Yes | Issued-at timestamp (Unix seconds) |

The controlling email is the object's **`Owner`** header, not a payload field. (Recording multiple controllers, for multi-provider control and recovery, is a roadmap extension and is not part of this version.)

### SBO Message

```
SBO-Version: 0.5
Action: post
Path: /sys/names/
ID: alice
Type: object
Content-Type: application/json
Content-Schema: identity.email.v1
Owner: alice@gmail.com
Public-Key: ed25519:<EPHEMERAL_KEY>
Auth-Cert: <browserid certificate binding EPHEMERAL_KEY to alice@gmail.com>
Signature: <envelope signature>

{"profile":"/alice/profile","iat":1703001234}
```

### Validation

1. `Owner` MUST be an identity reference that grounds to an email controller (or a key controller).
2. The message MUST be authorized for `Owner` per [Authorization](#authorization) — i.e. attributed to the controlling email via `Auth-Cert`, or signed by the controlling key.
3. If `profile` is present, it MUST reference a readable object.

### Recovery

Because the identity is the *name* (and the reputation anchored to it), not a key, recovery does not depend on key custody:

- If the controlling email is regained, the holder simply continues to authorize as that email.
- To change the controlling email (e.g. after losing access to a provider), the holder `transfer`s the name record to the new email (`New-Owner`), authorized as the current controller. Claims and reputation bound to the name survive the change.

## Key-Rooted Identity (`identity.v1`)

Key-rooted identities carry a public key and are authorized by a direct signature from it. They are used by genesis roots and by self-sovereign users who choose not to rely on a provider. The schema is unchanged from earlier versions.

All such identities use `Content-Type: application/jwt` and `Content-Schema: identity.v1`.

### JWT Payload

```json
{
  "iss": "self" | "domain:<domain>",
  "sub": "<identifier>",
  "public_key": "ed25519:<hex>",
  "profile": "/path/to/profile",
  "iat": 1703001234
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | `"self"` (self-signed) or `"domain:<domain>"` (certified by a repository domain) |
| `sub` | string | Yes | Subject identifier |
| `public_key` | string | Yes | Public key with algorithm prefix |
| `profile` | string | No | Path to a profile object |
| `iat` | number | Yes | Issued-at timestamp (Unix seconds) |

### Validation Rules

1. `Public-Key` header MUST match `public_key` in the JWT payload.
2. If `iss: "self"`, the JWT MUST be signed by `public_key`.
3. If `iss: "domain:<domain>"`, the JWT MUST be signed by the key from `/sys/domains/<domain>` (a repository root-of-trust domain — see below), and `sub` MUST be scoped to that domain.

> **Note.** `iss: "domain:<domain>"` here means certification by a **repository root-of-trust domain** (an on-chain `domain.v1` object), used for repository-internal identities such as `sys`. It is *not* the mechanism for ordinary user identities, which are email-rooted and attributed via DNSSEC.

## Sovereignty Upgrade (email → key, over time)

An email-rooted identity at the repository's **primary domain** may become
self-sovereign without changing its identity string or namespace. This unifies the
email identity `<local>@<D>` with the local name record `/sys/names/<local>`: they
are the **same party**, reached by different credentials over time.

**Primary domain.** A repository is authoritative for domain `D` iff a
`/sys/domains/D` object exists. This version assumes a **single** primary domain
per repository (the lone `/sys/domains/*` entry); multi-domain repositories need
domain-qualified name records and are deferred.

**Resolution override (record wins).** When resolving the controller of an email
`<local>@<D>` where `D` is the primary domain:

1. if `/sys/names/<local>` exists, resolve **through that record** (a key-rooted
   record → its key controls; an email-rooted record → recurse) — the on-chain
   record is the identity's control policy and **overrides browserid**;
2. otherwise the email is browserid-rooted, as usual (the onramp).

So before the holder publishes a key record, control flows through the domain's
browserid provider (the onramp); after, through the pinned key — and a
browserid cert minted by the domain no longer authorizes, so the operator can no
longer silently impersonate the holder. The record is public, so any tampering is
evident.

**Canonical identity (stable across the upgrade).** The author's durable identity
(the `creator` segment, and the policy `$user` variable) resolves to the same
string whichever credential signed: an attributed email yields `<local>@<D>`
directly; a signature by a pinned key resolves the key to its local name `<local>`
and, on a primary-domain repo, canonicalizes to `<local>@<D>`. The holder's
objects therefore stay in one namespace before and after going sovereign.

**Anti-hijack.** Because `/sys/names/<local>` governs `<local>@<D>`, creating it
must require control of `<local>@<D>` (see the Policy/Authorization specs). A
malicious domain operator can still front-run the claim; this is *evident* and
does not worsen the pre-upgrade trust, but cannot be fully eliminated without
giving up the email onramp.

## Domain Objects (`domain.v1`)

A `domain.v1` object at `/sys/domains/<domain>` establishes a domain as a **root of trust within a repository** — for example, in Mode B genesis, where the domain certifies the `sys` identity. It is a key-rooted identity for the domain, self-signed and pinned on chain.

A `domain.v1` MAY additionally be **self-certifying**: its `public_key` is proven to control the DNS zone `<domain>` by a `dnssec.v1` evidence object (the `_browserid.<domain>` DNSSEC chain; see the [Authorization Specification](./SBO%20Authorization%20Specification.md#dnssec-evidence-auth-evidence)) whose every RRSIG window contains the domain object's inclusion time. This binds domain authority into **genesis validity**: whoever verifies the genesis block — a full replayer, or (in the trustless-proof future) the base case of a recursive state proof — thereby verifies the domain's DNSSEC proof against the genesis DA-block time, so domain authenticity no longer rests on trusting the out-of-band `_sbo` discovery record. The evidence is therefore read from the **genesis block** at genesis-verification time, not from mutable state — a later user-attribution refresh of `/sys/dnssec/<domain>` does not affect it. Certification is **point-in-time**: it attests control at the object's inclusion time (genesis, for a genesis-pinned root) and, because the object is immutable, needs no refresh. Detecting a domain's post-genesis **lapse, transfer, or key rotation** (a liveness property) is out of scope for this version; a future revision may add a refreshable liveness proof (cf. the self-authorizing `/sys/dnssec/` refresh used for user attribution).

### JWT Payload

```json
{
  "iss": "self",
  "sub": "<domain>",
  "public_key": "ed25519:<hex>",
  "iat": 1703001234
}
```

### Validation Rules

1. `iss` MUST be `"self"`.
2. `sub` MUST match the `ID` in the SBO envelope.
3. The JWT MUST be signed by `public_key`, and the `Public-Key` header MUST match it.
4. A domain object MAY carry DNSSEC self-certification. When present — via an `Auth-Evidence` reference on the domain message, or a `dnssec.v1` object at the conventional `/sys/dnssec/<domain>` path resolved *as-of this object's block* — a verifier MUST: validate the evidence chain to the pinned root KSK with every RRSIG window containing this object's inclusion time; and check that the provider key read from the `_browserid.<domain>` record **equals** this object's `public_key`. A domain object whose self-certification is present but fails MUST be rejected. Absence of self-certification falls back to the repository-scoped, genesis-pinned trust of a plain self-signed domain object.

### Two senses of "domain" — do not conflate

| | Repository root-of-trust domain | User/provider email domain |
|---|---|---|
| Object | `domain.v1` at `/sys/domains/<domain>` (on chain) | None on chain |
| Key | Self-signed; MAY be the **same key** as the domain's `_browserid` provider key | The provider's `_browserid` key |
| Trust | On-chain, repository-scoped — and, when self-certifying, **DNSSEC-proven at the object's inclusion time** (point-in-time) | DNSSEC to the pinned DNS root KSK |
| Role | Certifies repository-internal identities (`sys`) | Attributes user writes (`Auth-Cert`) |

A single domain (e.g. `community.org`) MAY play both roles. It MAY keep them on **distinct keys**, or use a **single key** for both and mirror its `_browserid` DNSSEC proof on chain once (as a `dnssec.v1` object) to self-certify the root at genesis — the same object then also serves per-message user attribution (read as-of genesis for the root, current for users). Provider/email-domain keys are otherwise proven via DNSSEC per message and need not be mirrored on chain (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)).

## Community-Issued Identities (T1)

A repository MAY run its own browserid **primary identity provider** for its domain, issuing email-shaped names such as `alice@community.org`. This requires only that the repository operate a browserid provider and publish its key under `_browserid.<repo-domain>` with DNSSEC, exactly as any browserid primary IdP does. No SBO-specific on-chain configuration is required: the repository's domain is intrinsically authoritative for `*@<repo-domain>` via DNS, and such names attribute through the same DNSSEC path as any email.

### Issuance and backing

The provider decides how to authenticate a user before issuing a certificate. The recommended model authenticates the user via their *other* browserid identities — e.g. requiring proof of `alice@gmail.com` (and optionally additional providers) before issuing certificates for `alice@community.org`. The provider records the backing identity off chain.

### Properties

- **Non-SMTP names.** `alice@community.org` is an identifier in the repository's namespace; it need not receive mail. browserid certificates do not require SMTP for primary providers.
- **Pseudonymity (to the public).** On chain, only `alice@community.org` appears; the backing identity is known only to the issuing provider. This is pseudonymity with a trusted de-anonymizer (the provider), not zero-knowledge pseudonymity.
- **Ban the person, not the pseudonym.** Because the provider knows the backing identity, it can refuse to issue any `@<repo-domain>` name to that backing identity, defeating ban-evasion while preserving public pseudonymity.
- **Self-authenticating key rotation (optional, recommended).** Because the repository controls its own provider, it MAY sign each provider-key rotation with the previous key, from a pinned root. This makes the provider's key history self-authenticating and removes any residual reliance on live DNS for community-issued identities.

### Verification

A message authorized as `alice@community.org` is verified exactly like any email-rooted identity: the `Auth-Cert` is a certificate issued by `community.org`'s provider, and the DNSSEC chain proves that provider's key under `_browserid.community.org` to the pinned DNS root KSK.

## Profiles (`profile.v1`)

Profiles contain display information about an identity. An identity's `profile` field points to its profile object.

### Payload

```json
{
  "display_name": "Alice Smith",
  "bio": "Software developer and open source enthusiast",
  "avatar": "/alice/avatar.png",
  "banner": "/alice/banner.jpg",
  "location": "San Francisco, CA",
  "links": {
    "website": "https://alice.example.com",
    "github": "https://github.com/alice"
  },
  "metadata": {
    "pronouns": "she/her"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | string | No | Human-readable name (max 100 chars) |
| `bio` | string | No | Short biography (max 500 chars) |
| `avatar` | string | No | SBO path or URL to avatar image |
| `banner` | string | No | SBO path or URL to banner image |
| `location` | string | No | Free-text location |
| `links` | object | No | Key-value pairs of named links |
| `metadata` | object | No | Arbitrary key-value pairs |

A profile MUST be authorized by the identity that references it (the profile object's owner resolves to the same controller as the identity).

## Resolution Algorithms

```python
def resolve_identity(repo, ref):
    # Returns the controller (email or key) and profile for an owner reference.
    controller = resolve_controller(repo, ref)   # see "Owner References and Resolution"
    if controller is Unresolved:
        return None
    rec = fetch_name_record(repo, ref) if ref names /sys/names/* else None
    profile = rec.profile if rec else None
    return {"controller": controller, "profile": profile}

def resolve_domain(repo, domain):
    # Repository root-of-trust domain (key-rooted).
    obj = fetch(repo, f"/sys/domains/{domain}")
    jwt = parse_jwt(obj.payload)
    assert jwt["iss"] == "self"
    verify_jwt_signature(obj.payload, jwt["public_key"])
    assert obj.headers["Public-Key"] == jwt["public_key"]
    return jwt["public_key"]

def resolve_profile(repo, ref):
    ident = resolve_identity(repo, ref)
    if not ident or not ident["profile"]:
        return None
    profile = fetch(repo, ident["profile"])
    # profile object must be authorized by the same controller as the identity
    return parse_json(profile.payload)
```

## Repository Discovery (`_sbo` DNS)

To find a repository (its chain, appId, and genesis anchor) for an `sbo://` URI, clients query DNS:

```
_sbo.example.com. IN TXT "v=sbo1 repo=sbo+raw://avail:turing:506@12345/ genesis=sha256:abc123... node=https://sbo.example.com"
```

| Field | Required | Description |
|-------|----------|-------------|
| `v` | Yes | Record version (`sbo1`) |
| `repo` | Yes | Bare `sbo+raw://` database address, incl. the `@firstBlock` genesis anchor |
| `genesis` | No | Genesis hash (identity/verification) |
| `node` | No | Full-node URL serving the `/v1/*` data API |
| `checkpoint` | No | Bootstrap checkpoint URL (verified, not trusted) |

The `_sbo` record carries **no identity or trust root** — it only locates data. See the [URI Specification](./SBO%20URI%20Specification.md#dns-txt-record-format) for the authoritative field list and the bare-`repo=` rule, and the [Genesis Specification](./SBO%20Genesis%20Specification.md) for the bootstrap flow.

> Resolving a person → identity is on-chain (browserid broker pinned in genesis + `/sys/names/...`). Authentication-provider discovery (`_browserid` and the provider's service endpoints) is part of browserid and is described in the [SBO Authorization Specification](./SBO%20Authorization%20Specification.md), not here. There is no `h=` auth-host field and no `_sbo-id` record (both removed).

## Pseudonymous Identities (T2) — Roadmap

T1 makes an identity pseudonymous *to the public* but relies on the issuing provider as a trusted de-anonymizer. A future tier removes that trust using zero-knowledge proofs:

- A writer proves, in zero knowledge, that they hold valid certificates from one or more recognized providers (each chaining via DNSSEC to the pinned DNS root KSK) for a common hidden subject — revealing only that the identity is suitably backed.
- A deterministic **nullifier** derived from the hidden backing identity provides sybil-resistance and ban-the-person without revealing who the person is.

This makes an identity pseudonymous even to the issuer, with no trusted de-anonymizer, while remaining publicly verifiable. It is enabled by the same ZK machinery noted in the Core Specification's Attribution Capture and is **not specified in this version**.

## Security Considerations

- **Provider compromise.** A compromised provider can attribute a user's email to an attacker's key (the standard email-trust assumption). Multi-provider backing (roadmap) and T2 reduce reliance on any single provider.
- **Name squatting.** First-come name creation means names are claimed by whoever registers first; deployments may use stricter `/sys/names/*` policies.
- **DNSSEC dependence.** Attribution rests on DNSSEC and the pinned DNS root KSK; see the [Authorization Specification](./SBO%20Authorization%20Specification.md) for the trust analysis.

## Privacy Considerations

- Identity records, names, and profiles are public on chain.
- T0 direct-email identities expose the email address; T1 exposes only the community-issued name (backing known to the provider); T2 (roadmap) exposes neither.
- Users SHOULD NOT place sensitive information in profiles.

## References

- [SBO Specification](./SBO%20Specification.md) — Validity Layers, Attribution Capture, ownership
- [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) — `Auth-Cert`, envelope
- [SBO Genesis Specification](./SBO%20Genesis%20Specification.md) — roots, domains, name policy
- [SBO URI Specification](./SBO%20URI%20Specification.md) — references and discovery
- RFC 7519: JSON Web Token (JWT)
- RFC 8037: EdDSA Signatures in JOSE
