---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Authorization Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.5 (2026-11, audit)**: The browserid-ng four-object **device presentation** carried in `Auth-Cert` is the one normative attributed credential (Q1/S1); the single-JWT `Auth-Cert` and the `Auth-Warrant` header are retired. `sign:sbo:<action>` scope grammar documented. An empty scope list authorizes nothing (Q40). Wildcard cap of 32 on `path:` scopes with a polynomial matcher (Q38). The assertion is judged at the authoring instant bounded by a capped `W`; everything else at inclusion time (Q9). Owner references are never bare keys outside genesis (Q6).

## Abstract

This specification defines how an SBO message is **authorized**: how a signing key is **attributed** to an email identity using a browserid certificate plus DNSSEC evidence anchored to the pinned DNS root key-signing key (KSK), and how that attribution combines with ownership resolution to authorize a write.

**Authentication** — proving control of an email and obtaining a certificate — is performed by **browserid** and is out of scope here; this specification *consumes* a browserid certificate. Authentication is interactive and ephemeral; the authorization defined here is non-interactive and verifiable forever from the chain, by any client, with no network access. Self-sovereign (key-rooted) authorization by direct signature is the trivial case.

This is the concrete mechanism behind [Attribution Capture](./SBO%20Specification.md#attribution-capture) in the Core Specification and the [Authorization](./SBO%20Identity%20Specification.md#authorization) rules in the Identity Specification.

## Relationship to browserid

browserid (see the `browserid-ng` implementation) owns authentication and key discovery:

- user login and certificate issuance (the `cert_key` flow),
- primary-provider discovery via `_browserid.<domain>` TXT records under **DNSSEC**,
- the fallback **broker** for domains that run no provider (the broker itself enforces DNSSEC).

This specification does **not** redefine any of those. It defines only what SBO adds: using the resulting certificate as a write credential, the DNSSEC evidence that makes attribution objective, the on-chain trust anchors, the inclusion-time clock, and the verification algorithm.

## Authorization Modes

| Mode | Owner kind | Evidence carried | Verified by |
|------|------------|------------------|-------------|
| **Direct** | Key-rooted identity | none | `Public-Key` equals the owner's key; envelope signature |
| **Attributed** | Email-rooted identity | `Auth-Cert` (a four-object **device presentation**) + DNSSEC evidence | the presentation's join (access cert, assertion, warrant, config cert) + DNSSEC chains for its issuer(s) to the pinned root KSK |

Direct mode is used by genesis roots and self-sovereign users (see [Self-Sovereign Authorization](#self-sovereign-authorization)). Attributed mode is the only path for email-rooted identities and is the bulk of this document. There is **one** attributed credential: the browserid-ng **device presentation** ([The Device Presentation](#the-device-presentation-auth-cert)), which always contains a warrant. A write by the user's own device and a write by a delegated agent are the same object shape; they differ only in whether the warrant's `grantor` and `grantee` are the same identity. The presentation is fail-closed by construction: no object in it authorizes anything on its own, and the warrant names the one database it is good for. There is no separate `Auth-Warrant` header; the earlier single-certificate `Auth-Cert` and the standalone agent warrant are **retired** and MUST be rejected (a value that does not parse as a four-object presentation is not a credential).

## The Device Presentation (`Auth-Cert`)

`Auth-Cert` carries a browserid-ng **access presentation** (browserid-ng Protocol §6.1): four JWS objects joined by `~`:

```
Auth-Cert: <access_cert>~<assertion>~<warrant>~<config_cert>
```

| # | Object | `typ` | Signed by | Role in the write |
|---|--------|-------|-----------|-------------------|
| 1 | **access cert** | `browserid-access-cert-v1` | the grantee's IdP (`iss`) | Binds a short-lived **access key** to the `identity` (the grantee) and an opaque `holder`. The access key MUST equal the envelope's `Public-Key`: this is the key that signs the message. |
| 2 | **assertion** | browserid assertion | the access key | Proves possession of the access key **for this audience** (`aud` = this database, below). Short-lived (minutes). |
| 3 | **warrant** | `browserid-warrant-v1` / `-v2` | the config cert's key | A grant from `grantor` (the identity the write is attributed to) to `grantee` (the actor) over `(holder matcher) → audience [+ scopes]`. |
| 4 | **config cert** | `browserid-device-cert-v1`, `purpose: authorization` | the grantor's IdP (`iss`) | Binds the device key that signed the warrant to the grantor's identity, and MAY carry managed-identity `constraints`. |

Objects 1 and 4 are IdP-signed; their issuers' keys are what `Auth-Evidence` proves (one DNSSEC chain when `access_cert.iss == config_cert.iss`, two when a delegated grant crosses issuers). Every other signature in the bundle chains from those two keys, so the whole presentation verifies offline.

### Claims that SBO reads

```json
access_cert:  { "typ": "browserid-access-cert-v1", "iss": "example.com", "identity": "alice@example.com",
                "holder": "…", "public-key": "<access key>", "iat": …, "exp": … }
assertion:    { "aud": "sbo+raw://avail:turing:506/", "iat": …, "exp": … }
warrant:      { "typ": "browserid-warrant-v2", "grantor": "alice@example.com", "grantee": "alice@example.com",
                "binding": { … holder matcher … }, "audience": "sbo+raw://avail:turing:506/",
                "scopes": ["sign:sbo:post", "path:/u/alice@example.com/**"], "iat": …, "exp": … }
config_cert:  { "typ": "browserid-device-cert-v1", "purpose": "authorization", "iss": "example.com",
                "identities": ["alice@example.com"], "holder": "…", "public-key": "<device key>", "iat": …, "exp": … }
```

| Claim | Rule |
|-------|------|
| `access_cert.public-key` | MUST equal the envelope `Public-Key` (the SBO signing key). |
| `access_cert.identity` | The **grantee** (actor of record). MUST equal `warrant.grantee`. |
| `access_cert.iss` | MUST be authoritative for the grantee: equal to the grantee's email domain, or a recognized broker. |
| `warrant.grantor` | The identity the write is **attributed to** (the effective author, unless `as:` selects otherwise — see below). An exact email, never a pattern. |
| `config_cert.iss` | MUST be authoritative for the grantor (its domain, or a recognized broker); `config_cert.identities` MUST cover the grantor (exact, or the §4.6 subaddress rule: a cert for `user@d` covers `user+tag@d`). |
| `warrant.audience`, `assertion.aud` | MUST both identify **this database** ([The audience rule](#the-audience-rule-canonical-offline-verifiable)). |
| `warrant.binding` / `holder` | The warrant's holder matcher MUST cover `access_cert.holder` (the join that stops a warrant being wielded by a different device or agent). |
| `warrant.scopes` | MUST permit this write ([Warrant Scopes](#warrant-scopes)). |
| windows | Access cert, config cert, warrant: `[iat, exp]` MUST contain the **inclusion time**. Assertion: `[iat, exp]` MUST contain the **authoring instant** ([The Inclusion-Time Clock](#the-inclusion-time-clock)). |
| revocation `status` refs | NOT evaluated on replay (they need the network); a submitting node checks them fail-closed at its submit gate, which is advisory ([Validity Layers](./SBO%20Specification.md#validity-layers)). |

### Envelope binding

browserid-ng pairs an access cert with an audience-bound assertion. SBO keeps the assertion (it is what confines the presentation to this database) and adds a second binding: the **SBO envelope itself** is signed by the access key, which proves possession for this exact message. `Auth-Cert` and `Auth-Evidence` precede `Public-Key` in the header block, so they are inside the signature and cannot be stripped or swapped (see the [Wire Format Specification](./SBO%20Wire%20Format%20Specification.md)). A presentation cannot be replayed to authorize a different message, and a message cannot be re-homed under a different presentation.

### Self-grant and delegated grant

- **Self-grant** (`grantor == grantee`): the user's own device acts. The write is attributed to the user.
- **Delegated grant** (`grantor != grantee`): an agent or another person acts under a warrant the grantor's device signed. By default the write authorizes as the **grantee** (the agent as itself); with an `as:<grantor>` scope it authorizes **as the grantor** ([On-behalf writes](#on-behalf-writes)). A delegated grant can never exceed what the grantor's own config cert and IdP vouch for: `config_cert.iss` must be authoritative for the grantor, which is what makes cross-issuer delegation (grantor and grantee certified by different IdPs) safe.

### The audience rule (canonical, offline-verifiable)

**`audience` MUST be an `sbo+raw://` reference that identifies *this* database — never an `sbo://` DNS name.** The `_sbo` DNS record is discovery-only and is not a trust root (see the [URI Specification](./SBO%20URI%20Specification.md) and [Identity Specification](./SBO%20Identity%20Specification.md)); a validator replaying offline neither performs nor trusts DNS. An `sbo://` audience is therefore not verifiable on chain and MUST be rejected. (`sbo://mingo.place` remains the human-facing label a consent surface may *display*; the warrant it signs carries the resolved `sbo+raw://` form.) The assertion's `aud` MUST equal the warrant's `audience` byte-for-byte.

Given the database's canonical identity `(chain, appId, firstBlock, genesisHash)`, an audience `A` **identifies this database** iff `A` parses as an `sbo+raw://` reference and:

1. its authority equals `chain:appId` (**required**); and
2. if `A` carries an `@firstBlock` anchor, it equals this database's `firstBlock`; and
3. if `A` carries `?genesis=sha256:…`, it equals this database's `genesisHash`.

A **bare-authority** audience (`sbo+raw://avail:turing:506/`) thus authorizes the app across a regenesis; a **pinned** audience (`sbo+raw://avail:turing:506@3567386/?genesis=sha256:7c42…`) confines the grant to one genesis instance. Both are valid; the wallet chooses per request how broad a grant to ask for. The reference MUST be **bare** in the sense of the URI spec (no `path`/`creator`/`id`) — path-level restriction is expressed by scopes, not by the audience.

### Warrant Scopes

Scopes are opaque to the broker and IdP (browserid never interprets them); this specification defines the grammar SBO validators enforce. Each scope is a string `<dimension>:<value>`:

| Dimension | Constrains | Value |
|-----------|-----------|-------|
| `sign:sbo:<action>` | the message `Action` | `post` \| `transfer` \| `delete` \| `import`. This is the **browserid signing-grant form** (browserid-ng Protocol §5: `sign:<kind>:<what>` names what the user's wallet may be asked to sign); for an SBO write it constrains the action exactly like `action:`. Any other `sign:` kind (`sign:ledger:…`) is not an SBO write authorization and fails closed. |
| `action` | the message `Action` | `post` \| `transfer` \| `delete` \| `import` (synonym of `sign:sbo:<action>`; both forms accumulate into the one action dimension) |
| `path` | the message `Path` | a glob (`*` within a segment, `**` across segments), e.g. `/attestor/*`. Subject to the [wildcard cap](#wildcard-cap). |
| `schema` | the message `Content-Schema` | exact schema id, e.g. `nft.v1` |
| `as` | the **effective author** of the write (see [On-behalf writes](#on-behalf-writes)) | an email — MUST equal the warrant's `grantor`. At most one per warrant. Not a write constraint. |

Evaluation is deterministic (offline-replayable): **OR within a dimension** (any matching `path:` scope satisfies the path dimension) and **AND across dimensions** (every dimension that appears must be satisfied). A dimension that appears in no scope is unconstrained. A write is scope-authorized iff the scope list is non-empty (below) and the write satisfies every present dimension. The grammar is intentionally open to extension (`owner:`, `policy:`, `size:`, …); an **unrecognized dimension MUST cause the write to be UNAUTHORIZED** (fail-closed — a validator that does not understand a restriction must not ignore it).

**An empty scope list authorizes nothing.** A warrant for a ledger audience MUST carry at least one write-permitting scope (`sign:sbo:<action>` or `action:<action>`); a warrant whose `scopes` is empty or absent authorizes **no** write on this database. This is the on-chain analogue of browserid's "inert without a warrant" posture: a warrant minted for a web audience, or one minted without asking for a ledger grant, does not silently become a blanket write permission. (A warrant carrying only `path:` or `schema:` scopes is likewise not write-permitting; the action dimension must be granted explicitly.)

### Wildcard cap

A `path:` scope MUST contain at most **32 wildcard segments** (each `*` or `**` segment counts as one). A scope exceeding the cap is a malformed scope and the write is UNAUTHORIZED; a submitting node SHOULD reject such a presentation at its submit gate. The matcher MUST run in time polynomial in the pattern and path lengths (the memoised matcher shared with the [Policy Specification](./SBO%20Policy%20Specification.md#wildcard-cap); a backtracking matcher is exponential in the wildcard count and does not conform even under the cap). The cap is a size bound a second implementation can be held to, like the 256-character identifier limit; the polynomial requirement is what makes it a bound on work rather than on syntax alone.

### On-behalf writes

By default a delegated write authorizes as the **grantee's own identity** (`access_cert.identity`, e.g. `attestor@example.com`). To write to an object owned by the *grantor* — or to set the grantor as `Creator` — the agent must be authorized *as the grantor*, which the base grantee identity is not. The `as:` scope grants exactly that, scoped:

- A warrant carrying **`as:<email>`** (where `<email>` MUST equal the warrant's `grantor`) makes the **effective author** of writes under that warrant the **grantor** rather than the grantee. The write's owner-authorization, `Creator` integrity, policy actor (`$user`, `$email`), attestation subject and name-claim checks all evaluate against the grantor.
- Because the warrant is signed by the grantor's own config cert, `as:` can only ever name the grantor — an agent cannot be warranted to act as a third party.
- A self-grant with `as:` is a no-op (grantor and grantee coincide).

**Safety — delegation never exceeds the delegator.** An on-behalf write authorizes *as the grantor, under the same on-chain policy the grantor faces*. So it can do **at most what the grantor can do**, narrowed by the warrant's other scopes. It is not a policy bypass: a restriction the grantor is subject to still applies. The warrant can only ever *narrow* the grantor's authority, never widen it.

**Accountability — delegated, not silent.** The object's `Owner`/`Creator` is the grantor, but the presentation is part of the (message-bound) proof, so the write's provenance always names the grantee. Indexers MUST be able to surface "written by `<grantee>` acting as `<grantor>`." This is accountable delegation, not untraceable impersonation.

**Guardrails.**
1. An `as:` warrant MUST also carry at least one `path:` scope — an unrestricted act-as-grantor grant MUST be rejected. Impersonation is never repository-wide.
2. A repository MAY, by policy, decline to honor on-behalf warrants at all (a `direct-writes-only` repo); this hook is reserved (see [Policy Specification](./SBO%20Policy%20Specification.md)). Absent such a policy, on-behalf warrants are honored.

**One warrant, one author.** `as:` is a *per-warrant* mode: a warrant is either grantee-as-itself or on-behalf, never both (a single write has exactly one author). An agent that needs both — e.g. post to a shared area as itself *and* draft in the grantor's namespace as the grantor — holds **two warrants** at the same audience, distinguished by their scopes. Consequently a warrant's identity for grant/registry purposes is `(audience, scopes)`, not audience alone; two warrants may share an audience and differ only in mode.

## On-Chain Trust Anchors

Attribution verification requires exactly two small, governance-maintained objects on chain. Neither mirrors any provider's key.

### DNS root KSK — `/sys/trust/dns-root` (`dns-root.v1`)

The single global anchor. Its payload is an ordered history of root KSKs, so evidence created under an earlier root remains verifiable across rollovers.

```json
{
  "keys": [
    {
      "key_tag": 20326,
      "algorithm": 8,
      "public_key": "AwEAAa...base64...",
      "valid_from": 1538265600,
      "valid_until": null
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `key_tag`, `algorithm` | DNSKEY key tag and DNSSEC algorithm number (IANA) |
| `public_key` | The root KSK public key (DNSKEY RDATA, base64) |
| `valid_from` / `valid_until` | Activation window; `valid_until` null = current |

This object SHOULD be present from genesis and is updated only by repository governance on an IANA root-KSK rollover. It is the **only** key the protocol trusts a priori.

### Recognized brokers — `/sys/trust/brokers` (`brokers.v1`)

A governed list of broker domains permitted to vouch for emails whose own domain runs no provider.

```json
{ "brokers": ["broker.example"] }
```

A broker's signing key is itself DNSSEC-proven (under `_browserid.<broker-domain>`); only the **designation** "this domain may act as a broker" is a governance decision. An empty or absent list means only primary providers are accepted.

## DNSSEC Evidence (`Auth-Evidence`)

The presentation is only as trustworthy as the IdP keys that signed its access cert and config cert. `Auth-Evidence` proves such a key is authentic by exhibiting the DNSSEC chain from `_browserid.<issuer-domain>` to the pinned root KSK. A presentation whose two IdP-signed objects have different issuers needs evidence for each (one inline plus one on chain, or both on chain under `/sys/dnssec/<issuer>`).

### Structure

The evidence is the ordered DNSSEC validation chain, in DNS wire format ([RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)). For each zone on the path from `_browserid.<issuer-domain>` up to the root it contains the records and signatures needed to validate that link:

1. The `_browserid.<issuer-domain>` `TXT` RRset (which contains the provider key) and its `RRSIG`.
2. For each zone up to the root: the `DNSKEY` RRset and its `RRSIG`, and the `DS` RRset at the parent and its `RRSIG`.
3. The root `DNSKEY` RRset and its `RRSIG`, validated against the **pinned root KSK**.

Validation is standard DNSSEC validation, with the additional rule that **every `RRSIG` inception/expiration window MUST contain the inclusion time** (not merely "now"). The validated provider key is read from the `_browserid` TXT record (browserid key format).

### Carriage

The optional `Auth-Evidence` header carries the evidence one of two ways:

| Form | Value | Meaning |
|------|-------|---------|
| Inline | `inline:<base64>` | The full chain, in the message |
| Reference | `ref:<sbo-path-or-uri>` | A reference to an on-chain evidence object |

Either way the evidence is recorded on chain. When attribution is required and `Auth-Evidence` is absent, a verifier MAY locate evidence for the issuer key and inclusion time from the conventional `/sys/dnssec/` namespace; if none is available, the message is unauthorized.

### Evidence object (`dnssec.v1`)

DNSSEC chains are large (kilobytes) and identical for all writes under one provider key during its signature-validity window. To avoid per-write bloat, the chain MAY be posted once as a self-authenticating evidence object and referenced thereafter:

- `Content-Schema: dnssec.v1`, payload = the DNSSEC chain (as above), conventionally under `/sys/dnssec/`.
- Because the object validates against the pinned root KSK, it is **self-authenticating** — posting it is not a trusted write; any client re-validates it independently.
- Writes during the window reference it via `Auth-Evidence: ref:...`; the certificate (small) remains per-message in `Auth-Cert`.

The same `dnssec.v1` evidence object also serves **domain self-certification**: a `domain.v1` whose key is the provider key certified by this evidence is DNSSEC-verifiable at its inclusion time (see [Domain Objects](./SBO%20Identity%20Specification.md#domain-objects-domainv1), Validation Rule 4). For a genesis-pinned root the relevant read is the object *as-of the genesis block* (point-in-time, no refresh); for user attribution it is the current version (refreshed as RRSIGs age) — one object, two read semantics.

## The Inclusion-Time Clock

Several windows above must be checked against a single, agreed time. SBO defines the **inclusion time** `T` of a message as the timestamp of the data-availability block in which it is included.

All of the following windows MUST contain `T`:

- the access cert, config cert and warrant `[iat, exp]`,
- every `RRSIG` `[inception, expiration]` in the evidence,
- the root KSK `[valid_from, valid_until]` (the `/sys/trust/dns-root` entry in force at `T`),
- a recognized-broker designation, if applicable.

Using inclusion time (rather than wall-clock "now") is what makes a write **durably** verifiable: a from-scratch replayer re-checks the same windows against the same `T` and reaches the same result, forever. This inclusion-time clock is the canonical time source for SBO and is reused by other time-bounded rules (e.g. future recovery timelocks).

### The authoring instant (assertion only)

The **assertion** is the one object whose window is judged at the write's **authoring instant** `A`, not at `T`. An assertion lives minutes; a write can wait longer than that between signing and inclusion (batching, DA latency), so judging it at `T` would make honest writes fail by timing. `A` is derived deterministically from the message: the `HLC` header's physical component, which the [Content Specification](./SBO%20Content%20Specification.md#author-clock-hlc) bounds to `T_b − W ≤ A ≤ T_b + ε` with `W` capped by the protocol maximum (reference 24 h). A message with no `HLC` has `A = T`. Because `W` is bounded, an attacker cannot back-date `A` far enough to resurrect an expired assertion, and because `A` is in the signed message, every replayer computes the same `A`. Nothing else uses `A`: certs, warrants, DNSSEC windows and the root KSK are judged at `T`, so a long-lived credential cannot be made to look valid by authoring a write inside its window and including it after revocation-by-expiry.

## Verification Algorithm

```
function authorize(message, chain_state):
    # Layer 1 — envelope validity (deterministic; see Wire Format Spec)
    if not verify_envelope(message):            # signature over the received bytes, Content-Hash, well-formedness
        return UNAUTHORIZED

    owner      = effective_owner(message)        # Owner, else Creator; a message naming neither is invalid (Identity Spec)
    controller = resolve_controller(owner)       # Identity Spec
    if controller is Unresolved:
        return UNAUTHORIZED

    # Direct (key-rooted) authorization
    if controller is KeyController(K):
        return AUTHORIZED if message.PublicKey == K else UNAUTHORIZED

    # Attributed (email-rooted) authorization: the device presentation
    addr = controller.email
    T    = inclusion_time(message)                       # DA block time
    A    = authoring_instant(message, T)                 # HLC physical (bounded by W), else T

    pres = parse_presentation(message.AuthCert)          # access_cert ~ assertion ~ warrant ~ config_cert
    if pres is None:                                     return UNAUTHORIZED   # legacy single cert: not a credential
    ac, asn, w, cc = pres

    # 1. Signing-key binding and identities
    if ac["public-key"] != message.PublicKey:            return UNAUTHORIZED
    grantee = ac["identity"];  grantor = w["grantor"]
    if w["grantee"] != grantee:                          return UNAUTHORIZED
    if not holder_matcher_covers(w, ac["holder"]):       return UNAUTHORIZED
    if not identities_cover(cc["identities"], grantor):  return UNAUTHORIZED   # exact, or user@d covers user+tag@d

    # 2. Issuer authority (each IdP vouches only for its own domain, or is a recognized broker)
    brokers = recognized_brokers(chain_state, T)
    if domain_of(grantee) != ac["iss"] and ac["iss"] not in brokers:  return UNAUTHORIZED
    if domain_of(grantor) != cc["iss"] and cc["iss"] not in brokers:  return UNAUTHORIZED

    # 3. DNSSEC-proven IdP keys, windows at T (one chain per distinct issuer)
    keys = {}
    for iss in distinct(ac["iss"], cc["iss"]):
        evidence  = load_evidence(message, iss)          # inline, ref:, or /sys/dnssec/<iss>
        keys[iss] = dnssec_validate(evidence,
                        owner_name = "_browserid." + iss,
                        root_ksk   = pinned_root_ksk(chain_state, T),   # /sys/trust/dns-root
                        at_time    = T)                                 # every RRSIG window must contain T
        if keys[iss] is None:                            return UNAUTHORIZED

    # 4. Signatures and windows
    if not verify_jws(ac, keys[ac["iss"]]):              return UNAUTHORIZED
    if not verify_jws(cc, keys[cc["iss"]]):              return UNAUTHORIZED
    if not verify_jws(w,  cc["public-key"]):             return UNAUTHORIZED   # warrant signed by the config cert's device key
    if not verify_jws(asn, ac["public-key"]):            return UNAUTHORIZED   # assertion signed by the access key
    if not (ac["iat"] <= T <= ac["exp"]):                return UNAUTHORIZED
    if not (cc["iat"] <= T <= cc["exp"]):                return UNAUTHORIZED
    if not (w["iat"]  <= T <= w["exp"]):                 return UNAUTHORIZED
    if not (asn["iat"] <= A <= asn["exp"]):              return UNAUTHORIZED   # the assertion, at the authoring instant
    if cc["constraints"] or ac["constraints"]:
        if not constraints_satisfied(cc, ac, w):         return UNAUTHORIZED   # managed identities (browserid-ng §4.7)

    # 5. Audience and scopes: THIS database, THIS write
    if asn["aud"] != w["audience"]:                      return UNAUTHORIZED
    if not audience_identifies_db(w["audience"], chain_state): return UNAUTHORIZED
    if not scopes_authorize(w["scopes"], message):       return UNAUTHORIZED   # empty list ⇒ false; unknown dimension ⇒ false

    # 6. Effective author: the grantee by default, the grantor under `as:`
    effective_email = grantee
    as_scope = scope_value(w["scopes"], "as")
    if as_scope is not None:
        if as_scope != grantor:                          return UNAUTHORIZED
        if not has_path_scope(w["scopes"]):              return UNAUTHORIZED   # guardrail 1
        if repo_rejects_on_behalf(chain_state):          return UNAUTHORIZED   # guardrail 2
        effective_email = grantor

    # 7. The write is authorized for `effective_email`: owner match, Creator,
    #    name-claim and the policy actor all evaluate against it.
    if effective_email != addr:                          return UNAUTHORIZED
    return AUTHORIZED
    # Provenance recorded for indexers: grantee (actor), grantor, both issuers.
```

The last step is the same email-controller match a single-identity write performs, run against the *effective* author: for a self-grant or a default delegated write that is the grantee, so the write may touch objects the grantee owns (or that policy grants it); for an on-behalf write it is the grantor, so no per-object policy is needed. Revocation `status` refs carried by the three chain objects are **not** consulted here: replay must not depend on a network fetch. A submitting node checks them fail-closed at its submit gate, which is advisory.

Every input is on-chain (`chain_state`, the message, the pinned root KSK) or derived deterministically from them, so all correct clients reach the same decision and no sequencer, checkpoint, or trusted recorder is involved.

### Creator integrity

`effective_owner` is `Owner → else Creator`, so the algorithm above
authorizes the `Creator` reference *only when no `Owner` is present*. But `Creator`
is the object's immutable **author attribute** and gates provenance/ownership
defaulting. A writer must not be able to file an object under another identity's
`Creator`.

**Rule:** when a message declares a `Creator`, the signer MUST also be authorized
for it — `authorize` is additionally run with `owner = Creator`. This holds for
all actions. (When `Creator` is absent the creator is derived from the signer's
own attribution or name, so it is controlled by construction.) There is no
signer-key fallback: a message that names neither `Owner` nor `Creator` resolvable
to a name or an email is invalid, and an explicit bare-key `Owner`/`Creator`/
`New-Owner` is invalid, outside the genesis mode objects (see the
[Identity Specification](./SBO%20Identity%20Specification.md#owner-references)).

### Name-claim anti-hijack (primary-domain repos)

On a repository authoritative for a primary domain `D`, a local name `<local>`
governs the identity `<local>@D` (the [Sovereignty
Upgrade](./SBO%20Identity%20Specification.md#sovereignty-upgrade-email--key-over-time)).
**Creating** `/sys/names/<local>` therefore MUST be authorized as `<local>@D`:
`authorize` is run with `owner = "<local>@D"`. The first claim is satisfied by
browserid attribution to that email; a later key rotation by the already-pinned
key (the email resolves through the existing record). Off a primary-domain repo,
or before the root policy exists (genesis), name claims are first-come.

"First-come" here is the **global `(path, id)` first-valid-write-wins** invariant
(see [State Commitment](./SBO%20State%20Commitment%20Specification.md#slot-occupancy-and-create-race-resolution)):
the anti-hijack authorization requirement layers *on top of* it — policy makes the
slot claimable only by the rightful email, and uniqueness makes the first valid
claim final.

## Self-Sovereign Authorization

A key-rooted owner (a genesis root, or a self-sovereign user with an `identity.v1`) is authorized by **direct signature**: the message's `Public-Key` must equal the owner's key, and the envelope signature must verify. No `Auth-Cert`, no `Auth-Evidence`, and no DNSSEC are involved. This is the `KeyController` branch above. The future self-sovereign tier with multi-provider recovery is noted in the Identity Specification and is out of scope here.

## Required DNSSEC Algorithms

Verifiers MUST support at least:

| Algorithm | Number | Status |
|-----------|--------|--------|
| ECDSAP256SHA256 | 13 | REQUIRED |
| RSASHA256 | 8 | REQUIRED |
| ED25519 | 15 | RECOMMENDED |

Only **positive** proofs are used (a key is present in a signed RRset); NSEC/NSEC3 negative-existence proofs are not required. Algorithm choices track [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624); deprecated algorithms (e.g. RSASHA1) MUST be rejected.

## Convergence and Durability

- **Convergence.** Attribution is a deterministic function of the message and on-chain state (the pinned root KSK and recognized brokers), so every correct client computes the same result. There is no divergence from differing live-DNS views.
- **Durability.** Because all windows are checked against the inclusion time and the evidence is on chain, a client replaying from genesis verifies any past message with no network access and no trusted intermediary, regardless of later provider-key or root-KSK rollovers.

## Trust Model

Trust reduces to exactly what email identity already implies:

- the **DNS root** and **DNSSEC** correctness (the same trust the web already places in the DNS hierarchy), and
- the deployment's **recognized-broker** designation (only for emails whose domain runs no provider).

No per-provider keys are trusted-written on chain; provider keys are *proven* per message. Because each piece of evidence was checkable against live DNS when it was posted, a forged chain is publicly auditable after the fact (Certificate-Transparency-style). A zero-knowledge proof of this verification is a future optimization that shrinks evidence and can conceal the provider domain and email (enabling the pseudonymous identity tier); it does not change the trust model.

## Security Considerations

- **Provider/broker compromise.** A compromised provider (or recognized broker) can attribute an email to an attacker's key — the standard email-trust assumption. Multi-provider backing and the pseudonymous tier (Identity Spec, roadmap) reduce reliance on any single provider.
- **Root KSK governance.** `/sys/trust/dns-root` is the protocol's a-priori trust; its update path MUST be tightly governed and SHOULD track IANA rollovers exactly.
- **Replay.** The access key signs the whole message and the assertion is audience-bound, so a presentation cannot be reused to authorize a different message or on a different database; identical re-posts are idempotent under last-write-wins.
- **Scope evaluation is untrusted input.** A warrant is authored by any wallet and evaluated by every node at the submit gate and on replay. The wildcard cap and the polynomial matcher bound the work one scope can cause; an empty scope list and an unknown dimension both fail closed.
- **Submit-time checks are advisory.** Revocation status, live DNS and wall-clock freshness are checked by a submitting node, not by replay. A writer that bypasses the node and submits to the DA layer directly is bound only by the replay rules above (see [Validity Layers](./SBO%20Specification.md#validity-layers)).
- **Clock.** Verifiers MUST use the inclusion time, not wall-clock, or durable verification breaks.

## Privacy Considerations

- `Auth-Cert` and DNSSEC evidence reveal the email address and provider domain (the public T0/T1 tiers).
- The pseudonymous tier (Identity Spec T2, roadmap) replaces these with a zero-knowledge proof that reveals neither.

## References

- [SBO Specification](./SBO%20Specification.md) — Validity Layers, Attribution Capture
- [SBO Identity Specification](./SBO%20Identity%20Specification.md) — identities, resolution, tiers
- [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) — `Auth-Cert`, `Auth-Evidence`, signature scope
- browserid (`browserid-ng`) — authentication, certificate issuance, `_browserid` discovery, broker
- RFC 4033/4034/4035, 6840 — DNSSEC; RFC 8624 — DNSSEC algorithm implementation requirements
- RFC 7519 — JSON Web Token (JWT); RFC 8037 — EdDSA in JOSE
