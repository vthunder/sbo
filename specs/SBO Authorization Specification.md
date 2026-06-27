---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Authorization Specification

**Part of SBO Protocol v0.5**

## Status
Draft

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
| **Attributed** | Email-rooted identity | `Auth-Cert` + DNSSEC evidence | certificate + DNSSEC chain to the pinned root KSK |

Direct mode is used by genesis roots and self-sovereign users (see [Self-Sovereign Authorization](#self-sovereign-authorization)). Attributed mode is the default path for email-rooted identities and is the bulk of this document.

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

## The Authentication Certificate (`Auth-Cert`)

`Auth-Cert` carries a **browserid certificate**: a JWT signed by the issuing provider's key that binds the SBO signing key to an email address.

### Claims

```json
{
  "iss": "example.com",
  "principal": { "email": "alice@example.com" },
  "public-key": "ed25519:<EPHEMERAL_KEY>",
  "iat": 1703001234,
  "exp": 1703087634
}
```

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | Issuing provider domain (a primary provider, or a recognized broker) |
| `principal.email` | Yes | The attributed email address |
| `public-key` | Yes | The certified key — MUST equal the message's `Public-Key` header |
| `iat` / `exp` | Yes | Validity window |

### Envelope-as-assertion

browserid normally pairs a certificate with a short, audience-bound *assertion* proving possession of the certified key. SBO does not use a separate assertion: the **SBO envelope itself** is signed by the certified `Public-Key`, which proves possession and binds the credential to that specific message. Consequences:

- No `aud` and no separate assertion are needed.
- A signature cannot be replayed to authorize a different message (the signature covers the message, including `Auth-Cert` — see the [Wire Format Specification](./SBO%20Wire%20Format%20Specification.md)).

### Constraints

- `public-key` MUST equal the envelope `Public-Key`.
- The inclusion time (below) MUST fall within `[iat, exp]`.
- `principal.email` MUST equal the email controller the message is authorized for.

## DNSSEC Evidence (`Auth-Evidence`)

The certificate is only as trustworthy as the provider key that signed it. `Auth-Evidence` proves that key is authentic by exhibiting the DNSSEC chain from `_browserid.<issuer-domain>` to the pinned root KSK.

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

## The Inclusion-Time Clock

Several windows above must be checked against a single, agreed time. SBO defines the **inclusion time** `T` of a message as the timestamp of the data-availability block in which it is included.

All of the following windows MUST contain `T`:

- the certificate `[iat, exp]`,
- every `RRSIG` `[inception, expiration]` in the evidence,
- the root KSK `[valid_from, valid_until]`,
- a recognized-broker designation, if applicable.

Using inclusion time (rather than wall-clock "now") is what makes a write **durably** verifiable: a from-scratch replayer re-checks the same windows against the same `T` and reaches the same result, forever. This inclusion-time clock is the canonical time source for SBO and is reused by other time-bounded rules (e.g. future recovery timelocks).

## Verification Algorithm

```
function authorize(message, chain_state):
    # Layer 1 — envelope validity (deterministic; see Wire Format Spec)
    if not verify_envelope(message):            # signature, Content-Hash, well-formedness
        return UNAUTHORIZED

    owner      = effective_owner(message)        # Owner, else Creator, else signer
    controller = resolve_controller(owner)       # Identity Spec
    if controller is Unresolved:
        return UNAUTHORIZED

    # Direct (key-rooted) authorization
    if controller is KeyController(K):
        return AUTHORIZED if message.PublicKey == K else UNAUTHORIZED

    # Attributed (email-rooted) authorization
    addr = controller.email
    T    = inclusion_time(message)

    cert = parse_jwt(message.AuthCert)
    if cert["public-key"] != message.PublicKey:        return UNAUTHORIZED
    if cert["principal"]["email"] != addr:             return UNAUTHORIZED
    if not (cert["iat"] <= T <= cert["exp"]):          return UNAUTHORIZED

    issuer = cert["iss"]
    # Authority: a primary provider for its own domain, or a recognized broker
    if domain_of(addr) != issuer and issuer not in recognized_brokers(chain_state, T):
        return UNAUTHORIZED

    evidence     = load_evidence(message)              # inline or referenced object
    provider_key = dnssec_validate(
        evidence,
        owner_name = "_browserid." + issuer,
        root_ksk   = pinned_root_ksk(chain_state, T),  # /sys/trust/dns-root
        at_time    = T)                                # every RRSIG window must contain T
    if provider_key is None:                           return UNAUTHORIZED
    if not verify_jwt_signature(cert, provider_key):   return UNAUTHORIZED

    return AUTHORIZED
```

Every input is on-chain (`chain_state`, the message, the pinned root KSK) or derived deterministically from them, so all correct clients reach the same decision and no sequencer, checkpoint, or trusted recorder is involved.

### Creator integrity

`effective_owner` is `Owner → else Creator → else signer`, so the algorithm above
authorizes the `Creator` reference *only when no `Owner` is present*. But `Creator`
independently determines the object's **identity in state** — its
`(path, creator, id)` trie segment (see the [State Commitment
Specification](./SBO%20State%20Commitment%20Specification.md#creator-as-path-segment)) —
while `Owner` gates the *path*. A writer must therefore not be able to file an
object under another identity's creator segment.

**Rule:** when a message declares a `Creator`, the signer MUST also be authorized
for it — `authorize` is additionally run with `owner = Creator`. This holds for
all actions. (When `Creator` is absent the creator is derived from the signer's
own attribution/name/key, so it is controlled by construction.)

### Name-claim anti-hijack (primary-domain repos)

On a repository authoritative for a primary domain `D`, a local name `<local>`
governs the identity `<local>@D` (the [Sovereignty
Upgrade](./SBO%20Identity%20Specification.md#sovereignty-upgrade-email--key-over-time)).
**Creating** `/sys/names/<local>` therefore MUST be authorized as `<local>@D`:
`authorize` is run with `owner = "<local>@D"`. The first claim is satisfied by
browserid attribution to that email; a later key rotation by the already-pinned
key (the email resolves through the existing record). Off a primary-domain repo,
or before the root policy exists (genesis), name claims are first-come.

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
- **Replay.** The certified key signs the whole message, so a credential cannot be reused to authorize a different message; identical re-posts are idempotent under last-write-wins.
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
