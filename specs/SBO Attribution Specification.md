---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Attribution Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.5 (2026-11, audit)**: §3/§4/§4a rewritten around the four-object device presentation in `Auth-Cert` (Q1); `Auth-Warrant` gone. New §3a: the `/sys/trust/dns-root` history read at inclusion time is the trust root for every proof (Q3). §5 gains the normative monotonic-freshness rule for `/sys/dnssec/<domain>` refreshes (Q16). No bare-key owners (Q6).

## Abstract

This specification defines how an SBO ledger attributes a **browserid-ng email
identity** to an on-chain **`ed25519:` key** — deterministically and **offline**,
at replay time, with no live connection to the identity provider. It layers the
ledger-specific machinery (identity rooting, evidence objects, trust anchors) on
the **offline-verification** primitive of the core identity protocol.

Dependency direction: SBO depends on browserid-ng, not the reverse. The general
capability — *"a browserid-ng certificate can be verified with no live fetch when
accompanied by a detached RFC 9102 DNSSEC proof for its issuer"* — is defined in
the **browserid-ng Protocol Specification, §6.3 (Offline verification with
detached DNSSEC proofs)**. This document specifies only how the ledger *uses*
that capability.

Reference implementation: `sbo-core/src/device_attribution.rs`, `sbo-core/src/authorize.rs`,
`sbo-daemon/src/validate.rs`.

## 1. Motivation

Core browserid-ng verification resolves an issuer's key over a live authenticated
DNS channel. On a ledger there is no live channel when a validator replays a
block; it must decide, deterministically and offline, *"did this signing key
speak for this email at this block height?"* SBO answers with a **self-contained
proof** carried in (or referenced by) the write: a browserid-ng certificate plus
a detached DNSSEC proof for the certificate's issuer. This is only possible
because the browserid-ng trust root is DNSSEC — a DNSSEC proof is a portable
artifact; a Web-PKI / `.well-known` fetch is not.

## 2. Identity rooting

An object's owner reference resolves to a controller:

- **Key-rooted** (`identity.v1`) — the owner *is* an `ed25519:` key
  (`Controller::Key`). Writes are authorized by signature alone. A key-rooted
  name is established once via a `/sys/names/<name>` claim.
- **Email-rooted** (`identity.email.v1`, or a bare email) — the owner is an
  email (`Controller::Email`). Each write MUST carry attribution (§3) proving
  the signing key spoke for that email at inclusion time.

An email-rooted owner may itself be a browserid **agent identity** (a `+tag`
sub-address a human delegated headlessly). In the device model there is no
separate agent credential: every presentation carries a warrant, and an agent
write is simply one whose warrant `grantor` (the human) differs from its
`grantee` (the agent). See the [Authorization
Specification](./SBO%20Authorization%20Specification.md#the-device-presentation-auth-cert)
for the normative rules; §3 and §4a below record how the reference
implementation applies them.

A bare key is **not** an owner (Identity Specification, Q6): every write names
a name or an email, and the only key-only objects are the genesis mode objects.

## 3. The attribution proof

A write attributing signer key `K` to email `e` carries:

- **`Auth-Cert`** — a browserid-ng **device presentation**
  `access_cert~assertion~warrant~config_cert`
  (`browserid_core::device::AccessPresentation`). The access cert binds `K`
  (`public-key = K`) to the grantee identity under issuer `iss_a`; the config
  cert, under issuer `iss_c`, binds the device key that signed the warrant to
  the grantor; the warrant grants grantor → grantee for this database's
  audience with scopes; the assertion, signed by `K`, proves possession for
  that audience. The attributed email `e` is the warrant's **grantor** when the
  scopes carry `as:<grantor>`, else the **grantee**.
- **`Auth-Evidence`** — a detached DNSSEC proof (browserid-ng §6.3) for an
  issuer's `_browserid` record. One proof is needed per **distinct** issuer in
  the presentation (`iss_a`, and `iss_c` when it differs). Each MAY be supplied
  as:
  - `inline:<base64url>` — the proof bytes in the envelope;
  - `ref:<sbo-path>` — a reference to an on-chain object holding them; or
  - **absent** — resolved from the conventional **`/sys/dnssec/<iss>`** object.

`/sys/dnssec/<domain>` objects (`dnssec.v1`) hold the RFC 9102 proof bytes for a
domain and are **self-authorizing**: policy grants create/update on
`/sys/dnssec/**` to any signer under a `dnssec_proof` restriction (see the
[Policy Specification](./SBO%20Policy%20Specification.md#self-authorizing-dnssec-objects-dnssec_proof)),
because the proof attests its own domain — it needs no prior identity to post.
This is what lets a fresh proof be published permissionlessly for *any* domain,
subject to the monotonic-freshness rule of §5.

There is no `Auth-Warrant` header and no single-certificate `Auth-Cert`; a
value that does not parse as a four-object presentation attributes nothing.

## 3a. Trust root for the DNSSEC proofs

Every proof in §3 validates against the **pinned DNS root KSK history** in
`/sys/trust/dns-root` (`dns-root.v1`, Authorization Specification): the
verifier takes the root key whose `[valid_from, valid_until]` contains the
write's **inclusion time** and validates the chain's root `DNSKEY` RRset
against it. This on-chain history is the anchor used at inclusion time; a
validator MUST NOT substitute a root key compiled into its DNSSEC library, and
MUST be able to validate evidence created under an earlier root after an IANA
rollover (the history is append-only, governed by the root policy). A proof
whose chain roots in a key outside the history, or outside its window at the
inclusion time, attributes nothing.

## 4. Verification algorithm

`verify_device_attribution(public_key, presentation, get_evidence, audience,
inclusion_time, authored_at, anchors)` (`sbo-core/src/device_attribution.rs`):

1. **Parse** the presentation; read the access cert issuer `iss_a` and the
   config cert issuer `iss_c`.
2. **Extract**, for each distinct issuer, the provider key and validity window
   from its DNSSEC proof (the `_browserid` published key; the RRSIG
   inception/expiration), validated against the `/sys/trust/dns-root` key in
   force at `inclusion_time` (§3a).
3. **Window** — `inclusion_time` MUST lie within every proof window.
4. **Authority** — for the grantee: `domain(grantee) == iss_a` or `iss_a` is a
   pinned broker; for the grantor: `domain(grantor) == iss_c` or `iss_c` is a
   pinned broker (`anchors.is_broker`, from `/sys/trust/brokers`). Domains are
   compared under the Identity Specification's comparison rule. This is what
   lets a broker-certified email (`iss = browserid.me`, unrelated to the email's
   domain) attribute, and what makes a cross-issuer delegation safe: an issuer
   can only vouch for identities in its own domain.
5. **Join** — the presentation verifies (`AccessPresentation::verify_at`): the
   access and config certs under their DNSSEC-proven issuer keys, the warrant
   under the config cert's key, the assertion under the access key; the
   warrant's holder matcher covers the access cert's holder; the config cert's
   identities cover the grantor; the assertion and warrant audiences equal the
   expected `sbo+raw://` audience; managed-identity constraints hold. Access
   cert, config cert and warrant windows are judged at `inclusion_time`; the
   **assertion** window is judged at `authored_at` (the HLC-derived authoring
   instant, bounded by the collection's `W`), else at `inclusion_time`.
6. **Key match** — the access cert's certified `public-key` MUST equal the
   signer `K`.

On success the signer is attributed to `e` (grantee, or grantor under `as:`)
for the intersection of the access cert and proof windows, and the warrant's
scopes are returned for the authorization layer to enforce (§4a). The daemon
uses this as its L2 authorization gate for email-rooted writes
(`sbo-daemon/src/validate.rs::device_effective_email`).

> **Host certificates (browserid-ng Protocol §4.2, forthcoming).** Once
> DNSSEC-signed host certificates land, step 5 generalizes from a single
> issuer-key check to verifying the certificate chain up to the DNSSEC key
> `K_dns` (directly, or via a host cert also signed by `K_dns`). To be specified
> here when host certs are implemented (browserid-ng bean `browserid-ng-dff5`).

## 4a. Authorization of the write (extends §4)

After §4 succeeds, the authorization layer (`sbo-core/src/authorize.rs`,
`authorized_write_email`) enforces the SBO-side rules on the verified
presentation:

7. **Audience** — the warrant's `audience` identifies this database
   (`audience_identifies_db`: authority match; `@firstBlock` / `?genesis` match
   if present).
8. **Scopes** — the write's `Action` / `Path` / `Content-Schema` satisfy the
   warrant scopes (`scopes_authorize`: AND across dimensions, OR within;
   `sign:sbo:<action>` and `action:<action>` both constrain the action; an
   **empty scope list authorizes nothing**; an unknown dimension or an unknown
   `sign:` kind ⇒ UNAUTHORIZED; `path:` scopes are subject to the wildcard
   cap).
9. **Effective author** — the write authorizes as the **grantee** by default;
   if the warrant carries `as:<grantor>` (combined with a `path:` scope), the
   effective author is the **grantor**, so owner/`Creator`/name-claim/policy
   checks evaluate against the grantor (an on-behalf write — see the
   Authorization Specification). An on-behalf write can never exceed what the
   grantor's own policy permits.

The attributed email on success is the **effective** author; indexers
additionally record the grantee, the grantor and both issuers as provenance.
Revocation status refs carried by the presentation are checked only at the
daemon's submit gate (`presentation_status_refs`), never on replay.

## 5. Evidence freshness

A `/sys/dnssec/<domain>` proof is refreshed before its RRSIG window lapses.

> **Operational note (non-normative, reference daemon since 2026-09-15).** A
> submitting node ensures evidence *at write time*: `POST /v1/submit`
> collects every issuer the batch's attribution will need (the access-cert
> and config-cert issuers of a device-model presentation; the `iss` of a
> legacy identity JWT), and for each whose on-chain proof would not cover
> inclusion (now + a margin, default 3600 s) captures a fresh RFC 9102 proof
> and enqueues a self-authorizing `dnssec.v1` refresh **ahead of** the write,
> so the refresh precedes it in chain order. The response lists them in
> `evidence_refreshed`. Clients need no refresh logic of their own; a writer
> that bypasses the daemon (submitting straight to the DA layer) remains
> responsible for freshness itself.
Because the proof is what authorizes an email-rooted write, a stale or
wrong-key proof breaks attribution for that domain until refreshed — so proof
freshness (and correct IdP key rotation) is operationally load-bearing.

> **Resolved (`mingo-jyzt`).** Under global `(path, id)` uniqueness (see the
> [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#object-identity-in-the-trie)),
> `/sys/dnssec/<domain>` is a single slot: the first valid writer creates it, and `creator`
> no longer keys the object, so a second writer can no longer *fork* the slot and the grindable
> low-sorting-key shadow is eliminated. Because the `/sys/dnssec/**` policy is self-authorizing
> (create **and update** granted to any signer), **any** party may refresh the slot in place with
> a newer proof; last-writer-wins (by `HLC`) means the current value is the most recently
> published proof. Evidence resolution reads that one occupying object and MUST still require its
> proof to validate for the domain at `inclusion_time`; a stale occupant is simply refreshed
> permissionlessly (as the daemon's freshness path already does) rather than shadowed by a
> competing fork.

### Monotonic freshness (normative)

Permissionless refresh must not become permissionless **rollback**. A refresh
of an occupied `/sys/dnssec/<domain>` slot is valid only if, in addition to
validating for `<domain>` at its inclusion time:

1. the new proof's **RRSIG expiration** for the `_browserid.<domain>` RRset is
   **≥** the current occupant's (a refresh never lowers the freshness horizon);
   and
2. the new proof's **DNSKEY set** for `<domain>` is the same as, or newer than,
   the occupant's: it MUST NOT reintroduce a key the occupant's set has rotated
   out (a pre-rotation key still inside its own RRSIG window is a valid chain
   but an older one).

A refresh that fails either comparison is invalid and leaves the occupant in
place. This is the `dnssec_proof` restriction's occupied-slot rule
([Policy Specification](./SBO%20Policy%20Specification.md#self-authorizing-dnssec-objects-dnssec_proof));
it is one comparison against the stored occupant, deterministic on replay,
and closes the attack where an attacker replaces a fresh proof with an older
valid chain to pin a rotated-out provider key (or to shorten the window so
attribution lapses).

## 6. Trust anchors

- **`/sys/trust/dns-root`** — the pinned DNS root KSK history (§3a); the key
  in force at the write's inclusion time anchors every RFC 9102 proof chain.
  It is the protocol's only a-priori trust, and it is read from the chain, not
  from the validator's library.
- **`/sys/trust/brokers`** — the pinned set of broker issuers whose
  broker-certified emails are honored (§4 step 4). `browserid.me` is the
  default. Payload is the object form `{ "brokers": [...] }`.

## 7. Security considerations

- Attribution inherits the browserid-ng trust root: it is exactly as strong as
  the DNSSEC chain for `iss`. A domain without DNSSEC cannot be a primary here;
  its users attribute via a pinned broker.
- Evidence is self-authorizing but *not* trust-granting: posting a
  `/sys/dnssec/<domain>` object proves nothing about identity — it merely makes
  a domain's already-DNSSEC-signed key available on-chain. Attribution still
  requires §4 steps 3–6.
- Windows are intersected (§4 result), so attribution is bounded by the
  shorter of the certificate and proof lifetimes; expiry is enforced against
  `inclusion_time`, not wall-clock, for deterministic replay.
