---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Attribution Specification

**Part of SBO Protocol v0.5**

## Status
Draft

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

Reference implementation: `sbo-core/src/attribution.rs`,
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

## 3. The attribution proof

A write attributing signer key `K` to email `e` carries:

- **`Auth-Cert`** — a browserid-ng certificate with `principal.email = e`,
  `public-key = K`, issued by `iss`.
- **`Auth-Evidence`** — a detached DNSSEC proof (browserid-ng §6.3) for `iss`'s
  `_browserid` record. It MAY be supplied as:
  - `inline:<base64url>` — the proof bytes in the envelope;
  - `ref:<sbo-path>` — a reference to an on-chain object holding them; or
  - **absent** — resolved from the conventional **`/sys/dnssec/<iss>`** object.

`/sys/dnssec/<domain>` objects (`dnssec.v1`) hold the RFC 9102 proof bytes for a
domain and are **self-authorizing**: policy grants create/update on
`/sys/dnssec/**` to any signer, because the proof attests its own domain — it
needs no prior identity to post. This is what lets a fresh proof be published
permissionlessly for *any* domain.

## 4. Verification algorithm

`verify_attribution(public_key, auth_cert, auth_evidence, inclusion_time, anchors)`
(`sbo-core/src/attribution.rs`):

1. **Parse** the certificate; read its issuer `iss`.
2. **Extract** the provider key and validity window from the DNSSEC proof for
   `iss` (the `_browserid` published key; the RRSIG inception/expiration).
3. **Key match** — the certified `public-key` MUST equal the signer `K`.
4. **Window** — `inclusion_time` MUST lie within both the proof window and the
   certificate's `iat…exp`.
5. **Signature** — the certificate MUST verify against the DNSSEC-proven
   provider key.
6. **Authority** — either `domain(e) == iss` (the email's own domain is a
   primary IdP), OR `iss` is a pinned broker (`anchors.is_broker(iss)`, from
   `/sys/trust/brokers`). This is what lets a broker-certified email
   (`iss = browserid.me`, unrelated to the email's domain) attribute.

On success the signer is attributed to `e` for the intersection of the
certificate and proof windows. The daemon uses this as its L2 authorization gate
for email-rooted writes (`sbo-daemon/src/validate.rs`).

> **Host certificates (browserid-ng Protocol §4.2, forthcoming).** Once
> DNSSEC-signed host certificates land, step 5 generalizes from a single
> issuer-key check to verifying the certificate chain up to the DNSSEC key
> `K_dns` (directly, or via a host cert also signed by `K_dns`). To be specified
> here when host certs are implemented (browserid-ng bean `28uc` Phase 2).

## 5. Evidence freshness

A `/sys/dnssec/<domain>` proof is refreshed before its RRSIG window lapses.
Because the proof is what authorizes an email-rooted write, a stale or
wrong-key proof breaks attribution for that domain until refreshed — so proof
freshness (and correct IdP key rotation) is operationally load-bearing.

> **Known issue (`mingo-jyzt`).** `/sys/dnssec/<domain>` objects are keyed by
> *creator*, and evidence resolution currently returns the first creator's
> object rather than a *valid* one — so multiple writers can fork the slot and a
> stale fork can win. Resolution MUST select a proof that validates for the
> domain at inclusion time (freshest valid window). This section is normatively
> incomplete until that is fixed.

## 6. Trust anchors

- **`/sys/trust/brokers`** — the pinned set of broker issuers whose
  broker-certified emails are honored (§4 step 6). `browserid.me` is the default.
- The **IANA DNSSEC root** anchors the RFC 9102 proof chains.

## 7. Security considerations

- Attribution inherits the browserid-ng trust root: it is exactly as strong as
  the DNSSEC chain for `iss`. A domain without DNSSEC cannot be a primary here;
  its users attribute via a pinned broker.
- Evidence is self-authorizing but *not* trust-granting: posting a
  `/sys/dnssec/<domain>` object proves nothing about identity — it merely makes
  a domain's already-DNSSEC-signed key available on-chain. Attribution still
  requires steps 3–6.
- Windows are intersected (step 6 result), so attribution is bounded by the
  shorter of the certificate and proof lifetimes; expiry is enforced against
  `inclusion_time`, not wall-clock, for deterministic replay.
