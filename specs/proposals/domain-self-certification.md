# Proposal: Self-Certifying `domain.v1` via a Genesis-Pinned DNSSEC Proof

Status: **Draft** — for review before applying to the normative specs.
Tracking: mingo-m6z7.

## Problem

A `/sys/domains/<D>` (`domain.v1`) object is today a **self-signed** JWT (`iss:"self"`, `public_key`, `sub:<D>`). Nothing on chain proves the signing key actually controls the DNS zone `<D>`. The binding "this chain represents `<D>`" rests entirely on out-of-band DNS control of the `_sbo.<D>` discovery record. A party handed only `appId@block/genesisHash` (no `_sbo` lookup) can verify repo-internal consistency but **cannot** confirm domain authenticity; and a plain-DNS `_sbo` spoof can point a victim at an impostor genesis whose self-signed `domain.v1` also claims `<D>`.

## Design (decided)

Make `domain.v1` **self-certifying from on-chain state** by binding its key to the zone with a **genesis-time DNSSEC proof**, reusing existing machinery:

1. **Reuse the `_browserid` provider key as the domain root key.** `_browserid.<D>` already publishes a DNSSEC-signed, repo-owned provider key (for Mingo: `ed25519:e021fda4…`, distinct from the external broker `browserid.me`). Use *that same key* as the `domain.v1` key and drop the separate domain key (`8ef0381e…`). No new DNS record, no new key.

2. **Point-in-time semantics (option i).** `domain.v1` is written once, at genesis; its `inclusion_time` is the genesis block time — a fixed historical instant. A single proof whose every RRSIG window brackets that instant certifies the domain **forever**. No periodic refresh (unlike user attribution, which refreshes because users keep making *new* writes).

3. **The proof is a `dnssec.v1` evidence object**, seeded at genesis under `/sys/dnssec/<D>` — the exact object type and `_browserid.<D>`-chain content already defined by the Authorization spec for user attribution. `domain.v1` references it (`Auth-Evidence: ref:/sys/dnssec/<D>`, or the conventional-namespace fallback). Verification is the standard DNSSEC-evidence check with the inclusion-time-clock rule, plus one added equality: the extracted provider key MUST equal `domain.v1.public_key`.

### One proof, two read semantics
Because the domain root key **is** the `_browserid` provider key, the same `/sys/dnssec/<D>` evidence object serves both:
- **domain self-cert** reads it *as-of the genesis block* (pinned, point-in-time), and
- **user attribution** reads the *current* version (refreshed over time — mingo-b763).

The versioned store gives this for free; genesis simply seeds the first `/sys/dnssec/<D>`.

### Trust-model notes
- Verification MUST use the **on-chain-mirrored genesis evidence**, never live DNS — so a later provider-key rotation cannot break historical domain verification.
- Reusing the (online) provider key as the (genesis-only) root key adds **no new post-genesis risk**: the domain key's only acts — signing `domain.v1` and certifying `sys` — happen once at genesis and are immutable; sys operates under its own key (`564aafe4…`) thereafter. A later provider-key compromise cannot rewrite genesis.
- **Deferred:** post-genesis domain **lapse / transfer / revocation** (a liveness property). This proposal certifies control *at genesis* only.

---

## Spec edits

Five specs change. Note (1) and (2) **reverse** existing normative statements ("distinct keys", "never mirrored on chain"), so they are edits, not additions.

### 1. `SBO Identity Specification.md` — "Domain Objects (`domain.v1`)"

**(a) Section prose** — after *"…self-signed and pinned on chain."* append:

> A `domain.v1` MAY additionally be **self-certifying**: its `public_key` is proven to control the DNS zone `<domain>` by a `dnssec.v1` evidence object (the `_browserid.<domain>` DNSSEC chain; see the [Authorization Specification](./SBO%20Authorization%20Specification.md#dnssec-evidence-auth-evidence)) whose every RRSIG window contains the domain object's inclusion time. A self-certifying domain object lets a client verify domain authority from **on-chain state alone**, with no trust in the out-of-band `_sbo` discovery record. Certification is **point-in-time**: it attests control at the object's inclusion time (genesis for a genesis-pinned root), and — because the object is immutable — needs no refresh. Post-genesis lapse/transfer/revocation is out of scope for this version.

**(b) Validation Rules** — add rule 4:

> 4. A domain object MAY carry DNSSEC self-certification. When present (via an `Auth-Evidence` reference, or a `dnssec.v1` object at the conventional `/sys/dnssec/<domain>` path resolved as-of this object's block), a verifier MUST: validate the evidence chain to the pinned root KSK with every RRSIG window containing this object's inclusion time; and check that the provider key read from the `_browserid.<domain>` record **equals** this object's `public_key`. A domain object whose self-certification is present but fails MUST be rejected. Absence of self-certification falls back to the repository-scoped, genesis-pinned trust of a plain self-signed domain object.

**(c) "Two senses of domain" table** — revise the root-of-trust column:

| Row | Was | Becomes |
|---|---|---|
| Key | *Self-signed, pinned at genesis* | Self-signed; **MAY be the same key as the domain's `_browserid` provider key** |
| Trust | *On-chain, repository-scoped* | On-chain, repository-scoped — **and, when self-certifying, DNSSEC-proven at the object's inclusion time (point-in-time)** |

And revise the closing sentence *"Provider/email-domain keys are **never** mirrored on chain; they are proven via DNSSEC per message"* →

> A domain playing both roles MAY use a **single key** for both and mirror its `_browserid` DNSSEC proof on chain once (as a `dnssec.v1` object) to self-certify the root at genesis; the same object then also serves per-message user attribution. Keeping the roles on distinct keys remains valid.

### 2. `SBO Genesis Specification.md`

**(a)** The note (~:401) *"…attributed via DNSSEC and **never stored on chain**…"* → 

> …attributed via DNSSEC. A domain's `_browserid` proof MAY be mirrored on chain **once**, as a `dnssec.v1` object under `/sys/dnssec/<domain>`, to **self-certify the repository root-of-trust domain** at genesis (see [Domain Objects](./SBO%20Identity%20Specification.md#domain-objects-domainv1)); per-message user-attribution evidence is otherwise not required to be stored.

**(b)** Mode B genesis description — add a step:

> **Self-certifying Mode B (recommended).** Set the `domain.v1` key to the domain's `_browserid` provider key, and seed a `dnssec.v1` object at `/sys/dnssec/<domain>` carrying the `_browserid.<domain>` DNSSEC chain captured at genesis-authoring time (RRSIG windows must bracket the genesis block). The domain then certifies `sys` **and** is itself DNSSEC-verifiable from state.

### 3. `SBO Authorization Specification.md` — "DNSSEC Evidence" / "Evidence object (`dnssec.v1`)"

Add a note to the `dnssec.v1` subsection:

> The same `dnssec.v1` evidence object also serves **domain self-certification**: a `domain.v1` whose key is the provider key certified by this evidence is DNSSEC-verifiable at its inclusion time (see [Domain Objects](./SBO%20Identity%20Specification.md#domain-objects-domainv1)). For a genesis-pinned root the relevant read is *as-of the genesis block*; for user attribution it is the current version — one object, two read semantics.

### 4. `SBO State Commitment Specification.md` — Overview

Extend the "attribution durability does not depend on checkpoints" paragraph (~:28) with:

> Likewise, a **self-certifying `domain.v1`** (see the [Identity Specification](./SBO%20Identity%20Specification.md#domain-objects-domainv1)) is verifiable directly from a snapshot: the domain object and its `dnssec.v1` evidence are ordinary state covered by the state root, so a fast-sync client can confirm domain authority from the loaded state alone, without a live `_sbo`/DNS lookup.

### 5. Deferred-scope note (Identity + Genesis)

Add, where domain trust is discussed:

> **Deferred:** detecting a domain's post-genesis **lapse, transfer, or key rotation** (a liveness property) is out of scope. Domain self-certification attests control at the object's inclusion time only. A future revision may add a refreshable liveness proof (cf. the self-authorizing `/sys/dnssec/` refresh used for user attribution).

---

## Implementation plan

Lands in the **batched regenesis** (with the resolution-based matching engine fix and, optionally, restoring `roles.admin:["sys"]`).

### Prerequisite (operational)
- The domain root key becomes the mingo `_browserid` provider key (`e021fda4…`), whose **secret lives in mingo-idp**. Genesis authoring needs it: import it into the keyring as an alias (e.g. `mingo-provider`) or run genesis with IDP-key access. Decide handling; the old `mingo-domain` key (`8ef0381e…`) is retired.
- A way to **capture the `_browserid.<domain>` DNSSEC chain** (RFC-4034 wire) at genesis-authoring time. Reuse whatever produces the user-attribution `/sys/dnssec/` proofs (dnssec self-auth work). Fetch-live or from-file.

### sbo-core
1. **`attribution.rs`** — add `verify_domain_self_cert(domain_public_key: &str, evidence: &[u8], domain: &str, inclusion_time: i64) -> Result<(), AttributionError>`: calls `verify_dnssec_proof_for_domain(evidence, domain)` (existing) → `(inception, expiration)`; re-extract provider key via `extract_provider_key` (existing); assert `provider_key == domain_public_key` (new `KeyMismatch`-style error) and `inclusion_time ∈ [inception, expiration]`. Pure, offline-testable.
2. No `domain.v1` **schema** change: `DomainClaims` stays `{iss, sub, public_key, iat}`. The proof is a *separate* `dnssec.v1` object; the binding is a validation rule, not a new field.

### sbo-daemon
3. **`validate.rs`** — in the domain-object validation path, when a `domain.v1` is applied: locate its evidence (explicit `Auth-Evidence: ref:` on the domain message, else `/sys/dnssec/<domain>` resolved as-of the domain object's block), and call `verify_domain_self_cert(...)` against the object's inclusion time. Start **warn-log on failure** (like the current genesis-hash check) to de-risk the first regenesis; flip to **hard-reject** once verified live. Add a startup/sync log line (`Domain <D> self-certified at block N` / `SELF-CERT FAILED`).
4. Ensure the daemon exposes/reads the domain object + evidence so the check runs during backfill of the genesis block.

### mingo-app (genesis)
5. **`genesis.rs`** —
   - Replace the `domain_signing_key` with the provider key (`e021fda4…`); `domain.v1` and the `sys` certification are signed by it. Remove references to the separate `8ef0381e…` key.
   - Seed a `dnssec.v1` object at `/sys/dnssec/<domain>` with the captured `_browserid.<domain>` chain, **before** `domain.v1` in the batch (so it is present when the domain object validates). Ensure ordering + genesis-mode acceptance.
6. **`bin/mingo.rs`** — `genesis` gains `--provider-key <alias>` (the `_browserid` key) and `--dnssec-evidence <file|--fetch>` to supply the chain. Update help + the emitted summary (print the domain key = provider key, evidence RRSIG window vs. expected genesis time).

### Tests
7. **sbo-core**: `verify_domain_self_cert` — accepts a matching key with inclusion time in-window; rejects key mismatch; rejects inclusion time outside window. Reuse the offline `verify_attribution_with_provider_key` test scaffolding (directly-supplied provider key) to avoid live DNS.
8. **mingo-app genesis**: the batch contains a `dnssec.v1` at `/sys/dnssec/<domain>` ordered before `domain.v1`; `domain.v1.public_key` == provider key; a `gencheck`-style assertion that self-cert verifies against the seeded evidence at a genesis-time timestamp.
9. **sbo-daemon**: apply a genesis with valid self-cert → `Domain self-certified`; tamper the evidence/key → rejected (once hard-reject is on).

### Rollout
10. Draft → apply the 5 spec edits (this branch). Then implement core→daemon→genesis. Then the **batched regenesis**: engine fix live + `roles.admin` (optional) + self-certifying `domain.v1`. Update `_sbo.<D>` per the regenesis checklist. Verify: `Genesis verified` + `Domain self-certified` + bootstrap `trust=OnChainCheckpoint`.

### Open questions
- Keep the point-in-time evidence as a distinct object, or allow `domain.v1` to *inline* the chain? (Separate object reuses `/sys/dnssec/` + de-dups with user attribution — preferred.)
- Enforce self-cert as **REQUIRED** for Mode B, or keep it optional (self-signed fallback)? Proposal: optional in the spec, but Mingo genesis always emits it.
- IDP-key handling at genesis (import vs. delegated signing) — security review before the ceremony.
