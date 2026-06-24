# Phase 7 Plan — the Mingo reference client + provider

**Date:** 2026-06-24
**Status:** Draft for review
**Goal:** Stand up **Mingo** (`docs/plans/2026-06-24-demo-ux-spec.md`) end-to-end: a
browser web app where a user signs up for a `<name>@mingo.place` pseudonym, joins
topic communities, posts/comments/votes, and sees their **Reputation Passport** —
all backed by the SBO stack. Phase 6 left **no protocol work**; Phase 7 is
client + provider + a thin daemon API.

This is itself a multi-session effort. Sub-phases are dependency-ordered, each
ending at a **demo checkpoint** (something you can show/curl). Build green per
step; pause for review per sub-phase, as in prior phases.

---

## Architecture

```
┌────────────┐  login → provision @mingo,    ┌─────────────────────────┐
│  Browser   │  cert binds key↔email          │  Mingo IdP               │
│  web app   │ ◀───────────────────────────▶ │  (browserid-ng broker    │
│  build:wasm│                                │   @ DNSSEC mingo.place)   │
│  sign:bid  │   (envelope built by sbo-wasm, └─────────────────────────┘
│  ┌───────┐ │    signed by browserid key)
│  │sbo-wasm│ │   HTTP read + submit
│  └───────┘ │ ◀───────────────────────────▶ ┌─────────────────────────┐
└────────────┘                                │  sbo-daemon + HTTP API   │
                                              │  (syncs the Mingo repo,  │
                                              │   serves confirmed state)│
                                              └───────────┬─────────────┘
                                                          │ submit_raw / sync
                                                          ▼
                                                  ┌───────────────┐
                                                  │   DA layer    │
                                                  │ (Avail/Turbo  │
                                                  │  or local dev)│
                                                  └───────────────┘
```

Three trust boundaries, unchanged from the spec: the **provider** attests "this
key speaks for `alice@mingo.place`" (login moment); the **DA layer** is the
durable, censorship-resistant record; the **daemon** is a *convenience* indexer
computing confirmed state by deterministic replay — never an authority (the
browser can verify via SBOQ proofs).

## What exists vs. what's new (grounded in the surface map)

| Capability | Status | Where |
|---|---|---|
| Provider (issue `@mingo.place` certs) | **Exists** — deploy only | browserid-ng broker (`/wsapi/authenticate_user`, `/wsapi/cert_key`, `/.well-known/browserid`) |
| Capture cert + DNSSEC evidence | **Exists** | `sbo-capture::capture_attribution` |
| Email-identity write | **Exists** | `presets::claim_email_identity` |
| Genesis (sys + root policy) | **Exists, thin** | `presets::genesis` / `genesis_with_domain*` |
| Submit raw signed wire → DA | **Exists** | IPC `Submit`, `turbo::submit_raw` |
| Object **proof** read (SBOQ) | **Exists** | IPC `ObjectProof`, `sboq` |
| Object **value** read / list | **Missing** | IPC `GetObject` is a stub (`main.rs:700`); no `list` IPC |
| HTTP API for the browser | **Missing** | `http.rs` serves only `/auth*` + `/health` |
| Browser-side envelope build + sign | **Missing** | no WASM/JS SBO lib |
| community/attestation/post/comment/reaction/collection message builders | **Missing** | `presets.rs` has none |
| The web client UI | **Missing** | — |

The two **load-bearing new pieces** are: a **browser SBO library (WASM)** so the
client can build and sign envelopes trustlessly, and a **daemon HTTP read/submit
API**. Everything else is composition or UI.

---

## Decisions — LOCKED (2026-06-24 review)

1. **Browser signing — `sbo-wasm` for serialization, browserid key for the
   signature; spike first.** Canonical signing bytes must match `sbo-core::wire`
   exactly, so we do **not** reimplement the envelope in TS. A new **`sbo-wasm`
   crate** exposes envelope-build + wire-serialize (the canonical-bytes producer),
   depending only on `sbo-core`'s wire/message subset — **not** state/daemon/RocksDB.
   The **ed25519 signature is produced by browserid's existing in-browser key
   component** (see #4), not a fresh key. The 7.0 spike validates this end to end
   before we commit to the architecture; "if it works, it's the direction."
2. **DA target — Avail testnet (then mainnet).** No local/mock DA. Avail is
   practically free at today's prices, so we run against the real DA layer for the
   demo (testnet first, mainnet a config switch). Simpler and more honest than a
   home-grown harness; the daemon's `turbo`/light-client path already targets it.
3. **Client ↔ daemon transport — extend the existing daemon.** Add read+submit
   HTTP routes (CORS) to the daemon's axum server (`http.rs`); **no separate
   gateway**. The CLI keeps the Unix-socket IPC.
4. **Signing key = the browserid cert-bound browser key, extended to sign SBO
   envelopes.** The SBO envelope **must** be signed by the same ephemeral key the
   provider cert binds to the email — otherwise the signature isn't attributable
   and the L2 check fails. So we **reuse browserid's in-browser key + signing
   component** (which already signs *assertions* in JS) and **extend it to also
   sign SBO canonical bytes**. This is a deliberate change to the browserid↔website
   contract and must be designed **very** carefully (see Risks): a malicious RP
   must not be able to coax the key into signing arbitrary content or forging
   envelopes. Requires **domain separation** (a distinct, namespaced signing
   operation for SBO envelopes vs assertions) and origin-gating. Cross-repo work in
   `~/src/browserid-ng` (the JS browser component) + a careful contract spec.
5. **Mingo = a browserid IdP that provisions a local identity.** `mingo.place`
   runs a browserid IdP: a user **signs in with browserid** (via an existing
   identity, e.g. their gmail, or a Mingo password account) and is then
   **provisioned a local `<name>@mingo.place` identity** (T1 community-issued — the
   Identity spec's community-as-IdP model; multi-IdP auth logic lives in the IdP).
   The **demo hardcodes certain emails → admin** (a config mapping recognized
   sign-ins to admin role attestations seeded at genesis). Seed content is authored
   by a few pre-provisioned `@mingo.place` accounts (7.5).

---

## Sub-phases

### 7.0 — `sbo-wasm` spike (de-risk the crux)
The whole client architecture hinges on this; build it first, prove it, then commit.
- **Spike `sbo-wasm`:** prove `sbo-core`'s wire+message subset compiles to `wasm32`
  and produces **canonical signing bytes byte-identical to the native serializer**
  (golden-vector test: same headers/payload → identical canonical bytes, native vs
  WASM). If the subset isn't WASM-clean (e.g. a native-only dep leaks in), carve a
  `sbo-wire` crate free of native-only deps.
- **Prove the signing seam:** sign those canonical bytes with an ed25519 key **the
  way browserid's browser component does**, and confirm `sbo-core`'s native verify
  accepts it. This is the parity that matters — serialization (WASM) + signature
  (browserid key) → a valid SBO envelope. Confirm the cert-bound key's algorithm
  (Ed25519) matches the SBO `Public-Key` expectation.
- **Checkpoint:** a browser-side build → (browserid-key) sign → `sbo-core` native
  verify of one `post.v1` envelope, end to end.

### 7.1 — Mingo provider bring-up (IdP that provisions local identities)
- Deploy the browserid-ng broker as the Mingo **IdP** at a DNSSEC-signed domain
  (`mingo.place`, IdP at e.g. `id.mingo.place`), with a `_browserid.<domain>` TXT
  key — mirroring the working `sandmill.org` setup.
- **Sign-in → provision flow:** a user authenticates (browserid via an existing
  identity, or a Mingo account) and the IdP issues a cert for their local
  `<name>@mingo.place` identity. Confirm the broker's account-creation
  (`stage_user`/`complete_user_creation`) + `cert_key` path supports this as the
  "native IdP" case (issuer == `mingo.place`).
- **Admin mapping (demo):** a config list of recognized emails → admin; at genesis
  these get `role:admin` attestations from the Mingo issuer (see 7.2/7.5).
- Provision a few seed accounts (`alice@mingo.place`, …).
- Verify `sbo-capture::capture_attribution` against the Mingo IdP yields a cert +
  DNSSEC evidence the **offline attribution verifier** accepts at a test inclusion
  time (the seam that must converge).
- **Checkpoint:** sign in → provision `alice@mingo.place` → `capture_attribution`
  → valid `Auth-Cert` + `Auth-Evidence`, accepted by `authorize_message`.

### 7.2 — Aggregated genesis + bootstrap tooling
- Add a **bootstrap builder** (Rust binary or `presets` extension) that emits the
  Mingo genesis as concatenated wire messages:
  - `/sys/names/sys` (sys identity), `/sys/policies/root` (hub root policy),
    `/sys/trust/brokers` (pin the Mingo broker via `presets::set_trust_brokers`).
  - For each starter community (`cooks`, `woodworking`, `homelab`):
    `/communities/<id>/community` (`community.v1`), `/communities/<id>/policies/root`
    (open-membership policy: `member` role = attested `membership`, `post` grant on
    `spaces/**`, `not_attested` ban), and `/communities/<id>/spaces/general/_config`
    (`collection.v1`, `durability: batched`).
- This needs **new message builders** (7.2a) for `community.v1`, `collection.v1`,
  and policy JSON — thin wrappers over `presets::post`. Add to `presets.rs`.
- Submit via IPC `RepoCreate`; daemon syncs from genesis → confirmed state.
- **Checkpoint:** `sbo repo create` the Mingo repo; daemon syncs; the three
  community descriptors + policies are queryable (once 7.3 lands, via HTTP).

### 7.3 — Daemon HTTP read + submit API (for the browser)
- Implement the stubbed IPC `GetObject` (`main.rs:700`) over `state::get_object`,
  and add `ListObjects` (prefix + by-schema) over the existing
  `list_objects_by_path_prefix` / `list_objects_by_schema`.
- Add **HTTP routes** to `http.rs` (axum, CORS-enabled):
  - `GET /v1/object?path=&id=` → object value (+ optional `?proof=1` → SBOQ).
  - `GET /v1/list?prefix=` and `GET /v1/list?schema=` → object lists.
  - `POST /v1/submit` (body: raw signed wire bytes) → `turbo::submit_raw`.
  - `GET /v1/state-root` → latest `(block, root)` for freshness checks.
- **Checkpoint:** `curl` the Mingo communities, list `/communities/`, and submit a
  hand-signed `post.v1`; see it appear in confirmed state after inclusion.

### 7.4 — Browser SBO library + browserid signing extension
Two parts: the serialization kit (`sbo-wasm`) and the **careful** browserid
signing extension (#4).
- **`sbo-wasm` (serialization kit):**
  - `buildEnvelope({action, path, id, schema, owner, payload, hlc?, prev?, authCert?, authEvidence?})` → canonical bytes (+ the bytes to sign).
  - Schema payload helpers for `post/comment/reaction/membership(attestation)`.
  - HLC stamping (physical ms + counter) and `object_hash` (sha256 of wire).
  - `assembleWire(envelope, signature)` → wire bytes for `POST /v1/submit`.
  - Thin read client over the 7.3 HTTP API; optional SBOQ verify (reuse `sboq`).
- **browserid signing extension (`~/src/browserid-ng` JS component):** add a
  **namespaced** signing operation that signs SBO canonical bytes with the
  cert-bound browser key — distinct from assertion signing, **domain-separated**
  (e.g. a context tag the verifier checks) and **origin-gated** so only the Mingo
  app origin can request it. Write a short contract note: what the key will/won't
  sign, why a malicious RP can't forge envelopes or replay across origins. This is
  the security-sensitive change flagged in #4 — design + review before coding.
- **Checkpoint:** from the Mingo origin, build (`sbo-wasm`) + sign (browserid key)
  + submit a `post.v1` as `alice@mingo.place` and read it back via the API.

### 7.5 — Seed content tooling (make it feel alive)
- A script using the provider (7.1) + builders (7.2a/7.4) to author, as seed
  users: memberships, a spread of posts/comments/reactions in each community, and
  a handful of `role:*` / `badge:*` attestations (so the **passport** has rows and
  the **feed** has content + votes).
- **Checkpoint:** the Mingo repo has a believable amount of content; a sample
  user's passport shows ≥3 badges/roles across communities.

### 7.6 — The web client app
- The UI from demo spec §4: sign-up (pick handle → provider cert → post
  `identity.email.v1` via `claim_email_identity`), hub feed, community view,
  thread, compose, **passport**, light founder/mod actions.
- Reads via the 7.3 API; writes via 7.4; login via the 7.1 provider.
- **Checkpoint:** click-through of the core loop — sign up, join `cooks`, post,
  comment, upvote, open your passport — against the real stack.

### 7.7 — Passport + feed views (client-side aggregation)
- **Passport:** read every `attestation.v1` whose subject resolves to the user
  (across community issuers in-repo), render badges/roles/vouches.
- **Feed:** read posts in a space, sort by votes (count `reaction.v1`) + recency.
  Plain ranking — trust-weighting is the documented fast-follow, **not** in v1.
- **Checkpoint:** passport and a ranked space feed render from live confirmed state.

### 7.8 — Quiet verifiability affordance
- A "how do I know this is real?" panel on a post: fetch its SBOQ proof
  (`GET /v1/object?...&proof=1`), verify in-browser (sboq), show signer/inclusion.
  Behind a subtle link — never the main pitch.
- **Checkpoint:** verify a post's proof in the browser, independent of the daemon.

### 7.9 — Conformance + hardening (spec §Client Conformance)
- Spot-check deterministic replay (a second daemon converges on the same root),
  inclusion-time attribution against the pinned root KSK, deterministic policy
  incl. attestation-defined roles. Tighten error/empty states in the client.
- **Checkpoint:** a short conformance note + a clean demo run.

---

## Critical path & risks

- **Critical path:** 7.0 (`sbo-wasm` spike) → 7.1 (provider) + 7.2 (genesis) → 7.3
  (API) → 7.4 (browser lib + signing extension) → 7.6 (UI). 7.5/7.7/7.8/7.9 enrich
  but don't block the loop.
- **Top risk — extending the browserid key to sign SBO envelopes (#4).** This
  changes the browserid↔website contract: the cert-bound key must sign SBO
  envelopes *without* opening a hole where a malicious RP forges envelopes, signs
  arbitrary content, or replays across origins. Mitigations: strict **domain
  separation** (assertion-signing vs SBO-envelope-signing are distinct, tagged
  operations), **origin-gating** to the Mingo app, and a written contract +
  security review before any code. Treat as a design gate within 7.4 (and touched
  in the 7.0 spike to confirm the key can produce SBO-valid signatures at all).
- **`sbo-wasm` serialization parity.** If the wire subset won't compile to `wasm32`
  cleanly, carve a `sbo-wire` crate free of native-only deps. Retire in 7.0.
- **Provider/DNSSEC ops.** The attribution seam needs a DNSSEC-signed Mingo domain
  with `_browserid` TXT. Known-good recipe exists (`sandmill.org`); config, but
  real infra.
- **Avail testnet reliability.** Real DA (decision #2) means demo flows depend on
  testnet liveness/latency; acceptable, but have a fallback RPC/endpoint and don't
  block local dev iteration on it (read-path work can use a synced snapshot).
- **Scope creep in the UI.** Keep 7.6 to the spec §4 screens; defer trust-weighted
  feed, repo-per-community, "bring your reputation," tip overlay.

## v1 demo scope (explicit)

**In:** one aggregated repo; `@mingo.place` T1 login; 3 communities; join; post;
comment; upvote; passport; light mod/founder actions; quiet proof panel.
**Out (deferred/fast-follow):** trust-weighted feed, tip/confirmed overlay (Phase
6.5), repo-per-community sovereignty, cross-repo "bring your reputation," native
mobile, real Avail mainnet.
