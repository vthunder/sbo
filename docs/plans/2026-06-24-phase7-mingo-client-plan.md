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
┌────────────┐   browserid (login, cert)     ┌─────────────────────────┐
│  Browser   │ ◀───────────────────────────▶ │  Mingo provider          │
│  web app   │                                │  (browserid-ng broker    │
│            │   sign envelopes (WASM)        │   @ DNSSEC mingo.place)   │
│  ┌───────┐ │                                └─────────────────────────┘
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

## Decisions to lock before building (§ Open questions)

1. **Browser signing: WASM vs TS reimpl.** *Recommend WASM.* Canonical signing
   bytes must match `sbo-core::wire` exactly or every signature is invalid — a TS
   reimplementation is a permanent divergence risk. Compile a **new `sbo-wasm`
   crate** exposing just envelope-build + ed25519-sign + wire-serialize (depends
   only on `sbo-core`'s wire/message/crypto — **not** state/daemon/RocksDB, which
   won't compile to WASM). Risk to retire early: confirm the wire+crypto subset is
   WASM-clean (a 7.0 spike).
2. **DA target for the demo: real Avail/TurboDA testnet vs local dev DA.**
   *Recommend a local dev DA harness for v1* (deterministic, free, no testnet
   flakiness), with real Avail as a later switch. Confirm a local/mock DA path
   exists or scope a thin one.
3. **Client ↔ daemon transport.** *Recommend extending the daemon's existing axum
   server* (`http.rs`) with read+submit routes (CORS for the browser), rather than
   a separate gateway. The CLI keeps using the Unix-socket IPC.
4. **Session key custody.** Ephemeral session key generated and held **in the
   browser** (localStorage/IndexedDB), bound to `@mingo.place` by the provider
   cert. Matches the spec's no-durable-key model. Re-login on cert expiry.
5. **Seed identities.** Seed content needs authored writes → seed users need
   certs. *Recommend* pre-provisioning a handful of `@mingo.place` seed accounts
   via the provider and scripting their writes (7.5), so the feed/passport look
   alive on first load.

---

## Sub-phases

### 7.0 — Decisions + WASM spike (de-risk the crux)
- Lock the decisions above.
- **Spike `sbo-wasm`:** prove `sbo-core`'s wire+message+crypto compile to
  `wasm32` and that a known envelope round-trips byte-identically to the native
  serializer (golden-vector test: same headers/payload/key → identical signing
  bytes + signature native vs WASM). If the subset isn't WASM-clean, carve a
  `sbo-wire` crate free of native-only deps.
- **Checkpoint:** a WASM module that signs one `post.v1` envelope, verified
  byte-equal to `sbo-core` native.

### 7.1 — Mingo provider bring-up
- Deploy the browserid-ng broker as the Mingo IdP at a DNSSEC-signed domain
  (`mingo.place`, broker at e.g. `id.mingo.place`), with a `_browserid.<domain>`
  TXT key — mirroring the working `sandmill.org` setup.
- Provision a few seed accounts (`alice@mingo.place`, …).
- Verify `sbo-capture::capture_attribution` against the new broker yields a cert +
  DNSSEC evidence that the **offline attribution verifier** accepts at a test
  inclusion time (this is the seam that must converge).
- **Checkpoint:** `capture_attribution(id.mingo.place, alice@mingo.place, …)` →
  valid `Auth-Cert` + `Auth-Evidence`, accepted by `authorize_message`.

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

### 7.4 — Browser SBO library (`sbo-wasm` consumed by the client)
- Flesh out `sbo-wasm` into the client's write/read kit:
  - `buildEnvelope({action, path, id, schema, owner, payload, hlc?, prev?, authCert?, authEvidence?})` → canonical bytes.
  - `sign(envelope, sessionKey)` → wire bytes ready for `POST /v1/submit`.
  - Schema payload helpers for `post/comment/reaction/membership(attestation)`.
  - HLC stamping (physical ms + counter) and `object_hash` (sha256 of wire).
  - Thin read client over the 7.3 HTTP API; optional SBOQ verify (reuse `sboq`).
- **Checkpoint:** from a browser console, build+sign+submit a `post.v1` as
  `alice@mingo.place` (cert from 7.1) and read it back via the API.

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

- **Critical path:** 7.0 (WASM spike) → 7.1 (provider) + 7.2 (genesis) → 7.3 (API)
  → 7.4 (browser lib) → 7.6 (UI). 7.5/7.7/7.8/7.9 enrich but don't block the loop.
- **Top risk — WASM signing parity.** If `sbo-core` wire/crypto won't compile to
  `wasm32` cleanly, we carve a `sbo-wire` crate. Retire this in 7.0 before
  committing to the client architecture. (Fallback: a tiny local signing helper
  the browser calls — worse trust story, avoid.)
- **Provider/DNSSEC ops.** The attribution seam needs a DNSSEC-signed Mingo domain
  with `_browserid` TXT. Known-good recipe exists (`sandmill.org`); it's config,
  but it's real infra to stand up.
- **DA dependency.** Decide local-dev vs Avail testnet early (7.0) — it gates how
  self-contained the demo is.
- **Scope creep in the UI.** Keep 7.6 to the spec §4 screens; defer trust-weighted
  feed, repo-per-community, "bring your reputation," tip overlay.

## v1 demo scope (explicit)

**In:** one aggregated repo; `@mingo.place` T1 login; 3 communities; join; post;
comment; upvote; passport; light mod/founder actions; quiet proof panel.
**Out (deferred/fast-follow):** trust-weighted feed, tip/confirmed overlay (Phase
6.5), repo-per-community sovereignty, cross-repo "bring your reputation," native
mobile, real Avail mainnet.
