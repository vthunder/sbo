# Handoff — continue at Phase 7 (Mingo client) with fresh context

**Date:** 2026-06-24
**For:** a fresh agent continuing the SBO reference-impl work, now at Phase 7.

## Read these first (in order)
1. **`docs/plans/2026-06-24-phase7-mingo-client-plan.md`** — the authoritative Phase 7
   plan. Decisions LOCKED, sub-phases 7.0–7.9, critical path, risks. 7.0 is marked DONE.
2. **`docs/plans/2026-06-24-demo-ux-spec.md`** — what we're building (Mingo) and why:
   product pitch, screens/wireframes, flows→SBO-writes, locked product decisions.
3. **`docs/plans/2026-06-23-reference-impl-reconciliation.md`** — the multi-phase plan;
   Phases 1–6 are DONE with per-substep detail; Phase 7 section points here.
4. **`~/src/browserid-ng/docs/plans/2026-06-24-typed-signing-extension-design.md`** —
   the browserid-ng signing extension design + threat model (the #4 decision).
5. Agent memory: `mingo-demo-direction.md` and `spec-evolution-direction.md`.

## Situation in one paragraph
The SBO Protocol v0.5 spec stack (14 specs, L0–L6) is complete. We reconciled
`reference_impl/` (Rust workspace) to it through **Phases 1–6, all DONE and committed
on `main`, build+test-green**. The impl drives identity/authorization/state/policy/
content off the two-layer controller model with email-rooted identities, attestations,
attestation-defined policy roles, and the content/write-model (post/comment/reaction,
HLC ordering + validity bound, Prev, LWW-by-HLC, collection.v1). **Phase 6.5 (tip vs
confirmed) was deliberately deferred** — not needed for the demo (see plan §6). We then
designed the demo end-to-end (**Mingo** — "Reddit, except you keep what you build"),
wrote the Phase 7 plan, and **completed the 7.0 `sbo-wasm` spike** (the crux risk:
browser-side SBO signing/serialization — proven feasible). Phase 7 = client + provider;
**no protocol work remains.**

## What's DONE this session (newest first, all on `main`)
- **`e72ded8` Phase 7.0** — `sbo-wasm` spike: new `reference_impl/sbo-wasm` crate
  `#[path]`-includes sbo-core's `error`/`crypto`/`message`/`wire`; **compiles to
  `wasm32-unknown-unknown`**; native test passes build→sign→serialize→parse→verify.
  Subset has zero native-only deps (Id/Path/ObjectType are in `message/envelope.rs`,
  no serde). Parity by construction (identical source). Crux risk retired.
- Phase 7 plan + decisions + the browserid-ng signing design (several doc commits).
- Demo locked as **Mingo** (renamed from "Commons"; domain `mingo.place`).
- **`Phase 6` (6.1–6.4, 6.6)** — content schemas; HLC type + validity-bound gate
  (new `ValidationStage::Ordering`); Prev format gate; LWW-by-HLC apply
  (`StoredObject.hlc/prev`, `hlc::LwwKey`/`lww_wins`, `validate::lww_admits`,
  suppression in `sync::write_object`); `collection.v1` + per-collection `W`.
- **`Phase 5`** earlier in session: `post`⇒{create,update}, `community.v1`, e2e test.

Run tests: `cargo test --workspace --exclude sbo-zkvm --exclude sbo-zkvm-methods`
(exclude needs RISC0 toolchain; pre-existing). `sbo-wasm` wasm build:
`cargo build -p sbo-wasm --target wasm32-unknown-unknown`. **Watch disk** — the build
cache has filled `/` before; `cargo clean` recovers ~12 GB.

## Locked Phase 7 decisions (do not relitigate; see plan §Decisions)
1. **Browser writes via `sbo-wasm`** (canonical serialization compiled to wasm32; NOT a
   TS reimpl — signing-byte parity is non-negotiable). 7.0 proved it.
2. **DA = Avail testnet** (then mainnet). No mock/local DA.
3. **Extend the existing daemon** with read+submit HTTP routes (axum `http.rs`, CORS);
   no separate gateway. IPC `GetObject` is currently a **stub** (`main.rs:700`); no HTTP
   read API exists yet.
4. **Signing = a browserid-ng typed signing extension** (reuse the cert-bound key the
   agent already holds for `alice@mingo.place`; parse-then-sign a well-formed SBO
   envelope; domain-separated by construction; origin/consent-gated; non-extractable
   `CryptoKey`). NOT a separate app-held key, NOT raw-key-in-JS. A separate key would
   *not* break the SBO model — it was rejected as duplicative. TOP RISK; design-review
   before code. Cross-repo (`~/src/browserid-ng`).
5. **Mingo = a browserid IdP that provisions a local `<name>@mingo.place` identity**
   (T1): sign in with browserid (e.g. gmail) → provisioned a local identity. Demo
   hardcodes certain emails → admin (seeded `role:admin` attestations at genesis).

**Residual spec gap to note in the Authorization spec:** writing as an identity needs an
IdP that runs `cert_key` over the writer's key; assertion-only third-party IdPs (T0)
support login but not first-party writes → hence T1 for the demo.

## What exists vs. what's new for the client (grounded; see plan's table)
- **Exists:** provider (browserid-ng broker — account creation + `cert_key`, native-IdP
  case), `sbo-capture::capture_attribution` (cert + DNSSEC), `presets::claim_email_identity`,
  raw-wire submit (IPC `Submit` → `turbo::submit_raw`), SBOQ proofs (IPC `ObjectProof`).
- **New/missing:** `sbo-wasm` (spike done; needs wasm-bindgen exports in 7.4); daemon HTTP
  read+submit API (+ implement stubbed `GetObject`, add list endpoints); message builders
  for `community/attestation/post/comment/reaction/collection` (presets has **none**); the
  web UI; the browserid signing extension.

## NEXT — recommended order (critical path: 7.0✓ → 7.1+7.2 → 7.3 → 7.4 → 7.6)
Two largely-independent tracks unblock the daemon HTTP API (7.3):
- **7.2 — aggregated genesis + message builders (pure Rust, this repo; good next step).**
  Add builders to `sbo-core/src/presets.rs` for `community.v1`/`collection.v1`/policy JSON
  and the content/attestation schemas (thin wrappers over `presets::post`). Then a bootstrap
  binary emitting the Mingo genesis: `/sys/names/sys`, `/sys/policies/root` (hub policy),
  `/sys/trust/brokers` (pin the Mingo broker), and per community (`cooks`/`woodworking`/
  `homelab`) a `community.v1` + open-membership policy + `spaces/general/_config`
  (`collection.v1`). Submit via IPC `RepoCreate`. See plan §7.2.
- **7.1 — Mingo provider bring-up (infra/ops + verification).** Deploy browserid-ng broker
  as the Mingo IdP at a DNSSEC-signed domain with `_browserid` TXT (mirror the working
  `sandmill.org` setup — see reconciliation plan's "Live browserid endpoints" notes).
  Verify `capture_attribution` against it is accepted by `authorize_message`. See plan §7.1.

Then **7.3** (daemon HTTP API), **7.4** (`sbo-wasm` wasm-bindgen + the browserid signing
extension — design-review first), **7.5** seed content, **7.6** web UI, **7.7** passport/feed
views, **7.8** proof panel, **7.9** conformance.

## Conventions (unchanged — follow them)
- **Specs (`specs/*.md`) are source of truth.** If code contact reveals a spec issue, fix
  the spec too. The residual-T0-gap note above is one such pending spec edit.
- **Per sub-step: build-green + commit (`feat(impl): Phase 7.x — …` / `docs(plans): …`) +
  pause for review.** Work on `main` (no feature branch, per the user's pattern).
- **Delegate mechanical churn** to subagents with exact instructions; do design/integration
  yourself; verify independently (build + targeted grep) before committing.
- Exclude `sbo-zkvm`/`sbo-zkvm-methods`; watch disk.
- The **browserid-ng repo is separate** (`~/src/browserid-ng`, on `main`). The signing-
  extension design note there is **uncommitted** (untracked) — ask before committing /
  branch first per the user's git rules.

## Key file map (impl)
- Schemas: `sbo-core/src/schema/{attestation,community,content,collection,identity}.rs`,
  wired in `schema/mod.rs::validate_schema`.
- Content/write model: `sbo-core/src/hlc.rs` (`Hlc`, `LwwKey`, `lww_wins`, bounds);
  daemon `validate.rs` (`check_hlc_bound`, `check_prev`, `lww_admits`, `ValidationStage::Ordering`,
  `collection_max_lag_ms`); apply suppression in `sync.rs::write_object`.
- L2/policy/resolve/attribution: `sbo-core/src/{authorize,resolve,attribution}.rs`,
  `policy/{types,evaluate}.rs`; daemon `validate.rs` (the integration surface).
- Client-relevant surfaces: daemon `http.rs` (auth+health only today), `ipc.rs`/`main.rs`
  (IPC variants incl. stubbed `GetObject` at `main.rs:700`, `RepoCreate`), `turbo.rs`
  (`submit_raw`), `proof/sboq.rs`; `sbo-capture/src/lib.rs`; `presets.rs`; `sbo-cli`.
- Spike: `sbo-wasm/{Cargo.toml,src/lib.rs}` (`#[path]` includes; spike test).
- Tests: `sbo-daemon/tests/l2_authorization.rs` (main integration surface), unit tests per
  `sbo-core` module.
