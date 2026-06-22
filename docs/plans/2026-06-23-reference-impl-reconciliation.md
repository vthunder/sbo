# Reference Implementation Reconciliation — Plan & Handoff

**Started:** 2026-06-23
**Goal (user-chosen):** Full vertical to a **working community demo** — reconcile `reference_impl/` to the L0–L6 SBO Protocol v0.5 specs, all the way to a reference community client. Multi-session effort; proceed in dependency-ordered phases, build green at each step, **pause per phase for review**.

This doc is the resumable handoff. The spec-side running log lives in agent memory `spec-evolution-direction.md`; the spec stack itself is complete (14 specs under `specs/`, L0–L6).

---

## Approach decisions (locked)

- **Attribution / DNSSEC** has two stages, not two competing impls:
  - **Verify (validator, every replayer, offline):** deterministic check of the carried `Auth-Evidence` (DNSSEC chain) against the **pinned root KSK** (`/sys/trust/dns-root`), with RRSIG windows covering the write's DA **inclusion time**. No live DNS. This is the spec-mandated, convergent attribution check. **MUST implement this.**
  - **Capture (client, online, once per cert/rotation):** gather the live DNSSEC chain for `_browserid.<domain>` up to root and bundle into `Auth-Evidence`. Live-DNS/resolver work lives here only.
- **Certs:** use the live **browserid.sandmill.org** instance for real certs; **tests use mocks** (mock evidence + a test pinned KSK). Confirm during Phase 1 that `sandmill.org` is DNSSEC-signed and publishes `_browserid.sandmill.org`; if not fully deployed, fall back to mock evidence + test KSK and wire live capture later.

## What the impl is today (survey 2026-06-23)

Real Rust workspace (~91 files, 8 crates): `sbo-core` (wire/message/jwt/schema/state/policy/proofs), `sbo-daemon` (Avail sync, light client, RISC Zero prover), `sbo-crypto`, `sbo-cli`, `sbo-avail`, `sbo-zkvm`, etc. Builds, has tests. ed25519-dalek, sha2, RocksDB, Tokio, Avail DA, RISC Zero zkVM.

**Two kinds of divergence:**

- **ACTIVELY WRONG (contradicts specs) — needs rip-and-replace:** the auth model. `sbo-core/src/jwt.rs` (931 lines) implements a *browserid clone* — nested `UserDelegation → SessionBinding → AuthAssertion` JWTs + `verify_auth_chain()` (line 580), plus `.well-known/sbo` auth discovery in `dns.rs`. The new specs DELETE this: browserid-ng owns auth; SBO uses the browserid **cert** + the **envelope-as-assertion** + **DNSSEC attribution**. No DNSSEC, no `Auth-Cert`/`Auth-Evidence`, no pinned root KSK today.
- **MERELY MISSING (additive):** email-rooted `identity.email.v1` (controller = Owner); attestation/community/post/comment/reaction/collection schemas; HLC/Prev/tip-confirmed write model; attestation-defined policy roles; durability tiers. `Genesis::validate()` is a `todo!()` stub (`sbo-core/src/genesis.rs:11`).

Key files: identity/jwt `sbo-core/src/jwt.rs`, `schema/identity.rs`; wire `message/envelope.rs`, `message/actions.rs`, `wire/parser.rs`, `wire/serializer.rs`; policy `policy/evaluate.rs`, `policy/types.rs`; state `state/db.rs`; proofs `proof/sbop.rs` (ZK), `proof/sboq.rs` (trie inclusion); daemon `sbo-daemon/src/{sync,lc,prover,main}.rs`; dns `sbo-core/src/dns.rs`.

---

## Phases (dependency-ordered)

### Phase 0 — Wire alignment  ⟢ IN PROGRESS (this session)
Add `Auth-Cert`, `Auth-Evidence`, `HLC`, `Prev` as optional `Option<String>` fields on `Message`; thread through `canonical_signing_content`, `serializer::HEADER_ORDER`, `parser::parse_at`; update all `Message {}` construction sites. Canonical order per the current Wire spec (HLC after Creator; Prev after Policy-Ref; Auth-Cert/Auth-Evidence after Related, before Public-Key). Build green, `sbo-core` tests pass. Additive only — no semantics yet.

### Phase 1 — Identity & Authorization (the core reconcile; the actively-wrong part)
- **Retire the browserid clone:** remove/deprecate nested `UserDelegation`/`SessionBinding`/`AuthAssertion`/`verify_auth_chain` and `.well-known/sbo` auth discovery. (Keep generic JWT + key-rooted `identity.v1` for genesis roots/domains.)
- **Add `identity.email.v1`:** controller = `Owner` header, no durable key; payload `{profile?, iat}`.
- **Attribution verifier (option-1, deterministic):** verify `Auth-Cert` (browserid cert binding ephemeral `Public-Key` ↔ email) + `Auth-Evidence` (DNSSEC chain) → pinned root KSK at inclusion time. Pin trust anchors `/sys/trust/dns-root`, `/sys/trust/brokers`. Pick a DNSSEC verification crate (verification-only, not a resolver).
- **Evidence capture (option-2, client/online):** helper to fetch live DNSSEC for `_browserid.sandmill.org` and emit `Auth-Evidence` (inline or as a self-authenticating `dnssec.v1` object). Cert obtained from browserid.sandmill.org.
- **Resolution:** `resolve_controller` (email vs key), Owner→name→email indirection, hop limits, grounding rules.
- **browserid integration:** real certs from browserid.sandmill.org; mocks in tests.

### Phase 2 — Two-layer validity & state
Separate L1 envelope validity (deterministic, replayable) from L2 attribution (read-time/optimistic per spec). Align replay/state so canonical state matches the Validity-Layers model; well-formed-but-unattributed writes carried but filtered.

### Phase 3 — Attestation
`attestation.v1` schema + validation (issuer = Owner; fields subject/type/value/issued_at/expires?/evidence?; type regex; expires ≥ issued_at). Issuer-namespace storage convention. In-force check helper (issued_at ≤ t < expires) — consumed by Phase 4.

### Phase 4 — Policy extension
Attestation-defined roles `{attested:{type, by?}}` + `attested`/`not_attested` restriction conditions, resolved against in-force attestations by resolved subject at inclusion time. Extends `policy/evaluate.rs`.

### Phase 5 — Community
`community.v1` descriptor schema (thin: name/description/issuer/policy/members/spaces/open/created_at). Membership/roles/bans are attestations (Ph3) + policy (Ph4); little new code beyond the descriptor + conventions.

### Phase 6 — Content & write model
`post.v1`/`comment.v1`/`reaction.v1` schemas; HLC ordering (header from Ph0) with validity bound `T_b−W ≤ physical ≤ T_b+ε`; `Prev` causal links; LWW-by-HLC (non-CRDT, deterministic tiebreak); **tip vs confirmed** in the daemon; durability tiers on-chain/batched (+ `collection.v1` descriptor). Reaction aggregation stays off-chain.

### Phase 7 — Indexer & client conformance + reference community client
Verifiable query responses (results + State Commitment proofs + state root); completeness via subtree proofs (extend existing `sboq` trie proofs); client conformance (deterministic replay, inclusion-time attribution, deterministic policy incl. attestation roles, tip/confirmed). Then the **reference community client** wiring browserid (login) + SBO (data) into a working self-owned-community demo = the goal.

---

## Conventions
- Rust workspace; `cargo build` + `cargo test` green at each phase. Optional `--features zkvm`.
- Commit per phase (style: `feat(impl): ...` or similar). On `main` per user preference unless a phase risks a long red build — then a branch.
- Pause for review after each phase.
- `reference_impl/docs/` + `docs/plans/*` cite old versioned spec filenames — historical, leave unless a phase touches them.
- Spec files are the source of truth (`specs/*.md`). If code contact reveals a spec problem, fix the spec too (specs are hand-maintained; rerun the link/anchor/drift checks).
