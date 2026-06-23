# Reference Implementation Reconciliation — Plan & Handoff

**Started:** 2026-06-23
**Goal (user-chosen):** Full vertical to a **working community demo** — reconcile `reference_impl/` to the L0–L6 SBO Protocol v0.5 specs, all the way to a reference community client. Multi-session effort; proceed in dependency-ordered phases, build green at each step, **pause per phase for review**.

This doc is the resumable handoff. The spec-side running log lives in agent memory `spec-evolution-direction.md`; the spec stack itself is complete (14 specs under `specs/`, L0–L6).

---

## Approach decisions (locked)

- **Attribution / DNSSEC** has two stages, not two competing impls:
  - **Verify (validator, every replayer, offline):** deterministic check of the carried `Auth-Evidence` (DNSSEC chain) against the **pinned root KSK** (`/sys/trust/dns-root`), with RRSIG windows covering the write's DA **inclusion time**. No live DNS. This is the spec-mandated, convergent attribution check. **MUST implement this.**
  - **Capture (client, online, once per cert/rotation):** gather the live DNSSEC chain for `_browserid.<domain>` up to root and bundle into `Auth-Evidence`. Live-DNS/resolver work lives here only.
- **Live browserid endpoints — CONFIRMED (2026-06-23; supersedes the wrong `browserid.sandmill.org` url):**
  - **Broker:** `https://id.sandmill.org/` — discovery at `GET /.well-known/browserid` → `{"public-key":{"algorithm":"Ed25519","publicKey":"5w9yzPdFp5kjZZLbYl4jaR6EeS9VYGDEakzAf-a8Q9E"},"authentication":"/auth","provisioning":"/provision"}`. So broker signing key + `/auth` + `/provision` endpoints are live. Real cert issuance available via `/provision`.
  - **Demo:** `https://sandmill.org/browserid/demo` (200) — shows the end-to-end flow to mirror.
  - First Phase-1 step: read the demo + the browserid-ng broker code (`~/src/browserid-ng`) to learn the exact `/auth`+`/provision` request/response shapes.
- **DNSSEC deployment — CONFIRMED REAL (2026-06-23):** `sandmill.org` is DNSSEC-signed (DNSKEY alg 13 ECDSA-P256; DS `59066 13 1 5F95E0F94DACB020420E09286B3CB0118D928604` at parent → chains to root; Cloudflare 1.1.1.1 sets the AD flag → validates). `_browserid.sandmill.org` TXT: `v=browserid1; public-key-algorithm=Ed25519; public-key=sjL09EuHfTlyzzvVe53lCHV8LHeta4q6KMnjxRAO7ZI`, with RRSIG (alg 13, key tag 57592). So **real DNSSEC evidence is capturable**; pin the well-known IANA **root KSK**. Note: broker `.well-known` key (`5w9y…`) differs from the `_browserid.sandmill.org` DNS key (`sjL0…`) — clarify the broker-key vs primary-domain-key roles when reading the browserid-ng broker code.
- **Tests use mocks** (mock cert + mock evidence + a test pinned KSK); real broker + real DNSSEC for the live/demo path.

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

## Phase 1 — detail (research locked 2026-06-23)

### Tech choices (locked)
- **`browserid-core`** (path-local crate at `~/src/browserid-ng/browserid-core`, reusable, not on crates.io) — depend on it directly. Provides `Certificate` (parse/verify/is_expired), `DnsRecord::parse` (`_browserid` TXT: `v=browserid1; public-key-algorithm=Ed25519; public-key=<b64url>`), `PublicKey`, `KeyPair`. **Cert = EdDSA JWT**, claims `CertificateClaims { iss, exp, iat?, public_key, principal: Email{email} }`; signed by the issuer (provider/broker) key; binds the ephemeral `public_key` (= SBO `Public-Key` header) ↔ email.
- **`dnssec-prover`** (crates.io, TheBlueMatt; no-std+alloc, minimal deps) — RFC 9102 transferable DNSSEC proofs. Default `validation` feature = OFFLINE verify a proof against a single pinned root key (THE deterministic verifier). `std`/`query` feature = build the proof by querying a resolver (the capture step). No-std means it can later run inside the zkVM guest.
- browserid-ng's own DNSSEC is LIVE-query + AD-flag only (`browserid-broker/src/dns_fetcher.rs`, hickory-client) — NOT reusable for deterministic verification; that's why we use `dnssec-prover`.

### Auth-Cert / Auth-Evidence formats
- **`Auth-Cert`** = the browserid `Certificate` JWT (base64url JOSE), as defined by browserid-core.
- **`Auth-Evidence`** = an RFC 9102 DNSSEC proof of `_browserid.<provider-domain>` (the provider key), serialized; inline (`inline:<b64>`) or `ref:<sbo-ref>` to a self-authenticating `dnssec.v1` object (post-once-reference-many).

### Deterministic verifier algorithm (the L2 attribution check)
Given a message, its `Auth-Cert`, `Auth-Evidence`, `Public-Key`, and the DA block **inclusion time** `t`, plus pinned anchors `/sys/trust/dns-root` (root KSK) and `/sys/trust/brokers`:
1. Parse `Auth-Cert` → `iss` (domain), `principal.email`, `public_key`, `exp`, `iat`. Require `public_key == Public-Key` header.
2. Verify `Auth-Evidence` (RFC 9102 proof) against the pinned **root KSK** → yields the validated `_browserid.<iss>` provider key + the proof's RRSIG validity window. (No live DNS.)
3. Check the inclusion time `t` lies within: the proof's RRSIG window AND the cert `[iat, exp]`.
4. Verify the cert signature against the validated provider key.
5. Authority binding: `email`'s domain == `iss` (primary), OR `iss` ∈ pinned `/sys/trust/brokers` (broker path; broker enforces DNSSEC itself).
→ Conclusion: `Public-Key` speaks for `email` at inclusion time `t`. (Deterministic ⇒ all replayers converge.)

### Capture flow (client/online; real broker)
Broker `id.sandmill.org`: `GET /.well-known/browserid` → `{public-key, authentication:/auth, provisioning:/provision}`. `/auth` = `/wsapi/authenticate_user` `{email, pass}` → session cookie. `/provision` = `/wsapi/cert_key` `{email, pubkey:{algorithm,publicKey}, ephemeral}` → `{success, cert, reason}`. Then build the `_browserid` RFC 9102 proof via `dnssec-prover` query. Tests mock all of this.

### Delete-map (browserid-clone auth — the "actively wrong" code)
- **`sbo-core/src/jwt.rs`**: DELETE `UserDelegationClaims`/`SessionBindingClaims`/`AuthAssertionClaims`/`VerifiedAuth` (≈150–204), `create_user_delegation`/`create_auth_assertion` (≈444–485), the 3 `decode_*_claims` for them (≈487–500), `verify_session_binding`/`verify_user_delegation`/`verify_auth_assertion`/`verify_auth_chain` (≈502–642), and their tests (≈753–930). **KEEP** generic JWT infra (JwtError/Algorithm/JwtHeader/Issuer), `IdentityClaims` (identity.v1), `DomainClaims` (domain.v1), `Profile`, encode/decode/verify helpers, `create_self_signed_identity`/`create_domain_certified_identity`/`create_domain` + their verifies + tests.
- **`sbo-core/src/dns.rs`**: DELETE `DiscoveryDocument`+`fetch_discovery*` (`.well-known/sbo` auth discovery, ≈174–247), `_sbo-id` email-identity discovery (`SboIdRecord`/`IdentityDiscoveryResponse`/`parse_sbo_id_record`/`resolve_identity_host`/`resolve_email`, ≈264–380). **KEEP** `SboRecord`/`parse_sbo_record`/`resolve`/`is_dns_uri`/`resolve_uri` (domain/repo discovery), `parse_email`.
- **`sbo-cli`**: DELETE `commands/auth.rs` + `commands/session.rs` entirely; remove their `mod` decls in `commands/mod.rs`; remove `AuthCommands` enum + dispatch in `main.rs`; REWRITE the email-identity flows in `commands/identity.rs` (`import_email`/`create_domain_certified`/`resolve`, ≈713–1184) for the new model (or stub until built).
- **`sbo-daemon`**: DELETE the 4 IPC handlers `RequestSessionBinding`/`PollSessionBinding`/`RequestIdentityProvisioning`/`PollIdentityProvisioning` (`main.rs` ≈1406–1838) + their state maps + the Request variants in `ipc.rs`.
- **`sbo-auth-demo`**: DELETE the entire crate + remove from root `Cargo.toml` `members`.

### OPEN DESIGN ITEM surfaced by code contact (2026-06-23) — owner representation
The impl parses `Owner`/`Creator` as the `Id` type (RFC 3986 unreserved: ALPHA/DIGIT/-._~) and uses `creator` as a **literal trie path segment** (`state/db.rs object_to_segments`) and in the trie key `format!("{}:{}:{}", path, creator, id)` + filesystem paths. So an email controller `alice@gmail.com` fails (`@` invalid; a `:`-containing ref would break the key delimiter). Today owners/creators are always Id-valid NAMES. Email-rooted ownership needs a decision (ripples into the State Commitment "creator as literal segment" model + filesystem sync). Options: (A) ownership via `/sys/names/<name>` only — bare-email owners disallowed (needs a spec tweak; adds a name-registration step); (B) email-capable `IdentityRef` on the wire + encoded/hashed storage segment (supports spec's bare-email owner; segments become opaque → State Commitment spec update); (C) relax `Id` to allow `@` (not `:`) + change the trie-key delimiter off `:` (minimal, human-readable segments, `@` ok on POSIX; key-rooted owners still go via `/sys/` names). **PENDING USER DECISION before 1.4/1.5.** 1.2 (identity.email.v1 schema) merges into 1.4 since its controller = Owner depends on this.

### Sub-step sequencing (each build-green, commit)
1. **Delete** the browserid-clone (above). Build green, tests pass (functionality reduced — no auth flow yet). Reviewable commit.
2. **`identity.email.v1`** schema + validation (controller = `Owner`, payload `{profile?, iat}`); keep key-rooted `identity.v1` for roots.
3. **Attribution module**: depend on `browserid-core` + `dnssec-prover`; implement the verifier algorithm above; pin `/sys/trust/dns-root` + `/sys/trust/brokers`; mock cert + mock RFC 9102 proof + test root KSK fixtures + tests.
4. **resolve_controller** (email vs key) + Owner→name→email indirection + hop limits + grounding.
5. **Two-layer validity wiring**: L1 envelope validity deterministic; L2 attribution at inclusion time; well-formed-but-unattributed carried-but-filtered.
6. **Capture** (CLI/daemon): real broker `/provision` + `dnssec-prover` query to emit `Auth-Cert`/`Auth-Evidence`; rewrite the CLI identity flows. (browserid HTTP endpoint cert wrinkle may force mock issuance temporarily — DNS evidence is real.)

---

## Conventions
- Rust workspace; `cargo build` + `cargo test` green at each phase. Optional `--features zkvm`.
- Commit per phase (style: `feat(impl): ...` or similar). On `main` per user preference unless a phase risks a long red build — then a branch.
- Pause for review after each phase.
- `reference_impl/docs/` + `docs/plans/*` cite old versioned spec filenames — historical, leave unless a phase touches them.
- Spec files are the source of truth (`specs/*.md`). If code contact reveals a spec problem, fix the spec too (specs are hand-maintained; rerun the link/anchor/drift checks).
