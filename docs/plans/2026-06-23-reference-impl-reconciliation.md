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

### Phase 2 — Two-layer validity & state  ⟢ NEXT (see `2026-06-23-phase2-handoff.md`)
Align canonical state + policy with the Validity-Layers model now that the L2 gate exists. Block-inclusion-time plumbing (`2219521`) and the carry-but-filter gate (`ad2c67f`) already landed in Phase 1. **Concrete scope discovered during the Phase-1 review:**
- **Stored-owner model is wrong for email owners.** `message_to_stored_object` (`sbo-daemon/src/validate.rs` ~419) sets `StoredObject.owner = signing_key`. For email-rooted objects that's the *ephemeral* key (meaningless); the real controller is in `owner_ref`. Make state + ownership checks key off the resolved controller, not the signer key.
- **`effective_owner` fallback missing.** Spec `authorize()` (Authorization Spec §Verification Algorithm) uses `effective_owner = Owner → else Creator → else signer`. The impl's L2 gate only fires on an explicit `Owner` header (`if let Some(owner)`); ownerless writes bypass L2 via the legacy key path. Implement the fallback so the signer is the effective owner when no Owner/Creator is present.
- **Policy `$owner` uses the old key model.** `policy/evaluate.rs:237` (`"owner" => owner == actor`) and `effective_owner` derivation compare against the signer-key owner; they must resolve `$owner` to the controller (email or key) for email-rooted objects.
- **Evidence fallbacks unimplemented.** `authorize::parse_auth_evidence` only handles `inline:`; `ref:<sbo-ref>` and the `/sys/dnssec/` namespace lookup (Authorization Spec line 140) return unauthorized. Wire the referenced-evidence path.
- **State Commitment / creator derivation:** `object_to_segments` uses `creator` as a literal trie segment, and `creator` comes from `resolve_creator` whose fallback chain is `msg.creator → name-of-signing-key → key-hex`. For a **nameless email (T0) author** that collapses to the *ephemeral* cert key, so her objects key under per-rotation subtrees: after a browserid cert rotation she can no longer update her own content (the creator-keyed `get_object` lookup misses) and her objects scatter as if authored by different people. Names dodge this via the creator-independent `get_first_object_at_path_id`; general content has no escape hatch. **Fix:** insert the **attributed email** (the same deterministic `message_attribution` result 2.1 computes — who the *signer* is proven to be, NOT `msg.owner`, since creator≠owner in general) into the fallback chain ahead of `key-hex`, so all of an email author's writes share `creator = <email>` across key rotation. This requires threading `L2Context` into `resolve_creator`/`message_to_stored_object` (they currently take `msg`+`state` but not `l2`). Attribution is inclusion-time-pinned, so the creator segment stays a deterministic function of message + chain state (replay-safe). Amend the **State Commitment** + **Identity** specs to pin down "the creator segment is the resolved/attributed controller, not the signing key."

### Review fixes (2026-06-23, post Phase 1)
Pre-Phase-2 adversarial review of the L2 code found + fixed two issues:
- **Email-identity name-claim rotation bug:** `validate_name_claim` matched the rotating ephemeral signer key, locking email owners out after browserid cert rotation. Now email-rooted name records re-authorize via L2 against the stored `owner_ref` (mirrors `validate_post`'s update branch).
- **`/sys/trust/brokers` never seeded:** broker-path attribution (email domain ≠ cert issuer, e.g. `@sandmill.org` via `id.sandmill.org`) failed closed on a live daemon. Added `presets::set_trust_brokers` to post the list **on-chain** (required for deterministic replay — a local-config fallback would diverge). **Genesis must include it** (seed in genesis mode, or via an authorized key once policy governs `/sys/trust/`). `load_trust_anchors` already reads it. Regression tests added in `l2_authorization.rs`.

### CLI email-identity model correction (2026-06-23)
The 1.6 CLI conflated "capture attribution" with "register a `/sys/names/` name", auto-inventing a name from every email — contradicting the Identity spec (a bare email owns objects **directly**; a name is optional; only `<local>@<repo-domain>` is canonical, lines 68/116/45). Reworked `sbo id create --email` to honor the **T0/T1** distinction via `dns::extract_domain(uri)`:
- email domain **==** repo domain (T1) → register the canonical local-part name;
- external email / no-domain repo (T0) → **no** name by default (own directly as `Owner: <email>`); an explicit `name` registers a handle, with a privacy warning that it reveals the email.
`import_email` now just *verifies* control (no fabricated name). Dropped the lossy `name_from_email`. The daemon resolution side was already spec-correct. (Specs unchanged — this was an impl gap.)

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

### Progress (2026-06-23)
- ✅ 1.1 delete browserid-clone (`4de7d7f`)
- ✅ 1.3 attribution verifier `sbo-core/src/attribution.rs` (`450cbec`) — cert+DNSSEC→email, browserid-core + dnssec-prover, 9 offline tests + 1 #[ignore] live
- ✅ owner-repr = option C (decided)
- ✅ 1.4a + 1.2 email-capable `Id` (`@`) + trie delimiter `\x1f` + `identity.email.v1` schema (`f03056b`)
- ✅ 1.4b `sbo-core/src/resolve.rs` resolve_controller + is_authorized (`54a34e9`)
- ✅ 1.5 wire L1/L2 into validate+replay (daemon): `sbo-core/src/authorize.rs` (pure `authorize_owner`/`authorize_message` = resolve_controller + attribution + is_authorized; `parse_auth_evidence` `inline:`/`ref:`; 12 unit tests). Daemon `validate.rs`: `L2Context` (inclusion_time + trust anchors from `/sys/trust/brokers`), `name_lookup` over `/sys/names/<name>` (identity.v1→KeyRooted via JWT payload, identity.email.v1→EmailRooted via owner_ref), L2 gate after schema (carry-but-filter → `ValidationStage::Attribution`), update-path L2 for email-rooted existing objects. `StoredObject` gained `content_schema`+`owner_ref` (additive). Fixed a latent delimiter bug (`object_exists_at_path_id`/`get_first_object_at_path_id` still used `:` after the `\x1f` migration). 6 daemon integration tests. **Block inclusion time is now wired (`2219521`):** the Avail SDK's `block.timestamp()` (the `timestamp.set` inherent) is fetched in `rpc.rs`, carried on `sbo_rpc::BlockData.timestamp` (Option<i64> seconds), and passed through `process_block` into `L2Context::for_block`. Positive email-attribution end-to-end needs real DNSSEC → covered by authorize/attribution unit tests + the `#[ignore]` live test.
- ✅ 1.6 capture flow (`804b88a` + 1.6b): new **`sbo-capture`** crate — `BrokerClient` (discover/authenticate `/wsapi/authenticate_user`/provision `/wsapi/cert_key`, cookie session) + `capture_evidence` (dnssec-prover `tokio` `build_txt_proof_async` for `_browserid.<issuer>`) + `capture_attribution` → `{auth_cert, auth_evidence: inline:<b64url>, issuer}`. Added `sbo_core::authorize::encode_auth_evidence_inline` and `presets::claim_email_identity` (builds the signed `identity.email.v1` w/ Owner+Auth-Cert+Auth-Evidence). CLI de-stubbed: `create_domain_certified` (capture→build→print message; broker URL/password via `SBO_BROKER_URL`/`SBO_BROKER_PASSWORD`/`SBO_DNS_RESOLVER` env), `import_email` (capture + keyring email assoc), `resolve` (email-is-controller + local name). 6 capture unit tests + **1 live test PASSING against real `_browserid.sandmill.org`** (captures + offline-validates), preset roundtrip test. **On-chain submit is now wired:** `sbo id create --email <addr> <uri>` submits the captured `identity.email.v1` via the existing `SubmitIdentity` IPC (`turbo.submit_raw` sends the raw wire bytes, which already carry Owner/Auth-Cert/Auth-Evidence); omit the URI to print for manual posting. **Remaining: a real broker cert needs a valid account on `id.sandmill.org` (operational — we own the domain, make accounts as needed); the DNSSEC half is proven live.**


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
The impl parses `Owner`/`Creator` as the `Id` type (RFC 3986 unreserved: ALPHA/DIGIT/-._~) and uses `creator` as a **literal trie path segment** (`state/db.rs object_to_segments`) and in the trie key `format!("{}:{}:{}", path, creator, id)` + filesystem paths. So an email controller `alice@gmail.com` fails (`@` invalid; a `:`-containing ref would break the key delimiter). Today owners/creators are always Id-valid NAMES. Email-rooted ownership needs a decision (ripples into the State Commitment "creator as literal segment" model + filesystem sync). Options: (A) ownership via `/sys/names/<name>` only — bare-email owners disallowed (needs a spec tweak; adds a name-registration step); (B) email-capable `IdentityRef` on the wire + encoded/hashed storage segment (supports spec's bare-email owner; segments become opaque → State Commitment spec update); (C) relax `Id` to allow `@` (not `:`) + change the trie-key delimiter off `:` (minimal, human-readable segments, `@` ok on POSIX; key-rooted owners still go via `/sys/` names). **DECIDED 2026-06-23: option C.** Email owners are stored as-is (`alice@gmail.com` is a valid Id / trie segment / folder); trie-key delimiter moves off `:` to `\x1f`. Bare-email ownership preserved (spec unchanged). 1.2 (identity.email.v1 schema) proceeds alongside.

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
