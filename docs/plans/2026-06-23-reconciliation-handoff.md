# Reconciliation Handoff — resume at Phase 1.5

**Date:** 2026-06-23
**For:** a fresh agent continuing the reference-impl reconciliation.

## Read these first
1. **`docs/plans/2026-06-23-reference-impl-reconciliation.md`** — the authoritative plan: goal, locked decisions, the full phase list, the Phase-1 detail (verifier algorithm, delete-map, tech choices, owner-repr decision, sub-step progress). Everything below is a summary; that doc is the source of truth.
2. Agent memory `spec-evolution-direction.md` — strategic running log (north star, the L0–L6 spec design history).

## Situation in one paragraph
The SBO Protocol v0.5 **spec stack is complete** (14 specs under `specs/`, L0–L6: substrate → Identity → Authorization → Attestation → Community → Content → Indexer/Client). We are now **reconciling `reference_impl/` (Rust workspace) to those specs**, goal = a working self-owned-community demo. Working in dependency-ordered phases, build green + commit + pause-for-review at each. Phase 0 (wire) and most of Phase 1 (identity/auth) are done; **resume at Phase 1.5.**

## What's DONE and committed (on `main`)
- **Phase 0** (`423bf63`): added `Auth-Cert`/`Auth-Evidence`/`HLC`/`Prev` optional wire headers to `Message` + parser/serializer/canonical order.
- **1.1** (`4de7d7f`): deleted the old browserid-clone auth (nested UserDelegation/SessionBinding/AuthAssertion JWTs + `verify_auth_chain` in `jwt.rs`, `.well-known/sbo` discovery in `dns.rs`, `sbo-cli` auth/session commands, 4 daemon IPC session/provisioning handlers, the whole `sbo-auth-demo` crate). CLI email-identity flows (`import_email`/`create_domain_certified`/`resolve` in `sbo-cli/.../identity.rs`) are **stubbed** with `anyhow::bail!`.
- **1.3** (`450cbec`): `sbo-core/src/attribution.rs` — deterministic `verify_attribution(public_key, auth_cert, auth_evidence, inclusion_time, anchors) -> Attribution{email,key,valid_from,valid_until}`. Uses `browserid-core` (path dep, cert parse/verify) + `dnssec-prover` 0.6 (RFC 9102 offline proof validation; IANA root KSK is **hardcoded in the crate** — not injectable). Split into `verify_attribution` (full) + `verify_attribution_with_provider_key` (testable without DNSSEC). 9 offline tests + 1 `#[ignore]` live test.
- **owner-repr = option C**: emails stored as-is. `Id::new` now allows `@`; trie-key delimiter moved off `:` to `\x1f`.
- **1.4a + 1.2** (`f03056b`): email-capable `Id`; `identity.email.v1` schema arm (payload `{profile?, iat}`, iat required, controller = `Owner` header required).
- **1.4b** (`54a34e9`): `sbo-core/src/resolve.rs` — pure `resolve_controller(reference, lookup_closure, hop_limit) -> Controller{Email|Key|None|Unresolved}` (null:/email/name→key or email-indirection, cycle + hop-limit guards, cross-repo refs → Unresolved/TODO) and `is_authorized(controller, signer_key, attributed_email)`.

Build is green (76 `sbo-core` lib tests pass). NOTE: `sbo-zkvm`/`sbo-zkvm-methods` fail to build only due to a missing RISC0 toolchain in this env — **pre-existing and expected**; use `cargo build/test -p sbo-core` etc., or `--workspace --exclude sbo-zkvm --exclude sbo-zkvm-methods`.

## NEXT: Phase 1.5 — wire L1/L2 validity into validate + replay
This is the integration that makes attribution actually **enforced on replay**. It crosses from `sbo-core` into `sbo-daemon`. Steps:
1. **Two layers.** L1 = envelope validity (signature, content-hash, schema, policy-over-the-signer-key) — deterministic, already mostly in `sbo-core/src/message/validate.rs` + `schema` + the daemon's policy eval. L2 = attribution: the signer `Public-Key` speaks for the object's `Owner` controller.
2. **L2 check** = `resolve_controller(Owner, lookup, hop_limit)` then `is_authorized(controller, signer_key, attributed_email)`, where `attributed_email` is `Some(email)` iff `attribution::verify_attribution(public_key, auth_cert, auth_evidence, inclusion_time, anchors)` succeeds and returns that email. Key-rooted owners need no cert (direct-signature match).
3. **Inclusion time** must be threaded from the DA block into validation (the block timestamp). Find where the daemon processes blocks/messages (`sbo-daemon/src/sync.rs`, `validate.rs`, `main.rs`) and pass the block time down.
4. **Trust anchors** (`/sys/trust/dns-root`, `/sys/trust/brokers`): `dnssec-prover` hardcodes the root KSK, so `dns-root` is informational for now; `brokers` is the authorized-broker list — source it from a pinned `/sys/trust/brokers` object (or a config constant initially, with a TODO to read the object). The `lookup` closure for `resolve_controller` fetches `/sys/names/<name>` records from the state DB and maps them to `resolve::NameRecord` (KeyRooted if identity.v1 w/ public_key, EmailRooted(owner) if identity.email.v1).
5. **Carry-but-filter**: per the Validity-Layers spec, well-formed-but-unattributed (L1-valid, L2-failing) messages are carried by the DA layer but **disregarded as unauthorized** on replay (do not mutate owned state). Make sure replay filters on L2 for owner-authorized actions.
6. Tests: an email-owned object write authorized by a valid (mock) attribution applies; the same write without/with-bad attribution is rejected; key-rooted owner still works by direct signature.

Keep it build-green; commit `feat(impl): Phase 1.5 — ...`; pause for review.

## Then: Phase 1.6 — capture flow
Mint `Auth-Cert`/`Auth-Evidence` for real: broker at **`https://id.sandmill.org/`** (`GET /.well-known/browserid` → `{public-key, authentication:/auth, provisioning:/provision}`; `/auth` = `/wsapi/authenticate_user {email,pass}` → session cookie; `/provision` = `/wsapi/cert_key {email, pubkey:{algorithm,publicKey}, ephemeral}` → `{success, cert, reason}`). Build the `_browserid.<domain>` RFC 9102 proof via `dnssec-prover`'s `query` feature (`std`/`tokio`). Demo flow: `https://sandmill.org/browserid/demo`. `sandmill.org` DNSSEC is real & validating; `_browserid.sandmill.org` publishes an Ed25519 key. Rewrite the stubbed CLI identity flows. Tests use mocks.

## Conventions
- Specs (`specs/*.md`) are source of truth; if code contact reveals a spec issue, fix the spec too and rerun the link/anchor/drift greps (see this session's git log for the one-liners).
- Build green + commit + pause-for-review per sub-step. Work on `main`.
- Delegate mechanical churn (struct-field threading, wide call-site edits) to subagents with a precise spec; do the design/integration yourself. Give subagents exact instructions — they lack this context.
- After completing a sub-step, verify the subagent's work independently (build + targeted grep) before committing.

## Phases after 1 (additive; see plan doc)
2 two-layer-validity polish · 3 attestation.v1 · 4 policy attestation-defined roles · 5 community.v1 · 6 content (post/comment/reaction + HLC/Prev/tip-confirmed/durability tiers) · 7 indexer/client conformance + the reference community client (the demo).
