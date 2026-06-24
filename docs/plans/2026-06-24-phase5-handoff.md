# Phase 5 Handoff — Community descriptor (and beyond)

**Date:** 2026-06-24
**For:** a fresh agent continuing the reference-impl reconciliation at Phase 5.

## Read these first
1. **`docs/plans/2026-06-23-reference-impl-reconciliation.md`** — the authoritative plan. Phases 1–4 are marked **DONE** with per-substep detail; see the **Carry-forward notes / known gaps (post Phase 4)** section. Phase 5–7 scope is there.
2. **`specs/SBO Community Specification.md`** — Phase 5's target spec.
3. Prior handoff **`docs/plans/2026-06-23-phase2-handoff.md`** for the Phase-2 mental model (two-layer validity), still the backbone.
4. Agent memory `spec-evolution-direction.md` — strategic running log.

## Situation in one paragraph
SBO Protocol v0.5 spec stack (14 specs, L0–L6) is complete. We're reconciling `reference_impl/` (Rust workspace) to it. **Phases 1–4 are DONE, committed on `main`, build+test-green.** The impl now drives identity/authorization/state/policy/storage off the **two-layer controller model** (L1 envelope + L2 attribution), with email-rooted identities as first-class owners and authors, attestations (`attestation.v1`), and attestation-defined policy roles/conditions. **Phase 5** adds the `community.v1` descriptor — a thin pointer object; membership/roles/bans are already expressible as attestations (Ph3) + policy (Ph4), so this is mostly a schema + conventions phase, like Phase 3.

## What's DONE (Phases 1–4), newest first — all on `main`
Run the suite with: `cargo test --workspace --exclude sbo-zkvm --exclude sbo-zkvm-methods` (22 groups green). `sbo-zkvm*` need a RISC0 toolchain — pre-existing, exclude. **Watch disk** — the build cache filled `/` once during Phase 1 (`cargo clean` recovered ~12 GB).

- `f9f3e2d` **Phase 4** — attestation-defined roles & policy conditions.
- `7615ef6` **Phase 3** — `attestation.v1` schema, validation, in-force helper.
- `f13473a` **2.6** — carry-but-filter audit + regression test.
- `22fa02a` **2.5** — creator segment = attributed controller (email authors stable across key rotation).
- `b95cc30` **2.4** — resolve `ref:`/`/sys/dnssec` Auth-Evidence.
- `c5a0c07` **2.3** — policy `owner` identity resolves to the controller.
- `fce5ba6` **2.2** — ownership checks key off the resolved controller.
- `3ae9d75` **2.1** — `effective_owner` fallback + always-on L2 gate.
- (Phase 1 earlier: identity/attribution/capture — see plan.)

## Where things live (the map you'll need)
- **Pure L2/policy logic (`sbo-core`):**
  - `src/authorize.rs` — `authorize_message`/`authorize_owner`/`message_attribution`/`parse_auth_evidence`/`encode_auth_evidence_inline`/`cert_issuer`.
  - `src/resolve.rs` — `resolve_controller` (bare email / **bare key** / name / cross-repo), `Controller`, `is_authorized`.
  - `src/attribution.rs` — deterministic cert+DNSSEC verifier.
  - `src/schema/attestation.rs` — `Attestation`, `validate_attestation`, `is_in_force(t)`, `storage_path(issuer, subject)`; wired into `schema/mod.rs::validate_schema` as the `attestation.v1` arm.
  - `src/policy/types.rs` — `Policy`/`Grant`/`Restriction`/`Identity` (incl. `Attested{attested}`), `AttestedSource{type, by?}`, `Requirements` (incl. `attested`/`not_attested`).
  - `src/policy/evaluate.rs` — `evaluate(policy, actor, action, target_path, owner, signer_is_owner, is_attested, message)`; `is_attested: &AttestedCheck` (= `&dyn Fn(&AttestedSource)->bool`); `extract_namespace_owner`.
  - `src/message/envelope.rs` — `Id` now allows `:` and `@` (attestation type IDs, key refs, emails).
  - `src/state/db.rs` — `get_first_object_at_path_id`, `list_objects_by_path_prefix`, `list_objects_by_schema`, `object_to_segments` (creator = resolved controller).
- **Daemon integration (`sbo-daemon/src/validate.rs`):** `validate_message` (gate order: signature → schema → **L2 attribution gate on effective owner** → action), `L2Context`, `effective_owner_ref`, `attributed_email`, `resolve_creator` (Creator → attributed email → name → key-hex), `message_to_stored_object` (`owner_ref` = effective owner, always), `stored_owner_ref`, `l2_authorize`, `resolve_evidence`, `check_policy` (computes `signer_is_owner` + the `is_attested` closure), `attested_subject_matches`. Block apply path in `sync.rs` (`write_object` takes `&L2Context`).
- **Tests:** `sbo-daemon/tests/l2_authorization.rs` (the main integration surface — L2 gate, ownership, evidence, creator, carry-but-filter, attestation-gated role), plus unit tests in each `sbo-core` module.

## Conventions (unchanged, follow them)
- **Specs (`specs/*.md`) are source of truth.** If code contact reveals a spec issue, fix the spec too (Phase 4 did this for the `Id` charset). Rerun link/anchor sanity greps when you touch anchors.
- **Per sub-step: build-green + commit (`feat(impl): Phase 5.x — …`) + pause for review.** Work on `main`.
- **Delegate mechanical churn** (wide signature threading, struct-field edits) to subagents with exact instructions; do design/integration yourself; verify independently (build + targeted grep) before committing.
- **Tests:** offline unit/integration by default; live network paths behind `#[ignore]`. Positive attribution (authz + creator) is only live-DNSSEC-testable (hardcoded IANA root) — cover negatives/fallbacks offline.
- Exclude `sbo-zkvm`/`sbo-zkvm-methods`; watch disk.

## NEXT: Phase 5 — `community.v1` descriptor
**Scope (thin — mostly schema + conventions; see `SBO Community Specification.md`):**
- **`community.v1` schema** (new arm in `sbo-core/src/schema/`, mirror `attestation.rs`): an object whose payload is JSON with fields — `name` (req), `issuer` (req), `policy` (req, path/URI), `description?`, `members?` (default `/members/`), `spaces?` (default `/spaces/`), `open?` (advisory bool), `created_at?` (number). The descriptor **carries no logic** — validate field presence/types only; do **not** enforce that the issuer/policy objects exist (resolved at read time).
- **Storage conventions** (document + maybe a helper, not enforced): repo-per-community → descriptor at `/sys/community`; aggregated → `/communities/<id>` with `community.v1`. Membership = `membership` attestation; open = self-issued `{"attested":{"type":"membership"}}`, curated = `{"attested":{"type":"membership","by":"<issuer>"}}`; ban = `ban` attestation + policy `not_attested`; roles = `role:*` attestations + attestation-defined policy roles. **All of this already works** via Ph3+Ph4 — Phase 5 just adds the descriptor and (optionally) presets/tests demonstrating an end-to-end open and curated community.
- Authorization of a `community.v1` write is the existing L2 gate (issuer = `Owner`). No new auth code.

**Likely first move:** add `schema/community.rs` (`Community` type + `validate_community`), wire into `validate_schema`, unit-test field validation; then a daemon integration test composing descriptor + membership attestation + a policy role to show join/post/ban end-to-end (reuse the `attestation_defined_role_gates_policy` test as a template).

**Strongly consider fixing the `post`⇒{create,update} gap first** (see plan's Carry-forward notes): communities will grant `can: ["post"]` and expect create+update. It's ~5 lines in `policy/evaluate.rs` `action_matches` + tests. Cheap, and Phase 5/6 tests will want it.

## After Phase 5
- **Phase 6 — Content & write model** (the big one): `post.v1`/`comment.v1`/`reaction.v1`; HLC ordering with the inclusion-time validity bound `T_b−W ≤ physical ≤ T_b+ε`; `Prev` causal links; LWW-by-HLC deterministic tiebreak; **tip vs confirmed** in the daemon (first time it surfaces); durability tiers + `collection.v1`.
- **Phase 7 — Indexer/client conformance + the reference community client** (the demo goal): verifiable query responses (extend `sboq` trie proofs), conformance, then the browserid-login + SBO-data self-owned-community client.
