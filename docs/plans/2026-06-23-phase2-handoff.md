# Phase 2 Handoff — Two-Layer Validity & State

**Date:** 2026-06-23
**For:** a fresh agent starting Phase 2 of the reference-impl reconciliation.

## Read these first
1. **`docs/plans/2026-06-23-reference-impl-reconciliation.md`** — the authoritative plan. See the **Phase 2** entry (concrete scope) and the **Phase-1 progress** + **Review fixes** + **CLI email-identity model correction** sections.
2. **`specs/SBO Authorization Specification.md`** — the canonical `authorize()` algorithm (§Verification Algorithm) and the inclusion-time clock. This is the spec Phase 2 aligns the impl to.
3. **`specs/SBO Identity Specification.md`** — Owner references & resolution, the `/sys/names/` namespace, T0/T1 tiers.
4. Agent memory `spec-evolution-direction.md` — strategic running log.

## Situation in one paragraph
SBO Protocol v0.5 spec stack is complete (14 specs, L0–L6). We're reconciling `reference_impl/` (Rust workspace) to it. **Phase 1 (Identity & Authorization) is DONE, reviewed, and committed on `main`** — including the deterministic attribution verifier, the L2 gate wired into daemon replay (carry-but-filter), real Avail block-inclusion-time, the `sbo-capture` crate (broker cert + live DNSSEC), and CLI email flows. **Phase 2** reconciles the *canonical state + policy* to the two-layer model — the impl still stores/authorizes against the legacy "owner = signer key" model in places the new controller model should drive.

## Phase 1 — what's DONE and committed (on `main`)
Newest first; all build-green, full workspace test-green (22 groups; use `--workspace --exclude sbo-zkvm --exclude sbo-zkvm-methods`).
- `7a154e8` test: cover the real `message → StoredObject → name_lookup` write-path.
- `85e6cf6` fix(cli): honor the **T0/T1** email-identity model (stop auto-naming every email; bare email owns directly; only `<local>@<repo-domain>` is canonical).
- `6fbca36` fix: **L2 review fixes** — (a) email-identity name-claim updates re-authorize via L2 (rotation no longer locks owners out); (b) `presets::set_trust_brokers` seeds `/sys/trust/brokers` **on-chain** (required for deterministic replay).
- `0832058` test: live `#[ignore]` end-to-end capture+verify (gated on broker creds).
- `f097fa3` feat: submit attributed `identity.email.v1` on-chain via `sbo id create --email <addr> <uri> [name]` (reuses `SubmitIdentity` IPC; raw bytes already carry the auth headers).
- `2219521` feat: thread the **Avail block inclusion time** (`block.timestamp()` → `BlockData.timestamp` → `L2Context::for_block`).
- `a49ed45`/`804b88a` feat: **`sbo-capture`** crate + CLI de-stub.
- `ad2c67f` feat: **Phase 1.5** — L2 gate in daemon `validate.rs` (`L2Context`, `/sys/names` resolver, `ValidationStage::Attribution` carry-but-filter); `sbo-core::authorize`; `StoredObject` gained `content_schema` + `owner_ref`; fixed a `:`→`\x1f` delimiter bug.

### Key Phase-1 artifacts (where things live)
- **Pure L2 logic:** `sbo-core/src/authorize.rs` (`authorize_owner`/`authorize_message`/`message_attribution`/`parse_auth_evidence`), `sbo-core/src/resolve.rs` (`resolve_controller`/`is_authorized`), `sbo-core/src/attribution.rs` (deterministic verifier).
- **Daemon integration:** `sbo-daemon/src/validate.rs` (`L2Context`, `load_trust_anchors`, `name_lookup`, `l2_authorize`, the gate in `validate_message`, the email-rooted branches in `validate_post`/`validate_name_claim`).
- **Tests:** `sbo-daemon/tests/l2_authorization.rs` (11), `sbo-core/src/authorize.rs` unit tests, `sbo-capture` (6 + 2 `#[ignore]` live).

### Verified sound in review (don't re-litigate)
- **L2 determinism holds** — no wall-clock/random/order-dependent state in the attribution/resolve/authorize path; time comes from the block. `Genesis::validate` is a `todo!()` but has **no live callers**. `/sys/trust/brokers` is write-locked after genesis (default policy grants nothing on `/sys/trust/`).

## NEXT: Phase 2 — align canonical state + policy to the two-layer model
The L2 *gate* exists; Phase 2 makes *stored state and policy* consistent with it. Concrete work items (grounded in the review):

1. **Stored-owner model.** `message_to_stored_object` (`sbo-daemon/src/validate.rs` ~419) sets `StoredObject.owner = signing_key`. For email-rooted objects this is the *ephemeral* key — meaningless for later ownership checks. The resolved controller lives in `owner_ref`. Make ownership/update checks key off the **resolved controller**, not the signer key. (`StoredObject` already carries `owner_ref` + `content_schema` from Phase 1.)

2. **`effective_owner` fallback** (Authorization Spec §Verification Algorithm: `Owner → else Creator → else signer`). The current L2 gate only fires `if let Some(owner) = &msg.owner`; ownerless writes bypass L2 via the legacy key path. Implement the fallback so the signer is the effective owner when no `Owner`/`Creator` is present, and route it through the same authorize path.

3. **Policy `$owner`** (`sbo-core/src/policy/evaluate.rs:237`, and `effective_owner` derivation ~26–35). `"owner" => owner == actor` compares against the signer-key owner; resolve `$owner` to the **controller** (email or key) for email-rooted objects so policy grants like `/$owner/**` work for email identities.

4. **Carry-but-filter on canonical state.** Confirm L1-valid/L2-failing writes are carried by DA but never mutate owned state on replay (the gate already returns `Invalid` → skipped; verify the replay/state-root path matches the Validity-Layers model end-to-end, incl. tip vs confirmed if it surfaces).

5. **Evidence fallbacks** (`sbo-core/src/authorize.rs::parse_auth_evidence`). Only `inline:` is handled; implement `ref:<sbo-ref>` and the `/sys/dnssec/` namespace lookup (Authorization Spec line 140) so referenced evidence resolves.

6. **State Commitment + creator derivation** (`sbo-core/src/state/db.rs::object_to_segments`, `sbo-daemon/src/validate.rs::resolve_creator`). `creator` is a literal trie/storage-key segment, and `resolve_creator`'s fallback chain (`msg.creator → name-of-signer → key-hex`) collapses a **nameless email (T0) author** to her *ephemeral* cert key. Consequence: after a browserid cert rotation she can't update her own content (creator-keyed `get_object` misses → treated as a new object) and her objects fragment under per-key subtrees. Names avoid this via creator-independent lookup; general content does not. **Fix:** put the **attributed email** (the deterministic `message_attribution` result from 2.1 — who the *signer* is, not `msg.owner`, since creator≠owner in general) into the chain ahead of `key-hex`, so an email author's writes share a stable `creator` across rotation. Needs `L2Context` threaded into `resolve_creator`/`message_to_stored_object`. Inclusion-time-pinned ⇒ deterministic/replay-safe. Update the State Commitment + Identity specs to specify the creator segment is the resolved/attributed controller, not the signing key. (Surfaced in Phase-2 review; this is the concrete reason item 6 matters — without it the email tier silently fragments at the storage layer even though authz is correct.)

Sequence by dependency; build-green + commit + pause-for-review per sub-step.

## Conventions (unchanged from Phase 1)
- Specs (`specs/*.md`) are source of truth. If code contact reveals a spec issue, fix the spec too and rerun the link/anchor/drift greps.
- Build green + commit (`feat(impl): Phase 2.x — …`) + pause-for-review per sub-step. Work on `main`.
- Delegate mechanical churn (wide call-site edits, struct-field threading) to subagents with exact instructions; do the design/integration yourself. Verify a subagent's work independently (build + targeted grep) before committing.
- Tests: offline unit/integration by default; live network paths behind `#[ignore]` (run with `-- --ignored`). The positive email-attribution path is only live-testable (hardcoded IANA root) — covered by `verify_attribution_with_provider_key` unit tests + the `#[ignore]` e2e.
- `sbo-zkvm`/`sbo-zkvm-methods` fail to build without a RISC0 toolchain — **pre-existing**; exclude them. Watch disk: the build cache filled `/` once during Phase 1 (`cargo clean` recovered 12 GB).

## Phases after 2 (additive; see plan doc)
3 attestation.v1 · 4 policy attestation-defined roles · 5 community.v1 · 6 content (post/comment/reaction + HLC/Prev/tip-confirmed/durability) · 7 indexer/client conformance + the reference community client (the demo goal).
