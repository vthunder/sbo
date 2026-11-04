<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS4: layers never audited before

**Status:** skeptic pass complete, 2026-11-04. Epic `sbo-ax7t`, bean
`sbo-f8cj`. Scope: everything the July 2026 review (sbo-ix77) did not
touch or that was written since: the daemon's validation glue
(`validate.rs` owner fast-path, name claims, attestation conditions, HLC
bound, creator/owner fallbacks), the mempool overlay (`pending.rs`,
`state_view.rs`), fast-sync trust (`bootstrap.rs`, `trust.rs`), the
filesystem mirror (`sync.rs::write_object`, `repo.rs`), IPC (`ipc.rs`,
`main.rs::handle_request`), the DA client (`sbo-avail`, `lc.rs`), the CLI
keyring, `sbo-capture`. Oracle: `docs/design/threat-model.md` I8, I9, I13,
I15, I16, I24, I25, I26, I27, I28, I29, I33, I34; decisions Q6, Q7, Q9,
Q12–Q16, Q20 (`docs/security-audit-2026-11-decisions.md`).

**Method.** Reviewer pass over every file in scope, then a skeptic pass that
tried to refute each WS1 lead by reading the callers or writing a test.
Every verdict below is backed by a test that runs today. Tests encoding an
invariant that FAILS today are `#[ignore]`d with an
`// AUDIT-2026-11 Dx: fails today` comment and are the acceptance test for
the fix; everything else passes today and pins what the audit re-verified.
No production code was changed.

| Crate | Test file | Pass | Ignored (fail today) |
|---|---|---|---|
| sbo-daemon | `crates/sbo-daemon/tests/audit_2026_11_ws4.rs` | 7 | 16 |
| sbo-core | `crates/sbo-core/tests/audit_2026_11_ws4.rs` | 2 | 1 |

Run the failing set with
`cargo test -p sbo-daemon --test audit_2026_11_ws4 -- --ignored`. No
dependency changes.

## 1. Verdicts on the WS1 candidates

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| D7 | **CONFIRMED** | High | `sync.rs:1294-1312` (`warn!` only, write already applied); `main.rs:1706-1733` (genesis mismatch `error!` only). Validation never reads the evidence: `validate_message` has no self-cert step. | `d7_domain_with_failing_self_cert_is_invalid` (ignored); `d7_genesis_mismatch_is_reported_by_verify_genesis` (passes: `Repo::verify_genesis` does return `Err`, `main.rs` discards it) |
| D11 | **CONFIRMED** (fail-open half) | Medium | `validate.rs:2085-2090` `list_objects_by_schema(..).unwrap_or_default()` | `d11_not_attested_fails_closed_on_state_read_error` (ignored); `d11_ban_is_enforced_with_healthy_state` (passes) |
| D12 | **CONFIRMED** | Medium | `validate.rs:2165` (`message_to_stored_object` copies `msg.policy_ref` from any authorized updater) | `d12_policy_ref_is_not_changed_by_a_non_creator` (ignored) |
| D15 | PARTIAL | Low | `trust.rs::TrustGate::observe`; `main.rs:1690-1700` (`timeout_blocks` stops sync, reads stay refused). A bounded wait exists; the spec's degrade fallback does not. | `d15_enforcing_gate_stays_gated_without_claims` (passes) |
| D16 / D55 | **CONFIRMED** | Low | `validate.rs:383-403` (`e_<16 hex>` / `unknown`), `:510-518` (`effective_owner_ref` → signer key) | `d16_unnamed_signer_creator_is_a_truncated_key` (passes, pins the sentinel) |
| D17 | PARTIAL | Low | `pending.rs:142` vs `pending.rs:246`: `pending_still_wins` says confirmed wins on a missing HLC, `overlay_wins` says pending wins. Divergence lasts only until the confirming write lands (then the pending row is dropped), so reads converge; `sbo-hy4r` / `sbo-y757` stay the tracked items for the ordering half. | `d17_overlay_and_reconcile_disagree_on_missing_hlc` (passes, documents) |
| D20 | **CONFIRMED** (socket mode); REFUTED (`RepoRemove` arbitrary path) | Medium | `ipc.rs:242` binds with the process umask → `0755` measured; every command, including `Shutdown`, `ApproveSignRequest`, `RepoAdd{path}`, needs only socket access. `RepoRemove` deletes `repo_dir_for_uri(..)` under the daemon's own state dir (`repo.rs:207-211`), never the caller-supplied mirror path. | `d20_ipc_socket_is_owner_only` (ignored; measured mode `755`) |
| D21 | **CONFIRMED** | High | `envelope.rs:97-118` (`Id::new("..")` ok, `Path::parse("/../")` ok); `sync.rs:1084-1095` joins the segments into `repo.path` verbatim; `:1180-1182` `with_extension("tmp")`; `:1221-1224` any fs error returns `Err` from `process_block`. | `d21_dot_segments_are_not_valid_ids` (ignored, core); `d21_object_id_and_collection_name_share_a_grammar` (passes) |
| D22 | **CONFIRMED** (unbounded `W`); REFUTED (arithmetic overflow) | Medium | `validate.rs:439-460` (`collection_max_lag_ms`: `_config` at the write's own path, no cap; `saturating_mul`), `hlc.rs:66` (`t_b_ms - max_lag_ms` cannot overflow for `t_b ≥ 0`, `lag ≥ 0` — `validate_collection` rejects negatives); `validate.rs:180-187` `authored_at` feeds the presentation expiry. | `d22_collection_w_is_capped_by_a_protocol_maximum` (ignored); `d22_default_w_rejects_an_hour_old_authoring_instant` (passes) |
| D23 | **CONFIRMED** | Medium (Critical together with D5) | `validate.rs:763-767` (`!root_policy_exists` ⇒ allow) — the same predicate serves the submit gate (`main.rs::submit` calls `validate_message`) | `d23_no_root_policy_rejects_ordinary_writes` (ignored) |
| D25 | PARTIAL | Low | `sync.rs:1040-1060` keeps the original wire bytes and `object_hash` across a move (by design: creator and hash invariant; the mirror file is renamed, not rewritten). The "source policy not evaluated for the owner" half is the D57 fast-path. | `d57_owner_transfer_out_of_denied_path_is_invalid` (ignored) |
| D26 | **CONFIRMED** | High | `bootstrap.rs:62-66` (`evaluate_trust` inserts `SYS_AUTHORITY` as a backer whenever the policy lists it, with no claim read); `:252-262` (`bootstrap_provisional` takes the manifest's root); `:296-301` (default policy degrades to `RootTrust::ServingNode`). The key-pinned walk-forward in `trust.rs` is sound but only runs when `[trust]` is configured. | `d26_authority_does_not_back_a_root_without_a_signed_checkpoint` (ignored) |
| D27 | **CONFIRMED** | High | `bootstrap.rs:128-135` (`put_policy_version(hash, policy)` as given; the doc comment claims a content-hash check that does not exist) | `d27_snapshot_policy_versions_are_verified_against_their_hash` (ignored) |
| D28 | **CONFIRMED** | Medium | `rpc.rs:399-410` (missing timestamp is non-fatal); `validate.rs:2085` (`unwrap_or(0)`); `:415` (bound skipped when `None`) | `d28_unknown_inclusion_time_does_not_lift_a_ban`, `d28_unknown_inclusion_time_does_not_skip_the_hlc_bound` (both ignored) |
| D33 | **CONFIRMED by reading** (no offline fixture) | Medium | `policy/evaluate.rs:224-250` checks validity only (`verify_dnssec_proof_for_domain` returns the window and nothing compares it to the incumbent's); `validate_post` update path has no monotonic rule. Decision Q16 (a). A test needs a real RFC 9102 chain; WS3's fuzz corpus or WS6's fixtures should supply one. | — (routed to WS6 with the dnssec verifier) |
| D34 | **CONFIRMED** | Low | `bootstrap.rs:24` names the authority `sys-checkpointer`; `trust.rs:56-64` pins `ed25519:` keys and rejects names. Two trust models, no shared config value. | `d34_legacy_authority_name_is_not_a_pinnable_key` (passes) |
| D39 / D9 | **ACCEPTED RISK** (Q20) | — | `sbo-avail/src/client.rs:188-240`, `sbo-rpc/src/client.rs`; see §4. | — |
| D56 | **CONFIRMED** | Medium | `validate.rs:692-704` routes every `/sys/names/` write to `validate_name_claim`, which never calls `check_policy` | `d56_name_claim_evaluates_root_policy` (ignored) |
| D57 | **CONFIRMED** | Medium | `validate.rs:745-758` (`l2_authorize(owner_ref).is_ok()` short-circuits policy on update); `:926-940` (same for transfer/delete) | `d57_owner_update_under_denied_path_is_invalid`, `d57_owner_update_ignores_restrictions`, `d57_owner_transfer_out_of_denied_path_is_invalid` (ignored) |
| D58 | **CONFIRMED by reading** | Medium | `sync.rs:834` (`write_object(..)?` aborts `process_block` mid-block after earlier messages were applied), `:1340-1345` (`run` logs and moves to the next block; head is never advanced for the failed block, so the block is re-processed on the next tick but any already-applied writes stand). Needs a sync harness; WS8 can demonstrate it with D21's collision. | — |
| Q6 (daemon) | **CONFIRMED** gap | Medium | `resolve.rs:128-129` (`is_key_reference` → `Controller::Key`), `validate.rs:510-518` (signer fallback) | `q6_explicit_bare_key_owner_is_rejected`, `q6_signer_fallback_owner_is_rejected_after_genesis` (ignored) |

### 1.1 D57 — the owner fast-path (Medium; Q13 decided: spec wins)

`validate_post` authorizes an update by asking whether the signer speaks for
the object's stored `owner_ref`; if so the policy is never evaluated. The
same shape sits in `validate_transfer` for the source path. Three things the
spec says are absolute are therefore unavailable against an owner: `deny`
(the Policy spec's "no grants can override a deny"), `restrictions`
(`max_size`, `schema`, `content_type`, `not_attested` bans), and the
absence of an `update` grant. Concretely: a community that bans a member by
attestation cannot stop that member editing their existing posts; a bridge
lock written as `deny` does not hold the object; a size cap holds everyone
except the author. Q13 settles the shape: the owner is a principal like any
other, and the implicit grant becomes an explicit `to: owner` grant in the
presets and root policy.

Remediation: delete the short-circuit in both functions and always call
`check_policy` with `signer_is_owner` carrying the controller match (it
already does, via `evaluate_policy_for`). Before regenesis, run every policy
on app 506 through the new rule with its owners and confirm nothing that
should admit stops admitting (Q13 note). The `/sys/dnssec/**` self-authorizing
policy already grants `update` to `*`, so evidence refreshes are unaffected.

### 1.2 D56 — name claims outside policy (Medium; Q14 decided)

`/sys/names/` has its own authorization: anti-hijack on a primary-domain
repo and controller-only updates. Nothing else: the root policy's grants,
`deny` and restrictions on `/sys/names/**` are dead text. A deployment that
wants invite-only names, or wants to ban a key from claiming, cannot. Fix:
run `check_policy` (Create on an empty slot, Update on an occupied one) in
`validate_name_claim` after the existing checks, keeping the anti-hijack
rule as an additional gate.

### 1.3 D11 / D28 — attestation conditions on a bad clock or a bad read

`attested_subject_matches` enumerates `attestation.v1` objects; a RocksDB
error yields an empty set, which `not_attested` reads as "not banned". The
same function pins the clock at `t = 0` when the block carried no timestamp,
so no attestation is in force and every ban lifts; `check_hlc_bound` skips
its bound for the same reason. Two nodes, one with the timestamp and one
without, apply different writes from the same block. The threat model's
I13 and I16 say both must fail closed. Fix: propagate the read error as
`ValidationStage::State` (the rest of the daemon already does this for
`get_object`), and treat a missing block timestamp as a fetch failure that
retries rather than a block that validates (Q23 below).

### 1.4 D22 — `W` is whatever `_config` says (Medium; Q9 decided)

`collection_max_lag_ms` reads `max_authoring_lag_s` from the collection's
own `_config` with no ceiling. Anyone who can create at `<path>/_config`
sets the window to a century; the test admits a write authored 50 years
before inclusion. For attributed writes `authored_at` is that instant, so
the presentation's assertion and access cert are judged at a time the
writer chose. Overflow was refuted: `validate_collection` rejects negative
lags and `saturating_mul` plus a non-negative `t_b` keep `within_bound`
inside `i64`. Fix per Q9: protocol maximum for `W` (reference 24 h) applied
in `collection_max_lag_ms`, `_config` writes require an explicit grant
(`id: "_config"` restriction or a `govern`-like rule), and only the
assertion is judged at `authored_at`.

### 1.5 D26 / D27 — fast-sync trusts the serving node (High; Q12 decided)

`bootstrap_with_policy` under the default `{[sys-checkpointer], 1}` policy
adopts the manifest's checkpoint root with one "backer" that is nothing but
the policy's own entry; if no checkpoint is advertised it adopts the
manifest's snapshot root outright (`RootTrust::ServingNode`). The
`verify_and_load_payload` root check then confirms only that the snapshot
hashes to the root the node told us. `policy_versions` are loaded with no
check at all, so a forged pinned policy version — the frozen governance a
P2 pin points at — lands in the client's database and authorizes writes.
The key-pinned walk-forward in `trust.rs` is the correct design and is
unaffected, but it is opt-in. Fix per Q12: delete the name-based path,
make `sys-checkpointer` a pinned key, require a signed `checkpoint.v1`
(read from chain, or from the manifest and verified by signature) before a
root counts, reconstruct `policy_versions` from covered objects or verify
each against its content hash, and gate `bootstrap_provisional` behind an
explicit flag.

### 1.6 D21 — the filesystem mirror (High)

The mirror path is `repo.path / <path segments> / <id>` built from the
on-chain strings with no encoding. The identifier grammar admits `.` and
`..`, so `Path: /../../` plus any id writes `wire_data` outside the repo
directory (as the daemon's user, at a location the writer picks relative
to the mirror). Separately, an id and a collection name share the grammar:
once `/c/x` exists as a file, a later `/c/x/y` fails `create_dir_all`, the
`?` at `sync.rs:834` aborts the block on this node, and the rest of the
block's messages are not applied (D58): a one-node fork from an
unprivileged write, anywhere a `create` grant exists. `a.b` and `a.tmp`
share one temp file. WS8 should demonstrate the escape against a tempdir
mirror. Fix: reject dot segments in the grammar (spec and core), and make
the mirror best-effort (state DB is authoritative; a mirror write failure
logs and never aborts the block) with an encoding that cannot collide
(Q24).

### 1.7 D20 — IPC (Medium)

The socket is created with the process umask; measured `0755`. Every
request is trusted: `Shutdown`, `ApproveSignRequest` (approves a sign
request on the user's behalf), `RepoAdd` with any mirror directory,
`Submit` (spends TurboDA credit). On a multi-user host any local account
drives the daemon. `RepoRemove` was refuted as an arbitrary delete: it
removes the daemon's own `repos/<uri>` state dir, not the mirror path. Fix:
`set_permissions(0o600)` after bind (and `0700` on the parent), which is
the whole fix on a single-user host; see Q22.

### 1.8 D7 — self-certification (High; spec says MUST reject)

`domain.v1` validation ends at the JWT self-signature. The DNSSEC
self-cert is evaluated after the write is applied, in `write_object`, and
its failure is a `warn!`. The Identity spec's Rule 4 is a MUST. Since
`validate_message` never looks at the evidence, the fix is to move the
check there (fetch the referenced `dnssec.v1`, `verify_domain_self_cert`
at inclusion time, reject on error), which also makes it apply at the
submit gate. The genesis half (expected hash mismatch only logged) is D5's
remediation under Q7.

## 2. New findings

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| W4-1 | CONFIRMED | Low | `validate.rs:2086` scans every `attestation.v1` object on every attested check, for every grant and restriction that names one; a community with many attestations pays O(n) per write per condition. Not exploitable beyond cost; noted for the remediation of D11. | — |
| W4-2 | CONFIRMED | Info | `bootstrap.rs:124-127` doc comment says each policy version is "verified against its claimed content-hash"; no such check exists (D27). | `d27_*` |
| W4-3 | CONFIRMED | Low | `sbo-capture/src/lib.rs:83` builds a default `reqwest` client (redirects followed) for the broker/IdP conversation; the base URL is operator-chosen, so this is the browserid-ng D15 class with no attacker steering. | — |
| W4-4 | REFUTED | — | `sbo-core/src/keyring.rs`: key files `0600`, directory `0700`, atomic rename. | `keyring_files_are_owner_only` (passes) |

## 3. Invariants re-verified (passing tests)

- **I13 (healthy path)**: an in-force `not_attested` ban rejects the write
  when the state read succeeds (`d11_ban_is_enforced_with_healthy_state`).
- **I24/I25 (default)**: the default `W` rejects an authoring instant an
  hour before inclusion (`d22_default_w_rejects_an_hour_old_authoring_instant`).
- **I27 (half)**: `Repo::verify_genesis` reports a hash mismatch; what is
  missing is a caller that acts on it.
- **Trust gate**: an enforcing anchor is gated until pinned keys vouch, and
  a name is not a pinnable key (`d15_*`, `d34_*`).
- **Host**: keyring permissions (`keyring_files_are_owner_only`).

## 4. July 2026 findings touching these layers, re-verified

| July | Then | Now |
|---|---|---|
| sbo-3gqo self-cert warn-only | High | **Still open** (D7). Evidence is now read from the object's own `ref:` or the single `/sys/dnssec/<domain>` slot, which under global uniqueness closes the "refresh shadows genesis evidence" half; the warn-only half stands. |
| sbo-zocd not_attested fail-open | Medium | **Still open** (D11). |
| sbo-zocd Policy-Ref unrestricted | Medium | **Still open** (D12). |
| sbo-zocd trust-gate liveness | Low | **Partially addressed**: `timeout_blocks` bounds the wait but stops sync rather than degrading (D15). |
| sbo-zocd legacy owner fallback | Low | **Still open**; superseded by Q6 (no signer fallback after genesis). |
| sbo-7bl8 DA trusted from RPC | High | **Accepted risk this round (Q20).** What the Avail light client verifies, from its public documentation (information only, not re-derived here): it follows finalized headers from a full node, samples cells and verifies each sampled cell's KZG proof against the header's data root commitment, and in app-client mode fetches and verifies every cell of the app's rows before reconstructing the app data it serves on its HTTP API. So the data the daemon receives from `127.0.0.1:<lc port>` has been checked against a finalized header by a local process, not merely relayed from a remote RPC. What the daemon does not do on top of that: pin the block hash (hardcoded zero), refuse to advance on "app data not available" (it skips the block), cross-check the URI's chain id against the node's genesis hash. Avail is replacing this client; follow-up bean `sbo-wn15` (deferred). |
| sbo-hy4r mempool order | High, in progress | Carried as D17; the overlay/reconcile wobble documented here is a tip-visibility issue, the on-chain ordering gap remains sbo-hy4r's. |

## 5. What needs Dan's decision

Appended to `docs/security-audit-2026-11-decisions.md` as Q22–Q25:

1. **Q22 IPC authorization model** (D20): socket `0600` alone, or
   per-command authorization on top.
2. **Q23 block without an inclusion time** (D28): retry the fetch and never
   process the block, or process it with every attributed/attested write
   failing closed.
3. **Q24 mirror encoding and failure policy** (D21/D58): reject dot
   segments at the grammar and make the mirror best-effort with a
   collision-free encoding, or keep the mirror authoritative and halt sync
   on any mirror error.
4. **Q25 overlay rule on a missing HLC** (D17): align `overlay_wins` with
   `pending_still_wins` (confirmed wins) or keep the optimistic tip.

## 6. High+ for WS8

1. **D21** filesystem escape via `Path: /../../` against a tempdir mirror,
   and the `/c/x` file vs `/c/x/y` collection collision stalling a block
   (D58) — needs the sync harness, run with `rpc_only` against canned
   blocks.
2. **D26/D27** forged manifest root and forged `policy_versions` loaded by
   a client bootstrapping from a hostile serving node (an in-process axum
   server serving `/v1/sync-points` and `/v1/snapshot`).
3. **D7** a `domain.v1` with failing evidence applied and logged, then used
   to certify `sys` (Mode B) — demonstrates the trust-root consequence.
4. **D23 + D5** writes accepted on a repo with no root policy at the submit
   gate (`POST /v1/submit`), forwarded to DA with the node's TurboDA key.
