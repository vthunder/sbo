<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# sbo Security Audit — 2026-11-04

**Scope:** full-pass adversarial audit of the sbo repository: the fifteen
protocol specs and two proposals in `specs/`, and the reference
implementation under `crates/` (`sbo-core` wire, message, policy,
resolution, authorization, attribution, DNSSEC, genesis, URI, HLC, proofs,
state, schemas, keyring; `sbo-crypto`; `sbo-types`; `sbo-rpc`; `sbo-avail`;
`sbo-capture`; `sbo-daemon` validation, sync, filesystem mirror, mempool
overlay, submit queue, fast-sync, trust gate, HTTP and IPC; `sbo-cli`;
`sbo-wasm`; `sbo-zkvm` read only), plus the supply chain, CI, the
sbo-daemon deployable in `~/src/mingo/deploy/sbo-daemon/`, secrets and
logging. The rest of mingo is out of scope (Dan, 2026-11-03). Nine
workstreams (WS1–WS9), tracking epic `sbo-ax7t`, branch `audit-2026-11`.
Threat model: `docs/design/threat-model.md` (adversaries A1–A10, boundaries
B1–B14, invariants I1–I36).

**Method.** WS1 read every spec against the code and produced candidates
D1–D58 and spec findings S1–S23, carrying forward the twelve open leads of
the July 2026 review (`sbo-ix77`, epic `sbo-f5wn`). Each candidate was then
re-verified by a skeptic in the owning workstream (WS4 daemon layers, WS5
HTTP/IPC, WS6 crypto core) whose default was *refute unless a test proves
it*; every confirmed finding is encoded as an `#[ignore]`d test tagged
`AUDIT-2026-11 <id>` (`grep -rn AUDIT-2026-11 crates`) or as an
`EXPECTED_FAIL` entry in a WS2 runner, and **un-ignoring that test (or
removing that entry) is the acceptance criterion for the fix**. WS2 built
135 conformance vectors in 8 suites run by 5 runners against every duplicate
implementation; WS3 added proptest suites to four crates and twelve
cargo-fuzz targets (~28M executions, two real crashes found); WS7 ran
cargo-audit, cargo-deny and gitleaks and created the repo's first CI; WS8
built thirteen PoCs against in-process harnesses and loopback listeners
only. Severities below are the **post-verification** severities. Decisions
Q1–Q21 were settled by Dan on 2026-11-04; Q22–Q40 are open
(`docs/security-audit-2026-11-decisions.md`), so remediation beans that
depend on one are `draft` and name it.

**Suite tally (localtest, 2026-11-04, `cargo test --workspace --no-fail-fast`):
517 passed, 1 failed, 94 ignored across 50 test binaries; 518 / 0 / 94 after
one WS3 generator fix** (`dns_record_parsing` let its junk carry a `v=` token, which
the parser's own last-wins rule honoured; `prop_assume!` added). The audit
binaries alone:

| Binary | Pass | Ignored (fail today) |
|---|---|---|
| `sbo-core` ws2 core/generate, ws3 wire/policy/proofs/role_cycle/time_scopes/uri_identity, ws4, ws6 | 68 | 35 |
| `sbo-crypto` ws2, ws3 trie, ws6 | 9 | 4 (+1 under `--features kzg`) |
| `sbo-types` ws2 | 1 | 0 |
| `sbo-rpc` ws3 decode | 3 | 1 |
| `sbo-wasm` ws2 | 4 | 0 |
| `sbo-daemon` authz matrix, ws2, ws3, ws4, ws5, ws6, ws7 | 37 | 36 |
| `sbo-daemon` WS8 PoCs (`#[ignore]`d by design; assert the broken behaviour) | — | 13 |

WS2 runners carry 84 `EXPECTED_FAIL` entries (types 13, crypto 2, core 38,
wasm 24, daemon 7) that count as open findings and are not in the ignored
column. `cargo metadata --locked` on the final manifests: OK. Per-workstream
reports: `docs/security-audit-2026-11-ws1-threat-model-spec.md`,
`-ws2-conformance.md`, `-ws3-fuzz-proptest.md`, `-ws4-layers.md`,
`-ws5-http-surface.md`, `-ws6-crypto-core.md`, `-ws7-supply-chain.md`,
`-ws8-pocs.md`.

## Executive summary

The design core holds where it was built: Ed25519 only with pinned
lengths and `alg`; the two ed25519 wrappers return identical verdicts on
every vector; the device-presentation attribution verifier checks the
envelope key against the access cert, the issuer against DNSSEC evidence
at inclusion time, the audience, the `as:` rules and cross-issuer
delegation, and fails closed on missing evidence; policy composition
(deny beats grant, restrictions narrow, descendant constraints are
byte-exact narrowings) holds under 50+ properties; trie proofs are sound
and complete; no credential has ever been committed in 514 commits; 28M
fuzz executions found two real crashes and nothing in `dnssec-prover`.
Every one of the twelve open July 2026 leads is still present. The
material findings are **enforcement that the specs promise and the code
never implemented**, in six themes:

1. **The payload and the envelope are not bound.** `Content-Hash` is never
   checked (D1, Critical, PoC), so any relay rewrites a signed write; the
   signature verifies a reconstruction of the headers rather than the
   received bytes (D2, High), so duplicate and reordered headers are
   malleable and a relay-appended header changes the raw object hash
   (W6-4/Q32); the trie has no leaf/internal separation (D4, High) and
   loses an object at a prefix path (W3-4). One canonical-bytes helper and
   one state-commitment version bump close the group (Q18, Q32).
2. **No bootstrap rule.** `Genesis::validate` is `todo!()` and a repo with
   no root policy accepts every write and every policy from anyone, at the
   submit gate too; a `genesisHash` mismatch only logs (D5/D23, Critical,
   PoC). The domain self-certification the Identity spec makes a MUST is a
   `warn!` after the write is applied (D7, High, PoC). The pinned root KSK
   is decorative (D6, High).
3. **Policy that the owner, a name claim, or a typo can walk around.** The
   owner fast-path skips `deny`, restrictions and bans (D57); name claims
   never see policy (D56); unknown condition keys fail open (W3-3);
   `Policy-Ref` is repointable by any updater (D12); `not_attested` fails
   open on a read error (D11); a missing block timestamp lifts every ban
   (D28); the `W` window is unbounded and unprivileged (D22).
4. **Chain-wide denial of service from one write.** A cyclic role policy
   stack-overflows every node (D10, High, PoC); ten `**` in a policy
   pattern or a wallet-authored warrant scope never finish matching
   (W3-1/W3-2, High); one DA submission panics every node's sync task
   (W3-10) or every light node's SBOP parser (W3-9); a gzip-flagged
   submission inflates to GiB on every node (W3-7); an indexer's
   non-existence proof panics the client (W3-8).
5. **Trust in whoever is serving.** Fast-sync counts a name as a backer with
   no signed checkpoint and adopts the serving node's root and its forged
   pinned policy versions (D26/D27, High, PoC); the filesystem mirror
   writes wherever an on-chain `Path: /../` says and a collision forks one
   node (D21/D58, High, PoC); the daemon is written for loopback but
   deployed on `0.0.0.0` with `*` CORS and the private-network header, so
   any web page spends its TurboDA credit (W5-1, High, PoC); the
   submit-gate status fetch and evidence capture are blind SSRF and
   resolver amplification before any signature check (W5-4, W5-9, W5-2);
   nothing answers 429 (W5-3); the IPC socket is 0755 (W5-8).
6. **Supply chain and operations.** The repo had no CI at all (W7-1, closed
   during the audit); 34 RUSTSEC advisories close with `cargo update` and
   deleting an unused `reqwest 0.11` (W7-2/W7-6); the deploy workflow pins
   actions by mutable tag (W7-8); the container runs as root with the
   checkpoint and attestor keys on its volume (W7-12).

**Counts (post-verification, confirmed findings only).**

| Severity | Count | Ids |
|---|---|---|
| Critical | 2 | D1, D5/D23 |
| High | 12 | D2, D4, D6, D7, D9, D10, D21/D58, D26, D27, W3-1, W3-2, W5-1/D38 |
| Medium | 29 | D3/W6-4, D11, D12, D13/D54, D17/W2-2/W2-3, D18/W5-4/D52, D20/W5-8, D22, D28, D33, D50/W5-5, D56, D57, Q6 (bare-key owners), W3-3, W3-4, W3-6 (SBOQ), W3-7, W3-8, W3-9, W3-10, W5-2, W5-3, W5-9, W7-1 (closed), W7-2, W7-6, W7-8, W7-12 |
| Low | 22 | D14, D15, D16/D55, D24/W6-3, D30/W6-1, D34, W2-1, W2-4/S18, W4-1, W4-3, W5-6, W5-7, W5-10/D37, W6-2, W7-3, W7-4, W7-5, W7-9, W7-11, W7-13, W7-14, I24 |
| Info | 10 | D8 (Q19), D32, D39 (Q20), W3-5, W3-11, W4-2, W6-5, W7-7, W7-10, Q40 |

Downgrades and refutations on verification (details in §2): **D18 High →
Medium** (needs an attacker-run DNSSEC IdP plus an admitted write); **D3
High → Medium, partial** (raw and reserialized hashes agree on canonical
input, pinned against the live genesis; only D2 inputs differ); **D8 and
D39 scoped to Info** by Q19 and Q20 (the Avail light client verifies
finality and availability itself; Avail is replacing it); **D22 overflow
half refuted**, unbounded `W` stands; **D20 `RepoRemove` arbitrary delete
refuted**, socket mode stands; **D37 XSS, open redirect and id-entropy
halves refuted**, never-expiring requests stand; **D24 masked**: the
restriction denies everything today (W6-3), the forged-issuer hole sits
behind that; **D30 non-canonical `S` refuted** (dalek rejects it), the
small-order key stands as W6-1; **D51 refuted** as a crash (3.8M
executions); **D41–D48 refuted on reading**; **I7 and I26 hold**.

## 1. Severity ledger

Columns: final severity; where; the acceptance test(s) or vector ids
(un-ignore, or delete from `EXPECTED_FAIL`); PoC if WS8 reproduced it; the
decision reference and its state; the remediation bean. Test file
abbreviations: `core-ws6` = `crates/sbo-core/tests/audit_2026_11_ws6.rs`;
`core-ws4` = `crates/sbo-core/tests/audit_2026_11_ws4.rs`; `ws3-<x>` =
`crates/sbo-core/tests/audit_2026_11_ws3_<x>.rs` (`wire`, `policy`,
`role_cycle`, `time_scopes`, `uri_identity`, `proofs`); `crypto-ws6` /
`crypto-ws3` = the `sbo-crypto` files; `rpc-ws3` = `sbo-rpc`; `d-ws4`,
`d-ws5`, `d-ws6`, `d-ws7`, `d-ws3` = the `crates/sbo-daemon/tests/audit_2026_11_<ws>.rs`
files; `authz` = `audit_2026_11_authz_matrix.rs`; `poc-*` =
`audit_2026_11_poc_{core,fastsync,http}.rs`; `runners` = the five WS2
`EXPECTED_FAIL` tables (vector ids from `conformance/`).

### Critical

| # | Finding | Where | Acceptance | PoC | Decision | Bean |
|---|---|---|---|---|---|---|
| D1 | `Content-Hash` is never verified against the payload: any relay swaps a signed write's payload (same length) and every replayer accepts it; P2 policy versions are keyed by the *claimed* hash, so a hostile policy body is filed under a benign policy's hash. July `sbo-d5nm`. | `sbo-core/src/wire/parser.rs:169`; `message/validate.rs`; `sbo-daemon/src/sync.rs:1240` | `core-ws6`: `d1_payload_swap_on_a_signature_valid_envelope_is_rejected`, `d1_payload_without_content_hash_is_rejected`; `d-ws6`: `d1_daemon_rejects_a_payload_that_does_not_match_content_hash`; `ws3-wire`: `d1_swapped_payload_is_rejected`; runners W-CH-01 | WS8 P1, P1b (`poc-core`: 12-byte body swapped, `Valid`; all-grants policy filed under a benign hash) | Q11 (b) satisfied | `sbo-xd6u` |
| D5 / D23 / S19 | `Genesis::validate` is `todo!()`; while no root policy exists every post and every `policy.v2` from any key is accepted, in any block and at the submit gate; a `genesisHash` mismatch at the anchor only logs; no one-genesis-per-anchor rule. July `sbo-9d7l`. | `sbo-core/src/genesis.rs:13`; `sbo-daemon/src/validate.rs:733,772`; `main.rs:1706-1733` | `core-ws6`: `d5_genesis_validate_accepts_the_live_mode_b_batch`, `d5_genesis_validate_rejects_a_batch_without_a_root_policy`; `d-ws6`: `d5_without_a_root_policy_*` (2); `d-ws4`: `d23_no_root_policy_rejects_ordinary_writes` | WS8 P2 (`poc-core`: stranger plants an all-grants root and posts into another namespace) | Q7 (a) settled; **Q33 open** (batch shape) | `sbo-3q6x` (blocked by `sbo-eefz`) |

### High

| # | Finding | Where | Acceptance | PoC | Decision | Bean |
|---|---|---|---|---|---|---|
| D2 / S22 | Signature verifies a reconstruction: headers into a `HashMap` (duplicates last-wins, order dropped), `Content-Length` accepts `+2`/`002`, uppercase hex accepted. A duplicate `Path:` is read differently by first-wins and last-wins parsers. July `sbo-h75z`. | `parser.rs:123-130`, `:159`; `envelope.rs::canonical_signing_content` | `core-ws6`: `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected`, `d2_uppercase_hex_is_rejected`; `ws3-wire` `d2_*` (3); runners W-ORD-01, W-DUP-01/02, W-CL-01/02, W-HEX-01/02 | WS6/WS2 differential (not rebuilt) | **Q32 open** (helper shape) | `sbo-cusw` (blocked by `sbo-zom8`) |
| D4 / W3-4 | State trie has no leaf/internal domain separation (root collision shown across all four trie implementations); an object at a strict prefix of another's segments is evicted from every root and proof. July `sbo-hedq`. | `sbo-crypto/src/trie.rs` `compute_hash`/`compute_node_hash`, `insert_into` | `crypto-ws6`: `d4_leaf_and_internal_node_hashes_are_domain_separated`; `crypto-ws3`: `d4_leaf_and_subtree_commit_to_different_roots`, `w3_4_prefix_paths_coexist_in_the_commitment`; runners TRIE-03 | demonstration only (no attacker-chosen leaf) | Q18 (a) settled | `sbo-39qi` (blocked by `sbo-eefz`) |
| D6 / S4 | The pinned root KSK is decorative: `dnssec-prover` validates against compiled-in `root_hints()`, `verify_rr_stream` takes no anchors, `/sys/trust/dns-root` is never read; replay diverges across library versions at the next rollover. July `sbo-y5ek`. | `sbo-core/src/attribution.rs:30-62`; `dnssec-prover-0.6.8/src/validation.rs:18` | none possible today (W6-5); new `AUDIT-2026-11 D6` test over the fixture | — | Q3 (a) settled | `sbo-evne` (blocked by `sbo-ospt`) |
| D7 | Domain self-certification failure is a `warn!` after the write is applied; `validate_message` never reads the evidence, so a `domain.v1` with garbage evidence is `Valid` and can certify `sys`. Identity spec Rule 4 is a MUST. July `sbo-3gqo`. | `sbo-daemon/src/sync.rs:1294-1312` | `d-ws4`: `d7_domain_with_failing_self_cert_is_invalid` | WS8 P3 (`poc-core`) | none needed | `sbo-c46r` |
| D9 / W3-5 | `verify_kzg_proof` returns `Ok(true)` after point checks, no pairing; `merkle.rs` is dead code with a prover/verifier mismatch. July `sbo-7bl8` (KZG half). | `sbo-crypto/src/kzg.rs:116-157`; `merkle.rs` | `crypto-ws6`: `d9_kzg_verify_rejects_a_proof_that_does_not_open_the_commitment` (`--features kzg`) | — | Q20 (c): fail closed now, pairing with `sbo-wn15` | `sbo-db6p` |
| D10 | Role resolution recurses through `Role` and `Any` with no visited set or depth bound; no validation pass on write; a cyclic `policy.v2` crashes every node that evaluates a governed write. July `sbo-bynl`. | `sbo-core/src/policy/evaluate.rs:342-380` | `core-ws6`: `d10_cyclic_role_policy_does_not_crash_the_evaluator`, `d10_cyclic_role_policy_is_rejected_at_parse`; `ws3-role_cycle`: `d10_cyclic_roles_terminate`, `d10_self_referencing_role_terminates`, `d10_role_chain_depth_is_bounded` | WS8 P6 (`poc-core`: child process dies with stack overflow) | Q17 (a) settled | `sbo-sla3` |
| D21 / D58 | `Id::new("..")` and `Path::parse("/../")` succeed and the mirror joins on-chain segments verbatim: `Path: /../../` writes outside the repo directory as the daemon's user; an id/collection-name collision makes `create_dir_all` fail and the `?` aborts the block on this node only (one-node fork). | `sbo-core/src/message/envelope.rs:97-118`; `sbo-daemon/src/sync.rs:834, 1084-1095` | `core-ws4`: `d21_dot_segments_are_not_valid_ids`; `ws3-uri_identity`: `d21_dot_segments_are_rejected`; runners W-ID-01/02, ID-REJ-07/08, PATH-REJ-04/05 | WS8 P4 (`poc-core`: file lands as a sibling of the repo dir; `AlreadyExists` on the collision) | **Q24 open** | `sbo-vu8s` |
| D26 | Fast-sync counts `sys-checkpointer` as a backer with no checkpoint read, takes checkpoint roots from the untrusted manifest, and falls back to the serving node's own root (`RootTrust::ServingNode`). | `sbo-daemon/src/bootstrap.rs:62-66, 252-262, 296-301` | `d-ws4`: `d26_authority_does_not_back_a_root_without_a_signed_checkpoint` | WS8 P5 (`poc-fastsync`: forged root at height 999,999 backed; hostile axum node's root adopted end to end) | Q12 (a) settled | `sbo-syib` |
| D27 / W4-2 | Snapshot `policy_versions` (the frozen governance P2 pins point at) are loaded as given, outside the root check; the doc comment claims a hash check that does not exist. | `bootstrap.rs:124-135` | `d-ws4`: `d27_snapshot_policy_versions_are_verified_against_their_hash` | WS8 P5 (`poc-fastsync`: forged all-grants version loads under the pinned hash) | Q12 (a) settled | `sbo-syib` |
| W3-1 | `PathPattern::match_parts` and `IdPattern::glob_match` backtrack over every split: O(n^k) in wildcards; a policy pattern (needs `govern`) with ten `**` stalls every node replaying a write beneath it. | `sbo-core/src/policy/path.rs` | `ws3-policy`: `w3_1_path_pattern_matching_is_polynomial`, `w3_1_id_pattern_matching_is_polynomial` | — | **Q38 open** | `sbo-0qqq` |
| W3-2 | The same recursion on warrant `path:` scopes, authored by any wallet, evaluated at the submit gate and on replay (the externally reachable DoS of this set). | `sbo-core/src/authorize.rs::path_glob_matches` | `ws3-time_scopes`: `w3_2_scope_path_glob_is_polynomial` | — | **Q38 open** | `sbo-0qqq` |
| W5-1 / D38 | `*` CORS and `Access-Control-Allow-Private-Network: true` on every response while the deployable binds `0.0.0.0:5000`: any web page a user visits `POST`s `/v1/submit` to da.sandmill.org and the node pays TurboDA for whatever validates. | `sbo-daemon/src/http.rs:300-345`; mingo `deploy/sbo-daemon/Dockerfile:68` | `authz`: `public_mode_*` (4), spend cells (2); `d-ws5` CORS tests | WS8 P7 (`poc-http`: foreign-origin preflight allowed; `POST` reaches the spend path, counted) | Q15 (a) settled | `sbo-b4cx` |

### Medium

| # | Finding | Where | Acceptance | PoC | Decision | Bean |
|---|---|---|---|---|---|---|
| D3 / W6-4 / Q35 | `object_hash` and `genesisHash` are over `wire::serialize(msg)`; identical for canonical input (live genesis pinned), different for D2 inputs; and "unknown headers are ignored" conflicts with `sha256(raw_sbo_bytes)`: a relay-appended header is accepted and changes the raw hash. July `sbo-2tue`. | `sync.rs:1122`; `genesis.rs::genesis_hash`; `wire/serializer.rs` | `core-ws6`: `d3_every_accepted_message_is_canonical`, `d2_unsigned_unknown_header_is_rejected`; `ws3-wire`: `d3_unknown_header_survives_or_rejects`; runners W-INJ-01/02, nine `object_hash_raw` vectors | — | **Q32, Q35 open** | `sbo-xypz` (blocked by `sbo-zom8`, `sbo-eefz`) |
| D11 / W4-1 | `not_attested` fails open on a state-read error (`unwrap_or_default`); every attested check scans all `attestation.v1` objects. July `sbo-zocd`. | `validate.rs:2085-2090` | `d-ws4`: `d11_not_attested_fails_closed_on_state_read_error` | — | none needed | `sbo-slsm` |
| D12 | `Policy-Ref` set/update is not restricted to the creator. July `sbo-zocd`. | `validate.rs:2165` | `d-ws4`: `d12_policy_ref_is_not_changed_by_a_non_creator` | — | none needed | `sbo-mlyp` |
| D13 / D54 / S6 | No identity comparison rule; four byte-exact sites; `Id` admits several `@` and the two split rules disagree (`a@mingo.place@evil`); uppercase domains alias paths. July `sbo-zocd`. | `resolve.rs:70-90`; `device_attribution.rs:260-270`; `dns.rs::parse_email` | `ws3-uri_identity`: `d13_uppercase_domain_is_not_a_valid_identity_reference`, `d54_identity_has_exactly_one_at`; runners W-ID-03/04, ID-REJ-09..12, IDC-02/06, IDD-02/04, IDR-02 | — | Q5 (a) settled | `sbo-3ao9` (blocked by `sbo-lv2x`) |
| D17 / W2-2 / W2-3 | `overlay_wins` lets an HLC-less pending write shadow a confirmed one that reconcile then drops; the tip view serves a pending policy object that tip validation does not enforce (`sbo-y757`). On-chain ordering half stays `sbo-hy4r`. | `pending.rs:142, 246`; `state_view.rs:170-180` | runners LWW-06..08, POL-01; `d-ws4`: `d17_overlay_and_reconcile_disagree_on_missing_hlc` (inverts) | — | **Q25 open** | `sbo-5fja` |
| D18 / W5-4 / D52 | Submit-gate status fetch uses a default client (redirects, no address guard, uncapped body) and never compares the URI host to the authority; needs an attacker-run DNSSEC IdP plus an admitted write (hence Medium). | `sbo-daemon/src/status.rs:76-82, 220-250`; `device_attribution.rs:109-138` | `d-ws5`: `status_fetch_never_dials_a_non_public_address`, `status_fetch_requires_uri_host_to_equal_the_authority` | in-process dial observed (WS5) | none needed | `sbo-xqo2` |
| D20 / W5-8 | IPC socket created with the process umask (0755 measured); every command (`Shutdown`, `ApproveSignRequest`, `RepoAdd` any path, `Submit`) needs only socket access. | `ipc.rs:242` | `d-ws4`: `d20_ipc_socket_is_owner_only`; `d-ws5`: `ipc_socket_is_created_mode_0600` | — | **Q22 open** | `sbo-e4z9` |
| D22 / S10 | `W` is read from the collection's own `_config` with no ceiling and no privilege; `authored_at` feeds the presentation expiry, so a hostile `_config` resurrects expired credentials (a 50-year-old authoring instant is admitted). | `validate.rs:439-460` | `d-ws4`: `d22_collection_w_is_capped_by_a_protocol_maximum`; `ws3-time_scopes`: `d22_max_authoring_lag_has_a_protocol_maximum` | — | Q9 (a) settled | `sbo-wc85` |
| D28 | A block whose timestamp cannot be read is processed with attestations at `t = 0` (bans lift) and no HLC bound; nodes with and without the timestamp apply different writes from the same block. | `rpc.rs:399-410`; `validate.rs:2085` | `d-ws4`: `d28_unknown_inclusion_time_does_not_lift_a_ban`, `d28_unknown_inclusion_time_does_not_skip_the_hlc_bound`; runners TIME-01 | — | **Q23 open** | `sbo-zyny` |
| D33 | `/sys/dnssec/<domain>` refresh checks validity only: any party replaces the proof with an older chain or a pre-rotation key still inside its window. | `policy/evaluate.rs:224-250` | new `AUDIT-2026-11 D33` test over the fixture | — | Q16 (a) settled | `sbo-uv8a` (blocked by `sbo-ospt`) |
| D50 / W5-5 / W3-7 | Snapshot decode inflates gzip without a cap (254 KiB → 768 MiB peak); the chain-data decoder has the same shape on every syncing node; bootstrap fetches follow redirects. | `snapshot.rs:117-120`; `sbo-rpc/src/decode.rs`; `bootstrap.rs:185-197` | `d-ws5`: `snapshot_fetch_refuses_redirects`, `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it`; `d-ws3`: `d50_snapshot_inflation_is_capped`; `rpc-ws3`: `w3_7_gzip_inflation_is_capped` | in-process (WS5 counting allocator) | none needed | `sbo-q11b` |
| D56 / S14 | `/sys/names/` claims never evaluate policy: grants, `deny` and `not_attested` bans on names are dead text. | `validate.rs:692-704` | `d-ws4`: `d56_name_claim_evaluates_root_policy` | — | Q14 (a) settled | `sbo-hw7b` |
| D57 / S13 | The owner fast-path on update, transfer and delete skips the whole policy: `deny` (bridge lock), restrictions (`max_size`, schema, `not_attested` bans) and `can: ["update"]` are unavailable against an owner. | `validate.rs:745-758, 926-940` | `d-ws4`: `d57_owner_update_under_denied_path_is_invalid`, `d57_owner_update_ignores_restrictions`, `d57_owner_transfer_out_of_denied_path_is_invalid` | — | Q13 (a) settled | `sbo-2jtp` (blocked by `sbo-eefz`) |
| Q6 / S7 / D16 / D55 | Bare-key owners: an explicit `ed25519:` literal is a controller with no name record, email or DNSSEC; a message with no owner falls back to the signer key; `resolve_creator` emits `e_<16 hex>` / `unknown` sentinels. July `sbo-4arq`. | `resolve.rs:128-129`; `validate.rs:383-403, 510-518` | `d-ws4`: `q6_explicit_bare_key_owner_is_rejected`, `q6_signer_fallback_owner_is_rejected_after_genesis` | — | Q6 settled (full removal; genesis anchor exempt) | `sbo-yd72` (blocked by `sbo-eefz`) |
| W3-3 | Policy documents accept unknown keys: a misspelled restriction (`max_sise`) is an empty requirement that fails open. | `policy/types.rs` | `ws3-policy`: `w3_3_unknown_policy_keys_are_rejected` | — | **Q39 open** | `sbo-zzx7` (blocked by `sbo-eefz`) |
| W3-6 (SBOQ) | `obj_start + Object-Length` wraps in release past the bounds check into a slice panic; SBOQ is what an indexer serves for `?proof=1`, so a hostile indexer crashes the client. SBOP half is Low. | `proof/sboq.rs`, `proof/sbop.rs` | `ws3-proofs`: `w3_6_sboq_huge_object_length_does_not_panic`, `w3_6_sbop_huge_receipt_length_does_not_panic` | — | none needed | `sbo-ch88` |
| W3-8 | `verify_nonexistence_proof` indexes `path_segments[idx]` unchecked; the proof an indexer returns for a missing top-level object arrives with an empty list and panics the verifying client. | `sbo-crypto/src/trie.rs:1246` | `crypto-ws3`: `w3_8_nonexistence_verifier_rejects_short_path_segments` | — | none needed | `sbo-ch88` |
| W3-9 | SBOP parser slices past the end when the image has no blank line (fuzz-found); one DA submission panics every light node's sync task. | `proof/sbop.rs:113` | `ws3-proofs`: `w3_9_sbop_without_blank_line_does_not_panic` (seed committed) | — | none needed | `sbo-ch88` |
| W3-10 | Batch splitter computes `pos + Content-Length` unchecked (fuzz-found); `Content-Length: 18446744073709551615` wraps into a slice panic in release; one DA submission kills every node's sync task, and `/v1/submit` parses the same way. | `wire/parser.rs:75` | `ws3-wire`: `w3_10_huge_content_length_does_not_panic` (seed committed) | — | none needed | `sbo-ch88` |
| W5-2 | `/v1/dnssec?domain=` runs a live DNSSEC chain walk through the node's resolver for any caller and any domain (`needed_by` is caller-chosen). | `http.rs::dnssec_v1` | `authz`: `public_mode_dnssec_capture_refuses_a_foreign_origin`, `public_mode_flood_on_dnssec_hits_429` | — | **Q30 open** | `sbo-o2c0` |
| W5-3 | No route answers 429; 500 submits from one source all answer 200. | `http.rs` | `authz`: rate-limit cells (2) | — | Q15 (a) settled | `sbo-b4cx` |
| W5-9 | `/v1/submit` runs one live DNSSEC capture per issuer named by unverified presentation claims before any signature check (I2 class on the write path); a capture failure answers 500 before validation. | `main.rs:640-668` | new `AUDIT-2026-11 W5-9` test | — | none needed | `sbo-xqo2` |
| W7-1 | No CI existed; `[skip ci]` trailers and `make watch` were vestigial; only `ip-approval-gate` is required on `main`. **Closed during the audit**: `test.yml`, `supply-chain.yml`, `conformance.yml`, `fuzz-smoke.yml`, `dependabot.yml`. Residual: required checks (Q28). | `.github/` | gate runs | — | **Q28 open** (residual) | `sbo-9zs4` |
| W7-2 | 41 RUSTSEC advisories, 34 after reasoned ignores; 26 close with `cargo update`, 8 with W7-6; the gate is red on `main` until they land. | `Cargo.lock` | `supply-chain.yml` green | — | **Q26, Q29 open** | `sbo-bzp7` |
| W7-6 | Unused `reqwest 0.11` in `sbo-core` is the sole holder of rustls 0.21, webpki 0.101, webpki-roots 0.25, hyper 0.14, h2 0.3 (8 advisories, no upgrade path). | `crates/sbo-core/Cargo.toml:23` | `supply-chain.yml` green | — | **Q26 open** | `sbo-bzp7` |
| W7-8 | mingo `deploy-daemon.yml` pins every action by mutable tag with `packages: write` and the dokku key (browserid-ng W7-2 class, same SHAs). | `~/src/mingo/.github/workflows/deploy-daemon.yml` | — | — | none needed | `sbo-ju44` (mingo) |
| W7-12 | Daemon container runs as root; `/data` holds the checkpoint and attestor secret keys, state and the socket; any RCE is uid 0 (browserid-ng W7-8 class). | `~/src/mingo/deploy/sbo-daemon/Dockerfile` | — | — | **Q27 open** | `sbo-33xa` (mingo + infra) |

### Low

| # | Finding | Where | Acceptance | Decision | Bean |
|---|---|---|---|---|---|
| D14 | URI parser mis-splits an id containing `:` (`role:mod` → creator `role`); the Core spec's percent-encoding sentence contradicts its own `id_char` set (S23). July `sbo-zocd`. | `uri.rs:239-330` | `ws3-uri_identity`: `d14_colon_ids_round_trip_through_the_uri` | **Q37 open** | `sbo-jijr` |
| D15 | Trust gate bounds the wait (`timeout_blocks`) but stops sync rather than degrading; the spec's fallback is unimplemented. July `sbo-zocd`. | `trust.rs`; `main.rs:1690-1700` | `d-ws4`: `d15_enforcing_gate_stays_gated_without_claims` (extend) | none needed | `sbo-prqd` |
| D24 / W6-3 | `require_payload_signed_by` denies every payload today (`/sys/domains/<d>` without a trailing slash fails `Path::parse`); behind that it only pattern-matches the issuer string and never verifies the JWT signature. Medium once the path is fixed. | `policy/evaluate.rs:253-300` | `core-ws6`: `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer` | none needed | `sbo-qfvj` |
| D30 / W6-1 | Both ed25519 wrappers use non-strict `verify`: the identity point as a public key with `R = identity, S = 0` verifies every message (self-inflicted; the one place a strict verifier elsewhere would disagree). Non-canonical `S` is rejected (refuted half). | `sbo-core/src/crypto/ed25519.rs:61`; `sbo-crypto/src/ed25519.rs:70` | `core-ws6`: `w6_1_small_order_public_key_universal_signature_is_rejected`; runners ED-REJ-04 | **Q32 open** (lands with D2) | `sbo-cusw` |
| D34 | `bootstrap.rs` names the checkpoint authority (`sys-checkpointer`) while `trust.rs` pins keys; two trust models, no shared value. | `bootstrap.rs:24`; `trust.rs:56-64` | `d-ws4`: `d34_legacy_authority_name_is_not_a_pinnable_key` (passes; inverts with the fix) | Q12 (a) settled | `sbo-syib` |
| W2-1 | `sbo-types` grammar (re-exported as `sbo_core::Id`, used by the zkVM guest) rejects `@ + :` and case-folds actions, admitting `create`/`update`; 13 vectors differ from the wire grammar. | `sbo-types/src/id.rs:30`, `action.rs:30` | runners (types) 13 entries; `ws3-uri_identity`: `sbo_types_id_is_subset_of_core_id` flips | **Q36 open** | `sbo-nepw` (blocked by `sbo-lv2x`) |
| W2-4 / S18 | Checkpoint `state_root` is `sha256:<hex>` in the spec, bare hex in `trust.rs`; a spec-shaped checkpoint never counts as a backer. | `trust.rs:91-103` | runners CP-01, CP-03 | **Q34 open** | `sbo-mux6` |
| W4-1 | O(n) attestation scan per attested condition per write. | `validate.rs:2086` | with D11 | none needed | `sbo-slsm` |
| W4-3 | `sbo-capture` builds a default `reqwest` client (redirects followed) for the operator-chosen IdP base URL (browserid-ng D15 class, no attacker steering). | `sbo-capture/src/lib.rs:83` | — | none needed | `sbo-hs4r` |
| W5-6 | `/v1/sync-points` and `/v1/snapshot` skip the read gate: a provisional node serves a manifest derived from unverified state to the next bootstrapper. | `http.rs` | `authz`: read-gate cells | Q15 (a) settled | `sbo-b4cx` |
| W5-7 | `submit` ignores the read gate: while gated it validates against provisional state, stages and pays. | `main.rs::submit` | `authz`: read-gate cell | Q15 (a) settled | `sbo-b4cx` |
| W5-10 / D37 | Any `GET /auth` creates a pending sign request that never expires; the 64-bit id is the bearer the status route releases the assertion to. XSS, open redirect and id-entropy halves refuted. No caller in sbo or mingo. | `http.rs::auth_popup_page`, `::get_auth_status` | `d-ws5`: `auth_popup_pending_requests_are_bounded` | **Q31 open** | `sbo-d9pn` |
| W6-2 | `dnssec-prover 0.6.8` has no Ed25519 (alg 15): a primary domain signed with alg 15 can never be attributed (fail closed, availability only). | `dnssec-prover/src/validation.rs:131` | — | with Q3 | `sbo-evne` |
| W7-3 | `avail-rust` is a git dependency on `branch = "main"` in three manifests; every `cargo update` silently moves the DA client. | `crates/{sbo-rpc,sbo-daemon,sbo-cli}/Cargo.toml` | `deny.toml` sources | **Q29 open** | `sbo-bzp7` |
| W7-4 | `browserid-core` pinned at two revs (`b83cce1` in sbo-core, `2582555` in sbo-capture/sbo-cli): two copies compiled. | three manifests | — | none needed | `sbo-bzp7` |
| W7-5 | `sbo-daemon config init` writes `config.toml` (holding the TurboDA key) at umask 0644; key files are never mode-asserted on load. | `config.rs:369,498` | `d-ws7`: `w7_5_sample_config_holding_the_turbo_da_key_is_owner_only` | none needed | `sbo-hs4r` |
| W7-9 | Deploy workflow `ssh-keyscan`s the dokku host on every run (TOFU per run). | mingo `deploy-daemon.yml` | — | none needed | `sbo-ju44` (mingo) |
| W7-11 | Floating base-image tags; 7-hex `SBO_REV` clone at build. | mingo `Dockerfile:37,45` | — | none needed | `sbo-ju44` (mingo) |
| W7-13 | The auth request id (the D37 bearer) is logged at `info`. | `http.rs:633, 824` | — | **Q31 open** | `sbo-d9pn` |
| W7-14 | `-d save-raw-block` writes to the fixed, symlink-followable `/tmp/sbo-debug` (debug flag only, never on in the deployment). | `rpc.rs:243` | — | none needed | `sbo-hs4r` |
| I24 | `Hlc::within_bound` arithmetic panics on overflow in debug. | `hlc.rs:66` | `ws3-time_scopes`: `i24_hlc_bound_arithmetic_is_checked` | Q9 (a) settled | `sbo-wc85` |

### Info

| # | Finding | Bean |
|---|---|---|
| D8 | zkVM guest proves a trie transition over some data: `_actions_hash` discarded, witnesses never derived from `actions_data`, zero data root on `header_data: None`, any first `prev_state_root` trusted (Critical as a trust claim; July `sbo-5rww`). Q19 (a): experimental, no trust claim this round. D49 guest arithmetic unreached. | `sbo-35bs`, `sbo-a90r`; `sbo-5rww` kept as the deferred tracker |
| D32 | `Auth-Warrant` is parsed, serialized and signed but never consumed (S1). | `sbo-xs2u`, `sbo-hzb0` |
| D39 | DA read path: zero block hash, "app data not available" advances the height, no chain-id cross-check. Q20 (c): the Avail light client verifies finality and availability itself; Avail is replacing it (July `sbo-7bl8`). | `sbo-wn15` (deferred); `sbo-7bl8` kept |
| W3-5 | `sbo-crypto/src/merkle.rs` is dead code with a prover/verifier mismatch. | `sbo-db6p` |
| W3-11 | Identity and domain JWT claim types are mutually decodable (confused object, not a forged one). | `sbo-qfvj` |
| W4-2 | `bootstrap.rs` doc comment claims a policy-version hash check that does not exist. | `sbo-syib` |
| W6-5 | No offline DNSSEC fixture or synthetic chain builder exists; every DNSSEC path is covered only by ignored live tests. | `sbo-ospt` |
| W7-7 | `sbo-zkvm-methods` has no `license` field. | `sbo-bzp7` |
| W7-10 | Image also tagged `:latest`; GHCR package public by necessity (no secrets in it). | `sbo-ju44` (drop `:latest` if unused) |
| Q40 | `scopes_authorize([])` is `true`: an empty warrant scope list authorizes everything; nothing emits one today. | `sbo-hcqt` (**Q40 open**) |

### Spec-only items

Settled 2026-11-04 and carried by one spec-edit bean per document:
Authorization `sbo-xs2u` (Q1/S1, S2, Q38, Q40), Wire Format `sbo-hzb0`
(Q4 eight rules, S2, Q32, S21, S22), Core `sbo-x2a5` (Q13, Q24, Q37, S20),
Identity `sbo-uji1` (Q5/S6, Q6/S7, T1-operator sentence), Policy
`sbo-skvm` (S12, Q17, Q38, Q39), Genesis `sbo-jh9c` (Q7/S8, Q8/S9, Q33,
Q35, Q2/S3, S19), State Commitment `sbo-3bme` (Q18, D4, W3-4, Q34),
Content `sbo-whtm` (Q9/S10), Bridge `sbo-a8he` (Q10/S11), Indexer & Client
`sbo-4rc3` (S17, hostile-indexer text), Attribution `sbo-mwz9` (Q1, Q3,
Q16), ZK design doc and READMEs `sbo-a90r` (Q19). Code sides of S13, S14,
S19, S22 are in the ledger above.

## 2. Refuted leads

Recorded so the reasoning is on record; no action.

- **D20 `RepoRemove` arbitrary delete.** It removes `repo_dir_for_uri(..)`
  under the daemon's own state dir (`repo.rs:207-211`), never the
  caller-supplied mirror path. The socket-mode half stands (W5-8).
- **D22 arithmetic overflow.** `validate_collection` rejects negative lags,
  `saturating_mul` plus a non-negative `t_b` keep `within_bound` inside
  `i64`. The unbounded-`W` half stands.
- **D37 XSS, open redirect, id entropy.** `html_escape` covers the five
  characters and the value lands in text and a double-quoted JS string; no
  handler redirects, and `postMessage` to the opener-supplied origin is the
  browser's own same-origin check; the id is 64 random bits (I35's floor).
  The never-expiring request half stands (W5-10).
- **D24 forged issuer as a takeover.** The restriction denies every payload
  today (W6-3), the live root policy does not use it, and the anti-hijack
  rule uses browserid attribution; the hole is real but masked (Low until
  the path bug is fixed).
- **D30 non-canonical scalar.** ed25519-dalek 2.2 rejects `S + L` in both
  wrappers (`i7_non_canonical_scalar_is_rejected_by_both_wrappers`,
  `non_canonical_s_is_rejected_by_both`, ED-REJ-03). Only the small-order
  key stands (W6-1). The two wrappers return identical verdicts on every
  vector (I7 holds).
- **D3 silent mutation of a signed field.** Every unmodelled header is in
  the canonical signing order, so a signer that covered one fails to verify
  after the parser drops it; raw and reserialized hashes agree for every
  canonical message including the live genesis. What remains is D2 plus the
  Q32 spec conflict (Medium, partial).
- **D51 RFC 9102 bytes crash `dnssec-prover`.** 3.8M fuzz executions: no
  panic, no spurious `Ok`.
- **D49 zkVM guest arithmetic.** Not reached: the guest needs the risc0
  toolchain and is scoped out (Q19).
- **D41–D48.** Refuted on reading: creator-string matching is guarded by the
  creator-integrity check; `Path::parse(..).unwrap()` in policy evaluation
  only sees validated paths; the zero-root sentinel in `PartialTrie::new`
  is unreachable for a non-empty state.
- **WS5 surface leads.** Unbounded submit body (axum's 2 MiB default limit:
  3 MiB answers 413); `?repo=` reaching another repo's credentials
  (`resolve_repo` selects among followed repos only); `sbo://` TXT `node=`
  SSRF from HTTP (`dns.rs::resolve` is reached only from the CLI and IPC);
  plain-http status URI (refused before any connection); status fetch
  without on-chain authority evidence (fails closed before any connection);
  IPC framing wedge (a malformed line is answered and the connection
  survives); outbound Avail/TurboDA targets steerable by a request
  (endpoints come from `config.toml` only).
- **W4-4 keyring permissions.** Directory 0700, files 0600, atomic rename
  (`keyring_files_are_owner_only`, `keyring_directory_and_key_files_are_owner_only`).
- **I26 LWW total order; I7 wrapper agreement; batch rules 1, 2, 3, 5 of
  Q4.** All hold today (WS3 properties, WS2 B-01..B-06).

**Re-verified and pinned** (passing tests, by workstream): signature covers
every modelled header; JWT `alg` pinned to EdDSA and signature length to 64;
envelope key must equal the access-cert key; grantee and grantor issuers
must be their domain or a pinned broker; inclusion time outside the DNSSEC
window rejects; wrong audience rejects; `as:` must name the grantor, appear
once and travel with a `path:` scope; a delegated grant whose grantor
issuer has no evidence fails closed; config cert for `alice@d` covers
`alice+bot@d` (WS6 §3). Deny beats grant; a grant is necessary and
sufficient; restrictions narrow exactly; descendant constraints are
byte-exact narrowings; an undefined `$owner` fails closed; the action
lattice; the attribution window is the intersection of every DNSSEC window;
expiries are judged at `authored_at` never the wall clock; the audience
rule; URI render/parse fixed point; trie proofs sound and complete; witness
matches the rebuilt root; SCALE compact decoding inverts a reference
encoder (WS3 §2). sbo-core and sbo-wasm agree on all 37 wire vectors; the
kit reproduces the canonical vector byte for byte; all four trie
implementations agree on every root (WS2 §3). Default `W` rejects an
hour-old authoring instant; an in-force ban rejects on a healthy read; an
enforcing anchor stays gated until pinned keys vouch (WS4 §3). Reads open
to every principal; 2 MiB body cap; IPC survives a malformed line (WS5 §5).
TurboDA, checkpoint and attestor secrets reach the container only through
dokku env and are written 0600; keyring 0700/0600 (WS7 §5).

## 3. Cross-implementation disagreement (WS2)

135 vectors, 8 suites, 5 runners (sbo-types, sbo-crypto, sbo-core,
sbo-wasm, sbo-daemon), all green in CI with `EXPECTED_FAIL` tables. Genuine
disagreement, where two implementations in the repo return different
verdicts today, exists in exactly four places:

| Vectors | Disagreement | Finding |
|---|---|---|
| ID-OK-03..06, PATH-OK-03, ACT-REJ-01..04 | `sbo-types` (the zkVM guest's grammar) rejects every email-rooted and agent identity sbo-core accepts, and admits `create`/`update` as actions | W2-1 (Q36) |
| LWW-06..08 | `overlay_wins` lets an HLC-less pending write beat the chain; `lww_admits` and `pending_still_wins` do not | W2-2 / D17 (Q25) |
| POL-01 | the tip view serves a pending policy object that tip validation does not enforce | W2-3 / `sbo-y757` (Q25) |
| CP-01, CP-03 | spec-shaped `state_root: sha256:<hex>` checkpoints are not claims | W2-4 / S18 (Q34) |

Everything else the vectors flagged is the stack agreeing with itself
against the spec: D1 (W-CH-01), D2 (W-ORD/DUP/CL/HEX/INJ), D3 (W-OK-05 and
nine `object_hash` vectors), D4 (TRIE-03 across all four trie
implementations), D13/D54 (identity suite), D21 (dot segments in all three
grammars), D28 (TIME-01: the same chain data admits a banned writer on a
node without the block timestamp), D30 (ED-REJ-04 small-order key in all
three wrappers). sbo-core and sbo-wasm are the same source compiled twice
and agree on every vector; batch rules 1, 2, 3 and 5 of Q4 hold today.

## 4. July 2026 re-verification

Every open lead of the 2026-07-08 review (`sbo-ix77`) was re-checked at
`30e267c`. All twelve are still present; two July fixes held.

| July bean | Then | Now | Carried as |
|---|---|---|---|
| `sbo-d5nm` Content-Hash never verified | Critical | **Still open**, now compounded by P2 pins keyed on the claimed hash; PoC | D1 → `sbo-xd6u` |
| `sbo-9d7l` genesis unimplemented / fail-open / hash advisory | Critical | **Still open**; `verify_genesis` exists but its error is discarded; PoC | D5 → `sbo-3q6x` |
| `sbo-5rww` zkVM proves no validity | Critical | **Still open**; scoped out by Q19, marked experimental | D8 → `sbo-35bs`; bean kept, deferred |
| `sbo-h75z` signature over reconstruction | High | **Still open**: order, duplicates, `+N`/`00N`, uppercase hex, non-strict verify all reproduced | D2 → `sbo-cusw` |
| `sbo-bynl` circular roles | High | **Still open**; `Any` nesting adds a second recursion; child-process crash PoC | D10 → `sbo-sla3` |
| `sbo-7bl8` DA trusted from RPC; KZG stub | High | KZG half **still open** (`Ok(true)` reproduced); DA half **accepted risk** (Q20: the light client verifies finality and availability; Avail is replacing it); finality-gated *submission* landed (f2fdb9f) | D9 → `sbo-db6p`; D39 → `sbo-wn15`; bean kept, deferred |
| `sbo-3gqo` self-cert warn-only | High | **Still open** on the warn-only half; the "refresh shadows genesis evidence" half is closed by global uniqueness (evidence read from the object's own `ref:` or the single slot) | D7 → `sbo-c46r` |
| `sbo-2tue` object_hash over re-serialized bytes | High | **Partial**: identical for canonical input (live genesis pinned); differs only on D2 inputs; spec conflict Q32 | D3 → `sbo-xypz` |
| `sbo-y5ek` pinned root KSK decorative | High | **Still open**; the library has no anchor injection and no alg 15; no offline fixture exists to test it | D6 → `sbo-evne` (fixture `sbo-ospt` first) |
| `sbo-hedq` trie domain separation | High | **Still open**; root collision demonstrated; plus W3-4 prefix eviction | D4 → `sbo-39qi` |
| `sbo-4arq` bare-key owners | High | **Still open**; Dan widened the fix to full removal (Q6) | → `sbo-yd72` |
| `sbo-rx1z` bridge unimplemented | High | **Still open**; spec to be marked aspirational (Q10) | S11 → `sbo-a8he` |
| `sbo-zocd` medium roundup | Medium | Policy-Ref, not_attested fail-open, normalization, URI decoding, trust-gate liveness, legacy owner fallback, bootstrap-proof anchor, KZG: **all still open** | D12 `sbo-mlyp`, D11 `sbo-slsm`, D13 `sbo-3ao9`, D14 `sbo-jijr`, D15 `sbo-prqd`, Q6 `sbo-yd72`, D26 `sbo-syib`, D9 `sbo-db6p` |
| `sbo-0web` docs / spec drift | Normal | **Still open**; superseded by the spec-edit beans; stub APIs under D5; T1-operator sentence under Identity | `sbo-3q6x`, `sbo-uji1`, `sbo-lv2x` |
| `sbo-y757` reads vs validation policy | Normal | **Still open**, reproduced in-process (POL-01) | W2-3 → `sbo-5fja` |
| `sbo-hy4r` mempool order divergence | High, in progress | Partially addressed (finality-gated batching); overlay wobble carried as D17, ordering gap stays here | `sbo-5fja` + `sbo-hy4r` |
| `sbo-vos1` unprivileged policy install | High | **Fixed** (4b28d8e, `govern`); re-verified by reading `require_govern` and the existing shadowing test | — |
| `sbo-4tka` `/u/` attested lookup | High | **Fixed** (b6ac8ba); `attested_subject_matches` scans by schema regardless of path | — |

The July epic `sbo-f5wn` is closed; its scrapped children name their
successor bean and every unchecked July item is carried in that bean's
checklist. **Pattern.** July fixed call sites that were in scope and left
the spec's enforcement promises (Content-Hash, genesis, self-cert, anchor)
as beans; none of those beans moved in four months while the policy and
attribution layers grew on top of the unenforced base. This pass encodes
each promise as a test per layer so the next regression fails CI.

## 5. Remediation order

Criticals and Highs first inside each group; groups ordered so one change
closes several tests. Beans are parented to `sbo-ax7t`; `blocked-by`
relations are set where a fix depends on another. `draft` beans wait on
the named decision in `docs/security-audit-2026-11-decisions.md`.

1. **Wire integrity (Q32 first).** D1 `xd6u` (Critical, PoC done, no
   blocker: land first) → canonical-bytes helper `zom8` (Q32) → D2/W6-1
   `cusw` → D3/Q35 `xypz`. Parser robustness W3-6/8/9/10 `ch88` (two
   fuzz-found DoS) needs no decision and lands beside D1.
2. **Bootstrap and anchors.** D7 `c46r` (no blocker); fixture `ospt` →
   D6 `evne` and D33 `uv8a`; D5/D23 `3q6x` (Q33) with the regenesis;
   fast-sync D26/D27/D34 `syib`.
3. **State-commitment v2 + regenesis bundle** `eefz` (Q33, Q39): D4/W3-4
   `39qi`, D3 `xypz`, owner fast-path D57 `2jtp`, bare-key removal Q6
   `yd72`, strict policy parse W3-3 `zzx7`, genesis reorder `3q6x`,
   brokers shape and self-cert requirement (in the Genesis spec bean
   `jh9c`). Survey app 506's policies before cutting over.
4. **Chain-wide DoS.** D10 `sla3` (no blocker); glob matcher W3-1/W3-2
   `0qqq` (Q38); inflate caps D50/W5-5/W3-7 `q11b`.
5. **Policy enforcement in the daemon.** D56 `hw7b`; D11/W4-1 `slsm`; D12
   `mlyp`; D22/I24 `wc85`; D28 `zyny` (Q23); D17/W2-2/W2-3 `5fja` (Q25);
   D15 `prqd`; D24/W3-11 `qfvj`.
6. **Identity rule.** helper `lv2x` → D13/D54 `3ao9` → grammar W2-1 `nepw`
   (Q36); D14 `jijr` (Q37); mirror D21/D58 `vu8s` (Q24).
7. **HTTP and IPC surface.** public mode W5-1/W5-3/W5-6/W5-7 `b4cx`
   (High, no blocker) → infra X-Forwarded-For `9oq0`; SSRF/capture
   D18/W5-9 `xqo2`; `/v1/dnssec` W5-2 `o2c0` (Q30); auth popup
   W5-10/W7-13 `d9pn` (Q31); IPC D20 `e4z9` (Q22); checkpoint form W2-4
   `mux6` (Q34); empty scopes `hcqt` (Q40).
8. **Supply chain and operations.** `bzp7` (R7-1/R7-2/W7-3/W7-4/W7-7; Q26,
   Q29; turns the gate green) → required checks `9zs4` (Q28); mingo
   workflow pins W7-8/9/11 `ju44`; non-root container W7-12 `33xa` (Q27,
   blocked by public mode so the healthcheck lands on the new config);
   host hygiene W7-5/W7-14/W4-3 `hs4r`; D9/W3-5 `db6p`; zkVM experimental
   `35bs` + `a90r`; fuzz cadence `kcyq`.
9. **Spec edits** (one bean per document, §1 "Spec-only items"): land the
   settled parts now, the Q22–Q40 parts as each decision arrives.

Before deploying anything from groups 1, 3 or 7, re-sync a scratch node
from app 506 on localtest and compare its state root with da.sandmill.org's;
group 3 changes the root by design and ships only with the regenesis.

## 6. Remediation status (2026-11-05)

Dan accepted every recommendation for Q22–Q40 on 2026-11-05 (Q32 revised to
(c), sign-what-was-sent, after discussion; Q41, the empty-state root,
surfaced during remediation and was decided (a) the same day). The
remediation landed on `audit-2026-11` the same day in two waves of
file-disjoint agent groups, each in its own worktree, merged by the
coordinator with a full workspace run after every merge.

**Landed in this repository (54 remediation beans + 13 spec-edit beans,
all `completed`):** wire integrity (D1, D2, D3, W3-6/8/9/10, W6-1, Q32,
Q35); identity rule and one grammar (Q5, D13, D54, Q36, D14, D21/D58);
policy engine (D10, W3-1/W3-2, Q38, Q40, D24, D9/W3-5); daemon HTTP/IPC
surface (W5-1/3/6/7, Q15, Q30, Q31, D18/W5-4/W5-9, D50/W5-5/W3-7, Q22,
W7-5/W7-14/W4-3, Q34); daemon policy enforcement (D56, D11/W4-1, D12,
D22/S10, Q23, Q25, D15); bootstrap anchors and fast-sync (D7, W6-5, D6/S4,
D33/Q16, D26/D27/D34); state-commitment v2 (D4/W3-4, Q41); the regenesis
bundle's sbo side (W3-3/Q39, Q6, D57/Q13, D5/D23/S19/Q7/Q33); supply chain
(Q26/Q29, R7-1, R7-2, W7-3/4/7); all spec edits (§1 spec-only items and the
decided parts of Q1–Q41).

**Test state:** `cargo test --workspace` on localtest: 663 pass / 0 fail /
6 ignored (was 518 / 0 / 94 at audit close). The six remaining ignores are
generators and live-network tests (`generate_conformance_vectors`,
`write_mingo_genesis_v6_fixture`, `capture_browserid_chain_to_file`,
`live_capture_*`) plus `poc_d10_inner_evaluate_cycle`, which pins the inner
evaluator and is superseded by the parse-time rejection. Every
`AUDIT-2026-11` acceptance test is un-ignored and passing; every WS8 PoC is
inverted to assert rejection. `cargo audit` and `cargo deny check` are
green (one new advisory, RUSTSEC-2026-0344, ignored under the Q19 rule with
review 2027-02-01). The fuzz workspace builds on nightly against the
vendored `dnssec-prover`.

**Not done here (open beans):** the mingo-side regenesis (`sbo-eefz`,
in-progress: genesis v7 batch, app 506 policy survey, da.sandmill.org
re-sync; builder requirements are on the bean); infra beans that execute
in mingo, sandmill-infra or GitHub settings (`sbo-33xa` with the deploy-time
config changes, `sbo-ju44`, `sbo-9zs4`, `sbo-9oq0`); the launchd fuzz job
(`sbo-kcyq`); deferred `sbo-5rww`, `sbo-7bl8`, `sbo-wn15`; the Q37 route-2
spec note (`sbo-8j2t`, draft).

**Behaviour changes a deployer must know** (also on `sbo-33xa` and
`sbo-eefz`): HTTP public mode is derived from a non-loopback bind and needs
`SBO_HTTP_ALLOWED_ORIGINS` and `SBO_HTTP_BEARER_TOKENS`; `/v1/dnssec` and
the `/auth` popup are gone; the live root policy's `/sys/names/*` grant
matches nothing under the container-only rule; bare-key owners and the
signer fallback are gone, so every write carries an `Owner`; the state root,
`object_hash`, the trie format and the empty root all change, and the
genesis batch order is strict, so the live chain needs the regenesis before
this daemon serves it; the filesystem mirror layout is `<seg>.d/`;
`dnssec-prover` is vendored under `vendor/` with one added function; a
fast-synced node no longer authorizes under a superseded pinned policy
ancestor (needs full replay; follow-up noted on `sbo-syib`).
