<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS8: proof-of-concept demonstrations

**Status:** complete, 2026-11-04. Epic `sbo-ax7t`, bean `sbo-cka2`. Scope:
a working PoC for every post-verification High/Critical handed over by WS4
(`-ws4-layers.md`), WS5 (`-ws5-http-surface.md`) and WS6 (`-ws6-crypto-core.md`),
plus the WS1 ordering list (`-ws1-threat-model-spec.md` §6).

**Rules honoured.** Every PoC runs against an in-process harness or a loopback
listener this test opens itself: a `StateDb` in a tempdir, `validate_message`
and the policy evaluator called directly, `bootstrap` against an in-process
axum server, and the daemon HTTP router against a mock `RepoApi`. No production
host, no Avail, no TurboDA, no real keys; the DA spend is a counter. No
production code or spec changed.

**Where the PoCs live.** `#[ignore]`d so CI does not run them; run with
`cargo test -p sbo-daemon --test audit_2026_11_poc_core --test
audit_2026_11_poc_fastsync --test audit_2026_11_poc_http -- --ignored`.

| Test file | PoCs | Result on localtest |
|---|---|---|
| `crates/sbo-daemon/tests/audit_2026_11_poc_core.rs` | D1, D1/P2, D5/D23, D7, D21, D58, D10 | 8 pass (reproduced) |
| `crates/sbo-daemon/tests/audit_2026_11_poc_fastsync.rs` | D26 (unit + end-to-end), D27 | 3 pass (reproduced) |
| `crates/sbo-daemon/tests/audit_2026_11_poc_http.rs` | W5-1 (preflight + spend path) | 2 pass (reproduced) |

Unlike the WS4/5/6 acceptance tests (which assert the *fixed* behaviour and
fail today), a WS8 PoC asserts the *broken* behaviour and passes today; when a
fix lands, the matching acceptance test flips to green and the PoC assertion
inverts — intentional, so a reader is never shown a green PoC of a closed hole.

## 1. PoCs built and reproduced

### P1 — D1 payload swap on a signature-valid envelope (Critical)

`poc_d1_payload_swap_is_accepted_by_the_daemon_gate`. A victim signs
`{"amount":1}`; a relay keeps the headers and signature and substitutes
`{"amount":9}` (same length, so `Content-Length` still matches). Measured:
the 12-byte body is swapped under an untouched signature;
`verify_message` returns `Ok`, and the daemon's full `validate_message`
returns `Valid`. Any party on the path between signer and chain — the DA
layer, a node, a browser extension — rewrites a signed write's content.

### P1b — D1 + P2 pin confusion (Critical, compounding)

`poc_d1_policy_version_filed_under_a_mismatched_hash`. A `policy.v2` write
whose body grants `{to:"*", can:["*"], on:"/**"}` carries a header
`Content-Hash` equal to a *benign* policy's hash. `verify_message` accepts the
mismatch (the header hash is never checked against the body), and the daemon
indexes policy versions by that header hash (`sync.rs:1240`). So a hostile
policy body is filed under the hash a child policy pinned (P2): the pinned,
"frozen" governance a community relies on resolves to all-grants. The PoC
asserts the mismatch is accepted and that the bodies genuinely differ.

### P2 — D5 / D23 stranger takeover of a root-policy-less repo (Critical)

`poc_d5_stranger_takes_over_a_rootless_repo`. On an empty state (no
`/sys/policies/root`), a stranger's `policy.v2` at `/sys/policies/root`
granting everyone everything is `Valid`, and so is a stranger's post into
`/communities/cooks/posts/`. This is the submit-gate and replay behaviour of a
node pointed at a forged seed or a wrong anchor, or any node before genesis
replays: genesis mode is accept-all. Combined with the non-fatal
`genesisHash` mismatch (WS4/WS6 D5), a forged seed keeps syncing.

### P3 — D7 failing self-cert domain certifies sys (High)

`poc_d7_failing_self_cert_domain_is_accepted`. A `/sys/dnssec/evil.example`
`dnssec.v1` object carrying garbage ("not-a-proof") is written, then a
`domain.v1` for `evil.example` referencing it is `Valid` — `validate_message`
never reads the evidence (the self-cert check is a post-write `warn!` in the
sync path). A domain whose DNSSEC self-certification cannot verify is admitted
and can go on to certify `sys` (Mode B), i.e. become a forged trust root.

### P4 — D21 filesystem-mirror escape, and D58 collision stall (High)

`poc_d21_path_dotdot_escapes_the_mirror` replicates `write_object`'s mirror
join verbatim (`sync.rs:1104-1112`). `Path::parse("/../")` and `Id::new` admit
dot segments, so the join `repo_mirror / ".." / "pwned"` writes `pwned` as a
**sibling of the repo directory**, outside the mirror (measured: the written
file canonicalises to `root/pwned`, and `!starts_with(repo_mirror)`). More
`..` climb further. The write runs as the daemon's user at a location the
on-chain writer chooses.

`poc_d58_id_collection_collision_blocks_the_mirror` shows the companion: once
`/c/x` exists as a file, `create_dir_all` for `/c/x/y` errors
`AlreadyExists` — the `?` at `sync.rs:834` that aborts `process_block`
mid-block on this node (a one-node fork from an unprivileged write wherever a
`create` grant exists).

### P5 — D26 / D27 hostile serving node (High)

- `poc_d26_authority_backs_a_forged_root_with_no_checkpoint`: under the
  default trust policy `{[sys-checkpointer], 1}`, `evaluate_trust` returns
  `Some(1)` for a root the attacker invented at height 999,999 with **no**
  `checkpoint.v1` object — the authority "backs" anything.
- `poc_d26_hostile_node_root_adopted_end_to_end`: an in-process axum node
  serves a `/v1/sync-points` manifest and a gzip `/v1/snapshot` it built;
  `bootstrap` adopts the node's asserted root, loads its objects, and reports
  `OnChainCheckpoint`/`ServingNode` trust — the serving node alone chose the
  client's state.
- `poc_d27_forged_policy_version_loads_into_a_fast_sync_client`: the honest
  object set reconstructs the advertised root (so the root check passes), and a
  forged `(hash, all-grants policy)` whose key is **not** that policy's content
  hash is loaded by `verify_and_load_payload` and retrievable under the pinned
  hash. The doc comment claims a content-hash check that does not exist.

### P6 — D10 role-cycle crash (High)

`poc_d10_role_cycle_crashes_the_evaluator` re-execs the test binary at an
inner helper that evaluates a grant to `role:a` under a policy with
`a → b → a`. The child terminates abnormally (stack overflow); the parent
asserts the non-zero exit. A cyclic-role `policy.v2` on chain crashes every
node that evaluates a write it governs — a deterministic, chain-wide DoS a
`govern` grantee (or anyone, before D5 is fixed) can plant.

### P7 — W5-1 cross-origin submit against a public bind (High)

- `poc_w5_1_cross_origin_preflight_is_allowed`: the CORS preflight for a
  cross-origin `OPTIONS /v1/submit` from `https://evil.example` succeeds and
  carries `Access-Control-Allow-Private-Network: true`.
- `poc_w5_1_foreign_origin_submit_reaches_the_spend_path`: the real
  foreign-origin `POST /v1/submit` reaches `RepoApi::submit` (a mock counts one
  invocation with the posted body length). On the deployed `0.0.0.0:5000`
  bind, any page a user visits spends the node's TurboDA credit for a write the
  repo admits. The spend is counted, never performed.

## 2. Candidates demonstrated in-process by their owning workstream (not re-built)

| Finding | Where it is already shown | Why WS8 did not rebuild it |
|---|---|---|
| D2 duplicate/reordered-header malleability | WS6 `d2_*` (parse differential), WS2 cross-impl vectors | a cross-parser differential is a vector-suite job, not a live PoC; the live effect reduces to D1's acceptance of non-canonical bytes |
| D4 trie root collision | WS6 `d4_leaf_and_internal_node_hashes_are_domain_separated` | demonstration only (no attacker-chosen 32-byte leaf exists; it is a SHA-256 preimage) |
| D18/W5-4 submit-gate SSRF | WS5 `status_fetch_never_dials_a_non_public_address` (dials a loopback listener) | the dial is already observed in-process; an end-to-end form needs a live DNSSEC zone (heavy), and WS5 rated it Medium |
| D50/W5-5 snapshot gzip bomb | WS5 `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it` (254 KiB → 768 MiB peak, counting allocator) | the inflate is already measured in-process |
| D57 owner fast-path past deny/ban | WS4 `d57_*` | pure `validate_message` assertions; no live instance adds anything |
| D22 unbounded `W` | WS4 `d22_collection_w_is_capped_by_a_protocol_maximum` (50-year-old authoring instant admitted) | `validate_message`-level, already shown |

## 3. Refuted / not reproduced

| Attempt | Outcome |
|---|---|
| D23 → measurable TurboDA spend on a rootless repo end-to-end | The accept half is P2; the spend is downstream of `submit()`, which needs the private `DaemonState`. P7 measures the spend reach via the router + mock; wiring a live `DaemonState` with a mock submitter adds no information and was not built. |
| D21 escape through the full `SyncEngine::write_object` | `write_object` is private and needs an `LcManager`/`RpcClient`; the PoC replicates its exact join instead, which is a faithful reproduction of the vulnerable line. The grammar-accepts-dot-segments root cause is pinned by WS4's core test. |

Nothing listed as a PoC target was refuted as a finding; the two rows above are
scope/packaging notes, not severity changes.

## 4. Severity changes

None. Every PoC confirms the WS4/5/6 post-verification severity. The two
Criticals (D1, D5) and the Highs (D7, D21/D58, D26/D27, D10, W5-1) all
reproduce as rated.

## 5. Q11 ordering note

Q11 (decided (b): PoC D1 before any fix) is satisfied — P1 and P1b demonstrate
the payload swap and the pin confusion against the daemon gate on the parent
commit, with no production change on the branch. WS9 can proceed to file the D1
fix bean; un-ignoring WS6's `d1_*` acceptance tests is its acceptance
criterion, and these PoCs should be updated to assert rejection at the same
time.

## 6. What needs Dan's decision

None from WS8. All PoCs confirm decisions already recorded (Q7, Q11, Q12,
Q13, Q15, Q17). No Q-item is appended.
