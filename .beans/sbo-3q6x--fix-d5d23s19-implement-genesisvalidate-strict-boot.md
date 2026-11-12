---
# sbo-3q6x
title: 'Fix D5/D23/S19: implement Genesis::validate, strict bootstrap, fatal genesisHash mismatch, no genesis mode'
status: completed
type: bug
priority: critical
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T11:26:02Z
parent: sbo-ax7t
---

**Critical.** `genesis.rs:13` is `todo!()`; while no root policy exists `validate_post` (`validate.rs:733,772`) accepts every post and every policy write from any key, at the submit gate too (D23); a `genesisHash` mismatch at the anchor only logs (`main.rs:1706-1733`); nothing enforces one genesis per anchor (S19). WS8 P2: a stranger plants an all-grants root and posts anywhere. July `sbo-9d7l`; also the `indexer::process_block` `todo!()` stub from `sbo-0web`.

Depends on: Q7 (a) settled; **Q33 (open)** for the batch shape. Blocked by: state-commitment v2 bundle (the live genesis is reordered there).

- [x] `Genesis::validate`: mode detection, object set, relative order, JWT signatures, same submission, first attempt wins
- [x] Call it at the anchor; mismatch or second genesis halts sync; a repo followed without an anchor scans for the first valid genesis
- [x] Remove genesis mode from `validate_post`/`validate_transfer`: with no root policy nothing is applied
- [x] Wire or delete the `indexer::process_block` stub
- [x] Acceptance (un-ignore): ws6 core `d5_genesis_validate_accepts_the_live_mode_b_batch` (re-read under Q33), `d5_genesis_validate_rejects_a_batch_without_a_root_policy`; ws6 daemon `d5_without_a_root_policy_*` (2); ws4 `d23_no_root_policy_rejects_ordinary_writes`, `d7_genesis_mismatch_is_reported_by_verify_genesis` caller acts on it

## Decision

Q33 decided (b) (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `crates/sbo-core/src/genesis.rs`: `Genesis::validate` / `validate_at(messages, inclusion_time, &TrustAnchors)` / `is_candidate`. Mode detection from the first message (`/sys/dnssec/<d>` → Mode B, `/sys/names/sys` → Mode A), the mode-object prefix in its relative order (A: sys, root; B: dnssec, domain, sys, root), each a signed `post` object with the right schema; JWT checks (self-signed sys with `sub: sys` and header key = payload key; self-signed `domain.v1` whose key is the `_browserid` provider key the `dnssec.v1` chain proves against the pinned root at the inclusion time — the same `extract_provider_key_with_anchors`/`check_domain_binding` the daemon's domain self-cert gate uses, so Mode B agrees with sbo-c46r; domain-certified sys with `iss: domain:<d>`); root policy signed by the sys key and parsing as a strict `policy.v2`; an `Owner`/`Creator` on a mode object may only name sys. Returns `GenesisInfo { mode, sys_key, sys_identity, prefix_len, root_policy }`. Unit tests: Mode A preset, wrong order / stranger / wrong signer / missing root, synthetic Mode B via `dnssec_fixture::SyntheticRoot` (window and key-binding negatives), Mode B without the dnssec opener.
- `crates/sbo-daemon/src/sync.rs`: `genesis_gate` per submission and repo. While `root_policy_present` is false: nothing before the anchor is applied; a block past an anchor with no genesis halts (`Err`); a submission that validates as a genesis and (when known) matches `expected_genesis` (hash over the submission bytes, Q35 (a)) has its prefix applied structurally (creator = sys identity, owner = `sys`), and the rest of the submission falls through to ordinary `validate_message` under the root policy it installed; a non-matching or invalid candidate is skipped (every message invalid). At the anchor with no known hash, a second structurally valid genesis with a different hash halts (ambiguous). At block end a repo whose anchor this is and that still has no root policy halts with `GENESIS FAILED` (covers the expected-hash mismatch). A repo followed without a hash records the accepted genesis via `set_expected_genesis`. Halting = `process_block` returns `Err`, which the sync loop treats as a stop-and-retry; it never advances the head.
- `crates/sbo-daemon/src/main.rs`: the non-fatal post-block genesis verification is removed (replaced by the gate above); `RepoCreate` refuses a genesis batch that does not pass `Genesis::validate`. `crates/sbo-daemon/src/validate.rs`: `validate_message` returns `Invalid` when no root policy exists (no genesis mode anywhere: posts, policy writes, `_config`, name claims, transfers); `root_policy_exists` plumbing removed.
- `crates/sbo-core/src/indexer.rs` (`Indexer::process_block` todo) deleted; `lib.rs` exports `Genesis, GenesisError, GenesisInfo, GenesisMode`.
- Fixtures: `mingo-genesis-v5.wire` stays only to pin its historical hash (`live_genesis_raw_and_reserialized_hashes_agree`); it is not a genesis under Q33 (b) (first message is the domain object, no dnssec opener, root last) and `d5_the_v5_live_batch_is_not_a_genesis_under_the_strict_window` pins that. New `mingo-genesis-v6.wire` (generator `audit_2026_11_genesis_v6_generate.rs`, test keys, Mode A): sys, root, then sys-checkpointer, trust/brokers (object form), and per community descriptor → `_config` → policy, every post-root write naming `Owner: sys`; hash `sha256:3cf23afe…`. Two layout findings for mingo's real v6 builder: (1) `_config` must precede the community policy (once the community policy governs the subtree it does not grant sys `govern`); (2) the root grant `on: "/sys/names/*"` never matches the `/sys/names/` container, so name claims are not admitted after genesis — the fixture uses `/sys/names/` as in the Genesis spec default. A Mode B fixture with test keys is not possible (needs a DNSSEC chain for a real domain); Mode B is covered by the synthetic-root unit test.
- Tests: core ws6 `d5_genesis_validate_accepts_the_v6_batch` (re-read under Q33 (b), replaces the live-Mode-B test), `d5_genesis_validate_rejects_a_batch_without_a_root_policy`, `d5_a_stranger_before_the_root_policy_breaks_the_genesis`; daemon ws6 `d5_without_a_root_policy_*` (2) un-ignored; ws4 `d23_no_root_policy_rejects_ordinary_writes` un-ignored; `d7_genesis_mismatch_is_reported_by_verify_genesis` still passes and the caller now acts on it (sync halts); WS8 `poc_d5_stranger_takes_over_a_rootless_repo` inverted; new daemon `audit_2026_11_genesis.rs` replays v6 through the two-step apply (prefix structural, rest ordinary) and checks a stranger cannot retake `/sys/names/sys`. Daemon tests that ran "in genesis mode" (no root policy, accept-all) now install an open root policy.
- Not covered by an automated test: the `sync.rs` halting paths themselves (need an LC/RPC harness); reviewed by reading.
- Regenesis bundle sbo-eefz: the live app 506 genesis fails strict mode (as Q7 anticipated), so the regenesis must use the new layout.
