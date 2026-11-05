---
# sbo-3q6x
title: 'Fix D5/D23/S19: implement Genesis::validate, strict bootstrap, fatal genesisHash mismatch, no genesis mode'
status: todo
type: bug
priority: critical
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Critical.** `genesis.rs:13` is `todo!()`; while no root policy exists `validate_post` (`validate.rs:733,772`) accepts every post and every policy write from any key, at the submit gate too (D23); a `genesisHash` mismatch at the anchor only logs (`main.rs:1706-1733`); nothing enforces one genesis per anchor (S19). WS8 P2: a stranger plants an all-grants root and posts anywhere. July `sbo-9d7l`; also the `indexer::process_block` `todo!()` stub from `sbo-0web`.

Depends on: Q7 (a) settled; **Q33 (open)** for the batch shape. Blocked by: state-commitment v2 bundle (the live genesis is reordered there).

- [ ] `Genesis::validate`: mode detection, object set, relative order, JWT signatures, same submission, first attempt wins
- [ ] Call it at the anchor; mismatch or second genesis halts sync; a repo followed without an anchor scans for the first valid genesis
- [ ] Remove genesis mode from `validate_post`/`validate_transfer`: with no root policy nothing is applied
- [ ] Wire or delete the `indexer::process_block` stub
- [ ] Acceptance (un-ignore): ws6 core `d5_genesis_validate_accepts_the_live_mode_b_batch` (re-read under Q33), `d5_genesis_validate_rejects_a_batch_without_a_root_policy`; ws6 daemon `d5_without_a_root_policy_*` (2); ws4 `d23_no_root_policy_rejects_ordinary_writes`, `d7_genesis_mismatch_is_reported_by_verify_genesis` caller acts on it

## Decision

Q33 decided (b) (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
