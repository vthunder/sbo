---
# sbo-bzp7
title: 'Fix W7-2/W7-6/W7-3/W7-4/W7-7/Q26/Q29: pin avail-rust by rev, cargo update, drop unused reqwest 0.11, one browserid-core rev'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:46:34Z
parent: sbo-ax7t
blocking:
    - sbo-9zs4
---

**Medium.** 34 RUSTSEC advisories after ignores: 26 close with `cargo update` (R7-1), 8 by deleting the unused `reqwest 0.11` in `sbo-core/Cargo.toml:23` (R7-2, the only holder of rustls 0.21). `avail-rust` tracked by `branch = main` in three manifests (W7-3). Two `browserid-core` revs compiled (W7-4). `sbo-zkvm-methods` has no license field (W7-7). The new `supply-chain.yml` gate is red until this lands.

Depends on: **Q26, Q29 (open)**; recommendations: land now, pin by rev.

- [x] Pin `avail-rust` by `rev` (sbo-rpc, sbo-daemon, sbo-cli)
- [x] `cargo update`; `cargo test --workspace` on localtest; commit `Cargo.lock`
- [x] Delete `reqwest 0.11` from sbo-core
- [x] One workspace-level `browserid-core` pin; `license.workspace = true` in zkvm-methods
- [x] Acceptance: `supply-chain.yml` green (cargo audit 0 vulns / 9 warnings, cargo deny all ok on localtest 2026-11-05; CI confirms at PR time)

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

2026-11-05, on audit-2026-11 (Q26 (a)). avail-rust and browserid-core moved to [workspace.dependencies], pinned by rev (avail-rust de07cce, the commit the lockfile already held; browserid-core b83cce1, the newer of the two revs, a superset of 2582555). Unused reqwest 0.11 deleted from sbo-core (rustls 0.21 gone; rustls 0.23.46 only). cargo update: the 34 open advisories close; one new one, RUSTSEC-2026-0344 (ruzstd decompression bomb), is reachable only via risc0-zkvm behind the non-default zkvm feature of sbo-crypto, absent from default daemon/CLI graphs on every target, fixed upstream only in 0.9.1 behind object/risc0; ignored in audit.toml and deny.toml with review 2027-02-01. deny.toml: unmaintained = workspace (WS7 policy, none direct); licenses.clarify for sbo-zkvm-methods removed since the manifest now inherits the license. Suite 518 pass / 0 fail / 94 ignored; cargo metadata --locked OK.
