---
# sbo-bzp7
title: 'Fix W7-2/W7-6/W7-3/W7-4/W7-7/Q26/Q29: pin avail-rust by rev, cargo update, drop unused reqwest 0.11, one browserid-core rev'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
blocking:
    - sbo-9zs4
---

**Medium.** 34 RUSTSEC advisories after ignores: 26 close with `cargo update` (R7-1), 8 by deleting the unused `reqwest 0.11` in `sbo-core/Cargo.toml:23` (R7-2, the only holder of rustls 0.21). `avail-rust` tracked by `branch = main` in three manifests (W7-3). Two `browserid-core` revs compiled (W7-4). `sbo-zkvm-methods` has no license field (W7-7). The new `supply-chain.yml` gate is red until this lands.

Depends on: **Q26, Q29 (open)**; recommendations: land now, pin by rev.

- [ ] Pin `avail-rust` by `rev` (sbo-rpc, sbo-daemon, sbo-cli)
- [ ] `cargo update`; `cargo test --workspace` on localtest; commit `Cargo.lock`
- [ ] Delete `reqwest 0.11` from sbo-core
- [ ] One workspace-level `browserid-core` pin; `license.workspace = true` in zkvm-methods
- [ ] Acceptance: `supply-chain.yml` green

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
