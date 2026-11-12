---
# sbo-wn15
title: 'Follow-up: migrate DA read path to Avail''s new light-node implementation'
status: todo
type: task
priority: deferred
created_at: 2026-11-04T20:48:46Z
updated_at: 2026-11-04T20:48:46Z
parent: sbo-ax7t
---

Deferred from audit 2026-11 (Q20, Dan 2026-11-04): the Avail light client the daemon queries verifies finality and data availability itself, and Avail is expected to replace it with a new light-node implementation within a couple of months. When that lands: re-evaluate D9/D39 (zero block hash in `sbo-avail/src/client.rs`, 'app data not available' advancing the height, KZG stub `verify_kzg_proof`, no chain-id cross-check against the URI) against the new node's guarantees, and port `sbo-avail`/`lc.rs`/`rpc.rs` to its API. Until then D9/D39 are an accepted risk recorded in `docs/security-audit-2026-11-ws4-layers.md` §4.
