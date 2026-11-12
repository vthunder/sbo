---
# sbo-xypz
title: 'Fix D3/Q35: object_hash and genesisHash over the bytes as included on chain'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T10:35:50Z
parent: sbo-ax7t
---

**Medium** (Partial: identical for canonical input, pinned by `live_genesis_raw_and_reserialized_hashes_agree`). `sync.rs:1122` hashes `wire::serialize(msg)`; the State Commitment spec says raw bytes; the Genesis spec says canonical serialization (Q35). After the canonical-bytes helper every accepted message is canonical, so both definitions coincide and the code can hash the received bytes. July `sbo-2tue`.

Blocked by: canonical-bytes helper (Q32), state-commitment v2 bundle (root changes). Decisions: Q32, Q35 (open).

- [x] Retain the received bytes through parse; `object_hash = sha256(received)`; same for `genesis_hash`
- [x] Acceptance: WS2 nine `object_hash_raw` vectors out of the daemon runner's `EXPECTED_FAIL`; ws3_wire `d3_unknown_header_survives_or_rejects`

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `wire::parse_batch_raw` returns each message with the exact bytes it was parsed from.
- `sbo-daemon/src/sync.rs` `process_block`: parses with `parse_batch_raw`, verifies each message with `verify_received(msg, raw)`, passes `raw` to `write_object`, and `object_hash = sha256(raw)`; the mirror file and the verbose log use the received bytes. `sbo-daemon/src/main.rs` submit path keeps the raw bytes per message (client messages and evidence refreshes) and hashes them.
- `sbo_core::genesis_hash_from_wire` = `sha256(bytes as included)` after the batch parses (Q35 (a)); `genesis_hash(&[Message])` stays for producers and is equal for canonical input.
- WS2 core runner: `OBJECT_HASH_EXPECTED_FAIL` emptied (the nine non-canonical vectors are now rejected at parse; for every accepted vector raw and reserialized hashes agree). ws3_wire `d3_unknown_header_survives_or_rejects` un-ignored.
- Regenesis note: for the live mingo v5 genesis the raw-bytes hash and the reserialized hash are identical (`live_genesis_raw_and_reserialized_hashes_agree` still pins `sha256:ca27c6…85bc`), so the genesisHash and state root do not change for canonical input. If the regenesis bundle (sbo-eefz) changes the genesis content, the fixture `crates/sbo-core/tests/fixtures/mingo-genesis-v5.wire`, `LIVE_GENESIS_HASH` and the WS2 `object_hash_raw` vectors must be regenerated from the new on-chain bytes.
