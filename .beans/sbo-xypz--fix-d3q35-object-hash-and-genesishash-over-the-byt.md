---
# sbo-xypz
title: 'Fix D3/Q35: object_hash and genesisHash over the bytes as included on chain'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Medium** (Partial: identical for canonical input, pinned by `live_genesis_raw_and_reserialized_hashes_agree`). `sync.rs:1122` hashes `wire::serialize(msg)`; the State Commitment spec says raw bytes; the Genesis spec says canonical serialization (Q35). After the canonical-bytes helper every accepted message is canonical, so both definitions coincide and the code can hash the received bytes. July `sbo-2tue`.

Blocked by: canonical-bytes helper (Q32), state-commitment v2 bundle (root changes). Decisions: Q32, Q35 (open).

- [ ] Retain the received bytes through parse; `object_hash = sha256(received)`; same for `genesis_hash`
- [ ] Acceptance: WS2 nine `object_hash_raw` vectors out of the daemon runner's `EXPECTED_FAIL`; ws3_wire `d3_unknown_header_survives_or_rejects`

## Decision

Q32 decided (c), not (a): sign what was sent. Signing content = received header block minus the Signature line; an unknown header is valid iff it is inside the signature and placed after the modelled headers; consumers never reserialize (bytes in, bytes out: verify, hash, store and forward the received bytes); a Critical header lists headers an old client must not skip; experimental headers use the X- prefix. Do NOT reject unknown headers as such; reject only unsigned ones (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
