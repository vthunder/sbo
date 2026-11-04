---
# sbo-7bl8
title: DA inclusion fully trusted from RPC; no reorg handling; stubbed block hash + KZG
status: todo
type: bug
priority: deferred
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-11-04T21:35:03Z
parent: sbo-ax7t
blocked_by:
    - sbo-wn15
---

AvailClient (client.rs) accepts whatever the endpoint returns: no inclusion/KZG verification, block hash hardcoded [0u8;32] (client.rs:237), 'not available' -> empty block that advances height (client.rs:193). Monotonic height+1 poller, no finality/reorg awareness. Resolver never cross-checks URI chain id vs node genesis_hash. verify_kzg_proof is a stub returning Ok(true) (kzg.rs:154).
- [ ] Verify DA inclusion (KZG/data-root) rather than trusting RPC
- [ ] Reorg/finality handling
- [ ] Cross-check connected node network/genesis_hash against the URI's CAIP-2 chain id
- [ ] Implement verify_kzg_proof (full pairing) or remove the stub caller
- [ ] Don't advance height on a 'not available' response

## Audit 2026-11

Re-verified as D9/D39. Decision Q20 (c): the Avail light client verifies finality and data availability itself (WS4 §4 note); DA-side changes (KZG pairing, reorgs, chain-id cross-check, never advancing past unobtained data) wait for the light-node migration (sbo-wn15). The KZG stub returning Ok(true) is fixed separately in sbo-db6p (fail closed).
