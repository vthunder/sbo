---
# sbo-slsm
title: 'Fix D11/W4-1: not_attested fails closed on a state-read error; index attestations'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:2085-2090` `unwrap_or_default()` turns a RocksDB error into 'not banned'; every attested check scans all `attestation.v1` objects (W4-1). July `sbo-zocd`.

- [ ] Propagate the read error as `ValidationStage::State`
- [ ] Index attestations by subject/type
- [ ] Acceptance (un-ignore): ws4 `d11_not_attested_fails_closed_on_state_read_error`
