---
# sbo-f8cj
title: 'WS4: code review of layers never audited before'
status: todo
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-03T08:06:40Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

The July 2026 review (sbo-ix77) covered wire, identity, policy, attestation/state commitment, genesis, URI/DNS, zkVM, DA client, daemon validate/sync. Reviewer-then-skeptic over everything it did not touch or that was written since (ac48868 onward: device-cert model, delegated attribution, as: writes, cross-issuer warrants, signing grants, submit gate, finality-gated DA submission, policy P1–P4, global uniqueness, Related header):
- daemon `repo.rs` filesystem sync: on-chain path/id → local filesystem mapping (traversal, symlinks, case-folding on APFS, collisions)
- `pending.rs` mempool overlay, `submit_queue.rs`, `turbo.rs` (TurboDA credentials, per-repo), finality gating, divergence (sbo-hy4r)
- `snapshot.rs` fast-sync, `bootstrap.rs`, `lc.rs` light client, `trust.rs` TrustGate (liveness fallback), backer verification
- `evidence.rs`, `status.rs` (write-time DNSSEC capture, status-list fetch at the submit gate: SSRF class, caches, negative cache, fail-closed revocation)
- `device_attribution` + `attribution.rs` delegated attribution, warrants, binding sets, cross-issuer, agent-attributed writes
- `sbo-capture` (client-side cert + evidence capture), `sbo-cli` (keyring file permissions, key material handling, `identity`/`domain`/`da` commands), `sbo-wasm` kit, `keyring.rs`
- `state_view.rs` read vs validation policy disagreement (sbo-y757), `state/db.rs` rocksdb usage, index drop on delete
- daemon `config.rs` / `main.rs` defaults (bind addresses, default_repo, debug flags writing to /tmp/sbo-debug)
Candidates from WS1 routed here are confirmed/refuted with tests (ignored AUDIT-2026-11 on confirm). Findings W4-n.

- [ ] per-layer candidate list
- [ ] skeptic pass with tests
- [ ] report `docs/security-audit-2026-11-ws4-layers.md`
