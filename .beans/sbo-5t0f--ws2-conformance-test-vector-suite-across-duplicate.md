---
# sbo-5t0f
title: 'WS2: conformance / test-vector suite across duplicate implementations'
status: in-progress
type: task
priority: normal
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T20:39:38Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

Build a vector suite under `conformance/` (JSON vectors + expected verdict) and a runner for every implementation of the same check in this repo; any disagreement between implementations is a finding. Expected-fail tables double as the open ledger. Land it in CI (the repo has no CI today: WS7 creates `.github/workflows`; WS2 adds its job there).

Duplicate implementations to pit against each other (confirm the list while reading):
- ed25519 sign/verify: `sbo-core/src/crypto/ed25519.rs` vs `sbo-crypto/src/ed25519.rs` (strict vs non-strict, malleable S, small-order points, key length)
- sha256 / object_hash: `sbo-core/src/crypto/hash.rs` vs `sbo-crypto/src/hash.rs` vs daemon `sync.rs` object_hash vs State Commitment spec (raw bytes vs re-serialized)
- wire parser/serializer round trip: `sbo-core/src/wire` vs `sbo-wasm` kit builder vs zkVM guest (what it re-parses)
- path / id / identifier grammar: `sbo-types` vs `sbo-core/src/uri.rs` vs `policy/path.rs` vs daemon `repo.rs` filesystem mapping
- policy evaluation: `sbo-core/src/policy/evaluate.rs` vs daemon `validate.rs` / `state_view.rs` (which policy is in force at replay, sbo-y757)
- trie / proof verification: `sbo-crypto/src/trie.rs` vs zkVM guest witness checks vs `sbo-core/src/proof` (SBOP/SBOQ) vs `sbo-daemon/src/prover.rs`
- identity/owner resolution and email/name comparison: `resolve.rs`, `envelope.rs`, `device_attribution`, daemon
- time: HLC, inclusion time vs cert/warrant/RRSIG windows across `attribution.rs`, `evidence.rs`, `status.rs`

- [ ] enumerate duplicate implementations (table in report)
- [ ] vectors + runners; expected-fail tables
- [ ] CI job
- [ ] disagreements written up as findings W2-n with AUDIT-2026-11 tests
- [ ] report `docs/security-audit-2026-11-ws2-conformance.md`

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q1 (a): vectors encode the four-object device presentation inside Auth-Cert; Auth-Warrant is dead on the wire.
- Q4 (b): per-message batch semantics, ordered and state-threaded; vectors for the eight rules.
- Q5 (a): identity comparison = exactly one @, domain lowercased A-label, local part byte-exact; canonical on-chain form lowercase domain.
- Q2 (a): brokers.v1 is { "brokers": [...] }.
