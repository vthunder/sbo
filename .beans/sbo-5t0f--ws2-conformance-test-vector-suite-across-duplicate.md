---
# sbo-5t0f
title: 'WS2: conformance / test-vector suite across duplicate implementations'
status: completed
type: task
priority: normal
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T20:58:31Z
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

- [x] enumerate duplicate implementations (table in report)
- [x] vectors + runners; expected-fail tables
- [x] CI job
- [x] disagreements written up as findings W2-n with AUDIT-2026-11 tests
- [x] report `docs/security-audit-2026-11-ws2-conformance.md`

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q1 (a): vectors encode the four-object device presentation inside Auth-Cert; Auth-Warrant is dead on the wire.
- Q4 (b): per-message batch semantics, ordered and state-threaded; vectors for the eight rules.
- Q5 (a): identity comparison = exactly one @, domain lowercased A-label, local part byte-exact; canonical on-chain form lowercase domain.
- Q2 (a): brokers.v1 is { "brokers": [...] }.

## Summary of Changes

Done 2026-11-04. `conformance/` holds 8 suites, 135 vectors (5 generated from a fixed seed by `sbo-core/tests/audit_2026_11_ws2_generate.rs`, 3 hand-authored); expected verdicts are the spec's. Five runners (sbo-types, sbo-crypto, sbo-core, sbo-wasm, sbo-daemon; 19 tests) each carry an `EXPECTED_FAIL` table tagged `AUDIT-2026-11 <id>`; removing an entry is the acceptance test. CI job `.github/workflows/conformance.yml` runs all five and checks the vectors regenerate byte-identically. Report `docs/security-audit-2026-11-ws2-conformance.md`.

Genuine cross-implementation disagreements: W2-1 sbo-types grammar diverges from sbo-core::message (13 vectors); W2-2 overlay LWW on a missing HLC (= D17 half, Q25); W2-3 tip reads vs tip validation policy (= sbo-y757, Medium); W2-4 checkpoint `state_root` form (S18, Q34). Confirmed by vector for other workstreams: D1, D2, D3, D4, D13, D21, D28, D30 (small-order only; non-canonical S refuted), D54. Batch rules 1, 2, 3, 5 of Q4 hold today. New decisions Q34–Q37.
