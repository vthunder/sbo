---
# sbo-iye5
title: 'WS6: crypto core and verification re-check'
status: completed
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T20:55:58Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

Reviewer-then-skeptic over the verification core, oracle = WS1 invariants. Two ed25519 wrappers (`sbo-core/src/crypto`, `sbo-crypto`): strict verify, key/sig length pins, small-order, batch use. Envelope signature scope: canonical signing content vs received bytes, duplicate/reordered/unknown headers, hex case, Content-Length (July sbo-h75z); Content-Hash never verified (July sbo-d5nm, Critical lead); object_hash input (sbo-2tue). Trie (`sbo-crypto/src/trie.rs`): leaf/internal domain separation (sbo-hedq), non-inclusion proofs, SBOP/SBOQ (`sbo-core/src/proof`). KZG/BLS/SRS (`kzg.rs` stub returning Ok(true), `srs_data.rs` provenance, `poly*.rs`), merkle. Attribution: JWT/browserid cert verification (`jwt.rs`, alg pinning, typed signing), DNSSEC chain validation (`dns.rs`, `attribution.rs`, dnssec-prover, pinned root KSK sbo-y5ek, RRSIG windows at inclusion time), domain self-cert (sbo-3gqo), status-list verification against DNSSEC-proven keys, warrant verification + binding sets + revocation fail-closed, cross-issuer rules, subaddress rules (compare with browserid-ng D1). Genesis validation (sbo-9d7l) and genesis-hash pinning. zkVM guest + verifier (sbo-5rww: state unbound from block data, bootstrap anchor) read for what it proves. Every verdict backed by a test; confirmed-open leads as ignored AUDIT-2026-11 tests. Findings W6-n. July leads get a 'Then / Now' table.

- [x] candidate verdict table
- [x] tests per crate (pass / ignored tally)
- [x] July re-verification table
- [x] report `docs/security-audit-2026-11-ws6-crypto-core.md`

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q1 (a) device presentation is normative; Q3 (a) pinned root KSK must be injectable into dnssec-prover; Q6 remove bare-key owners (core resolve/authorize side); Q7 (a) strict genesis — check whether the live app 506 genesis passes; Q8 (a) self-cert required for Mode B at next regenesis; Q11 (b) PoC D1 before any fix; Q17 (a); Q18 (a) raw-bytes object_hash + trie domain separation ship together as state-commitment v2 with regenesis; Q19 (a) zkVM marked experimental, no remediation.

## Summary of Changes

Skeptic pass done 2026-11-04. Report: `docs/security-audit-2026-11-ws6-crypto-core.md`. Tests (no production code or deps changed): `crates/sbo-core/tests/audit_2026_11_ws6.rs` (13 pass / 14 ignored), `crates/sbo-crypto/tests/audit_2026_11_ws6.rs` (2 / 1, +1 under `--features kzg`), `crates/sbo-daemon/tests/audit_2026_11_ws6.rs` (0 / 3); fixture `crates/sbo-core/tests/fixtures/mingo-genesis-v5.wire`.

Verdicts: D1 Critical confirmed (payload swap + no Content-Hash; P2 pins keyed by claimed hash), D2 High confirmed (order, duplicates, +N/00N, uppercase hex, non-strict verify), D3 partial (reduces to D2 + spec conflict Q32), D4 High confirmed (root collision shown), D5 Critical confirmed (todo!(), genesis mode accepts all, hash mismatch non-fatal), D6 High confirmed by reading (no offline DNSSEC fixture exists; dnssec-prover has no anchor injection and no alg 15), D8 read-only (Q19), D9 High confirmed (KZG Ok(true)), D10 High confirmed (child-process crash), D24 partial (restriction denies everything today, never verifies the JWT), D30 Low confirmed, D32 Info. New: W6-1 small-order universal forgery under non-strict verify (Low), W6-2 no Ed25519 DNSSEC (Info), W6-3 require_payload_signed_by unusable (Low), W6-4 unknown headers vs raw-bytes object_hash spec conflict (Medium, Q32), W6-5 no DNSSEC fixture (Info). Live v5 genesis: Mode B plain, root policy last of 14; passes Q7 only under Q33 (a); fails Q8 (a) regardless, regenesis needed; mingo repo carries v5 wire while GENESIS.md documents v6. Decisions Q32, Q33 appended. WS8 order in report §6.
