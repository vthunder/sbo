---
# sbo-iye5
title: 'WS6: crypto core and verification re-check'
status: in-progress
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T20:39:38Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

Reviewer-then-skeptic over the verification core, oracle = WS1 invariants. Two ed25519 wrappers (`sbo-core/src/crypto`, `sbo-crypto`): strict verify, key/sig length pins, small-order, batch use. Envelope signature scope: canonical signing content vs received bytes, duplicate/reordered/unknown headers, hex case, Content-Length (July sbo-h75z); Content-Hash never verified (July sbo-d5nm, Critical lead); object_hash input (sbo-2tue). Trie (`sbo-crypto/src/trie.rs`): leaf/internal domain separation (sbo-hedq), non-inclusion proofs, SBOP/SBOQ (`sbo-core/src/proof`). KZG/BLS/SRS (`kzg.rs` stub returning Ok(true), `srs_data.rs` provenance, `poly*.rs`), merkle. Attribution: JWT/browserid cert verification (`jwt.rs`, alg pinning, typed signing), DNSSEC chain validation (`dns.rs`, `attribution.rs`, dnssec-prover, pinned root KSK sbo-y5ek, RRSIG windows at inclusion time), domain self-cert (sbo-3gqo), status-list verification against DNSSEC-proven keys, warrant verification + binding sets + revocation fail-closed, cross-issuer rules, subaddress rules (compare with browserid-ng D1). Genesis validation (sbo-9d7l) and genesis-hash pinning. zkVM guest + verifier (sbo-5rww: state unbound from block data, bootstrap anchor) read for what it proves. Every verdict backed by a test; confirmed-open leads as ignored AUDIT-2026-11 tests. Findings W6-n. July leads get a 'Then / Now' table.

- [ ] candidate verdict table
- [ ] tests per crate (pass / ignored tally)
- [ ] July re-verification table
- [ ] report `docs/security-audit-2026-11-ws6-crypto-core.md`

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q1 (a) device presentation is normative; Q3 (a) pinned root KSK must be injectable into dnssec-prover; Q6 remove bare-key owners (core resolve/authorize side); Q7 (a) strict genesis — check whether the live app 506 genesis passes; Q8 (a) self-cert required for Mode B at next regenesis; Q11 (b) PoC D1 before any fix; Q17 (a); Q18 (a) raw-bytes object_hash + trie domain separation ship together as state-commitment v2 with regenesis; Q19 (a) zkVM marked experimental, no remediation.
