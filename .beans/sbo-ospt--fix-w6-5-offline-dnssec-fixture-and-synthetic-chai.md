---
# sbo-ospt
title: 'Fix W6-5: offline DNSSEC fixture and synthetic chain builder for tests'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-ax7t
blocking:
    - sbo-evne
    - sbo-uv8a
---

Info, but a prerequisite. No offline DNSSEC fixture exists; every DNSSEC path is covered only by ignored live tests, and `dnssec-prover` has no Ed25519 (alg 15), so a synthetic chain needs an RSA or P-256 signer (W6-2). Blocks the D6 and D33 acceptance tests.

- [ ] Fixture builder (test-only RSA/P-256 zone signer) producing RFC 9102 chains rooted at a test anchor
- [ ] Captured real chain for mingo.place as a second fixture
