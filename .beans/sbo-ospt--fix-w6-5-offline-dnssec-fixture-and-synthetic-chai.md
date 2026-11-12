---
# sbo-ospt
title: 'Fix W6-5: offline DNSSEC fixture and synthetic chain builder for tests'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-05T10:44:23Z
parent: sbo-ax7t
blocking:
    - sbo-evne
    - sbo-uv8a
---

Info, but a prerequisite. No offline DNSSEC fixture exists; every DNSSEC path is covered only by ignored live tests, and `dnssec-prover` has no Ed25519 (alg 15), so a synthetic chain needs an RSA or P-256 signer (W6-2). Blocks the D6 and D33 acceptance tests.

- [x] Fixture builder (test-only RSA/P-256 zone signer) producing RFC 9102 chains rooted at a test anchor
- [x] Captured real chain for mingo.place as a second fixture

## Summary of Changes

- `vendor/dnssec-prover` (0.6.10, MIT/Apache) wired in through the workspace `[patch.crates-io]`; the single functional change is `validation::verify_rr_stream_with_anchors(rrs, &[DS])` (the IANA `verify_rr_stream` is a wrapper). No vthunder fork exists, so the crate is vendored in-tree (upstream tests/bin not vendored; `[profile.dev.package.dnssec-prover] opt-level = 2` keeps offline validation fast). Still no Ed25519/alg 15 (W6-2): alg-15-only zones fail closed as before.
- `sbo-core::dnssec_fixture` (feature `dnssec-fixtures`, test-only `ring` P-256 signer): `SyntheticRoot` / `ChainSpec` / `ZoneKey` build RFC 9102 chains for `_browserid.<domain>` rooted at a test key, with per-zone keys and per-RRset windows (rotation and rollback scenarios); `SyntheticRoot::dns_root_v1` emits the matching `/sys/trust/dns-root` payload. Byte-exact against the validator (unit tests in the module).
- `sbo-core/tests/fixtures/mingo-place-browserid.rfc9102`: a real chain for `_browserid.mingo.place` captured read-only via `sbo-capture/tests/capture_fixture.rs` (ignored, live; regenerate with the env vars documented there). `sbo-core/tests/audit_2026_11_dnssec.rs` validates it offline against the IANA root at a pinned inclusion time inside its RRSIG window, and against a `dns-root.v1` history built from the chain's own root KSKs.
- `attribution.rs`: `TrustAnchors` now carries the parsed `dns-root.v1` history (`RootKsk`, `parse_dns_root`, `root_anchors_at`), and every verifier has a `_with_anchors` form (`extract_provider_key_with_anchors`, `verify_dnssec_proof_for_domain_with_anchors`, `verify_domain_self_cert_with_anchors`), plus `dnssec_proof_freshness` / `check_dnssec_refresh_monotonic` for D33.
