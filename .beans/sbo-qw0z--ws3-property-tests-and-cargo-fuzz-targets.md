---
# sbo-qw0z
title: 'WS3: property tests and cargo-fuzz targets'
status: completed
type: task
priority: normal
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T21:26:08Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

proptest suites plus a standalone `fuzz/` cargo-fuzz workspace (copy the browserid-ng `fuzz/` layout and `make fuzz-smoke`), 90 s smoke per target, run on the localtest box. Findings W3-n encoded as ignored AUDIT-2026-11 tests.

Every parser: wire parser + headers (`sbo-core/src/wire`), URI parser (`uri.rs`, percent-decoding, ':' in ids), `sbo-types` path/id/action, policy JSON (`policy/types.rs`, delegation, descendant constraints, value conditions), JWT/cert parsing (`jwt.rs`), device attribution + warrant parsing (`device_attribution`, `attribution.rs`), attestation/identity/content/collection schemas (`schema/`), Avail block decode (`sbo-rpc/src/decode.rs`, `sbo-avail/src/blocks.rs`), snapshot format (`snapshot.rs`), IPC framing (`ipc.rs`), daemon config, genesis presets, DNSSEC evidence blobs (`dns.rs`, `evidence.rs`), status-list decode.
Every sign→verify path: envelope sign/verify (canonical signing content, reconstruction malleability sbo-h75z), SBOP/SBOQ proofs, trie inclusion/non-inclusion proofs (domain separation sbo-hedq), merkle, domain self-cert, warrant/cert verification, fast-sync backer signatures, zkVM receipt verification.
Every narrowing/composition rule: policy cascade down paths, govern capability, version pinning, descendant constraints, no-pin, role resolution (cycles sbo-bynl, depth), not_attested fail-open (sbo-zocd), warrant scope `sign:sbo:*` + binding sets + as: on-behalf narrowing, Policy-Ref ownership.
All time arithmetic: HLC (`hlc.rs`), inclusion-time clock, cert/warrant exp/iat windows at authoring instant, RRSIG inception/expiration at inclusion time, status-list ttl, root-KSK valid_from/valid_until, trust-gate timeouts.

- [x] proptest suites per crate (core 47/22, crypto 5/3, rpc 3/1, daemon 3/1 — pass/ignored)
- [x] fuzz/ workspace, 12 targets, seeds, make fuzz-smoke, launchd plist, fuzz-smoke.yml
- [x] smoke run tally: 12 targets × 90 s, ~28M executions, 0 crashes after guards; first pass found W3-9 and W3-10
- [x] report `docs/security-audit-2026-11-ws3-fuzz-proptest.md`; decisions Q38–Q40 appended

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q5 (a) identity rule; Q9 (a) assertion judged at authoring instant bounded by a capped W, everything else at inclusion time; Q17 (a) role cycles need write-time validation + eval guard (property: bounded depth); Q21 (a) weekly fuzz-smoke launchd.

## Summary of Changes

- proptest suites: sbo-core (wire, policy, role_cycle, time_scopes, uri_identity, proofs + support module), sbo-crypto (trie), sbo-rpc (decode), sbo-daemon (daemon): 58 passing properties, 27 ignored `AUDIT-2026-11` tests confirmed to fail today (D1, D2 ×3, D3, D4, D10 ×3, D13, D14, D21, D22, D50, D54, I24, W3-1 ×2, W3-2, W3-3, W3-4, W3-6 ×2, W3-7, W3-8, W3-9, W3-10).
- New findings W3-1..W3-11: W3-1/W3-2 exponential glob matching (High; policy patterns and warrant scopes), W3-3 unknown policy keys fail open, W3-4 prefix paths evict each other from the trie, W3-5 dead merkle.rs with prover/verifier mismatch, W3-6 unchecked SBOP/SBOQ lengths, W3-7 gzip bomb on the chain-read path, W3-8 non-existence verifier panic, W3-9 SBOP parser panic, W3-10 Content-Length overflow panic, W3-11 identity/domain JWT type confusion (Info).
- `fuzz/` standalone cargo-fuzz workspace: 12 targets, seeds, gen_seeds, README; `scripts/fuzz-smoke.sh`, Makefile `fuzz-smoke` / `fuzz-smoke-install`, launchd plist (Q21), `.github/workflows/fuzz-smoke.yml`.
- Report `docs/security-audit-2026-11-ws3-fuzz-proptest.md`; decisions Q38 (glob matcher), Q39 (strict policy parse), Q40 (empty scope list). Only dev-dependencies changed (proptest in four manifests).
