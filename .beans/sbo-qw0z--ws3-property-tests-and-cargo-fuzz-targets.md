---
# sbo-qw0z
title: 'WS3: property tests and cargo-fuzz targets'
status: todo
type: task
priority: normal
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-03T08:06:40Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

proptest suites plus a standalone `fuzz/` cargo-fuzz workspace (copy the browserid-ng `fuzz/` layout and `make fuzz-smoke`), 90 s smoke per target, run on the localtest box. Findings W3-n encoded as ignored AUDIT-2026-11 tests.

Every parser: wire parser + headers (`sbo-core/src/wire`), URI parser (`uri.rs`, percent-decoding, ':' in ids), `sbo-types` path/id/action, policy JSON (`policy/types.rs`, delegation, descendant constraints, value conditions), JWT/cert parsing (`jwt.rs`), device attribution + warrant parsing (`device_attribution`, `attribution.rs`), attestation/identity/content/collection schemas (`schema/`), Avail block decode (`sbo-rpc/src/decode.rs`, `sbo-avail/src/blocks.rs`), snapshot format (`snapshot.rs`), IPC framing (`ipc.rs`), daemon config, genesis presets, DNSSEC evidence blobs (`dns.rs`, `evidence.rs`), status-list decode.
Every sign→verify path: envelope sign/verify (canonical signing content, reconstruction malleability sbo-h75z), SBOP/SBOQ proofs, trie inclusion/non-inclusion proofs (domain separation sbo-hedq), merkle, domain self-cert, warrant/cert verification, fast-sync backer signatures, zkVM receipt verification.
Every narrowing/composition rule: policy cascade down paths, govern capability, version pinning, descendant constraints, no-pin, role resolution (cycles sbo-bynl, depth), not_attested fail-open (sbo-zocd), warrant scope `sign:sbo:*` + binding sets + as: on-behalf narrowing, Policy-Ref ownership.
All time arithmetic: HLC (`hlc.rs`), inclusion-time clock, cert/warrant exp/iat windows at authoring instant, RRSIG inception/expiration at inclusion time, status-list ttl, root-KSK valid_from/valid_until, trust-gate timeouts.

- [ ] proptest suites per crate
- [ ] fuzz/ workspace, targets, seeds, make fuzz-smoke
- [ ] smoke run tally (0 crashes or findings)
- [ ] report `docs/security-audit-2026-11-ws3-fuzz-proptest.md`
