---
# sbo-ax7t
title: 'Security audit 2026-11: full-pass adversarial audit of sbo'
status: in-progress
type: epic
priority: high
created_at: 2026-11-03T08:05:09Z
updated_at: 2026-11-05T08:40:47Z
---

Full-pass security audit of the sbo repo (specs + reference implementation: sbo-core, sbo-crypto, sbo-types, sbo-rpc, sbo-avail, sbo-capture, sbo-daemon, sbo-cli, sbo-wasm, sbo-zkvm), run with the browserid-ng 2026-11 method: reviewer-then-skeptic, every confirmed finding encoded as an ignored test tagged `AUDIT-2026-11 <id>` whose un-ignoring is the acceptance test for the fix, post-verification severities, PoCs only against a local instance with fake keys. No production code changes during the audit.

Branch: `audit-2026-11` (never pushed; main == origin/main). Docs: `docs/design/threat-model.md`, `docs/security-audit-2026-11-wsN-<topic>.md`, `docs/security-audit-2026-11-decisions.md` (running, published as a private artifact), ledger `docs/security-audit-2026-11.md`.

Prior art to re-verify (the 'July' of this audit): the 2026-07-08 full protocol + implementation review (bean sbo-ix77, epic sbo-f5wn and its 14 children, several still open: Content-Hash unverified sbo-d5nm, genesis fail-open sbo-9d7l, zkVM guest sbo-5rww, signature over reconstruction sbo-h75z, circular roles sbo-bynl, pinned root KSK decorative sbo-y5ek, self-cert warn-only sbo-3gqo, object_hash over re-serialized bytes sbo-2tue, trie domain separation sbo-hedq, DA trust sbo-7bl8, bare-key owners sbo-4arq, medium roundup sbo-zocd). Each open item is a candidate lead that the owning workstream confirms or refutes against today's code.

Workstreams: WS1 threat model + spec review (first, alone) → WS2–WS8 in parallel → WS9 ledger + remediation beans.

- [x] WS1 threat model + spec/design review (sbo-dl2l)
- [x] Spec decisions brought to Dan before WS2–WS8 launch (Q1–Q21 settled 2026-11-04)
- [x] WS2 conformance vectors (sbo-5t0f)
- [x] WS3 property tests + fuzz (sbo-qw0z)
- [x] WS4 never-audited layers (sbo-f8cj)
- [x] WS5 HTTP/IPC surface + authz matrix (sbo-s4xl)
- [x] WS6 crypto core + verification (sbo-iye5)
- [x] WS7 supply chain / CI / secrets / logging (sbo-ip5k)
- [x] WS8 PoCs (sbo-cka2)
- [x] WS9 ledger + remediation beans (sbo-q92z)
- [x] Decisions doc published as private artifact (done, updated through Q40); Q22–Q40 answers pending, then flip 20 draft beans
