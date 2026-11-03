---
# sbo-cka2
title: 'WS8: PoCs for every High+ candidate against a local instance'
status: todo
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-03T08:06:40Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
    - sbo-f8cj
    - sbo-s4xl
    - sbo-iye5
---

For every candidate rated High or above after the skeptic pass (and the WS1 ordering list), a working PoC against a local sbo-daemon or an in-process harness only, with fake identities / test keys only — never da.sandmill.org, never Avail turing with real credentials. Expected candidates: payload swap on a signature-valid message (Content-Hash), reconstruction malleability, policy/role cycle crash, genesis fail-open, filesystem traversal via on-chain paths (if WS4 confirms), submit-gate SSRF, resource exhaustion on proof/snapshot endpoints, mempool divergence. Each PoC lives under `crates/sbo-daemon/tests/audit_2026_11_poc_*.rs` or `poc/`, documented with measured impact. Findings W8-n (usually confirmations with impact numbers).

- [ ] High+ list agreed with WS9
- [ ] PoCs + measured impact
- [ ] refuted PoCs documented
- [ ] report `docs/security-audit-2026-11-ws8-pocs.md`
