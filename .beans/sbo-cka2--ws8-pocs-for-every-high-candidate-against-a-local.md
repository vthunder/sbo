---
# sbo-cka2
title: 'WS8: PoCs for every High+ candidate against a local instance'
status: completed
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-04T21:27:26Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
    - sbo-f8cj
    - sbo-s4xl
    - sbo-iye5
---

For every candidate rated High or above after the skeptic pass (and the WS1 ordering list), a working PoC against a local sbo-daemon or an in-process harness only, with fake identities / test keys only — never da.sandmill.org, never Avail turing with real credentials. Expected candidates: payload swap on a signature-valid message (Content-Hash), reconstruction malleability, policy/role cycle crash, genesis fail-open, filesystem traversal via on-chain paths (if WS4 confirms), submit-gate SSRF, resource exhaustion on proof/snapshot endpoints, mempool divergence. Each PoC lives under `crates/sbo-daemon/tests/audit_2026_11_poc_*.rs` or `poc/`, documented with measured impact. Findings W8-n (usually confirmations with impact numbers).

- [x] High+ list taken from WS4/5/6 reports and WS1 §6
- [x] PoCs + measured impact (13 tests, all reproduce)
- [x] refuted/not-rebuilt documented (report §3)
- [x] report `docs/security-audit-2026-11-ws8-pocs.md`

## Summary of Changes

13 PoCs across three test files, all reproduce on localtest, all `#[ignore]`d (CI-excluded):

- `audit_2026_11_poc_core.rs` (8): D1 payload swap accepted by the daemon gate; D1+P2 policy body filed under a benign/chosen hash; D5/D23 stranger takeover of a root-policy-less repo; D7 failing-self-cert domain accepted; D21 `/../` mirror escape (sibling of the repo dir); D58 id/collection create_dir_all collision aborting a block; D10 cyclic-role evaluator crash (child-process stack overflow).
- `audit_2026_11_poc_fastsync.rs` (3): D26 authority backs a forged root with no checkpoint; D26 end-to-end hostile serving node adopted by bootstrap; D27 forged pinned policy version loads into a fast-sync client.
- `audit_2026_11_poc_http.rs` (2): W5-1 cross-origin preflight allowed with the Private-Network header; foreign-origin POST /v1/submit reaches the spend path.

No production code/spec/dependency changed. No new decisions (Q11 ordering satisfied). D2/D4/D18/D50/D57/D22 already shown in-process by their owning workstream (report §2); nothing refuted as a finding (§3). Committed 3a062b4 on audit-2026-11.
