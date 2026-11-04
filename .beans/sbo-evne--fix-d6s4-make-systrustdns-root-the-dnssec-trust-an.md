---
# sbo-evne
title: 'Fix D6/S4: make /sys/trust/dns-root the DNSSEC trust anchor (patch dnssec-prover to take anchors)'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-04T21:31:37Z
parent: sbo-ax7t
---

**High.** `dnssec-prover 0.6.8` validates against compiled-in `root_hints()` and `verify_rr_stream` takes no anchors; `load_trust_anchors` never reads `/sys/trust/dns-root`. A governance rollover changes nothing and replay diverges across library versions. July `sbo-y5ek`. Q3 (a).

Blocked by: the W6-5 fixture bean. No open decision.

- [ ] Fork/patch `dnssec-prover` to accept trust anchors (and note alg 15 absence, W6-2)
- [ ] Read `/sys/trust/dns-root` history at inclusion time; verify `valid_from`/`valid_until` against inclusion time
- [ ] Acceptance: new test `AUDIT-2026-11 D6` — a chain rooted at a non-IANA key validates when pinned and rejects when not; rollover history spans old+new evidence
