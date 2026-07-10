---
# sbo-y5ek
title: Pinned on-chain root KSK (/sys/trust/dns-root) is decorative; library IANA root used instead
status: todo
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-07-08T15:48:57Z
parent: sbo-f5wn
---

attribution.rs:27-58,188 and validate.rs:74-84: dnssec-prover uses a compiled-in root_hints() with no injection point; TrustAnchors.root_ksk is 'informational only'. Spec makes /sys/trust/dns-root the single a-priori anchor and a rollover-spanning history so evidence stays verifiable forever. Governance updates to the on-chain anchor have zero effect. Breaks durability/convergence: after a root-KSK rollover old evidence can stop validating, and two replayers on different lib versions diverge.
- [ ] Wire the on-chain /sys/trust/dns-root history into DNSSEC validation as the trust anchor (fork/patch dnssec-prover or replace with an injectable validator)
- [ ] Verify the key valid_from/valid_until windows against inclusion time
- [ ] Tests: rollover history spans old+new evidence
