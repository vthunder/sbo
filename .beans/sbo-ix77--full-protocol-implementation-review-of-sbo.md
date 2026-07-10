---
# sbo-ix77
title: Full protocol + implementation review of SBO
status: completed
type: task
priority: normal
created_at: 2026-07-08T06:16:45Z
updated_at: 2026-07-08T06:22:41Z
---

Comprehensive review like the browserid-ng one: protocol-level issues, implementation gaps weakening guarantees, spec/impl mismatches, missing docs, general comments. Subsystems: wire format, identity, policy/authorization, attestation, state commitment, genesis, URI/DNS, zkVM proofs, DA layer, daemon validation/sync.

- [x] Read core specs (read master, wire-referenced, identity, authorization; delegated rest)
- [x] Wire format + envelope/parser vs spec — CRITICAL: Content-Hash never verified (payload swappable); reconstruction malleability
- [x] Identity + naming + resolution vs spec — bare-key ownership accepted (Critical); domain self-cert warn-only; no email/name normalization
- [x] Policy + authorization engine vs spec — DNSSEC validation is REAL (positive); pinned root KSK decorative; circular-role DoS; Policy-Ref restriction + genesis fail-open
- [x] Attestation + state commitment + checkpoints vs spec — fast-sync sound; zkVM guest verifies NO SBO validity; object_hash over re-serialized bytes
- [x] Genesis + domain self-cert + DNS/URI vs spec — Genesis::validate todo!(); genesis-hash advisory; Bridge/import unimplemented; DA trusts RPC; no reorg handling
- [x] zkVM validity proofs vs spec — recursion binding sound; guest checks no sig/policy/attribution; state unbound from block data
- [x] Daemon validation/sync/trust (covered across subsystem agents)
- [x] Synthesize report — delivered in chat

Summary of findings recorded in chat.
