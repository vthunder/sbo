---
# sbo-dl2l
title: 'WS1: threat model + spec/design review'
status: todo
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-03T08:06:39Z
parent: sbo-ax7t
---

Write `docs/design/threat-model.md` in the browserid-ng format (flows, adversaries A1..An with position/sees/can send/wants, ranked assets, trust boundaries the spec claims, numbered invariants I1..In phrased so WS2/WS3/WS5 can test them, accepted risks, out of scope). Then read all 15 specs + 2 proposals against the implementation and produce candidate leads D1..Dn (code) and spec findings S1..Sn (spec gaps/contradictions, spec-vs-code disagreements with a recommendation on which should move; default spec wins).

Scope of the model: writers (any key), delegated agents holding warrants, malicious indexer/daemon operator (untrusted reads, Indexer spec), DA/RPC provider (sbo-rpc, sbo-avail: inclusion, ordering, reorgs), network attacker (DNS/DNSSEC downgrade, status-list fetch), compromised or malicious browserid IdP/broker, co-tenant on a multi-repo daemon, genesis forger / fast-sync backer, local attacker on the daemon host (IPC socket, /tmp/sbo-debug, keyring files), policy governance insider. Assets: signing keys/keyring, warrants, root policy, trust anchors (/sys/trust/*), state root, genesis hash, TurboDA credentials, on-chain DNSSEC evidence.

Prior leads to carry forward as candidates: the open children of sbo-f5wn (July 2026 review) and sbo-4arq, sbo-y757, sbo-hy4r.

Report: `docs/security-audit-2026-11-ws1-threat-model-spec.md`. Decisions go into `docs/security-audit-2026-11-decisions.md` (Q1..). Runs alone first; its invariants are the oracle for WS2–WS8.

- [ ] threat-model.md
- [ ] spec-by-spec review vs code: Core, Wire, URI, Policy, Identity, Authorization, Attestation, Attribution, Community, Content, Indexer/Client, Genesis, Bridge, State Commitment, NFT, proposals
- [ ] candidate list D1..Dn with owning workstream and pre-verification severity
- [ ] spec findings S1..Sn with which-should-move recommendation
- [ ] decisions doc started and published as private artifact
- [ ] report committed
