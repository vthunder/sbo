---
# sbo-qv95
title: 'Global (path,id) uniqueness: drop creator from trie key'
status: in-progress
type: feature
created_at: 2026-07-16T14:15:05Z
updated_at: 2026-07-16T14:15:05Z
---

Core SBO change: make (path,id) globally unique (first valid write wins, resolved by inclusion order); drop creator from the state-trie key (leaf [path…,id]) while keeping it as an immutable stored attribute + wire Creator header. Resolves the mingo-jyzt under-specified-resolution / grindable-first-creator-tiebreak problem and the /sys/dnssec fork.

Decided with dan (2026-07-16) after a deep design review:
- Non-unique paths are right as the DEFAULT for the multi-writer core (attestations, content, personal namespaces, recovery-via-transfer), but "one canonical object per path" is a recurring first-class need currently met ~5 ad-hoc ways (is_name_claim_path hardcode, bridge bespoke import, genesis ordering, "assume one domain", + an unspecified grindable lexicographic-first-creator tiebreak).
- Original non-uniqueness motivations judged weak: verify-in-isolation/idempotency (moot — reads need replay anyway); fire-and-forget send-to-inbox (preserved via collision-resistant ids).
- Multi-writer semantics NOT lost: identity-in-path already provides them; reject a per-collection opt-out mode (maintenance surface, redundant).
- creator decision: drop from trie KEY (zk saving marginal — one SHA-256 level of ~N; real win is simplification: ~21 scan sites → point lookups, tiebreak & name-claim special-case gone). creator already stored, no new metadata.
- Sweep: NO hard blockers. One soft fix: mingo-web live post/comment/reaction ids from Date.now() at a shared path must become collision-safe (append author+random), same as seed.rs.
- Security: grindable squatting → front-runnable-only (the accepted /sys/names model). Personal/sys paths unaffected. Delete frees slot → recycling note.

## Plan
- [ ] Proposal doc specs/proposals/global-path-id-uniqueness.md (in progress) — dan reviews before live specs edited
- [ ] Apply coordinated edits to affected specs (State Commitment, Specification, URI, Identity, Community, Bridge, Content, Authorization; Attestation unchanged) — keep internally consistent
- [ ] Implement in sbo: object_to_segments/encode_object_key drop creator; collapse scan helpers to point lookups; global transfer destination-collision; SBOQ segment construction + proof fixtures; retire is_name_claim_path + dnssec_hlc grind stopgap
- [ ] mingo: collision-safe live ids (app.js); verify genesis/seed/poster unaffected
- [ ] Thorough tests (core change) incl. new: two-creators-one-slot rejected; transfer into occupied slot rejected; name-claim now general; dnssec single-slot refresh
- [ ] Re-genesis mingo (trie-key change → state root changes) — decide after impl
