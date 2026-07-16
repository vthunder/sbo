---
# sbo-qv95
title: 'Global (path,id) uniqueness: drop creator from trie key'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-16T14:15:05Z
updated_at: 2026-07-16T15:38:59Z
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
- [x] Proposal doc written + decisions resolved with dan (point-key; reorg/overlay normative paragraph; no delete cooldown; creator out of reference/URI grammar; freed-slot clarified)
- [x] Applied to all 10 specs (commit 9809152); consistency swept (zero (path,creator,id)/[creator:]); fixed self-authorizing /sys/dnssec wording + renamed Creator-as-Path-Segment heading→Object-Identity-in-the-Trie w/ inbound anchors
- [x] Implemented in sbo (workspace builds, 33 suites green, clippy clean, zkVM builds+tests pass — image-id unchanged). Reviewer caught + fixed a real bug: creator must be preserved on update (immutable) or the overlay drops valid self-auth /sys/dnssec refreshes; added regression test update_by_different_signer_preserves_immutable_creator. Reorg re-resolution is moot (daemon is forward-only today) — flagged for when reorg handling lands.
- [ ] mingo: collision-safe live ids (app.js); verify genesis/seed/poster unaffected
- [x] tests/global_uniqueness.rs: two-creators-rejected, transfer-into-occupied-rejected, delete-frees-slot, self-auth-single-slot, creator-immutable-on-update, proof round-trip; overlay supersession test in state_view.rs; name-claim general+anti-hijack via existing suites
- [ ] Re-genesis mingo (trie-key change → state root changes) — decide after impl
