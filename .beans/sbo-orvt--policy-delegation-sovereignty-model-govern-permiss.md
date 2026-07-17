---
# sbo-orvt
title: 'Policy delegation & sovereignty model: govern permission + version-pinning + descendant constraints'
status: todo
type: epic
priority: high
created_at: 2026-07-16T23:32:54Z
updated_at: 2026-07-17T09:28:31Z
---

Design converged with dan (2026-07-16/17). Replaces winner-take-all shadowing with a delegation model that spans strict-hierarchy → revocable → sovereign from one mechanism set. Fixes the sbo-vos1 capture bug as a side effect. Greenfield (no live users) — free to change validation semantics + regenesis.

## The reframe

Sovereignty is not a mode; it is the terms of a delegation, and the terms are frozen by a version PIN. A child policy pins the specific historical version of its ancestor policy it agreed to; that pinned version IS the contract (including any powers the ancestor reserved in it). Parent changes after the pin do not apply until the child voluntarily re-pins forward. This gives a consent-based governance upgrade path — a lockfile for authority — instead of freeze-forever or unilateral-change.

## Primitives

### P1 — `govern` is a distinct capability; a policy object is governed by its PARENT policy, not itself
- Installing/editing a `policy.v2` requires a `govern` permission, resolved against the nearest policy STRICTLY ABOVE the target — never the target's own policy. Kills self-mounting + the irreversible lock-in in sbo-vos1.
- `govern` is NOT implied by `create`/`post`/`*` (governance is meta-authority, outside the content action set). Members holding only `create` can no longer install policies → the sbo-vos1 planted-policy attack is dead.

### P2 — Version pinning (opt-in freeze + consent upgrade)
- A policy links to its ancestor policy via a fully-qualified URI pinned to a specific object CONTENT-HASH (block number carried as a locator hint only — content-hash pin is reorg-safe; finalized state only).
- At creation, the pin MUST be the current latest ancestor version (no cherry-picking a weak historical version).
- At update, the child may keep its pin or advance it to a then-current version (FORWARD-ONLY). It cannot move backward.
- The child's OWN governance (who may update the child policy) resolves against its pinned ancestor version → once pinned, a later ancestor amendment cannot reach in. That is the sovereignty property.
- Absent a pin, a child TRACKS the latest ancestor → the revocable / eminent-domain regime.

### P3 — Descendant-policy constraint clause (the ceiling/template, declarative)
- A parent policy may declare the allowed grants + mandated restrictions for its DIRECT child policies (decided: direct-children-only; each level re-delegates its own template downward, keeping every check local).
- Validated at child create/update: child grants ⊆ template; mandated restrictions present. This is how "any user under /users/* may grant a,b,c but must carry restriction z" is expressed.

### P4 — No-pin restriction (force tracking / strict hierarchy)
- A policy may forbid its direct children from pinning, forcing them to always track latest. Yields the strict top-down / unix-fs regime where the ancestor (admin) always dominates and can retighten at will. mingo does NOT use this; hierarchical-FS-style tenants would.

## The regime spectrum (one mechanism)

- Pinned child → frozen / SOVEREIGN (ancestor cannot reach in; reserved powers in the pinned version persist).
- Unpinned child tracking latest → REVOCABLE / eminent-domain (ancestor changes apply immediately).
- Parent forbids pinning → mandatory tracking / STRICT top-down.

## Consequences to accept

- A parent CANNOT tighten restrictions on an already-pinned child (immune until it re-pins). So an ancestor's only leverage over a non-complying pinned subtree is a COARSE reserved action baked into the pinned version — e.g. "delete the whole subtree."
- Policy history retention becomes consensus-load-bearing but BOUNDED: retain a historical policy version as long as some live policy pins it; refcount by pin; GC when unreferenced.
- Fast-sync interaction (cf mingo-cy17): a snapshot must include every STILL-PINNED historical policy version, not just head, or a fast-synced node cannot authorize writes under a pinned child.
- Ratchet hazard: a momentary over-permissive parent state can be captured permanently by whoever pins during it → treat parent-policy edits as one-way ratchets, never pass through a loose intermediate state.

## Mingo composition (deliberately NOT fully sovereign)

- Root policy (sys-owned) RESERVES `{to: admin(key=sys), can:[delete], on:/communities/<id>/**}` (community-removal) + the illegal-content/abuse restriction, and declares the descendant constraint clause for community policies.
- Root delegates `govern` on `/communities/<id>/` to the board creator identity.
- Communities either PIN root (chartered: permanent self-rule over membership/mods/their own bans, hub keeps ONLY community-removal + the reserved restriction) or stay UNPINNED (managed: hub tracks). Both keep the reserved community-removal.
- Members get NO `govern` → cannot install policies at all.
- Enforcement lever = the reserved community-removal (coarse; the hub cannot tighten a pinned community's policy, so "remove the board" is how it forces compliance). This is the honest-contract version: a community can read its pinned root and see the exact single power the hub retains.
- Ties to mingo-6phv: mingo's credible-delete/takedown mandate is logically incompatible with reserve-nothing sovereign communities — hence the reserved delete is mandatory, not optional.

## Open / to break down at build time

- Exact schema for the pinned-ancestor URI + the descendant constraint clause (policy.v2 → policy.v3?).
- Snapshot format change to carry pinned historical policy versions + the refcount GC rule.
- Migration/regenesis of the mingo chain onto the new root policy shape.
- Whether `govern` is a new ActionType or a permission string outside the action set (lean: outside, so `*` never grants it).
- P4 ceiling byte-exact freezing of reserved grants.

Break into child beans (P1 install-gate, P2 pinning + history, P3 constraint clause, P4 no-pin restriction, mingo regenesis) when moving to implementation.

## Build status (2026-07-17)

- P1 (sbo-whfw): DONE, merged to main (4b28d8e), LIVE via regenesis v5. Closes sbo-vos1.
- P2/P3/P4 (sbo-723r/vqzj/sbo-yxm5): DONE on branch `p234-policy-delegation` in worktree ~/src/sbo-p234, full workspace tests green, NOT pushed. Additive optional fields on policy.v2 (backward-compatible); pin references on-chain content_hash; policy_versions CF + refcount GC; snapshot format json+gzip/2 carrying pinned versions; descendant-constraint clause (direct-children); no-pin flag. NEEDS: dan review + push/merge. Also fixes a latent gap (fast-synced node policies CF was never populated).
- mingo composition (mingo-qjkf): DONE + LIVE as MANAGED (unpinned) communities. Pinned/chartered boards (with reserved-takedown contract) await P2-P4 merge + user-created boards (mingo-gj9r).

Epic left OPEN pending P2-P4 review/merge and the pinned-boards rollout.

## P2-P4 MERGED to main (2026-07-17)

Merge commit 65901c0; full workspace suite green (360 passed, 0 failed). The delegation model (P1 govern + P2 pinning/history + P3 constraint clause + P4 no-pin) is now all on sbo main. Deployed daemon (mingo) still pinned to P1 rev 4b28d8e for the managed-community regenesis; bump SBO_REV to pick up P2-P4 when moving to pinned/chartered boards.

## P2-P4 VALIDATED LIVE (2026-07-17)

mingo live-test S9-S13 all PASS against the production daemon (SBO_REV b6ac8ba): S9 pinning immunity (pinned child governable after ancestor revokes authority; unpinned sibling denied), S10 creation-pin-must-be-latest, S11 forward-only re-pin, S12 descendant-constraint (over-broad grant + missing mandated restriction rejected), S13 forbid_pinning. Each denial carried the exact expected daemon reason. The full delegation model (P1+P2+P3+P4) is now merged, deployed, and live-verified end-to-end.
