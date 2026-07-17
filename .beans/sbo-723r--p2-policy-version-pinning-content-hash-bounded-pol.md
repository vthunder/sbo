---
# sbo-723r
title: 'P2: policy version-pinning (content-hash) + bounded policy-history retention'
status: completed
type: feature
priority: normal
created_at: 2026-07-16T23:40:18Z
updated_at: 2026-07-17T00:23:01Z
parent: sbo-orvt
blocked_by:
    - sbo-whfw
---

Part of sbo-orvt. Opt-in frozen sovereignty + consent-based upgrade.

- A policy links to its ancestor via a fully-qualified URI pinned to the ancestor object's CONTENT-HASH (block number = locator hint only; content-hash pin is reorg-safe; finalized state only).
- At creation the pin MUST be the current latest ancestor version. At update, keep the pin or advance FORWARD to a then-current version (never backward).
- The child's own governance resolves against its PINNED ancestor version → later ancestor amendments cannot reach in (the sovereignty property). Absent a pin, the child TRACKS latest (revocable/eminent-domain regime).
- History retention: retain a policy version as long as some live policy pins it; refcount by pin; GC when unreferenced.
- Fast-sync (cf mingo-cy17): snapshots MUST include every still-pinned historical policy version, or a fast-synced node can't authorize writes under a pinned child.
- Ratchet hazard: a transient permissive ancestor state can be captured permanently by a pin → treat ancestor-policy edits as one-way ratchets.

## Todos
- [ ] policy schema: pinned-ancestor URI field (policy.v2 -> v3?)
- [ ] resolve_policy: honor pin (historical lookup) vs track-latest
- [ ] validate: creation pin == latest; update pin forward-only
- [ ] policy-version history store + refcount-by-pin GC
- [ ] snapshot format: carry still-pinned historical versions
- [ ] tests: pinned child immune to ancestor change; forward-only; fast-sync authorizes under pin



## Resolution (done, commit db14faf)
policy.v2 kept backward-compatible via an optional `pin` field. Policies CF value is now a PolicyEntry (policy + on-chain content-hash + block); historical versions live in a new policy_versions CF, refcounted by pin (policy_pinrefs CF), GC'd on zero. require_govern resolves a pinned child's governance against its pinned ancestor version. Creation pin==latest; update keep-or-forward (backward rejected). Snapshot bumped to json+gzip/2 (SnapshotPayload) carrying still-pinned versions; verify_and_load rebuilds the derived policy index + versions + refcounts. Design decision: no policy.v3 bump — additive optional fields on policy.v2, and the pin references the on-chain content_hash (not a re-serialized Policy, whose HashMap roles would be non-deterministic).
