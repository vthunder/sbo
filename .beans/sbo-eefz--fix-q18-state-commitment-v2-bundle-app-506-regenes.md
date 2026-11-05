---
# sbo-eefz
title: 'Fix Q18: state-commitment v2 bundle + app 506 regenesis (carries Q2, Q6, Q8, Q13, Q33, Q39)'
status: in-progress
type: task
priority: high
created_at: 2026-11-04T21:31:36Z
updated_at: 2026-11-05T11:31:30Z
parent: sbo-ax7t
blocking:
    - sbo-xypz
    - sbo-39qi
    - sbo-3q6x
    - sbo-2jtp
    - sbo-yd72
    - sbo-zzx7
---

Coordination bean for every change that alters the state root or needs a regenesis, shipped together once (Q18 (a)): raw-bytes `object_hash` (D3), trie domain separation (D4), the object-versus-container trie rule (W3-4), `brokers.v1` object shape (Q2), bare-key owner removal (Q6), self-certifying Mode B (Q8), explicit `to: owner` grant in presets/root policy (Q13), genesis batch reordered dnssec → domain → sys → root (Q33), strict policy parsing (Q39). Bump the State Commitment spec version, write the migration note, regenerate the mingo genesis (v7), re-run every policy on app 506 through the new owner rule before cutting over.

Depends on: **Q33, Q39 (open)**; Q2, Q6, Q8, Q13, Q18 settled. Blocks: D3, D4, Q6, D57, D5, W3-3 beans.

- [ ] Migration note (`docs/`) and spec version bump
- [ ] Survey app 506 policies for owner admission (Q13) and stray keys (Q39)
- [ ] New genesis batch in mingo (Q33 order, dnssec object, brokers object form)
- [ ] Regenesis and re-sync of da.sandmill.org (mingo-side task)

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes (sbo-side, 2026-11-05)

- Migration note: `docs/state-commitment-v2-migration.md` (v1 -> v2 table,
  the bundled items Q2/Q6/Q8/Q13/Q18/Q33/Q39 plus D3/D4 with their effect on
  genesis and policies, the regenesis procedure for mingo / app 506, and the
  residual empty-root divergence between spec text and implementation).
- Spec version: `specs/SBO State Commitment Specification.md` already
  carries the v2 changelog entry from the specs group; nothing further to
  bump. The umbrella "SBO Protocol v0.5" marker is left alone.
- D4 / W3-4 landed in `sbo-39qi` (same branch).

Still open, not doable in this repo:
- Survey app 506 policies (Q13 owner admission, Q39 stray keys): needs the
  live chain (q4-batch-survey / WS8-WS9).
- New genesis batch in mingo (v7) and the regenesis / re-sync of
  da.sandmill.org: mingo-side and infra tasks.

- [ ] Q41 (a): empty-state root follows the spec (sbo-flzk)

## Requirements for the mingo v6/v7 genesis builder (from the 2026-11 remediation, sbo-3q6x/sbo-yd72/sbo-2jtp)

- Submission order: Mode A = sys identity, root policy; Mode B = dnssec evidence, domain, sys, root (Q33 (b)); everything after the root policy is validated normally.
- _config objects must precede the community policy in the submission: once the community policy governs the subtree it does not grant sys govern, so a later _config is refused.
- Root grant on name claims must be on: "/sys/names/" (container), never "/sys/names/*"; the live v5 grant matches nothing under the container-only rule.
- Every post-root message carries Owner: sys (or a name/email). Bare-key owners and the signer fallback are gone; sbo-cli/sbo-wasm builders without Owner now produce invalid writes.
- Root policy carries {"to":"owner","can":["update","transfer","delete"],"on":"/**"}; community policies resolve nearest-ancestor so each must carry its own owner grants (live cooks/woodworking/homelab grant owners update only).
- Policies: no unknown keys (Q39), absolute patterns, defined roles, at most 32 wildcards per pattern, role depth at most 32. Identity/domain JWTs need typ identity.v1/domain.v1.
- State roots change (D3/D4/Q41 empty root 6f2225cc...); genesisHash is over the submission bytes. Reference fixture: crates/sbo-core/tests/fixtures/mingo-genesis-v6.wire (test keys, Mode A, 13 messages). Migration note: docs/state-commitment-v2-migration.md.
- /sys/trust/dns-root is not in the live genesis; until posted, the IANA library anchors apply (D6 fallback).
