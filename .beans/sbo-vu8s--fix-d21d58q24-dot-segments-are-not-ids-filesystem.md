---
# sbo-vu8s
title: 'Fix D21/D58/Q24: dot segments are not ids; filesystem mirror is best-effort with a collision-free layout'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:20:48Z
parent: sbo-ax7t
---

**High.** `Id::new("..")` and `Path::parse("/../")` succeed; `sync.rs:1084-1095` joins on-chain segments into the mirror path verbatim, so `Path: /../../` writes outside the repo dir as the daemon's user (WS8 P4). An id and a collection name share the grammar: once `/c/x` is a file, `/c/x/y` fails `create_dir_all` and the `?` at `sync.rs:834` aborts the block on this node only (one-node fork, D58). `a.b`/`a.tmp` share a temp file.

Depends on: **Q24 (open)**; recommendation (a).

- [x] Grammar: `.` and `..` rejected in `Id::new` / `Path::parse` (and Core spec §Identifier Syntax)
- [x] Mirror best-effort: state DB authoritative, mirror failure logs and never aborts `process_block`; collision-free layout (`<id>.d/` for collections or encoding)
- [x] Acceptance (un-ignore): core ws4 `d21_dot_segments_are_not_valid_ids`; ws3_uri_identity `d21_dot_segments_are_rejected`; WS2 W-ID-01/02, ID-REJ-07/08, PATH-REJ-04/05 out of `EXPECTED_FAIL`; invert WS8 `poc_d21_*`, `poc_d58_*`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- Grammar: `Id::new` rejects `.` and `..` (`DotSegment`), hence `Path::parse` too; Core spec §Identifier Syntax amended (reserved segments; ABNF comment).
- New `sbo_daemon::mirror`: collision-free layout — collections as `<seg>.d/`, objects as `<id>` (a trailing `.d` on an object id is escaped as `%2Ed`), temp files `<name>%tmp`; `%` is outside the id charset so the encoding is injective. `sync.rs` writes through `mirror::write_object` and logs (never propagates) mirror errors in `write_object` and in the transfer move; `main.rs` object/names/domains readers use the same layout.
- Un-ignored core ws4 `d21_dot_segments_are_not_valid_ids`, ws3_wire `d21_dot_segments_are_rejected` (narrowed to `.`/`..`: `...` is an ordinary id per ID-OK-10), EXPECTED_FAIL W-ID-01/02, ID-REJ-07/08, PATH-REJ-04/05 removed from core, wasm and types runners; WS8 `poc_d21_*` / `poc_d58_*` inverted (no longer ignored).
- Operational note: existing mirrors on disk use the old flat layout; the mirror is a view, so a resync (or deleting the repo dir) rebuilds it. mingo-side readers of the mirror, if any, must adopt `<seg>.d/`.
