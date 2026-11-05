---
# sbo-vu8s
title: 'Fix D21/D58/Q24: dot segments are not ids; filesystem mirror is best-effort with a collision-free layout'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**High.** `Id::new("..")` and `Path::parse("/../")` succeed; `sync.rs:1084-1095` joins on-chain segments into the mirror path verbatim, so `Path: /../../` writes outside the repo dir as the daemon's user (WS8 P4). An id and a collection name share the grammar: once `/c/x` is a file, `/c/x/y` fails `create_dir_all` and the `?` at `sync.rs:834` aborts the block on this node only (one-node fork, D58). `a.b`/`a.tmp` share a temp file.

Depends on: **Q24 (open)**; recommendation (a).

- [ ] Grammar: `.` and `..` rejected in `Id::new` / `Path::parse` (and Core spec §Identifier Syntax)
- [ ] Mirror best-effort: state DB authoritative, mirror failure logs and never aborts `process_block`; collision-free layout (`<id>.d/` for collections or encoding)
- [ ] Acceptance (un-ignore): core ws4 `d21_dot_segments_are_not_valid_ids`; ws3_uri_identity `d21_dot_segments_are_rejected`; WS2 W-ID-01/02, ID-REJ-07/08, PATH-REJ-04/05 out of `EXPECTED_FAIL`; invert WS8 `poc_d21_*`, `poc_d58_*`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
