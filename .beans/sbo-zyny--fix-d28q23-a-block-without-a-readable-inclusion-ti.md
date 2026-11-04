---
# sbo-zyny
title: 'Fix D28/Q23: a block without a readable inclusion time is a fetch failure, never processed'
status: draft
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `rpc.rs:399-410` treats a missing timestamp as non-fatal; `validate.rs:2085` then evaluates attestations at `t = 0` (bans lift) and skips the HLC bound. WS2 TIME-01: two nodes on the same chain data disagree about a banned writer.

Depends on: **Q23 (open)**; recommendation (a).

- [ ] Missing timestamp → retry like 'block not available'
- [ ] Acceptance (un-ignore): ws4 `d28_unknown_inclusion_time_does_not_lift_a_ban`, `d28_unknown_inclusion_time_does_not_skip_the_hlc_bound`; WS2 TIME-01 out of the daemon runner's `EXPECTED_FAIL`
