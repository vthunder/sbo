---
# sbo-jijr
title: 'Fix D14/Q37: '':'' in ids round-trips through the URI; drop percent-encoding'
status: completed
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:20:48Z
parent: sbo-ax7t
---

**Low.** `uri.rs:239-330` mis-splits an id containing `:` (`role:mod` parsed as creator `role`); the Core spec's percent-encoding sentence contradicts its own `id_char` set (S23).

Depends on: **Q37 (open)**; recommendation (a) ids are ASCII only.

- [x] Fix the creator/id split in the URI parser
- [x] Acceptance (un-ignore): ws3_uri_identity `d14_colon_ids_round_trip_through_the_uri`; WS2 ID-REJ-06 stays a reject

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `SboRawUri::id()` returns the whole last path segment (no `:` split); `creator()` always `None` (creator is an attribute, not an addressing element). Module doc grammar updated; `parse_creator_id` unit test replaced by `colon_in_id_is_not_a_creator_prefix` (decision changed the pinned behaviour).
- Core spec §Identifier Syntax: percent-encoding sentence replaced by "ASCII only, no percent-encoding"; ID-REJ-06 stays a reject.
- Un-ignored `d14_colon_ids_round_trip_through_the_uri`.
