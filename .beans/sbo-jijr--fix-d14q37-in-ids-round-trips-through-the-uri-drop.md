---
# sbo-jijr
title: 'Fix D14/Q37: '':'' in ids round-trips through the URI; drop percent-encoding'
status: draft
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Low.** `uri.rs:239-330` mis-splits an id containing `:` (`role:mod` parsed as creator `role`); the Core spec's percent-encoding sentence contradicts its own `id_char` set (S23).

Depends on: **Q37 (open)**; recommendation (a) ids are ASCII only.

- [ ] Fix the creator/id split in the URI parser
- [ ] Acceptance (un-ignore): ws3_uri_identity `d14_colon_ids_round_trip_through_the_uri`; WS2 ID-REJ-06 stays a reject
