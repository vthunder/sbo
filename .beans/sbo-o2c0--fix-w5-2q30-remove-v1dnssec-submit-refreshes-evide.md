---
# sbo-o2c0
title: 'Fix W5-2/Q30: remove /v1/dnssec (submit refreshes evidence itself)'
status: draft
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Medium.** `http.rs::dnssec_v1` runs a live DNSSEC chain walk for any caller and any domain (`needed_by` is caller-chosen); the one remaining caller is mingo-app's `appoint` CLI.

Depends on: **Q30 (open)**; recommendation (a) remove. If (b), fold into the public-mode bean.

- [ ] Remove the route (and the mingo `appoint` call; mingo-side note)
- [ ] Acceptance (un-ignore / retarget): matrix `public_mode_dnssec_capture_refuses_a_foreign_origin`, `public_mode_flood_on_dnssec_hits_429`
