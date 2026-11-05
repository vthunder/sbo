---
# sbo-o2c0
title: 'Fix W5-2/Q30: remove /v1/dnssec (submit refreshes evidence itself)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:27:08Z
parent: sbo-ax7t
---

**Medium.** `http.rs::dnssec_v1` runs a live DNSSEC chain walk for any caller and any domain (`needed_by` is caller-chosen); the one remaining caller is mingo-app's `appoint` CLI.

Depends on: **Q30 (open)**; recommendation (a) remove. If (b), fold into the public-mode bean.

- [x] Remove the route (and the mingo `appoint` call; mingo-side note)
- [x] Acceptance (un-ignore / retarget): matrix `public_mode_dnssec_capture_refuses_a_foreign_origin`, `public_mode_flood_on_dnssec_hits_429`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).



## Summary of Changes

Decided Q30 (a). Removed `GET /v1/dnssec` (`dnssec_v1`, `DnssecQuery`, `DnssecWindow`, `DnssecView`, `now_unix`) from `http.rs`. `RepoApi::get_object_raw` stays (the submit path's evidence refresh still reads `/sys/dnssec/<issuer>` through it). `/v1/submit` refreshes issuer evidence itself (`evidence.rs`, unchanged).

Tests: matrix `public_mode_dnssec_capture_refuses_a_foreign_origin` and `public_mode_flood_on_dnssec_hits_429` retargeted to `dnssec_route_is_gone` (404 in both modes); `gated_reads_answer_503_on_object_list_state_root_and_dnssec` dropped the dnssec URI.

**Mingo-side (not done here; sbo-33xa):** `mingo-app`'s `appoint` CLI still calls `GET /v1/dnssec`; it must drop that pre-check and just POST its write to `/v1/submit` (which refreshes evidence and reports `evidence_refreshed`). With sbo-b4cx it also needs the bearer (`SBO_HTTP_BEARER_TOKENS`) since it sends no browser `Origin`.
