---
# sbo-wc85
title: 'Fix D22/S10: protocol maximum for W; _config writes need an explicit grant; only the assertion is judged at authored_at'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:38:29Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:439-460` reads `max_authoring_lag_s` from the collection's own `_config` with no ceiling (a 50-year-old authoring instant is admitted); anyone with `create` there sets it; `authored_at` feeds the presentation expiry. Q9 (a).

- [x] Cap `W` (reference 24 h) in `collection_max_lag_ms`
- [x] `_config` writes require an explicit grant (`id: "_config"` restriction or govern-like rule)
- [x] Certs, warrants, DNSSEC windows at inclusion time; assertion only at `authored_at`
- [x] Acceptance (un-ignore): ws4 `d22_collection_w_is_capped_by_a_protocol_maximum`; ws3_time_scopes `d22_max_authoring_lag_has_a_protocol_maximum`, `i24_hlc_bound_arithmetic_is_checked`

## Summary of Changes

- `sbo-core::hlc`: new `MAX_AUTHORING_LAG_S` (24 h) / `MAX_AUTHORING_LAG_MS`; `Hlc::within_bound` uses saturating arithmetic (I24).
- `sbo-core::schema::validate_collection` rejects `max_authoring_lag_s` above the protocol maximum; the daemon's `collection_max_lag_ms` clamps whatever a stored descriptor says to `[0, MAX_AUTHORING_LAG_MS]`, so a legacy or hostile `_config` cannot widen `W` past it.
- `_config` writes (`<path>/_config`, any schema) are a governance act: `validate_post` requires `govern` on the collection path from its governing policy (`ActionType::Govern`, which `*` never covers), never an ordinary `create`/`update` grant and never the owner fast-path. Genesis mode is unchanged.
- `sbo-core::device_attribution::verify_device_attribution_with_provider_keys`: the assertion stays judged at `authored_at` (the single-instant `verify_at` of browserid-core), and the access cert, config cert and warrant are additionally required to be unexpired at the block's inclusion time; DNSSEC windows were already at inclusion time. A back-dated authoring instant can no longer resurrect an expired cert or warrant.
- Un-ignored `d22_collection_w_is_capped_by_a_protocol_maximum` (ws4), `d22_max_authoring_lag_has_a_protocol_maximum` and `i24_hlc_bound_arithmetic_is_checked` (ws3 time_scopes).
