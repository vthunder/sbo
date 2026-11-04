---
# sbo-wc85
title: 'Fix D22/S10: protocol maximum for W; _config writes need an explicit grant; only the assertion is judged at authored_at'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:439-460` reads `max_authoring_lag_s` from the collection's own `_config` with no ceiling (a 50-year-old authoring instant is admitted); anyone with `create` there sets it; `authored_at` feeds the presentation expiry. Q9 (a).

- [ ] Cap `W` (reference 24 h) in `collection_max_lag_ms`
- [ ] `_config` writes require an explicit grant (`id: "_config"` restriction or govern-like rule)
- [ ] Certs, warrants, DNSSEC windows at inclusion time; assertion only at `authored_at`
- [ ] Acceptance (un-ignore): ws4 `d22_collection_w_is_capped_by_a_protocol_maximum`; ws3_time_scopes `d22_max_authoring_lag_has_a_protocol_maximum`, `i24_hlc_bound_arithmetic_is_checked`
