---
# sbo-b4cx
title: 'Fix W5-1/D38/W5-3/W5-6/W5-7/Q15: HTTP public mode (origin allowlist, no PNA header, per-source rate limit, submit/dnssec allowlist, read gate everywhere)'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:27:08Z
parent: sbo-ax7t
---

**High.** `http.rs:300-345` reflects `*` CORS and sets `Access-Control-Allow-Private-Network` on every response while the deployable binds `0.0.0.0:5000` (mingo Dockerfile:68): any web page spends the node's TurboDA credit through `/v1/submit` (WS8 P7). No route answers 429 (W5-3). `/v1/sync-points`, `/v1/snapshot` and `submit` skip the read gate (W5-6, W5-7). Q15 (a).

No open decision (Q30/Q31 are separate beans).

- [x] `[http] mode = loopback | public` (default by bind address; refuse `0.0.0.0` + loopback)
- [x] Public mode: drop the PNA layer; `AllowOrigin::list` from config; `/v1/submit` and `/v1/dnssec` gated on Origin ∈ allowlist or `Authorization: Bearer`
- [x] Per-source limiter keyed on the connection address (treat X-Forwarded-For as advisory; dokku nginx overwrites it, see browserid-ng Q7)
- [x] `check_read_gate` on sync-points, snapshot, submit
- [x] Acceptance (un-ignore): `audit_2026_11_authz_matrix.rs` `public_mode_*` (4), spend cells (2), rate-limit cells (2), read-gate cells (2); `audit_2026_11_ws5.rs` matching tests; invert WS8 `poc_w5_1_*`



## Summary of Changes

Decided Q15 (a). `crates/sbo-daemon/src/http.rs` now has two exposure modes (`HttpMode::{Loopback, Public}`, `HttpOptions`, `create_router_with`):

- **loopback** keeps the localhost convenience behaviour (open CORS, private-network header, no limits).
- **public**: `AllowOrigin::list` from `allowed_origins`, no PNA layer, `authorization` added to allowed headers; an admission middleware (`public_admission`) runs a per-source token-bucket limiter keyed on `ConnectInfo` (`X-Forwarded-For` is never read; `/health` and `OPTIONS` are exempt) with independent read (600/min) and spend (60/min) budgets, then gates `POST /v1/submit` on a configured bearer (401 when wrong/missing) or an allowlisted `Origin` (403 when foreign). `run_server` serves with `into_make_service_with_connect_info`.
- `check_read_gate` added to `/v1/sync-points`, `/v1/snapshot` and `/v1/submit` (W5-6, W5-7); `ApiError::{unauthorized, forbidden, too_many_requests}` added.

`config.rs`: new `[http]` section (`bind`, `mode`, `allowed_origins`, `bearer_tokens`, `reads_per_minute`, `spends_per_minute`), `HttpConfig::effective_mode` (derived from the bind address when `mode` is unset) and `HttpConfig::resolve`, which refuses `mode = "loopback"` on a non-loopback bind. Env overrides `SBO_HTTP_BIND` (unchanged name), `SBO_HTTP_MODE`, `SBO_HTTP_ALLOWED_ORIGINS`, `SBO_HTTP_BEARER_TOKENS`. `main.rs` resolves the options before spawning the server so a bad combination fails the start.

Tests: `audit_2026_11_authz_matrix.rs` rewritten for the public-mode default (every previously ignored cell un-ignored: `public_mode_submit_refuses_a_foreign_origin`, `public_mode_submit_refuses_an_anonymous_caller_without_bearer`, `public_mode_cors_does_not_reflect_a_foreign_origin`, `public_mode_does_not_set_private_network_header`, `public_mode_flood_on_submit_hits_429`, `gated_sync_points_and_snapshot_answer_503`, `gated_submit_is_refused`), the `today_*` pins renamed `loopback_mode_*`, new bearer / empty-allowlist / preflight / read-flood / independent-budget cells; WS8 `poc_w5_1_*` inverted (preflight refused, foreign POST never reaches `submit()`). 25 matrix + 2 PoC tests pass.

**Mingo-side (sbo-33xa carries it):** the deployed daemon binds `0.0.0.0:5000`, so it is public mode by derivation. The container must set `SBO_HTTP_ALLOWED_ORIGINS=https://mingo.place` (plus any other mingo-web origin) via `dokku config:set sbo-daemon ...` or `[http] allowed_origins` in `deploy/sbo-daemon/config.toml`, and `SBO_HTTP_BEARER_TOKENS=<secret>` for the `appoint` CLI / any non-browser submitter. Without either, `/v1/submit` answers 401/403 for everyone after deploy. `/health` is unchanged.
