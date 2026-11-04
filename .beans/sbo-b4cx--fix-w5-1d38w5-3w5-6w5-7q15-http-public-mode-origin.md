---
# sbo-b4cx
title: 'Fix W5-1/D38/W5-3/W5-6/W5-7/Q15: HTTP public mode (origin allowlist, no PNA header, per-source rate limit, submit/dnssec allowlist, read gate everywhere)'
status: todo
type: bug
priority: high
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**High.** `http.rs:300-345` reflects `*` CORS and sets `Access-Control-Allow-Private-Network` on every response while the deployable binds `0.0.0.0:5000` (mingo Dockerfile:68): any web page spends the node's TurboDA credit through `/v1/submit` (WS8 P7). No route answers 429 (W5-3). `/v1/sync-points`, `/v1/snapshot` and `submit` skip the read gate (W5-6, W5-7). Q15 (a).

No open decision (Q30/Q31 are separate beans).

- [ ] `[http] mode = loopback | public` (default by bind address; refuse `0.0.0.0` + loopback)
- [ ] Public mode: drop the PNA layer; `AllowOrigin::list` from config; `/v1/submit` and `/v1/dnssec` gated on Origin ∈ allowlist or `Authorization: Bearer`
- [ ] Per-source limiter keyed on the connection address (treat X-Forwarded-For as advisory; dokku nginx overwrites it, see browserid-ng Q7)
- [ ] `check_read_gate` on sync-points, snapshot, submit
- [ ] Acceptance (un-ignore): `audit_2026_11_authz_matrix.rs` `public_mode_*` (4), spend cells (2), rate-limit cells (2), read-gate cells (2); `audit_2026_11_ws5.rs` matching tests; invert WS8 `poc_w5_1_*`
