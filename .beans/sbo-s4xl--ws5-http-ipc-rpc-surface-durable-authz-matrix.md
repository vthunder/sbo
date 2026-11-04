---
# sbo-s4xl
title: 'WS5: HTTP / IPC / RPC surface + durable authz matrix'
status: completed
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-04T20:51:21Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

Daemon HTTP (`sbo-daemon/src/http.rs`): `/auth`, `/auth/request`, `/auth/status/:request_id`, `/health`, `/v1/object`, `/v1/list`, `/v1/submit`, `/v1/state-root`, `/v1/sync-points`, `/v1/snapshot`, `/v1/dnssec`; the `?repo=` selector and default_repo; CORS/set-header config; the auth popup page (XSS, open redirect, origin binding of the auth request/status pair, request-id entropy and polling); the submit gate (authz, body caps, replay/jti nonces, rate limiting, error enumeration of identities/names); proof endpoints (resource cost of `proof=1`, snapshot size); outbound fetches reachable from requests (status lists, DNSSEC, sbo:// TXT → RPC endpoint selection: SSRF/redirect/private-range guards). IPC (`ipc.rs`): unix socket path and mode, who can issue which commands, framing limits. Avail RPC/TurboDA clients (`sbo-rpc`, `sbo-avail`, `turbo.rs`): TLS, endpoint trust, credential handling. Rate limiting and X-Forwarded-For (deployed behind dokku nginx, same as browserid-ng W5-6). Deliverable: a durable authz matrix test (route × principal → expected status) in `sbo-daemon/tests/audit_2026_11_authz_matrix.rs`, failing cells ignored with AUDIT-2026-11 ids. Findings W5-n.

- [x] route inventory + principal model
- [x] authz matrix test
- [x] CSRF / redirect / SSRF / limits / enumeration pass
- [x] report `docs/security-audit-2026-11-ws5-http-surface.md`

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q15 (a): loopback mode keeps today's behaviour; public mode drops the private-network header, CORS restricted to a configured origin list, per-source rate limits, operator allowlist (origin or bearer) for /v1/submit and /v1/dnssec. Matrix expectations are written against public mode.

## Summary of Changes

Skeptic pass done 2026-11-04. 11 routes, 23 IPC commands, 3 principals (anonymous / foreign origin / allowed origin) plus the read-gate axis. WS1 leads: D38, D19, D18, D52, D50, D20 confirmed; D37 partial (XSS and id-entropy halves refuted). Findings W5-1..W5-10: High W5-1 (public `0.0.0.0:5000` bind with `*` CORS + `Access-Control-Allow-Private-Network`, any page spends the node TurboDA credit); Medium W5-2 (`/v1/dnssec` resolver amplifier), W5-3 (no 429 anywhere), W5-4 (submit-gate status fetch dials private hosts, follows redirects, host != authority; downgraded from High: needs an attacker DNSSEC IdP + an admitted write), W5-5 (bootstrap snapshot fetch follows redirects; 254 KiB gzip inflates to 768 MiB peak), W5-8 (IPC socket 0755), W5-9 (evidence capture driven by unverified presentation claims before any signature check); Low W5-6 (sync-points/snapshot skip the read gate), W5-7 (submit ignores the gate), W5-10 (sign requests created by any GET, never expire). 9 leads refuted with tests or reading. Tests: `crates/sbo-daemon/tests/audit_2026_11_authz_matrix.rs` 12 pass / 9 ignored, `audit_2026_11_ws5.rs` 8 pass / 6 ignored; every ignored test confirmed failing today on localtest. Report `docs/security-audit-2026-11-ws5-http-surface.md`; decisions Q22 (remove `/v1/dnssec`?) and Q23 (remove the unused `/auth` popup flow?) appended. No production code changed, no dependency changes.
