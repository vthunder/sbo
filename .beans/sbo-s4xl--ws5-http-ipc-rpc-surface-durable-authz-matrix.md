---
# sbo-s4xl
title: 'WS5: HTTP / IPC / RPC surface + durable authz matrix'
status: todo
type: task
priority: high
created_at: 2026-11-03T08:06:39Z
updated_at: 2026-11-03T08:06:40Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

Daemon HTTP (`sbo-daemon/src/http.rs`): `/auth`, `/auth/request`, `/auth/status/:request_id`, `/health`, `/v1/object`, `/v1/list`, `/v1/submit`, `/v1/state-root`, `/v1/sync-points`, `/v1/snapshot`, `/v1/dnssec`; the `?repo=` selector and default_repo; CORS/set-header config; the auth popup page (XSS, open redirect, origin binding of the auth request/status pair, request-id entropy and polling); the submit gate (authz, body caps, replay/jti nonces, rate limiting, error enumeration of identities/names); proof endpoints (resource cost of `proof=1`, snapshot size); outbound fetches reachable from requests (status lists, DNSSEC, sbo:// TXT → RPC endpoint selection: SSRF/redirect/private-range guards). IPC (`ipc.rs`): unix socket path and mode, who can issue which commands, framing limits. Avail RPC/TurboDA clients (`sbo-rpc`, `sbo-avail`, `turbo.rs`): TLS, endpoint trust, credential handling. Rate limiting and X-Forwarded-For (deployed behind dokku nginx, same as browserid-ng W5-6). Deliverable: a durable authz matrix test (route × principal → expected status) in `sbo-daemon/tests/audit_2026_11_authz_matrix.rs`, failing cells ignored with AUDIT-2026-11 ids. Findings W5-n.

- [ ] route inventory + principal model
- [ ] authz matrix test
- [ ] CSRF / redirect / SSRF / limits / enumeration pass
- [ ] report `docs/security-audit-2026-11-ws5-http-surface.md`
