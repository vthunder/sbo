---
# sbo-33xa
title: 'Infra (mingo + sandmill-infra): daemon container non-root, /data chown, read-only fs, healthcheck (W7-12/Q27)'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:54:51Z
parent: sbo-ax7t
blocked_by:
    - sbo-b4cx
---

Executes in `~/src/mingo/deploy/sbo-daemon/` and sandmill-infra `apps/hobby/sbo-daemon.conf`. The container runs as root with checkpoint and attestor secret keys, state and the socket on `/data` (Medium; browserid-ng W7-8 class).

Depends on: **Q27 (open)**; recommendation (a).

- [ ] `useradd -r -u 10001 sbo`, chown at build, `USER sbo`
- [ ] One-time chown of the dokku storage dir on the hobby host
- [ ] `--read-only --tmpfs /tmp --security-opt no-new-privileges` docker-options; `app.json` healthcheck on `/health`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Deploy-time changes surfaced by the 2026-11 remediation (mingo side)

- The daemon binds 0.0.0.0:5000 in the container, which now derives HTTP public mode. Set SBO_HTTP_ALLOWED_ORIGINS=https://mingo.place (plus any other web origins) and SBO_HTTP_BEARER_TOKENS=<secret> for the appoint CLI and other non-browser submitters, or /v1/submit answers 401/403 for everyone after deploy. Tunables: [http] reads_per_minute (600) and spends_per_minute (60) per source IP; /health unchanged (sbo-b4cx).
- mingo-app appoint must drop its /v1/dnssec pre-check (route removed, sbo-o2c0) and POST straight to /v1/submit with the bearer.
- The live genesis root policy grants on /sys/names/* which matches nothing under the container-only on rule; new name claims are denied until the root policy is amended via govern to /sys/names/ or the regenesis (sbo-eefz) lands with the corrected preset (sbo-hw7b).
- The filesystem mirror layout changed to <seg>.d/ directories; the mirror is a view and a resync rebuilds it (sbo-vu8s).
- The image COPYs config.toml 0644; the daemon now warns (and refuses if the file holds a credential). Make it 0600 in the Dockerfile (sbo-hs4r).
