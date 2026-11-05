---
# sbo-33xa
title: 'Infra (mingo + sandmill-infra): daemon container non-root, /data chown, read-only fs, healthcheck (W7-12/Q27)'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
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
