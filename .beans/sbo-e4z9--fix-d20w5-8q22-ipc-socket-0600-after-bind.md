---
# sbo-e4z9
title: 'Fix D20/W5-8/Q22: IPC socket 0600 after bind'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T08:40:30Z
parent: sbo-ax7t
---

**Medium.** `ipc.rs:242` binds under the process umask (measured 0755); every command (`Shutdown`, `ApproveSignRequest`, `RepoAdd` any path, `Submit`) needs only socket access. `RepoRemove` arbitrary delete was refuted.

Depends on: **Q22 (open)**; recommendation (a).

- [ ] `set_permissions(0o600)` after bind, `0700` parent
- [ ] Acceptance (un-ignore): ws4 `d20_ipc_socket_is_owner_only`; ws5 `ipc_socket_is_created_mode_0600`

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).
