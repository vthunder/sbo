---
# sbo-d9pn
title: 'Fix W5-10/D37/W7-13/Q31: remove the /auth popup flow and the six sign-request IPC commands'
status: draft
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Low.** `GET /auth` creates a never-expiring pending request for any caller; the 64-bit id is the bearer and is logged at info (W7-13). No client in sbo or mingo uses the flow.

Depends on: **Q31 (open)**; recommendation (a) remove. If (b): TTL sweep, per-source cap, 128-bit ids, stop logging the id.

- [ ] Remove routes, IPC commands, `SignRequest` storage
- [ ] Acceptance: ws5 `auth_popup_pending_requests_are_bounded` retargeted to 404
