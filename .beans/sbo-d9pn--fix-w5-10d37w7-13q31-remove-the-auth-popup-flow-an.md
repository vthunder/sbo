---
# sbo-d9pn
title: 'Fix W5-10/D37/W7-13/Q31: remove the /auth popup flow and the six sign-request IPC commands'
status: completed
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:27:08Z
parent: sbo-ax7t
---

**Low.** `GET /auth` creates a never-expiring pending request for any caller; the 64-bit id is the bearer and is logged at info (W7-13). No client in sbo or mingo uses the flow.

Depends on: **Q31 (open)**; recommendation (a) remove. If (b): TTL sweep, per-source cap, 128-bit ids, stop logging the id.

- [x] Remove routes, IPC commands, `SignRequest` storage
- [x] Acceptance: ws5 `auth_popup_pending_requests_are_bounded` retargeted to 404

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).



## Summary of Changes

Decided Q31 (a). Removed `GET /auth`, `POST /auth/request`, `GET /auth/status/:id` and the popup HTML, `generate_request_id`, `extract_app_name`, `html_escape` and the `SignRequestStore` trait from `http.rs` (`create_router` now needs only `RepoApi`); removed `SignRequest`, `SignRequestStatus`, `SignRequestResult` and the six IPC commands (`SubmitSignRequest`, `ListSignRequests`, `GetSignRequest`, `ApproveSignRequest`, `RejectSignRequest`, `GetSignRequestResult`) from `ipc.rs`; removed `sign_requests` from `DaemonState` and the six handler arms from `main.rs`. The W7-13 info-level id log went with the routes.

Tests: ws5 `auth_popup_pending_requests_are_bounded` un-ignored and retargeted: 1000 `GET /auth` are all 404 and the companion routes are 404; the three pre-audit popup pins (XSS escape, 64-bit id, assertion-to-any-holder) were deleted with the surface they pinned; matrix `unknown_sign_request_is_404_with_no_assertion` replaced by `auth_popup_routes_are_gone` (both modes).
