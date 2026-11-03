# Security audit 2026-11: open decisions

> **Status: open.** Product and design calls that remediation depends on,
> collected from each workstream as it lands. Each item: what was found, the
> options, and a recommendation. Reply per item number; answers are recorded
> here and in the affected beans. Branch `audit-2026-11`, epic `sbo-ax7t`.
> Method and format follow the browserid-ng 2026-11 audit
> (`~/src/browserid-ng/docs/security-audit-2026-11-decisions.md`).

## 1. Where things stand

| Workstream | Bean | Result |
|---|---|---|
| WS1 threat model + spec review | sbo-dl2l | Not started. |
| WS2 conformance vectors | sbo-5t0f | Blocked on WS1. |
| WS3 fuzz + proptest | sbo-qw0z | Blocked on WS1. |
| WS4 never-audited layers | sbo-f8cj | Blocked on WS1. |
| WS5 HTTP / IPC surface | sbo-s4xl | Blocked on WS1. |
| WS6 crypto core / verification | sbo-iye5 | Blocked on WS1. |
| WS7 supply chain / CI / secrets / logging | sbo-ip5k | Blocked on WS1. |
| WS8 PoCs | sbo-cka2 | Blocked on WS4/5/6. |
| WS9 ledger + remediation beans | sbo-q92z | Blocked on WS2–WS8. |

## 2. Decisions

(None yet. WS1 spec findings land here first as Q1..Qn.)

## 3. Already settled by spec edits (no decision needed)

(None yet.)

## 4. Next

WS1 runs alone; its spec decisions come to Dan before WS2–WS8 launch.
