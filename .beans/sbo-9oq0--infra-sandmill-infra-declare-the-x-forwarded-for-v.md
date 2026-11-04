---
# sbo-9oq0
title: 'Infra (sandmill-infra): declare the X-Forwarded-For value for sbo-daemon.conf and assert it in audit-host.sh'
status: todo
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

Executes in sandmill-infra. The dokku nginx template overwrites `X-Forwarded-For` with the connection address (verified for browserid-ng Q7); the rate limiter in the public-mode bean trusts the connection address and should keep working if the template changes.

- [ ] Declare `x-forwarded-for-value` in `apps/hobby/sbo-daemon.conf`; `audit-host.sh` asserts it
