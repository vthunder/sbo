---
# sbo-kcyq
title: 'Fix Q21: install the weekly fuzz-smoke launchd job on the dev box'
status: todo
type: task
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

WS3 shipped `scripts/launchd/org.sandmill.sbo-fuzz-smoke.plist` and `make fuzz-smoke-install` (Sundays 14:00, log `/tmp/sbo-fuzz-smoke.log`). Q21 (a).

- [ ] `make fuzz-smoke-install` on the dev box; confirm the first run
