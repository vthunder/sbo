---
# sbo-ju44
title: 'Infra (mingo): SHA-pin deploy-daemon.yml actions + dependabot, pin the dokku host key, full-length SBO_REV (W7-8/W7-9/W7-11)'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

Executes in `~/src/mingo`, not here. `deploy-daemon.yml` pins every action by mutable tag with `packages: write` and the dokku key (Medium, browserid-ng W7-2 class, same SHAs: checkout `3d3c42e5…`, setup-buildx `8d2750c6…`, login `c94ce9fb…`, build-push `10e90e36…`); `ssh-keyscan` TOFU per run (Low); 7-hex `SBO_REV` (Low).

- [ ] SHA-pin + `.github/dependabot.yml` (github-actions) in mingo
- [ ] Pin the sandmill.org host key in the workflow (sandmill-infra `keys/`)
- [ ] 40-hex `SBO_REV`; drop `:latest` if unused (W7-10)
