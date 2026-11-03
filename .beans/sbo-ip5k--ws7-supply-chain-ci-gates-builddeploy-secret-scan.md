---
# sbo-ip5k
title: 'WS7: supply chain, CI gates, build/deploy, secret scan, logging PII'
status: todo
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-03T14:16:04Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

The repo has no CI at all today (no `.github/`; `[skip ci]` trailers and `make watch` are vestigial) — first finding. Create `.github/workflows/test.yml` (cargo test, default-members) and `supply-chain.yml` (cargo-audit, cargo-deny licenses/sources/bans incl. the browserid-core git pin, gitleaks over full history) with SHA-pinned actions, as gates; WS2/WS3 jobs hang off it. Run cargo-audit and gitleaks now on localtest and record results. Review the deployable in `~/src/mingo/deploy/sbo-daemon/` (Dockerfile: root user, healthcheck, read-only fs, pinned base, cloned-at-rev integrity) and `~/src/mingo/.github/workflows/deploy-daemon.yml` (SHA pins, secrets, GHCR package visibility) — overlap with browserid-ng W7 expected, cite rather than duplicate. Config/secrets: TurboDA credentials, `~/.turbo/key-turing`, daemon config.toml, keyring at rest. Logging/analytics PII: emails, keys, warrants, request ids in tracing output; `/tmp/sbo-debug` raw block dumps; HTTP access logs. Dependency review: rocksdb, risc0, avail/subxt pins, dnssec-prover fork status, rustls versions. Findings W7-n.

- [ ] CI workflows created (test + supply-chain), gate status recorded
- [ ] cargo-audit / cargo-deny / gitleaks results
- [ ] Dockerfile + deploy workflow review (cross-repo, cite browserid-ng W7)
- [ ] logging PII review
- [ ] report `docs/security-audit-2026-11-ws7-supply-chain.md`

## Scope decision (Dan, 2026-11-03)

In scope from the mingo repo: only the sbo-daemon deployable — `~/src/mingo/deploy/sbo-daemon/` (Dockerfile, entrypoint.sh, config.toml), `~/src/mingo/.github/workflows/deploy-daemon.yml`, and the sandmill-infra side for that app. mingo-app, mingo-idp, mingo-web and `deploy/mingo/` are OUT of scope: anything noticed there is recorded as a lead for a later separate mingo audit, not as a finding here. Infra-side remediation for the daemon deployable is filed as task beans in mingo's beans, not sbo's.
