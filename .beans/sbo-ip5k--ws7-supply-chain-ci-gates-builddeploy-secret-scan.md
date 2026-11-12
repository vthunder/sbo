---
# sbo-ip5k
title: 'WS7: supply chain, CI gates, build/deploy, secret scan, logging PII'
status: completed
type: task
priority: normal
created_at: 2026-11-03T08:06:40Z
updated_at: 2026-11-04T20:51:38Z
parent: sbo-ax7t
blocked_by:
    - sbo-dl2l
---

The repo has no CI at all today (no `.github/`; `[skip ci]` trailers and `make watch` are vestigial) — first finding. Create `.github/workflows/test.yml` (cargo test, default-members) and `supply-chain.yml` (cargo-audit, cargo-deny licenses/sources/bans incl. the browserid-core git pin, gitleaks over full history) with SHA-pinned actions, as gates; WS2/WS3 jobs hang off it. Run cargo-audit and gitleaks now on localtest and record results. Review the deployable in `~/src/mingo/deploy/sbo-daemon/` (Dockerfile: root user, healthcheck, read-only fs, pinned base, cloned-at-rev integrity) and `~/src/mingo/.github/workflows/deploy-daemon.yml` (SHA pins, secrets, GHCR package visibility) — overlap with browserid-ng W7 expected, cite rather than duplicate. Config/secrets: TurboDA credentials, `~/.turbo/key-turing`, daemon config.toml, keyring at rest. Logging/analytics PII: emails, keys, warrants, request ids in tracing output; `/tmp/sbo-debug` raw block dumps; HTTP access logs. Dependency review: rocksdb, risc0, avail/subxt pins, dnssec-prover fork status, rustls versions. Findings W7-n.

- [x] CI workflows created (test + supply-chain), gate status recorded
- [x] cargo-audit / cargo-deny / gitleaks results
- [x] Dockerfile + deploy workflow review (cross-repo, cite browserid-ng W7)
- [x] logging PII review
- [x] report `docs/security-audit-2026-11-ws7-supply-chain.md`

## Scope decision (Dan, 2026-11-03)

In scope from the mingo repo: only the sbo-daemon deployable — `~/src/mingo/deploy/sbo-daemon/` (Dockerfile, entrypoint.sh, config.toml), `~/src/mingo/.github/workflows/deploy-daemon.yml`, and the sandmill-infra side for that app. mingo-app, mingo-idp, mingo-web and `deploy/mingo/` are OUT of scope: anything noticed there is recorded as a lead for a later separate mingo audit, not as a finding here. Infra-side remediation for the daemon deployable is filed as task beans in mingo's beans, not sbo's.

## Decisions affecting this workstream (settled 2026-11-04, see docs/security-audit-2026-11-decisions.md)
- Q21 (a) weekly fuzz-smoke launchd job is a WS7/WS3 shared item.

## Summary of Changes

Done 2026-11-04 (report `docs/security-audit-2026-11-ws7-supply-chain.md`). Added `.github/workflows/test.yml` and `supply-chain.yml` (cargo-audit, cargo-deny, gitleaks; SHA-pinned actions), `.github/dependabot.yml` (actions only), `.cargo/audit.toml`, `deny.toml`, `.gitleaks.toml`, `crates/sbo-daemon/tests/audit_2026_11_ws7.rs` (1 pass, 1 ignored: W7-5). Scanners on localtest: 41 RUSTSEC vulns (34 after reasoned zkvm-only ignores), all closable by `cargo update` + deleting the unused `reqwest 0.11` in sbo-core; cargo-deny licenses/sources/bans green; gitleaks clean over 514 commits. Findings W7-1..W7-14: no CI (W7-1), advisories (W7-2), avail-rust by branch (W7-3), two browserid-core revs (W7-4), config.toml 0644 with the TurboDA key (W7-5, ignored test), unused reqwest 0.11 holding rustls 0.21 (W7-6, Medium), unlicensed zkvm-methods (W7-7), mingo deploy workflow actions by tag (W7-8, Medium), ssh-keyscan TOFU (W7-9), :latest/public GHCR (W7-10), floating bases + short SBO_REV (W7-11), container runs as root (W7-12, Medium), auth request id logged (W7-13), /tmp/sbo-debug symlink-followable (W7-14). Decisions Q26–Q29 appended (WS4 holds Q22–Q25). Infra-side items for mingo/sandmill-infra task beans: W7-8, W7-9, W7-11, W7-12, required checks on main.
