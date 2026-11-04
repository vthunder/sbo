<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS7: supply chain, CI, build/deploy, secrets, logging

**Status:** workstream output, 2026-11-04. Epic `sbo-ax7t`, bean `sbo-ip5k`.
Oracle: `docs/design/threat-model.md` (assets: signing keys and keyring,
TurboDA credentials, trust anchors; adversary A9 local attacker on the daemon
host) and WS1 leads D35, D36. Scope decision (Dan, 2026-11-03): from the mingo
repo only the sbo-daemon deployable (`deploy/sbo-daemon/`,
`.github/workflows/deploy-daemon.yml`) and its sandmill-infra app definition
are in scope; everything else in mingo is a lead for a later audit. Nothing in
production code, specs, mingo, infra or any host was changed; `~/src/mingo`
and `~/src/sandmill-infra` were read only.

**Method.** Reviewer pass: run every scanner on `localtest` (cargo-audit
0.22.2, cargo-deny 0.20.2 installed for this, gitleaks 8.30.1), read every
`Cargo.toml` and the lockfile for git and duplicate dependencies, the
deployable's Dockerfile, entrypoint, config and workflow, the daemon's
config/credential handling, the keyring, every `tracing!`/`println!` that can
carry an identifier or secret, and the branch protection on `main`. Skeptic
pass: for each advisory, who pulls the crate and whether a compiled binary
links it; for each finding, what an attacker needs. Deliverables committed
with this report: `.github/workflows/test.yml`,
`.github/workflows/supply-chain.yml`, `.github/dependabot.yml`,
`.cargo/audit.toml`, `deny.toml`, `.gitleaks.toml`,
`crates/sbo-daemon/tests/audit_2026_11_ws7.rs` (1 pass, 1 ignored).

**Headline.** No credential has ever been committed in 514 commits. The
TurboDA, checkpoint and attestor secrets reach the container only through
dokku env and are written 0600 by the entrypoint. The repo had **no CI of
any kind**: `[skip ci]` trailers and `make watch` refer to workflows that do
not exist, and the only required status check on `main` is the external
IP-approval gate. The dependency picture is stale rather than dangerous: 41
RUSTSEC vulnerabilities in the lockfile, of which 26 close with a plain
`cargo update`, 8 more by deleting an **unused** `reqwest 0.11` dependency
from `sbo-core` (it is the only thing holding rustls 0.21), and the remaining
7 are reachable only from the experimental zkVM crate and are ignored with a
review date. The new gate is **red on main until R7-1 and R7-2 land**; that is
intentional, as in browserid-ng Q8.

## 1. Scanner results (localtest, 2026-11-04)

| Scanner | Result | Gate after ignore files |
|---|---|---|
| `cargo audit` | 41 vulnerabilities, 19 warnings (5 unmaintained, 12 unsound, 2 yanked) | **34 red**; all 34 close with R7-1 + R7-2 |
| `cargo deny check` | advisories FAILED, bans ok (35 duplicate-version warnings), licenses FAILED (LGPL via risc0; `sbo-zkvm-methods` has no `license` field), sources ok (git only from `vthunder`, `availproject`) | advisories red (same 34), licenses **green** after allow-listing LGPL for the zkvm subtree and clarifying the workspace crate |
| `gitleaks git` (full history, 514 commits, 5.98 MB) | **no leaks found** | green |
| targeted history grep (`x-api-key`, `bidk_`, `SBO_TURBO_DA_API_KEY=`, `SBO_CHECKPOINT_KEY=`, `SBO_ATTEST_KEY=`, 64-hex `secret_key` values) | nothing outside placeholders | — |

## 2. Dependency advisories

Who pulls what (from `cargo tree -i`, lockfile reverse edges for
feature-gated crates). Three roots explain the whole list:

- **`reqwest 0.11` in `sbo-core`** (`crates/sbo-core/Cargo.toml:23`,
  `rustls-tls`): **no code in sbo-core references reqwest**. It alone pins
  rustls 0.21.12, rustls-webpki 0.101.7, webpki-roots 0.25.4, hyper 0.14 and
  h2 0.3, none of which `cargo update` can move. Every other crate uses
  `reqwest 0.12` (native-tls) from the workspace table.
- **`reqwest 0.12` / `avail-rust` (jsonrpsee)**: rustls 0.23, rustls-webpki
  0.103, webpki-roots 1.0, quinn (http3, feature-gated: not compiled into the
  default members, present in the lockfile), h2 0.4, bytes.
- **risc0 (`sbo-zkvm`, non-default member, Q19 experimental)**: rsa (rzup),
  ruint, zip (circuit-recursion), tracing-subscriber 0.2 (ark), malachite and
  downloader (LGPL).

| Advisory | Crate | Pulled by | Linked by daemon/CLI? | Fix |
|---|---|---|---|---|
| RUSTSEC-2026-0382, -0098, -0099, -0104 | rustls-webpki 0.101.7 | reqwest 0.11 → rustls 0.21 | Yes, into sbo-core (dead code path; no request is ever built) | **R7-2** remove reqwest 0.11 |
| RUSTSEC-2026-0346, -0349 | rustls 0.21.12 | reqwest 0.11 | Yes (dead) | R7-2 |
| RUSTSEC-2026-0381 | webpki-roots 0.25.4 | reqwest 0.11 | Yes (dead) | R7-2 |
| RUSTSEC-2026-0258 | h2 0.3.27 | reqwest 0.11 → hyper 0.14 | Yes (dead) | R7-2 |
| RUSTSEC-2026-0258 | h2 0.4.12 | axum 0.7, reqwest 0.12 | **Yes**: inbound HTTP/2 to the daemon (behind nginx, h1 upstream; direct only on loopback deployments) | **R7-1** `cargo update` → 0.4.20 |
| RUSTSEC-2026-0382, -0098, -0099, -0104, -0049 | rustls-webpki 0.103.8 | hyper-rustls / jsonrpsee via avail-rust | Yes for the Avail RPC client TLS; name-constraint and distrusted-intermediate bugs need a CA-issued cert on the RPC path | R7-1 → 0.103.16 |
| RUSTSEC-2026-0285, -0346, -0348, -0349 | rustls 0.23.35 | avail-rust / hyper-rustls | Yes, client side to `turing-rpc.avail.so`; Brotli 1 GiB only if a hostile server is dialled | R7-1 → 0.23.46 |
| RUSTSEC-2026-0381, -0383 | webpki-roots 1.0.4, webpki-root-certs 1.0.4 | hyper-rustls, rustls-platform-verifier | Yes (root store for the RPC client) | R7-1 → 1.0.11 |
| RUSTSEC-2026-0037, -0185, -0338, -0339, -0340, -0342 | quinn-proto 0.11.13 | reqwest 0.12 http3 (feature off) | No: not compiled | R7-1 → 0.11.19 |
| RUSTSEC-2026-0007 | bytes 1.11.0 | axum, hyper, h2 | Yes; theoretical overflow | R7-1 → 1.12.1 |
| RUSTSEC-2026-0204 | crossbeam-epoch 0.9.18 | crossbeam-deque (rayon) | Yes; `fmt::Pointer` on invalid pointer, not reachable | R7-1 → 0.9.21 |
| RUSTSEC-2026-0418 | libz-sys 1.1.23 | librocksdb-sys | Build script env leak into the build dir; CI/deploy builders only | R7-1 → 1.1.31 |
| RUSTSEC-2026-0410 | zstd-sys 2.0.16 | librocksdb-sys | wasm allocator shim: not our target | R7-1 → 2.1.2 |
| RUSTSEC-2026-0344 | ruzstd 0.6.0 / 0.7.3 | object (backtrace), smoldot (avail-rust) | Decompression bomb; smoldot light-client path | R7-1 → 0.8.3 (0.7.3 line stays until avail-rust moves) |
| RUSTSEC-2025-0137, RUSTSEC-2026-0220 | ruint 1.17.0 | risc0-binfmt | No (zkvm only) | R7-1 → 1.21.1 |
| RUSTSEC-2023-0071 | rsa 0.9.9 | rzup (risc0-build) | No (zkvm build only); **no upstream fix** | ignored, review 2027-02-01 |
| RUSTSEC-2026-0367, -0368, -0369, -0429 | zip 2.4.2 | risc0-circuit-recursion | No (zkvm only); patched only in zip 9 | ignored, review 2027-02-01 |
| RUSTSEC-2025-0055 | tracing-subscriber 0.2.25 | ark-relations (risc0-groth16) | No (zkvm only); 0.2 line pinned by ark | ignored, review 2027-02-01 |
| RUSTSEC-2026-0119 | hickory-proto 0.24.4 | hickory-resolver in sbo-core (`sbo://` TXT lookups) | Encode side only, our own short names | ignored (same entry as browserid-ng), review 2027-02-01 |
| warnings | anyhow, event-listener, keccak (yanked), lru, memmap2, rand 0.8/0.9, tokio 1.48 unsound; instant, libsecp256k1, number_prefix, paste, rustls-pemfile unmaintained; spin yanked | mixed | not failing the gate | pick up with `cargo update` where a release exists |

`cargo update --dry-run` moves 306 packages, including `avail-rust` from
`de07cce1` to `3f2fe9e7` because it is pinned by **branch** (W7-3): a routine
update silently changes the DA client. **R7-1** should therefore be run after
pinning `avail-rust` to a `rev`, then `cargo test --workspace` on localtest,
then commit `Cargo.lock`. Remaining after R7-1 + R7-2: only the seven ignored
ids, all zkvm-only, so the gate is green for everything a deployed binary links.

## 3. CI, build and deploy findings

| # | Finding | Severity | Where | Remediation |
|---|---|---|---|---|
| **W7-1** | No CI existed: no `.github/` at all; `[skip ci]` trailers and `make watch` are vestigial; branch protection on `main` requires only the external `ip-approval-gate` context (enforce_admins on, no reviews, no test). Nothing would have surfaced §2, a broken build, or a failing audit pin. | Medium | repo settings, `.github/` | **Done this WS**: `test.yml` (cargo test on default members + the non-ignored `audit_2026_11` pins, toolchain 1.93.0 matching the deploy image), `supply-chain.yml` (cargo-audit, cargo-deny, gitleaks; push/PR/weekly), `dependabot.yml` (actions only). Remaining: add `test` and `supply-chain` jobs to the required checks on `main` (GitHub settings, infra task). |
| **W7-2** | 41 RUSTSEC advisories, 34 after reasoned ignores; none scanned before. | Medium | `Cargo.lock` | R7-1 `cargo update` (after W7-3), R7-2 (below). |
| **W7-3** | `avail-rust` is a git dependency on `branch = "main"` in three manifests (`sbo-rpc`, `sbo-daemon`, `sbo-cli`). The lockfile pins a commit, but every `cargo update` moves it, and a compromised or merely broken upstream `main` lands silently in the DA client. `deny.toml` `sources` now restricts git deps to the `vthunder` and `availproject` orgs. | Low | `crates/{sbo-rpc,sbo-daemon,sbo-cli}/Cargo.toml` | Pin by `rev`; bump deliberately. |
| **W7-4** | `browserid-core` is pinned at two different revs: `b83cce1` in `sbo-core` and `2582555` in `sbo-capture` and `sbo-cli`, so two copies of the identity/verification library are compiled and the capture side can disagree with the verifier. `sbo-core` carries a "DEV: temporary path dep" comment that no longer matches. | Low | `crates/sbo-core/Cargo.toml:27`, `sbo-capture:12`, `sbo-cli:18` | One workspace-level pin. WS2 may find a behavioural difference. |
| **W7-5** | `sbo-daemon config init` writes `~/.sbo/config.toml` with the process umask (0644) and then tells the operator to put the TurboDA `api_key` in it. On a shared dev box every local user reads the key. The deployed container takes the key from env instead, so production is unaffected. | Low | `crates/sbo-daemon/src/config.rs:369,498` (`fs::write`) | `OpenOptions::mode(0o600)`; test `w7_5_sample_config_holding_the_turbo_da_key_is_owner_only` (ignored, fails today: mode 0644). |
| **W7-6** | `sbo-core` declares `reqwest = "0.11"` with `rustls-tls` and never uses it; it is the sole reason rustls 0.21, webpki 0.101, webpki-roots 0.25, hyper 0.14 and h2 0.3 (8 advisories, no upgrade path) are in every binary. Also the only `rustls` in the daemon (`reqwest 0.12` is native-tls), so the July browserid-ng L11 note (rustls 0.21 EOL) applies here through dead code. | Medium | `crates/sbo-core/Cargo.toml:23` | **R7-2**: delete the dependency. |
| **W7-7** | `sbo-zkvm-methods` has no `license` field (the rest of the workspace inherits `MIT OR Apache-2.0`); cargo-deny reports the crate unlicensed. Clarified in `deny.toml` for now. | Info | `crates/sbo-zkvm/methods/Cargo.toml` | `license.workspace = true`. |
| **W7-8** | Deploy workflow (mingo `deploy-daemon.yml`): every action pinned by mutable tag (`actions/checkout@v4`, `docker/setup-buildx-action@v3`, `docker/login-action@v3`, `docker/build-push-action@v6`), with `packages: write` and the dokku deploy key in the job. Same class as browserid-ng W7-2, same SHAs apply (checkout `3d3c42e5…`, setup-buildx `8d2750c6…`, login `c94ce9fb…`, build-push `10e90e36…`). | Medium | `~/src/mingo/.github/workflows/deploy-daemon.yml` | mingo task bean: SHA-pin + `dependabot.yml` (github-actions). |
| **W7-9** | Same workflow: `ssh-keyscan -H sandmill.org` on every run trusts whatever host key answers (TOFU per run). A network attacker on the runner's path can impersonate the dokku host; the ed25519 deploy key is not disclosed by that, but the deploy reports success against a fake host and the real one is left on the old release. | Low | `deploy-daemon.yml` deploy step | Pin the host key in the workflow (`echo "sandmill.org ssh-ed25519 …" >> known_hosts`), as sandmill-infra `keys/` already records it. |
| **W7-10** | Image also tagged `:latest` (mutable) and the GHCR package is **public** by necessity (dokku pulls unauthenticated). Dokku releases the `:sha` tag, so `:latest` is informational; anyone can pull the daemon image, which contains the release binary, `config.toml` (public endpoints, no secrets) and `entrypoint.sh`. | Info | `deploy-daemon.yml` tags | None; drop `:latest` if nobody uses it. |
| **W7-11** | Dockerfile: base images by floating tag (`rust:1.93-bookworm`, `debian:bookworm-slim`); source obtained by `git clone` over https at a **short** 7-hex `SBO_REV` (prefix ambiguity is theoretical at 7 hex; the pin is not a verified tag or signed commit, GitHub TLS is the trust). Reproducibility only. | Low | `deploy/sbo-daemon/Dockerfile:37,45` | Full 40-hex `SBO_REV`; pin bases by digest if reproducibility is wanted. |

**Image contents (from the Dockerfile).** Runtime layer: `debian:bookworm-slim`
plus `ca-certificates libssl3 libstdc++6`, `/usr/local/bin/sbo-daemon`,
`/app/config.toml`, `/app/entrypoint.sh`. No source, no `.git`, no key, no
env file. `RUST_LOG=sbo_daemon=info,warn`, `SBO_HTTP_BIND=0.0.0.0:5000`,
`HOME=/data`. (Not built locally.)

## 4. Runtime hardening (deployable)

| Aspect | State | Finding |
|---|---|---|
| User | **root** (no `USER`); `/data` (RocksDB state, repos mirror, checkpoint + attestor secret keys, unix socket) root-owned | **W7-12 (Medium)**: any RCE in the daemon (WS5's surface: `/v1/submit`, `/v1/dnssec`, snapshot decode D50) is uid 0 in the namespace and reads `/data/checkpoint-key.json` and `/data/attest-key.json` regardless of their 0600 mode. Same as browserid-ng W7-8; the fix is the same shape: `useradd -r -u 10001 sbo`, `chown` at build, `USER sbo`, plus a one-time chown of the dokku storage dir on the hobby host (infra, `apps/hobby/sbo-daemon.conf`), and `--read-only --tmpfs /tmp --security-opt no-new-privileges` docker-options. |
| Healthcheck | none (`/health` exists) | Low: dokku's zero-downtime check is absent, so a release that fails to bind shows as a 502. `app.json` healthcheck on `/health`. |
| Secrets in | `SBO_TURBO_DA_API_KEY`, `SBO_CHECKPOINT_KEY`, `SBO_ATTEST_KEY` via `dokku config:set` (`sandmill-infra/secrets/sbo-daemon.env.age`); entrypoint writes the two key files 0600 | Fine. The values remain readable in the container environment (`/proc/1/environ`, `docker inspect`) for the life of the container, which is the dokku norm; browserid-ng W7-9 (one age recipient) applies to this file too, cite rather than duplicate. |
| `/data` reset | entrypoint wipes `/data/.sbo`, `/data/repos`, `/data/repos.json` once per marker name | Operational, documented in the file with the 2026-09-18 race. Not a security finding. |
| IPC socket | `/data/daemon.sock`, bound with the process umask, no `set_permissions`, no peer-credential check (`ipc.rs:240`) | In the container only root exists, so moot there; on a dev box any local user who can reach `~/.sbo/daemon.sock` (0755 home dirs on many distros) can issue every IPC command. Routed to WS5 (D-lead: IPC authz) rather than duplicated here. |

## 5. Secrets and keys at rest

- **History**: gitleaks default rules over all 514 commits: no leaks. The
  only 64-hex strings in the tree are test seeds, SRS points and example
  keys. **No credential has ever been committed.**
- **Keyring** (`sbo-core/src/keyring.rs`): directory 0700, `keyring.json` and
  every `<alias>.key` 0600, written to a temp file then renamed. Pinned by
  `keyring_directory_and_key_files_are_owner_only` (passes). Residual: the
  temp file is created at umask and chmod'ed afterwards (microsecond window),
  and no encryption at rest, both documented in the module header. `sbo key
  export` prints the secret to stdout by design and writes `--output` files
  0600.
- **Daemon key files**: `load_checkpoint_key` reads `{"secret_key": hex}`
  without asserting the file mode (entrypoint sets 0600; a hand-made file
  may not be). Low; fold into W7-5.
- **TurboDA credentials**: `config.rs::apply_env_overrides` takes
  `SBO_TURBO_DA_API_KEY[_<app_id>]` from env; the key is sent as `x-api-key`
  over https to `staging.turbo-api.availproject.org`; never logged (the
  `debug!` at `turbo.rs:63-64` prints the endpoint and the first 200 bytes of
  the payload, not the key). `~/.turbo/key-turing` is a path convention on
  the operator's machine, outside this repo; not read.
- **SRS provenance** (`sbo-crypto/src/srs_data.rs`): the first 256 G1 points
  are embedded as bytes with a comment pointing at
  `availproject/avail-core/kate/src/g1_g2_1024.txt` (Filecoin Powers of Tau,
  challenge_19) and a copy of that file sits beside it. Nothing verifies the
  embedded bytes against the source. Info: a unit test comparing the embedded
  array to the text file, or a documented sha256 of both, would make the
  provenance checkable. KZG verification is a stub anyway (D9, Q20).

## 6. Logging

Default filter `info` (`main.rs:1167`), container `sbo_daemon=info,warn`; no
`TraceLayer`, so no per-request access log from the daemon (nginx in front
keeps one). Every `tracing!` and `println!` that can carry an identifier was
read:

| Line | Prints | Asset | Severity |
|---|---|---|---|
| `http.rs:633`, `:824` (`info`) | the auth request id and the requesting origin | the 64-bit request id **is the bearer** that `/auth/status/:id` releases the assertion to (WS1 D37) | **W7-13 Low**: anyone with `dokku logs` can race the page. Log a prefix or the origin only. |
| `turbo.rs:64` (`debug`) | first 200 bytes of every DA submission (SBO headers: `Public-Key`, start of `Auth-Cert`) | public once on chain | Info |
| `sync.rs:1229` (`info`) | name claim `name -> pubkey` | public on chain | Info |
| `sync.rs:1306-1311` | domain name, self-cert verdict | public | Info |
| `main.rs:1496-1533` | whether key files loaded | none | fine |
| `rpc.rs:243` (`-d save-raw-block` only) | full block matrix + header to **`/tmp/sbo-debug/`**, fixed path, `create_dir_all` + `fs::write`, symlink-followable | public chain data; the hazard is the write, not the content: a local user pre-creates `/tmp/sbo-debug` as a symlink and the daemon overwrites files it owns elsewhere (D36) | **W7-14 Low** (debug flag only, never on in the deployment): write under the daemon's own dir (`Config::sbo_dir()/debug`) with `create_dir` + `O_NOFOLLOW`. |
| CLI `da.rs`, `identity.rs`, `domain.rs` | public keys, payloads, aliases | public | fine |

No line logs an API key, a secret key, a session cookie, a client IP or a
presentation in full. There is no analytics in this repo.

## 7. Overlap with browserid-ng WS7

| browserid-ng | Here | Note |
|---|---|---|
| W7-1 no scanning gate | W7-1 (wider: no CI at all) | Same shape of fix; this repo's gate also carries cargo-deny. |
| W7-2 actions by tag | W7-8 (mingo deploy workflow) | Same SHAs; mingo-side bean. |
| W7-3 shared `DOKKU_SSH_KEY` | same key, mingo repo secret | Cited; blast radius unchanged. |
| W7-7 floating base tags | W7-11 | Same verdict (Low, reproducibility). |
| W7-8 containers run as root | W7-12 | Same fix; infra chown on the hobby host instead of the identity host. |
| W7-9 one age recipient | applies to `sbo-daemon.env.age` | Cited; decided there (Q12 (a)). |
| Q7 X-Forwarded-For | same dokku nginx template on the hobby host: `$remote_addr`, overwritten | WS5's rate-limit design can trust the first hop today; declare it in `sbo-daemon.conf` and `audit-host.sh` as browserid-ng decided. |
| L11 rustls 0.21 EOL | W7-6 | Here it is dead code, so the fix is a deletion. |

## 8. What needs Dan's decision

Appended to `docs/security-audit-2026-11-decisions.md` as Q22–Q25:

1. **Q22 gate colour.** Land R7-1 (`cargo update` after pinning `avail-rust`)
   and R7-2 (drop `reqwest 0.11`) on the branch now so the gate is green at PR
   time, or keep the audit rule (no production change on the branch) and
   accept a red gate until the remediation bean lands. browserid-ng chose to
   land the bumps.
2. **Q23 non-root container** (W7-12): coordinated change with a storage
   chown on the hobby host; mingo-side beans.
3. **Q24 required checks on `main`**: add `test` and `supply-chain` next to
   `ip-approval-gate`.
4. **Q25 `avail-rust` pin by rev** (W7-3): pin and bump by hand, or keep
   tracking `main` with the lockfile as the pin.

## 9. Remediation items (for WS9)

| Id | Item | Severity | Lane |
|---|---|---|---|
| R7-1 | pin `avail-rust` by rev (W7-3), `cargo update`, `cargo test --workspace`, commit lockfile | Medium | sbo code |
| R7-2 | delete `reqwest 0.11` from `sbo-core` (W7-6) | Medium | sbo code |
| W7-4 | one `browserid-core` rev across the workspace | Low | sbo code |
| W7-5 | config.toml and key files 0600; assert mode on load | Low | sbo code (test ignored) |
| W7-7 | `license.workspace = true` in `sbo-zkvm-methods` | Info | sbo code |
| W7-13 | do not log the auth request id | Low | sbo code |
| W7-14 | debug dumps under the daemon dir, no symlink following | Low | sbo code |
| W7-1 (rest) | required status checks on `main` | Low | GitHub settings (infra task) |
| W7-8 / W7-9 / W7-11 | SHA-pin actions + dependabot, pin the dokku host key, full-length `SBO_REV` | Medium / Low / Low | mingo task beans |
| W7-12 | `USER` in the Dockerfile, chown `/data` on the hobby host, read-only fs / no-new-privileges, `app.json` healthcheck | Medium | mingo + sandmill-infra task beans |
| Q21 | weekly `make fuzz-smoke` launchd job (with WS3) | Info | dev box |
