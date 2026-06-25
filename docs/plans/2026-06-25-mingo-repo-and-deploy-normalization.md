# Plan — extract `vthunder/mingo` + normalize/fast deploys

**Date:** 2026-06-25
**Goal:** Move the Mingo reference implementation out of `vthunder/sbo` (which
becomes specs-only) into a new `vthunder/mingo` repo with deploy artifacts in
version control, and make deploys **fast** (the common change — an SPA tweak —
should ship in seconds; a code change should never pay the rocksdb compile or a
chain resync).

## Decisions (locked)
- **New repo `vthunder/mingo`** at `~/src/mingo`. `vthunder/sbo` keeps only specs
  (`specs/`, `docs/`, spec markdown); `reference_impl/` is removed from it.
- **`browserid-core` via Cargo git dependency, pinned `rev`** (`{ git =
  "https://github.com/vthunder/browserid-ng", rev = "…" }`). It stays canonical in
  `browserid-ng` (shared with the broker `id` app). browserid-ng is **public**, so
  the Docker `cargo` fetch needs **no deploy token**. Bumping it is a deliberate
  rev change.
- **Build on the dokku host via `git push`** (no CI yet), but with a **cargo-chef
  layered Dockerfile** + BuildKit cache mounts so rebuilds are fast.
- One **Cargo workspace** (shared `target/` → shared dep cache across both binaries).

## Current reality (what we're cleaning up)
- Implementation is all in `sbo/reference_impl/`: crates `sbo-core`, `sbo-crypto`,
  `sbo-types`, `sbo-rpc`, `sbo-daemon`, `sbo-avail`, `sbo-capture`, `sbo-cli`,
  `sbo-wasm`, `sbo-zkvm`, `mingo-idp`, plus the `mingo-web` SPA. `sbo-core` has a
  **path-dep on `browserid-core`** (attribution verify), which is canonical in
  `browserid-ng`.
- Two dokku apps, each a **flattened copy** of a subset + vendored `browserid-core`,
  with hand-written Dockerfiles that lived **only on the dokku host** (recovered by
  `git clone dokku@sandmill.org:<app>` after a power cut). Secrets committed in
  `config.toml`.
  - `sbo-daemon` → `da.sandmill.org`. Members: sbo-daemon/core/rpc/types/crypto.
  - `mingo` (`mingo-idp` binary) → `mingo.place`; also serves the `mingo-web` SPA
    same-origin. Members: browserid-core, mingo-idp.

## Target repo layout
```
mingo/                         # vthunder/mingo
  Cargo.toml                   # one workspace; browserid-core via git rev dep
  crates/
    sbo-core/ sbo-crypto/ sbo-types/ sbo-rpc/
    sbo-daemon/                # bin → da.sandmill.org
    sbo-avail/ sbo-capture/ sbo-cli/ sbo-wasm/ sbo-zkvm/
    mingo-idp/                 # bin → mingo.place (serves the SPA)
  web/mingo-web/               # static SPA (no build step)
  deploy/
    sbo-daemon/{Dockerfile,entrypoint.sh,config.toml}
    mingo/{Dockerfile,entrypoint.sh}
  Makefile                     # make deploy-daemon / deploy-mingo
  DEPLOYMENT.md                # this doc, trimmed to a runbook
```
`sbo` repo: delete `reference_impl/`, leave a README pointer to `vthunder/mingo`.

## Fast-deploy design (the priority)

### A. Rust build — cargo-chef + cache mounts
Today `COPY . . && cargo build` lets any file change re-trigger cargo, and a cache
miss = full rocksdb C++ recompile. Replace with the cargo-chef pattern so the
**dependency layer (incl. rocksdb) is keyed only on `Cargo.lock`**:
```dockerfile
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler
COPY --from=planner /src/recipe.json recipe.json
# Dep layer: only rebuilds when Cargo.lock changes. rocksdb compiled once.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo chef cook --release -p sbo-daemon --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p sbo-daemon && cp target/release/sbo-daemon /sbo-daemon
```
→ App-code change recompiles only our crates (seconds–low minutes), never rocksdb.

### B. SPA changes must never touch Rust
Copy `web/mingo-web` **only in the runtime stage**, after the build stage. An
`app.js` edit then reuses the cached binary layer entirely → **deploy in seconds**.
```dockerfile
FROM debian:bookworm-slim
COPY --from=build /mingo-idp /usr/local/bin/mingo-idp
COPY crates/mingo-idp/static /app/static
COPY web/mingo-web /app/mingo-web        # ← last layer; SPA-only deploys stop here
```

### C. No resync on deploy (done)
State persists on the `/data` dokku volume (fix already shipped: `HOME=/data` so the
RocksDB index at `$HOME/.sbo/...` lands on the persistent mount; entrypoint
self-heals a head/state mismatch by resetting the head to backfill). The daemon
serves reads from persisted state immediately on boot; chain sync catches up in the
background. So "deploy → serving" is fast regardless of sync.

### D. Cold-start resync (optional, later)
From an empty volume, RPC-only sync replays genesis→tip one block at a time
(~15–20 min for ~3.6k blocks). Only happens on volume loss. Future wins, low
priority now that state persists: concurrent/batched RPC range fetch; run
avail-light; or ship/restore a state snapshot.

### E. Build off-host (optional, later)
GitHub Actions → registry cache → `dokku git:from-image`. Removes build load from
the host. Deferred — chose host-build for now.

## Migration steps
1. `gh repo create vthunder/mingo` (public? match sbo). Create `~/src/mingo`.
2. Move `sbo/reference_impl/*` → `mingo/crates/*` + `mingo/web/mingo-web`
   (`git filter-repo` if history wanted). Add workspace `Cargo.toml`.
3. Swap `sbo-core`'s `browserid-core` path-dep → git rev dep (pin current
   `browserid-ng` HEAD `7d69c94…`). `cargo build` locally to validate.
4. Add `deploy/` cargo-chef Dockerfiles + the persistence/entrypoint fixes already
   live. Add `Makefile` deploy targets using the service key.
5. Point dokku apps at the new repo: add remotes
   (`dokku@sandmill.org:sbo-daemon`, `:mingo`), deploy once each, verify
   `da.sandmill.org` + `mingo.place`.
6. Move secrets out of `config.toml` → `dokku config:set sbo-daemon TURBO_DA_API_KEY=…`
   (read via env in config/loader).
7. Strip `reference_impl/` from `sbo`; README pointer.
8. Trim this doc into `mingo/DEPLOYMENT.md`.

## Operational runbook (current facts)
- **Dokku host:** `sandmill.org` (198.199.110.160). Apps: `sbo-daemon`, `mingo`,
  `id` (broker), others.
- **Deploy key:** `~/.ssh/donotuse_id_ed25519_service` (the `id_ed25519_service`
  the deploy scripts name was rotated to this filename). Deploy:
  `GIT_SSH_COMMAND="ssh -i ~/.ssh/donotuse_id_ed25519_service" git push <remote> master:master`.
- **Persistent volume:** `/var/lib/dokku/data/storage/<app>` → `/data` in-container.
  Daemon state lives under `/data/.sbo/repos/avail_turing_506/state`; head in
  `/data/repos.json`; object files under `/data/repos/mingo`.
- **DA:** Avail turing app 506, repo `sbo+raw://avail:turing:506/`, genesis block
  **3528752**. RPC-only sync (no light client) via `turing-rpc.avail.so`.
- **Gotchas discovered:** (1) state index must be on `/data` or redeploys wipe it
  while keeping the head (empty feed). (2) Stale deploy lock after an aborted
  push → `dokku apps:unlock <app>`. (3) `@mingo.place` posts currently fail the L2
  attribution gate (auth-evidence gap) — separate Phase 7 workstream, not a deploy
  issue.

## Open questions
- New repo public or private? (sbo is ?; browserid-ng is public.)
- Keep full git history (`git filter-repo`) or start fresh?
- Fold `sbo-cli`/`sbo-wasm`/`sbo-zkvm` into mingo too, or only the deployed set?
  (Recommend: move everything; one home for the impl.)
