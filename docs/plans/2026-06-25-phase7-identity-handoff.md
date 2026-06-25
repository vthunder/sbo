# Handoff — Phase 7 Mingo demo: identity model + continuation

**Date:** 2026-06-25
**For:** a fresh agent continuing the SBO **Mingo** reference-client work.

## TL;DR of where we are
Phases 7.0–7.4 (sbo-wasm kit, typed-signing extension, consent, cross-site
signer popup) are **done + deployed live**. 7.1 (provider/DA) is **live on Avail
turing** (genesis on-chain, daemon syncs, `/v1` read API works). 7.6 (web client)
is **scaffolded** (reads work; writes wired but gated). The **identity flow is
mid-pivot**: we built a quick `flow=mingo` federated path in the broker, then the
user corrected the architecture — the *correct* model is **`mingo.place` as a
real browserid primary IdP** that the broker discovers. Only the **foundation**
for that (the `/sign_in` primary-auth-return fix) is in. The old `flow=mingo`
path is still what's deployed/used and must be **replaced**.

---

## The identity architecture (LOCKED — this is the target)
- **Broker / agent = `browserid.me`** (browserid-ng, dokku app `id` on host
  `198.199.110.160`). Holds cert-bound key custody + runs the typed-signing
  popup. DNSSEC-signed, `_browserid.browserid.me` TXT = broker key
  `oBxScFH3vNkyb-ftfzrcqeW6AQjK5-08drvmSVW4SrQ`, pinned in `/sys/trust/brokers`.
  `BROKER_DOMAIN=browserid.me` (cut over). Broker key persists at
  `/data/broker-key.json`.
- **`mingo.place` = a browserid PRIMARY IdP** (TO BUILD). Login is fully
  browserid-native: the user authenticates an external identity, **Mingo** (not
  the broker) owns handle selection + claim, then a browserid login for
  `<handle>@mingo.place` triggers **discovery against `mingo.place`** → standard
  primary provisioning → mingo.place's IdP issues the cert (gated on the claim).
  browserid-ng already has the primary-IdP-*serving* code (`routes/primary.rs`,
  `provisioning_api.js`, `authentication_api.js`), so plan = **deploy
  browserid-ng as mingo.place's IdP** (sibling service) + `_browserid.mingo.place`
  + handle-claim gating. Decision: browserid-ng-as-mingo-IdP (not a from-scratch
  server). The generic **sbo-daemon** stays the DA gateway; the SPA stays static.
- **Key insight that simplifies it:** the `/sign_in` break was the *only* thing
  wrong with primary provisioning — the sandmill.org Laravel IdP and the dialog
  were already correct. Fixed (see below). So primary discovery works now.
- **`login ≠ registration`** (user's hard requirement): the handle question must
  come AFTER authentication (new users), or be a SEPARATE registration flow.
  Never prompt for a handle as part of "login" — login may be a returning user.

## Three symptoms the user is currently seeing (all = old path still live)
1. In-page `prompt()` for handle on login (client `app.js signIn`) — assumes
   login=registration. WRONG.
2. SMTP email fallback instead of sandmill.org primary discovery — because
   `flow=mingo` calls `stage_login` (email) unconditionally, never discovery.
   **sandmill.org IdP is NOT broken** (verified: `address_info` →
   `type:primary`, `.well-known` 200).
3. Handle screen inside the browserid dialog — the deployed dialog still has the
   `flow=mingo` `mingoHandle` screen. Not a redeploy miss; the replacement isn't
   built.

## What to REMOVE/REPLACE (the wrong-layer `flow=mingo` work)
- Broker (`browserid-ng`): `/wsapi/stage_login`, `/wsapi/complete_login`,
  `/wsapi/provision_mingo` (account.rs) + the dialog `flow=mingo` path
  (mingoCode/mingoHandle screens, `startMingoLogin`, `provisionAndFinish`,
  `flow`/`mingoHandle` state). Keep: `/admin/create_account` (seed accounts).
- Client (`mingo-web/app.js`): the `signIn` `prompt()` + `flow=mingo`/`handle`
  params.
- Replace with: Mingo registration flow (claim handle in Mingo, gated by an
  authenticated external identity) → browserid login for `<handle>@mingo.place`
  via standard discovery → mingo.place IdP provisions. Login (returning user) =
  plain browserid login for the user's `@mingo.place` identity.

## DONE this session (newest first)
- `/sign_in` is now the **primary-IdP auth-return handler** (postMessages
  `browserid_auth_complete` to the dialog + closes). The ONLY break in primary
  provisioning. Deployed. (`browserid-ng` commit `7d69c94`.)
- **RocksDB lock fix** (sbo `917dd3c`): shared process-wide `Arc<StateDb>`
  (`sbo_daemon::shared_state_db`) so the sync task + HTTP/IPC reads share one
  handle. Verified 60/60 concurrent reads OK.
- **Daemon reachability** (sbo `076c16f`): `SBO_HTTP_BIND` env (run
  `0.0.0.0:7890`); client defaults daemon URL to the page host.
- **7.1 LIVE on turing**: `presets::mingo_genesis` submitted (app 506, block
  3528752), daemon syncs via RPC-only fallback (no light-client binary needed),
  all 13 genesis writes applied; communities + `/sys/trust/brokers` queryable
  over `/v1`. RPC-fallback + `extract_sbo_payload` (strips Avail SCALE/cell
  framing) in sbo `58775d9`. `/v1/state-root` + SBOQ proofs fixed (`ba39773`).
- **7.6 client** (`reference_impl/mingo-web/`, sbo `dfac9ea`): static SPA, reads
  hub/community/thread/passport live; write path (build→popup-sign→submit) wired.
- Admin seed endpoint + a pre-provisioned account `danmills@mingo.place`
  (password `mingo-demo-2026`) — but that PASSWORD account is the rejected model;
  keep only for seed scripts.

## Critical infra facts
- **DA:** Avail turing, **app_id 506**. TurboDA key = `~/.turbo/key-turing-`
  **`unencrypted`** (the `key-turing` one ENCRYPTS via Enigma → unreadable on
  chain → breaks SBO replay). Daemon config `~/.sbo/config.toml`.
- **Daemon:** run `SBO_HTTP_BIND=0.0.0.0:7890 sbo-daemon start --foreground`
  (binary `reference_impl/target/debug/sbo-daemon`). Repo:
  `sbo+raw://avail:turing:506/`, state at `~/.sbo/repos/avail_turing_506/state`.
  Recreate genesis: `sbo repo create sbo+raw://avail:turing:506/ <path> --mingo
  --domain mingo.place --broker browserid.me`.
- **Client:** `cd reference_impl/mingo-web && python3 -m http.server 8090`.
- **Admin token:** `~/.mingo-admin-token` (also dokku `id` env `ADMIN_TOKEN`).
- **Broker deploy:** `cd ~/src/browserid-ng && git push dokku main` (rebuilds);
  static assets serve `Cache-Control: no-cache` (no stale agent JS).
- **DNS done:** `browserid.me` A→198.199.110.160, DNSSEC + `_browserid` TXT,
  AD-flag validates. `mingo.place` registered, A→Namecheap parking (NOT pointed
  at infra yet; needed when standing up its IdP + `_browserid.mingo.place`).

## NEXT STEPS (ordered)
1. **Stand up `mingo.place` as a primary IdP** (deploy browserid-ng instance for
   it; `_browserid.mingo.place` TXT + DNSSEC; point `mingo.place` A at the host).
   Add **handle-claim gating** to its provisioning (issue `<handle>@mingo.place`
   cert only if the authenticated user owns that claim).
2. **Rework Mingo identity UX:** separate **registration** (authenticate external
   identity → claim handle in Mingo) from **login** (browserid login for the
   user's `@mingo.place` identity, standard discovery). Remove the `flow=mingo`
   path + client `prompt()`.
3. **Remove the wrong-layer broker endpoints** (stage_login/complete_login/
   provision_mingo + dialog flow=mingo).
4. **Auth-Evidence for writes:** browser can't make a DNSSEC proof, so add a
   broker/daemon endpoint serving the `browserid.me` RFC-9102 proof
   (`sbo-capture::capture_evidence`); client folds it into the envelope before
   signing. Then real `@mingo.place` posts land.
5. **7.5 seed content** — UNBLOCKED NOW without any of the above, via **key-rooted**
   seed identities (claim name → self-issue `membership` → post/comment/react;
   the hub policy's `member` role accepts any in-force membership). Makes the
   feed/passport visibly alive + exercises write→DA→sync→read. Good parallel task.
6. Admin special-case: map `danmills@sandmill.org` (or the chosen external admin)
   → seeded `role:admin` attestation in the SBO layer.

## Open beans / follow-ups
- vthunder/browserid-ng#1 — non-extractable CryptoKey custody (deferred).
- vthunder/browserid-ng#2 — cross-site signing UX / FedCM-is-login-only (the
  popup signer is the near-term answer; FedCM only covers login, not signing).
- Grant breadth (session-scoped consent signs any envelope) — accepted for now.
- Primary-IdP login end-to-end NOT yet verified in a browser since the `/sign_in`
  fix — worth confirming a `danmills@sandmill.org` plain login completes.

## Key files
- Broker: `~/src/browserid-ng/browserid-broker/` — `src/routes/{account,primary,
  cert,mod}.rs`, `static/dialog.{js,html}`, `static/common/js/{sbo-sign,
  sbo-signer}.js`, `static/sign.html`, `static/communication_iframe/start.js`,
  `static/sbo-wasm/`. Design note: `docs/plans/2026-06-24-typed-signing-
  extension-design.md`.
- Reference primary IdP: `~/src/sandmill` (Laravel `BrowserIdController.php`,
  `routes/web.php` login → `return_to#AUTH_RETURN`).
- SBO impl: `reference_impl/sbo-core/src/{presets,attribution}.rs`,
  `sbo-daemon/src/{main,sync,http,repo,lib}.rs`, `sbo-wasm/src/{kit,bindings}.rs`,
  `mingo-web/`. Plan: `docs/plans/2026-06-24-phase7-mingo-client-plan.md`.
- Memory: `phase7-infra-topology.md`, `mingo-demo-direction.md`.
