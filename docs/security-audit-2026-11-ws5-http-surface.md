<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS5: HTTP / IPC / RPC surface and authz matrix

**Status:** skeptic pass complete, 2026-11-04. Epic `sbo-ax7t`, bean
`sbo-s4xl`. Scope: the daemon's HTTP router (`sbo-daemon/src/http.rs`, the
`RepoApi` implementation and submit path in `main.rs`), the submit-gate
fetchers (`status.rs`, `evidence.rs`, `sbo-capture`), the bootstrap fetchers
(`bootstrap.rs`, `snapshot.rs`), the IPC socket (`ipc.rs`, `main.rs::handle_request`),
and the outbound Avail / TurboDA clients (`sbo-rpc`, `sbo-avail`, `turbo.rs`).
Oracle: `docs/design/threat-model.md` I31–I36 (plus I2 for the pre-auth
fetch) and decision Q15 (public exposure mode). WS1 leads routed here:
D18, D19, D20 (shared with WS4), D37, D38, D50, D52.

**Deployment fact that sets the severities.** The daemon is written as a
loopback convenience server (`http.rs` header comment: "reflect any origin …
Reads/submit carry no cookies") but the deployable in
`~/src/mingo/deploy/sbo-daemon/Dockerfile:68` sets `SBO_HTTP_BIND=0.0.0.0:5000`
and dokku nginx publishes it as da.sandmill.org. Every verdict below is read
against that public exposure, which Q15 (decided 2026-11-04) turns into a
distinct "public mode".

**Method.** Reviewer pass over every route, every outbound fetch reachable
from a request, and every IPC command; then a skeptic pass that tried to
refute each candidate with an in-process test (axum `oneshot` against a mock
`RepoApi`, loopback listeners that record whether a fetcher dials them, a
counting global allocator for the inflate bomb). Every verdict is backed by a
test that runs today. Tests encoding an invariant that FAILS today are
`#[ignore]`d with an `// AUDIT-2026-11 W5-n: fails today` comment and are the
acceptance test for the fix; the rest pass and pin what was re-verified. No
production code or spec changed. No network beyond loopback, no production
host, no real keys.

| Test file | Pass | Ignored (fail today) |
|---|---|---|
| `crates/sbo-daemon/tests/audit_2026_11_authz_matrix.rs` | 12 | 9 |
| `crates/sbo-daemon/tests/audit_2026_11_ws5.rs` | 8 | 6 |

Run the failing set with
`cargo test -p sbo-daemon --test audit_2026_11_authz_matrix --test audit_2026_11_ws5 -- --ignored`
(the `/v1/dnssec` flood cell reaches the resolver when un-ignored; it is the
only one that leaves loopback). No dependency changes.

## 1. Route inventory and principal model

Eleven routes, one IPC socket, three outbound client families.

| Route | Handler | Reads state | Spends | Outbound fetch reachable from the request |
|---|---|---|---|---|
| `GET /health` | `health_check` | no | — | — |
| `GET /auth?origin=&challenge=` | `auth_popup_page` | writes a sign request | memory | — |
| `POST /auth/request` | `create_auth_request` | writes a sign request | memory | — |
| `GET /auth/status/:id` | `get_auth_status` | sign request | — | — |
| `GET /v1/object` | `get_object_v1` | gated | proof build (`proof=1`) | — |
| `GET /v1/list` | `list_objects_v1` | gated | full table scan (`prefix=/`) | — |
| `GET /v1/state-root` | `state_root_v1` | gated | — | — |
| `GET /v1/sync-points` | `sync_points_v1` | **not gated** | snapshot dir listing | — |
| `GET /v1/snapshot` | `snapshot_v1` | **not gated** | whole file into memory | — |
| `GET /v1/dnssec?domain=` | `dnssec_v1` | gated | live DNSSEC capture | UDP to `1.1.1.1:53` for any `domain` |
| `POST /v1/submit` | `submit_v1` → `DaemonState::submit` | **not gated** | TurboDA credit, DNSSEC captures, status fetches, overlay memory | DNS capture per issuer named in the body; `https` GET per status ref in the body |

Principals. The daemon has no sessions, cookies or tokens. A caller is
distinguished only by the browser `Origin` it carries, or none. The matrix
therefore uses three principals: **anonymous** (no `Origin`: curl, the CLI,
a proxy), **foreign origin** (a web page the operator did not allowlist),
**allowed origin** (Q15's allowlist, e.g. `https://mingo.place`). Q15 adds a
bearer for trusted non-browser clients; the matrix reserves 401 for the
anonymous-without-bearer cell. Reads are open to all three in every mode.
The read gate (`check_read_gate`) is a fourth axis: while a fast-sync
anchor is unverified, reads must answer 503.

IPC (`~/.sbo/daemon.sock`, `/data/daemon.sock` in the container): 23
commands, all unauthenticated beyond socket access. Mutating ones: `RepoAdd`
(any `path`, `create_dir_all` + mirror writes), `RepoRemove` /
`RepoRemoveByUri` (`remove_dir_all` of the repo state dir), `RepoRelink`,
`RepoCreate` (genesis submit), `Submit`, `SubmitIdentity`, `SubmitDomain`,
`SubmitSignRequest`, `ApproveSignRequest` (mints the assertion the popup
delivers), `RejectSignRequest`, `Shutdown` (a no-op, `TODO`).

Outbound clients: Avail RPC (`sbo-rpc`, operator-configured endpoint, TLS
via `avail-rust`), the Avail light client (`sbo-avail`, loopback HTTP to the
LC process), TurboDA (`turbo.rs`, `x-api-key` header over https to an
operator-configured endpoint). None of their targets are chosen by a request,
so they are out of the SSRF question; their trust posture is Q20 / WS7.

## 2. Verdicts on the WS1 candidates

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| D38 | **CONFIRMED** → W5-1 | High | `http.rs:300-345` (`allow_origin(Any)`, `SetResponseHeaderLayer` PNA on every response); bind `0.0.0.0:5000` in the mingo Dockerfile | `today_cors_is_star_and_private_network_header_is_always_set` (pins), `public_mode_*` ×4 (ignored) |
| D19 | **CONFIRMED** → W5-2, W5-3 | Medium | `http.rs::dnssec_v1` (live capture for any `domain`), no limiter anywhere | `public_mode_dnssec_capture_refuses_a_foreign_origin`, `public_mode_flood_on_*_hits_429` (ignored); `today_no_route_answers_429_under_a_flood` (pins) |
| D18 | **CONFIRMED** → W5-4 | Medium (was High) | `status.rs:76-82` (default client: redirects followed, no address check, `text()` uncapped), `:220-250` (no host == authority) | `status_fetch_never_dials_a_non_public_address`, `status_fetch_requires_uri_host_to_equal_the_authority` (ignored); two `status_fetch_*` pins |
| D52 | **CONFIRMED** (folded into W5-4) | Low | `device_attribution.rs:109-138` (`presentation_status_refs`, hand-rolled `uri_host`) | same |
| D50 | **CONFIRMED** → W5-5 | Medium | `bootstrap.rs:185-197` (`reqwest::Client::new()`), `snapshot.rs:117-120` (`read_to_end`) | `snapshot_fetch_refuses_redirects`, `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it` (ignored) |
| D20 | **CONFIRMED** (socket half) → W5-8 | Medium | `ipc.rs:242` (`UnixListener::bind` under the process umask) | `ipc_socket_is_created_mode_0600` (ignored) |
| D37 | **PARTIAL** → W5-10 | Low | `http.rs::auth_popup_page` (unauthenticated GET creates a request; nothing ever expires one; `DaemonState` has no sweep) | `auth_popup_pending_requests_are_bounded` (ignored); XSS and id-entropy halves refuted (§4) |

### 2.1 W5-1 — public bind with `*` CORS and the private-network header (High)

Every response carries `Access-Control-Allow-Origin: *` and
`Access-Control-Allow-Private-Network: true`; the preflight for a cross-origin
`POST /v1/submit` succeeds for any origin (pinned). On a loopback bind that
is the intended "any dev page may talk to my daemon" posture. On the
deployed `0.0.0.0:5000` behind nginx it means any web page a user visits can
`POST /v1/submit` to da.sandmill.org from the user's browser, and the node
validates, stages in its overlay and pays TurboDA for whatever validates.
The write still has to validate against the repo's policy, so the page needs
a key that some rule admits (any key may create under `/sys/dnssec/**` with a
valid proof; any email-rooted identity may write under `/u/<self>/`), which
is a low bar on a public repo. The cost is the node's DA credit, overlay
memory and chain spam, not integrity; Dan's note on Q15 that a proxy
bypasses CORS anyway is correct, which is why the allowlist is paired with
a per-source limiter (W5-3). The PNA header is the sharper half: it exists
so a *public* page may reach a *loopback* server, and sending it from a
public server advertises exactly the wrong thing.

Remediation (Q15 (a)): a `[http] mode = "loopback" | "public"` setting
(default `loopback` when the bind is a loopback address, `public` otherwise,
refusing to start if `0.0.0.0` is combined with `loopback`); in public mode
drop the PNA layer, replace `allow_origin(Any)` with the configured origin
list (`allow_origin(AllowOrigin::list(..))`), and gate `/v1/submit` and
`/v1/dnssec` on `Origin ∈ allowlist` or `Authorization: Bearer <configured>`.
Un-ignore the four `public_mode_*` cells plus the two spend cells.

### 2.2 W5-2 — `/v1/dnssec` is an unauthenticated resolver amplifier (Medium)

`dnssec_v1` reads the on-chain proof and, whenever it is absent or expires
before `needed_by + margin`, runs `sbo_capture::capture_evidence` for the
caller's `domain` against `1.1.1.1:53`. `needed_by` is caller-chosen, so
`needs_refresh` is always reachable; `domain` is any string
`Name::try_from` accepts. One GET costs the node a full DNSSEC chain walk
(several round trips) and returns a few KiB; the resolver sees the node as
the source. Nothing in `mingo-web` calls this route; `mingo-app`'s
`appoint` CLI still does (`appoint.rs:273`), and `/v1/submit` now refreshes
evidence itself (`evidence.rs` module doc). Decision Q22 asks whether the
route stays behind the allowlist or goes.

### 2.3 W5-3 — no route answers 429 (Medium)

Five hundred `POST /v1/submit` from one source in a loop all answer 200
(pinned). There is no limiter layer, so there is also nothing to feed
`X-Forwarded-For` to today; when one is added it must take the connection
address or the last hop. browserid-ng WS7 §6 confirmed the shared dokku
nginx template overwrites `X-Forwarded-For` with the connection address, so
trusting the header is safe on this host only as long as that template
holds; prefer the connection address and treat the header as advisory.

### 2.4 W5-4 — submit-gate status fetch is a blind SSRF (Medium, downgraded from High)

`StatusChecker::fetch_and_verify` builds its client with only a 10 s timeout:
reqwest's default policy follows up to ten redirects, there is no address
check, and the body is read whole. The test gives it `https://127.0.0.1:<port>/list`
and observes the connection arrive (TLS then fails, but the dial happened).
The URI host is never compared with the credential's `iss` (D52), so an IdP
may point the gate at any host.

Why Medium: the fetch runs only after `validate_message` returned `Valid`
and only for an authority whose DNSSEC evidence the node holds. The attacker
therefore needs a DNSSEC-signed domain running their own browserid IdP, and
a write that the repo's policy admits (easy on a public repo, see W5-1).
With that, each submit is one blind GET to an address of their choosing,
with redirects, from da.sandmill.org's network position. That is the
browserid-ng H1 / W6-5 class, which WS6 there also rated Medium. Fix:
`redirect::Policy::none()`, require `https`, resolve-and-reject non-global
addresses before connecting (copy `browserid_verifier::verify::validate_status_url`),
cap the body (`take(64 KiB)`), and require `uri_host(status.uri) == authority`
for the access and config certs (warrants stay signer-chosen, as in
browserid-ng §6.3). `authority_key`'s live capture (`status.rs:98-115`) is the
same amplifier as W5-2 and W5-9 and is bounded by the same per-source limit.

### 2.5 W5-5 — bootstrap snapshot fetch follows redirects; inflate is uncapped (Medium)

`fetch_manifest` and `fetch_snapshot` use `reqwest::Client::new()`; the test
bounces the bootstrapper from one loopback server to another and it follows.
`decode_snapshot_payload` inflates the whole stream before parsing: a
254 KiB body of compressed zeros drives the test binary's peak allocation to
768 MiB (the `Vec` doubling on top of the 256 MiB payload). The same decoder
reads local snapshot files. `node_url` is operator-chosen, so the redirect
half is operator-steered; the bomb half is served by whichever node the
operator bootstraps from, which the spec treats as untrusted. Fix:
`redirect::Policy::none()`, an address check, a `Content-Length`/stream cap
on the compressed bytes, and `GzDecoder::take(cap)` before `read_to_end`
with a cap derived from the manifest's `uncompressed_bytes` (itself capped).

### 2.6 W5-6, W5-7 — the read gate has holes (Low, Low)

`sync_points_v1` and `snapshot_v1` do not call `check_read_gate`, so a node
whose fast-sync anchor is still provisional serves a manifest and snapshots
derived from that unverified state to the next bootstrapper (W5-6).
`submit` does not consult the gate either: while gated it validates the
write against provisional state, stages it and pays for it (W5-7). Both are
one-line additions; both are ignored matrix cells.

### 2.7 W5-8 — IPC socket is world-connectable (Medium)

`UnixListener::bind` leaves the socket at the process umask; the test
observes `0755`. Any local user can then issue every command in §1,
including `RepoAdd` with an arbitrary `path` and `RepoRemove`, which
`remove_dir_all`s the repo's state directory, and `ApproveSignRequest`,
which mints the assertion a popup delivers. In the container the daemon is
the only user, so the deployed exposure is nil; on a developer machine it is
not. Fix: `chmod 0600` right after bind (or bind under a `0700` directory),
plus `SO_PEERCRED`/`LOCAL_PEERCRED` uid check for mutating commands if the
socket must stay shared. `Shutdown` being a no-op is noted, not a finding.

### 2.8 W5-9 — `/v1/submit` captures evidence for issuers named by unverified claims (Medium)

`DaemonState::submit` computes `required_issuers` from the presentation's
bare claims and runs `build_refreshes` (one live DNSSEC capture per stale
issuer) **before** `validate_message` checks a single signature
(`main.rs:640-668` vs `:678`). The pinned test shows a presentation signed
by an unrelated envelope key, which attribution would reject, still names
two attacker-chosen issuers. An unauthenticated POST therefore drives one
chain walk per invented domain through the node's resolver, and a capture
failure answers 500 before any validation. This is the I2 class (network
before signatures) on the write path. Fix: check the presentation's internal
consistency first (envelope key == access-key, cert signatures under their
embedded issuer keys, assertion over the audience) so only a self-consistent
bundle reaches the capture; cap issuers per submit at two; count captures
against the per-source limiter. The capture cannot move *after* full
validation, since attribution needs the fresh evidence it fetches.

### 2.9 W5-10 — sign requests are created by any GET and never expire (Low)

`GET /auth?origin=…` creates a pending request in daemon state for any
caller; `SignRequestStatus::Expired` is never assigned and nothing sweeps the
map. A thousand GETs leave a thousand pending entries (ignored test), which
also fill the operator's `ListSignRequests` view. Since no client in this
repo or mingo uses the popup flow (no `sbo auth approve` in `sbo-cli`, no
`sbo:response` listener in `mingo-web`), Q23 proposes removing the three
`/auth` routes and the sign-request IPC commands rather than hardening them.

## 3. Refuted leads

| Lead | Why refuted | Evidence |
|---|---|---|
| Reflected XSS on `/auth` via `origin` | `html_escape` covers `& < > " '`; the value lands in HTML text and inside a double-quoted JS string, so `"`, `<` and `</script>` cannot break out. A `\` or newline only yields a JS syntax error. | `auth_popup_escapes_the_origin_parameter` |
| Open redirect | No handler issues a redirect; the popup `postMessage`s to the `origin` the opener itself supplied, which is the browser's own same-origin check (the message is delivered only if the opener *is* that origin). | reading `http.rs` |
| Request id below I35 | 8 random bytes from `thread_rng` = 64 bits, I35's floor. Recorded as an observation: a bearer for the assertion with no expiry and no limiter should be 128 bits. | `auth_popup_request_id_is_64_random_bits` |
| Unbounded submit body | axum's `DefaultBodyLimit` (2 MiB) applies to the `Bytes` extractor: 3 MiB answers 413. | `submit_body_over_two_mib_is_413` |
| `?repo=` reaches another repo's credentials | `resolve_repo` selects only among followed repos and each repo has its own TurboDA key; no caller/repo binding exists, but that is W5-1's allowlist, not a traversal. The selector also matches the repo's *local path*, which leaks nothing a `RepoList` would not. | reading `main.rs:228-260` |
| `sbo://` TXT `node=` SSRF from HTTP | `dns.rs::resolve` is reached only from the CLI and IPC `RepoAdd`/`RepoRelink` (operator), never from a public handler; the `node=` endpoint is used by bootstrap and is W5-5. | reading |
| Plain-http status URI dialled | Refused before any connection. | `status_fetch_refuses_plain_http_without_connecting` |
| Status fetch without on-chain authority evidence | Fails closed before any connection. | `status_fetch_without_authority_evidence_never_connects` |
| IPC framing wedge | A malformed line is answered and the connection stays usable. | `ipc_malformed_line_is_answered_and_the_connection_survives` |
| Outbound Avail / TurboDA targets steerable by a request | Endpoints come from `config.toml` only. | reading `sbo-rpc`, `sbo-avail`, `turbo.rs` |

## 4. Observations (no finding)

- `submit` holds `state.read()` across every DNS capture and status fetch
  (10 s timeout each, sequential). Tokio's `RwLock` is write-preferring, so a
  burst of slow submits plus one pending IPC write (`RepoAdd`,
  `ApproveSignRequest`) stalls every HTTP reader behind it. Routed to WS4 as
  a lead (D-WS5-a); the limiter in W5-3 bounds it.
- `/v1/list?prefix=/` and `proof=1` are unbounded per request by design
  (public reads); W5-3's limiter is the control.
- `/auth/status/:id` serves the assertion to any holder of the id with no
  origin check — by design for the polling popup; pinned.
- `Shutdown` over IPC is a `TODO` no-op.
- `ApiError` messages echo the caller's `repo` selector and wire-parse
  errors verbatim; nothing sensitive, but worth a pass when the error shape
  is frozen.

## 5. Matrix tally

| Cell group | Pass | Ignored |
|---|---|---|
| Reads open to every principal; 404/405/501 shapes; unknown sign request | 4 | 0 |
| Read gate on object/list/state-root/dnssec | 1 | 0 |
| Read gate on sync-points/snapshot (W5-6), submit (W5-7) | 0 | 2 |
| Spend endpoints under Q15 public mode (W5-1, W5-2) | 2 | 3 |
| CORS / PNA headers (W5-1) | 1 | 2 |
| Rate limiting (W5-3) | 1 | 2 |
| Body and input caps | 3 | 0 |

## 6. What needs Dan's decision

- **Q22.** `/v1/dnssec`: keep it behind the Q15 allowlist, or remove it now
  that `/v1/submit` refreshes evidence itself (`mingo-app`'s `appoint` CLI
  is the one remaining caller).
- **Q23.** The `/auth` popup flow and the sign-request IPC commands have no
  caller in this repo or mingo: remove them, or keep and harden (expiry,
  per-source cap, 128-bit ids).

## 7. High+ list for WS8

1. W5-1: from a page on a foreign origin, `POST /v1/submit` to a local
   daemon bound on `0.0.0.0` with a write the repo admits; show the TurboDA
   call (or the submit queue entry with a stub submitter) and the overlay
   entry. Measure only; no production host.
2. W5-4 (Medium, but the ordering list in WS1 §6 asked for it): a local IdP
   on a test DNSSEC zone is heavy; the in-process `status_fetch_never_dials_a_non_public_address`
   already shows the dial. WS8 may skip the end-to-end form.
3. W5-5: the 254 KiB → 768 MiB inflate is measured in-process; a local
   serving node form is optional.
