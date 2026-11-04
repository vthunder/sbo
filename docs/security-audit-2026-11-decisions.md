# Security audit 2026-11: open decisions

> **Status: Q1–Q21 settled 2026-11-04; Q22–Q25 (WS4) open.** Product and design
> calls that remediation depends on, collected from each workstream as it
> lands. Each item: what was found, the options, and a recommendation.
> Reply per item number; answers are recorded here and in the affected
> beans. Branch `audit-2026-11`, epic `sbo-ax7t`. Method and format follow
> the browserid-ng 2026-11 audit
> (`~/src/browserid-ng/docs/security-audit-2026-11-decisions.md`).
> Threat model: `docs/design/threat-model.md`. WS1 report:
> `docs/security-audit-2026-11-ws1-threat-model-spec.md`.

## 1. Where things stand

| Workstream | Bean | Result |
|---|---|---|
| WS1 threat model + spec review | sbo-dl2l | Done 2026-11-03. 10 adversaries, 14 boundaries, 36 invariants. 50 code leads D1–D58 (3 Critical, 13 High pre-verification), 20 spec findings S1–S22. All 12 open July 2026 leads still present. 21 decisions below. |
| WS2 conformance vectors | sbo-5t0f | Running (Q1, Q4, Q5 settled). |
| WS3 fuzz + proptest | sbo-qw0z | Running. |
| WS4 never-audited layers | sbo-f8cj | Done 2026-11-04. 21 candidates: 15 confirmed, 3 partial, 1 refuted, D33/D58 confirmed by reading, D39 accepted risk (Q20). 4 new (W4-1..4). Tests: daemon 7 pass / 16 ignored, core 2 / 1. Decisions Q22–Q25 open. |
| WS5 HTTP / IPC surface | sbo-s4xl | Done 2026-11-04. 7 candidates: 6 confirmed, 1 partial. Findings W5-1..W5-10 (1 High: W5-1 public bind with `*` CORS + PNA; 6 Medium; 3 Low). Authz matrix 12 pass / 9 ignored; findings 8 / 6. Decisions Q22, Q23. |
| WS6 crypto core / verification | sbo-iye5 | Running (Q7, Q19 settled); D1–D6, D8–D10, D24, D30 otherwise ready. |
| WS7 supply chain / CI / secrets / logging | sbo-ip5k | Done 2026-11-04. No CI existed; `test.yml`, `supply-chain.yml` (cargo-audit, cargo-deny, gitleaks), dependabot added. 41 advisories, 34 after reasoned ignores, all closable by `cargo update` + dropping an unused `reqwest 0.11`. No secret ever committed (514 commits). 14 findings W7-1..14 (3 Medium). Decisions Q26–Q29. |
| WS8 PoCs | sbo-cka2 | Ordering list in the WS1 report §6. |
| WS9 ledger + remediation beans | sbo-q92z | Blocked on WS2–WS8. |

**Highest-severity candidates (pre-verification)**

| ID | Candidate | Where |
|---|---|---|
| D1 | `Content-Hash` never verified: any payload rides a signature-valid envelope; P2 policy pins key on the claimed hash. | `sbo-core/src/wire/parser.rs:169` |
| D5 | No genesis validation; no root policy ⇒ accept everything; genesis-hash mismatch only logs. | `genesis.rs:13`, `validate.rs`, `main.rs:1706` |
| D8 | zkVM "validity proof" proves no SBO validity and is unbound from block data. | `sbo-zkvm/methods/guest/src/main.rs` |
| D21 | On-chain `Path: /../` writes the mirror outside the repo dir; an id/collection collision stalls replay on one node. | `envelope.rs:97`, `sync.rs:936,1084,1321` |
| D26/D27 | Fast-sync adopts a root asserted by the untrusted serving node; snapshot `policy_versions` loaded unverified. | `bootstrap.rs` |
| D18 | `/v1/submit` fetches attacker-named `https://` status URIs with redirects and no address guard; live DNS capture for any authority. | `status.rs`, `main.rs:690` |
| D38 | CORS `*` + private-network header on a node bound to `0.0.0.0`: any web page submits with the node's TurboDA key. | `http.rs:300` |

## 2. Decisions

Each item: what was found, the options, and my recommendation. Reply per
item number.

### Q1. Which attribution model is normative (S1, S2, D32)

The Authorization spec describes `Auth-Cert` as one browserid JWT and
`Auth-Warrant` as a separate header. The code verifies the four-object
browserid device presentation (`access_cert~assertion~warrant~config_cert`)
carried in `Auth-Cert`; the legacy single-cert verifier is gone;
`Auth-Warrant` is parsed, signed and ignored. The Attribution spec §3
already describes the device model. WS2's vectors must encode one of them.

- (a) Spec moves: rewrite Authorization §Auth-Cert/§Agent Warrant around the
  device presentation, delete `Auth-Warrant` from the wire spec (breaking
  for nobody, since nothing emits it), document `sign:sbo:<action>` scopes.
- (b) Code moves: re-add the single-cert path and consume `Auth-Warrant`.
- (c) Keep both documented; vectors cover both.

**Recommendation: (a).** The device model is what browserid-ng ships and
what mingo produces; the single-cert text is history.

**Decided 2026-11-04 (Dan): (a).** History checked: `Auth-Warrant` was added 2026-07-11 (6b5d3f5) so an agent cert would be inert without a delegator-signed, audience-bound warrant; the 2026-07-20 device-cert refactor (ac48868) folded both properties into the four-object presentation (warrant is object 3, assertion carries the audience, fail-closed for every identity). Nothing was lost; carry the `sign:sbo:<action>` scope grammar into the rewrite.

### Q2. `brokers.v1` payload shape (S3)

Spec: `{ "brokers": ["broker.example"] }`. Code: a bare JSON array. A
spec-shaped object parses to no brokers (fail closed, every broker-certified
write rejected).

- (a) Code moves to the object form; the mingo genesis is regenerated.
- (b) Spec moves to the bare array.

**Recommendation: (b)** unless a regenesis is already planned for D3/D4
(Q18), in which case (a) rides along.

**Decided 2026-11-04 (Dan): (a).** Judged on shape alone (regenesis cost ignored): the object form matches `dns-root.v1` and can grow per-broker fields.

### Q3. Pinned root KSK (S4, D6, July `sbo-y5ek`)

`/sys/trust/dns-root` is the spec's single a-priori anchor; the code cannot
inject it into `dnssec-prover` and never reads the object.

- (a) Fork or patch `dnssec-prover` to accept trust anchors; read
  `/sys/trust/dns-root` at inclusion time; verify `valid_from/valid_until`.
- (b) Amend the spec: the IANA root as compiled into the validator is the
  anchor; `/sys/trust/dns-root` becomes an audit record; accept that a
  rollover can break replay of old evidence until the library updates.

**Recommendation: (a).** Durability of replay across the next IANA

**Decided 2026-11-04 (Dan): (a).**
rollover is the spec's central promise; (b) gives it up.

### Q4. Batch atomicity (S5, D29)

Wire spec: one invalid message rejects the batch. Daemon: per-message. The
daemon's own evidence-refresh-ahead feature puts a refresh and a client
write in one batch, which under (a) couples their fate.

- (a) Code moves to all-or-nothing; refreshes go in their own batch.
- (b) Spec moves to per-message with an explicit statement that intra-batch
  order is preserved and that each message is validated against the state
  left by the previous one.

**Recommendation: (b).** Atomicity buys nothing without smart-contract
semantics and costs the refresh design; the genesis case (the one listed
motivation) is covered by Q7.

**Independent survey 2026-11-04 (per Dan, before committing to (b)):** per-message is the only semantics any shipped code implements, and the live app 506 chain, its state roots and SBOP proofs already encode it; atomic would re-root the chain. Every intra-batch dependency (Policy-Ref, Auth-Evidence `ref:`, `_config` then items, transfer then update, attestation then attested write, same-slot double create) fails closed or falls back to the parent/default when the earlier message is rejected; the one "different meaning" case is a name-claim race changing a later object's creator attribute (cosmetic under global uniqueness). Atomic semantics would let one expiring assertion veto every other user's write and every evidence refresh in the shared `submit_queue` batch (griefing), undoing sbo-hy4r. Rules the spec text must state: (1) a submission that fails to parse is ignored whole; (2) strict submission order, N validated against state after 1..N-1; (3) a rejected message leaves state unchanged and is invisible to later messages; (4) an LWW loser is valid with no effect, not a rejection; (5) index within a submission is the slot tiebreak (State Commitment §"lower message index wins"); (6) state root and object_hash commit per block; (7) genesis is not an atomic exception, fail-closed bootstrap comes from Q7 ("root policy present by end of the anchor block"); (8) drop the multi-object-transfer atomicity claims, point clients at submit-time validation. Residual: IO error mid-block half-applies one node (D58).

**Decided 2026-11-04 (Dan): (b)**, with the eight rules above written into the Wire spec.

### Q5. One identity-comparison rule (S6, D13, D54)

No SBO spec states how two identity references compare. Code compares
byte-exact everywhere and `Id` admits several `@`.

- (a) Adopt browserid-ng §5: exactly one `@`, domain compared as a
  lowercased A-label, local part byte-exact; the canonical on-chain form is
  lowercase-domain, and a header carrying an uppercase domain is invalid
  (so paths like `/u/alice@Example.com/` cannot alias).
- (b) Byte-exact everywhere, reject uppercase domains at parse.

**Recommendation: (a)** with the canonical-form rule, so comparison and

**Decided 2026-11-04 (Dan): (a).**
path matching agree.

### Q6. Bare-key owners (S7, July `sbo-4arq`)

Identity spec lists `ed25519:<hex>` as a valid `Owner`; bean `sbo-4arq`
(2026-07) decided to reject explicit bare-key owners; code accepts them and
genesis roots depend on the signer-fallback form.

- (a) Keep bare keys for the signer fallback only; reject an explicit
  `Owner:`/`Creator:`/`New-Owner:` bare key; amend the spec table.
- (b) Keep bare keys everywhere; close `sbo-4arq` as won't-do and leave the
  spec.

**Recommendation: (a)**, as `sbo-4arq` already says.

**Decided 2026-11-04 (Dan): go further than (a) — remove bare-key owners entirely.** Explicit bare-key literals in `Owner`/`Creator`/`New-Owner` are rejected AND the signer-key fallback is dropped: every write names an owner that is a `/sys/names` name or an email; a message with no owner is invalid. Key-rooted name records stay (Mode A, self-sovereign users). The single exception is the genesis batch at the anchor, where `/sys/names/sys` is self-certifying under the Q7 strict rule. Spec: Identity owner-reference table and `resolve_controller` pseudocode lose the bare-key row. Owners: WS4 (daemon owner resolution), WS6 (core `resolve`/`authorize`).

### Q7. Genesis fail-closed shape (S8, S19, D5, D23, July `sbo-9d7l`)

The spec's "no root policy ⇒ invalid" has no definition of the bootstrap
window; the code's genesis mode accepts everything in any block until a
root policy appears.

- (a) Strict: the only writes valid before a root policy are the genesis
  batch at `@firstBlock`, validated by `Genesis::validate` (mode detection,
  order, signatures, same block, first attempt wins); a `genesisHash`
  mismatch or a second genesis at the anchor halts sync; a repo followed
  without an anchor or hash scans for the first valid genesis.
- (b) Lenient: keep genesis mode but confine it to the anchor block.

**Recommendation: (a).** Note the live app 506 was created under the
lenient rule; WS6 must check whether its genesis block passes (a) before the
rule ships.

**Decided 2026-11-04 (Dan): (a).** If the live app 506 genesis fails strict mode, regenesis.

### Q8. Self-certification required for Mode B (S9)

- (a) Required for Mode B from the next genesis; plain self-signed domains
  only in Mode A.
- (b) Optional (current spec), with the hard reject of D7 when present.

**Recommendation: (b)** now, (a) at the next regenesis.

**Decided 2026-11-04 (Dan): (a)**, shipping with the Q18 regenesis.

### Q9. Authoring instant vs inclusion time for credential windows (S10, D22)

The code judges the presentation's expiries at `authored_at` (HLC physical,
bounded by the collection's `W`) because a five-minute assertion cannot
survive batching latency; the Content spec says attribution is unchanged
and the Authorization spec says inclusion time. `W` is unbounded and set by
anyone who can create `_config`.

- (a) Spec: the assertion is the one object judged at the authoring instant
  (bounded by `W`); certs, warrants and DNSSEC windows stay at inclusion
  time. Protocol maximum for `W` (reference 24 h). `_config` writes require
  the collection's governing policy to grant them explicitly (a `govern`-like
  rule or `id: "_config"` restriction) rather than ordinary `create`.
- (b) Spec: everything at inclusion time; lengthen assertion TTL for the
  ledger audience instead.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).**

### Q10. Bridge spec status (S11, July `sbo-rx1z`)

- (a) Mark Status: Aspirational, not implemented; leave the text.
- (b) Remove the `import` action and bridge headers from the wire spec
  until implemented.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).**

### Q11. D1 fix ordering

Two-line parser change plus the P2 pin keying fix, versus letting WS8 show
the payload swap and the pin confusion first.

- (a) Fix now on the branch; PoC against the parent commit.
- (b) PoC first, then fix.

**Recommendation: (b)**, as in browserid-ng Q1: the report should carry a
shown impact, and the audit rule is no production change on the branch.

**Decided 2026-11-04 (Dan): (b).**

### Q12. Fast-sync trust (D26, D27)

- (a) A checkpoint root counts only when a `checkpoint.v1` object signed
  by a pinned checkpoint key is read and verified (from the chain, or from
  the manifest and then re-verified by signature); `sys-checkpointer`
  becomes a pinned public key, not a name; `bootstrap_provisional` is
  removed or gated behind an explicit `--trust-serving-node`;
  `policy_versions` are reconstructed from covered objects.
- (b) Keep the serving-node path for development, documented as untrusted.

**Recommendation: (a).** The spec is unambiguous that the manifest is
never a trust root.

**Decided 2026-11-04 (Dan): (a).**

### Q13. Owner fast-path versus policy (S13, D57)

- (a) Spec wins: owner updates, transfers and deletes evaluate `deny` and
  `restrictions` always, and `grants` as `to: owner` (so a policy without an
  owner grant denies the owner, as the spec allows).
- (b) Keep the fast-path for `grants` but apply `deny` and `restrictions`.

**Recommendation: (b).** It closes the bridge-lock and ban bypasses without
breaking every existing community policy that relies on the implicit owner
grant; revisit (a) with a spec note.

**Decided 2026-11-04 (Dan): (a), spec wins.** Nothing bypasses policy evaluation; the owner is a principal like any other. The implicit owner grant becomes an explicit default: the genesis presets and the default/root policy carry a `to: owner` grant for update/transfer/delete, so existing community policies keep working by inheriting it rather than by a code fast-path. Remediation must include a check that every policy on app 506 still admits its owners under the new rule before regenesis.

### Q14. Name claims under policy (S14, D56)

- (a) Evaluate the governing policy for `/sys/names/` creates and updates
  in addition to the anti-hijack check.
- (b) Keep name claims policy-free and amend the Identity/Genesis specs.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).** Dan: every path should be able to carry policy; name claims being policy-free was never intended.

### Q15. HTTP exposure model (D38, D18, D19)

The daemon is written as a localhost convenience (CORS `*`,
private-network header, no limits), but da.sandmill.org binds it publicly.

- (a) Two modes: loopback mode keeps today's behaviour; public mode
  disables the private-network header, restricts CORS to a configured
  origin list, rate-limits per source, and requires an operator-configured
  allowlist (origin or bearer) for `/v1/submit` and `/v1/dnssec`.
- (b) Public mode only adds rate limits; submit stays open (writer pays
  nothing, node pays TurboDA).

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).** Understood that an Origin allowlist only raises the bar (a proxy bypasses CORS); the per-source rate limit is the real bound on TurboDA spend, and a bearer is the knob for trusted non-browser clients.

### Q16. `/sys/dnssec/` rollback (D33)

- (a) A refresh must not lower the current occupant's RRSIG expiration
  (monotonic freshness), and must carry the same or a newer DNSKEY set.
- (b) Accept rollback as the documented cost of permissionless refresh.

**Recommendation: (a)**; it is one comparison in the policy check.

**Decided 2026-11-04 (Dan): (a).**

### Q17. Role cycles (D10)

- (a) Both: a policy-validation pass on write (cycles, unknown keys,
  pattern syntax) and a visited-set + depth bound at evaluation.
- (b) Evaluation guard only.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).**

### Q18. Root-changing fixes and regenesis (D3, D4, Q2)

Raw-bytes `object_hash` and trie domain separation each change every state
root and every proof.

- (a) Ship both together under a `state-commitment/v2` version, regenesis
  app 506, publish the migration note.
- (b) Ship separately.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).** Q2, Q6, Q8 and Q13 all ride this regenesis.

### Q19. zkVM scope (D8, July `sbo-5rww`)

- (a) Mark `sbo-zkvm` experimental in README and specs, feature-gated,
  carrying no trust claim; no remediation this round beyond that note.
- (b) Remediate: bind witnesses to `actions_data`, run SBO validation in
  the guest.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).**

### Q20. DA trust (D9, D39, July `sbo-7bl8`)

- (a) Document RPC trust as an accepted risk this round; fix only the
  silent-skip and zero-hash behaviours (never advance past unobtained data,
  cross-check the chain id).
- (b) Implement KZG and reorg handling now.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (c) do nothing this round.** Correction from Dan: the Avail light client the daemon queries verifies finality and data availability itself before serving app data, so it is closer to a local full node than to a trusted remote RPC; the WS1 framing overstated the trust. Avail is expected to replace the current light client with a new light-node implementation within a couple of months, so DA-side changes (KZG, reorgs, chain-id cross-check) wait for that. WS4 records D9/D39 as accepted risk with a note on what the LC verifies (read its API docs; information only) and files one deferred follow-up bean for the light-node migration.

### Q21. Fuzzing cadence (Info)

- (a) Weekly launchd `make fuzz-smoke` on the dev box, like browserid-ng
  Q29.
- (b) Manual only.

**Recommendation: (a).**

**Decided 2026-11-04 (Dan): (a).**

### Q22. IPC authorization model (WS4 D20)

The daemon's unix socket is created with the process umask (measured
`0755`); every command — `Shutdown`, `ApproveSignRequest`, `RepoAdd` to any
directory, `Submit` (TurboDA spend) — needs only socket access, so on a
multi-user host any local account drives the daemon. `RepoRemove` was
refuted as an arbitrary delete (it removes the daemon's own state dir).

- (a) `chmod 0600` the socket (and `0700` its parent) right after bind;
  same-uid callers keep full access. One line; enough for a single-user host
  and for the dokku container.
- (b) (a) plus a per-command authorization token for the mutating commands,
  for shared hosts.

**Recommendation: (a).** A same-uid process can already read the keyring,
so a token adds nothing on the hosts we run.

### Q23. A block with no inclusion time (WS4 D28)

`rpc.rs` treats a missing `timestamp.set` as non-fatal. `validate.rs` then
evaluates attestations at `t = 0` (every ban lifts), skips the HLC bound,
and fails attributed writes closed — so a node without the timestamp applies
a different set of writes from the same block than a node with it.

- (a) A block whose timestamp cannot be read is a fetch failure: retry, never
  process it, same as "block not available".
- (b) Process it with every attested, attributed and HLC-bearing write
  failing closed (deterministic, but divergent from nodes that have it).

**Recommendation: (a).** The timestamp is in the block; failing to read it is
transport, not chain state.

### Q24. Filesystem mirror encoding and failure policy (WS4 D21, D58)

On-chain path segments and ids are joined into the mirror path verbatim.
`Id` admits `.` and `..`, so a write escapes the repo directory; an id and a
collection name share one grammar, so `/c/x` (file) and `/c/x/y` (needs a
directory) collide; any mirror error aborts the block mid-way on that node
and `run` moves to the next block.

- (a) Grammar: `.` and `..` are not valid ids (spec Core §Identifier Syntax
  and core `Id::new`). Mirror: best-effort — the state DB is authoritative,
  a mirror write failure logs and never aborts validation or state; objects
  and collections get a collision-free layout (e.g. objects as
  `<id>` files, collections as `<id>.d/` directories, or percent-encoding of
  `.`-only segments).
- (b) Grammar fix only; keep the mirror authoritative and halt sync on any
  mirror error so an operator notices.

**Recommendation: (a).** A mirror error must not fork state; state is in
RocksDB and the trie, the mirror is a view.

### Q25. Overlay rule on a missing HLC (WS4 D17)

`overlay_wins` (read merge) lets a pending write without an HLC shadow a
confirmed one; `pending_still_wins` (reconcile) drops that pending write when
the confirming value lands. The tip can show a value that is about to be
discarded.

- (a) Align the read merge with reconcile: on a missing or unparseable HLC
  the confirmed value wins.
- (b) Keep the optimistic tip.

**Recommendation: (a).** One rule for both sides; HLC-less writes are the
legacy case anyway.

### Q26. WS7: supply-chain gate is red until the bumps land (W7-2, W7-6)

The new `supply-chain.yml` fails on main today: 34 RUSTSEC advisories, all of
which close with R7-1 (`cargo update`, after pinning `avail-rust` by rev) and
R7-2 (delete the unused `reqwest 0.11` from `sbo-core`, the only thing holding
rustls 0.21). Both are production changes (lockfile, one manifest line), which
the audit rule keeps off the branch.

- (a) Land R7-1 and R7-2 on the branch now so the gate is green at PR time
  (browserid-ng Q8 chose this).
- (b) Keep the audit rule; the gate stays red until the remediation bean lands.

**Recommendation: (a).** Nothing a deployed binary links stays vulnerable, and
a green gate on the first PR is what makes people keep it.

### Q27. WS7: daemon container runs as root (W7-12, Medium)

`/data` holds the checkpoint and attestor secret keys, the state index and the
unix socket, all root-owned; any RCE in the daemon is uid 0 in the namespace.
The fix needs a one-time chown of the dokku storage dir on the hobby host,
so it is coordinated with sandmill-infra (same shape as browserid-ng Q9).

- (a) `USER` in the Dockerfile + chown on the host + read-only fs /
  no-new-privileges docker-options + `app.json` healthcheck; mingo and
  sandmill-infra task beans.
- (b) Leave as is.

**Recommendation: (a).**

### Q28. WS7: required status checks on `main` (W7-1)

Branch protection on `vthunder/sbo` requires only the external
`ip-approval-gate`. The new `test` and `supply-chain` workflows are not
required, so a red run does not block a merge.

- (a) Add `test` and `supply-chain` to the required checks (GitHub settings;
  infra task bean).
- (b) Advisory only.

**Recommendation: (a)**, once Q26 makes the gate green.

### Q29. WS7: `avail-rust` tracked by branch (W7-3, Low)

Three manifests pin `avail-rust` to `branch = "main"`; the lockfile holds the
commit, but every `cargo update` moves it (the dry run jumps `de07cce1` to
`3f2fe9e7`).

- (a) Pin by `rev`; bump deliberately, as the `browserid-core` pins do.
- (b) Keep tracking `main`; rely on the lockfile.

**Recommendation: (a).** It also makes R7-1 a lockfile-only change.

### Q22. `/v1/dnssec` after submit-side evidence refresh (WS5 W5-2, Medium)

`GET /v1/dnssec?domain=` runs a live DNSSEC chain walk through the node's
resolver for any caller and any domain (`needed_by` is caller-chosen, so the
"refresh needed" branch is always reachable). `/v1/submit` now refreshes
issuer evidence itself (`evidence.rs`), `mingo-web` never calls the route,
and the one remaining caller is `mingo-app`'s `appoint` CLI.

- (a) Remove the route; `appoint` posts its write and lets submit refresh.
- (b) Keep it behind the Q15 allowlist / bearer and the per-source limiter.

**Recommendation: (a).** One fewer unauthenticated amplifier, and the
submit path already does the job once.

### Q23. The `/auth` popup flow and sign-request IPC commands (WS5 W5-10, Low)

`GET /auth`, `POST /auth/request`, `GET /auth/status/:id` plus the six
sign-request IPC commands implement a daemon-mediated login popup. No client
in this repo (`sbo-cli` has no `auth approve`) or in mingo (`mingo-web` has
no `sbo:response` listener) uses it; mingo logs in through browserid's own
popup signer. Today any GET creates a pending request that never expires,
and the assertion is a 64-bit bearer.

- (a) Remove the three routes and the six IPC commands (and `SignRequest`
  storage in `DaemonState`).
- (b) Keep and harden: TTL sweep, per-source cap, 128-bit ids.

**Recommendation: (a).** Dead surface is the cheapest surface to secure;
the device-cert model made this flow obsolete.

## 3. Already settled by the spec text (no decision needed)

- S12, S17, S20, S21: pure documentation gaps; WS9 files one task bean each.
- S18: WS2 decides by vector (one side changes).
- July `sbo-vos1` and `sbo-4tka` confirmed fixed by reading.

## 4. Next

All 21 decisions settled 2026-11-04. WS2–WS7 run in parallel; WS8 follows WS4/5/6; WS9 consolidates. New decisions from the skeptic passes are appended as Q22+.
