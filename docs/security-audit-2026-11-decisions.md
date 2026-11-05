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
| WS2 conformance vectors | sbo-5t0f | Done 2026-11-04. 135 vectors in 8 suites, 5 runners (19 tests) green in CI (`conformance.yml`) with expected-fail tables. 4 genuine cross-implementation disagreements (W2-1..W2-4); everything else is the stack agreeing with itself against the spec (D1, D2, D3, D4, D13, D21, D28, D30, D54 all confirmed by vector). Decisions Q34–Q37. |
| WS3 fuzz + proptest | sbo-qw0z | Done 2026-11-04. proptest: core 47 pass / 22 ignored, crypto 5 / 3, rpc 3 / 1, daemon 3 / 1. 12 cargo-fuzz targets in a standalone `fuzz/` workspace (`make fuzz-smoke`, weekly launchd, `fuzz-smoke.yml`). New findings W3-1..W3-11 (2 High: exponential glob matching in policy patterns and warrant scopes; W3-8/W3-9 verifier and parser panics on untrusted input). Decisions Q38–Q40. |
| WS4 never-audited layers | sbo-f8cj | Done 2026-11-04. 21 candidates: 15 confirmed, 3 partial, 1 refuted, D33/D58 confirmed by reading, D39 accepted risk (Q20). 4 new (W4-1..4). Tests: daemon 7 pass / 16 ignored, core 2 / 1. Decisions Q22–Q25 open. |
| WS5 HTTP / IPC surface | sbo-s4xl | Done 2026-11-04. 7 candidates: 6 confirmed, 1 partial. Findings W5-1..W5-10 (1 High: W5-1 public bind with `*` CORS + PNA; 6 Medium; 3 Low). Authz matrix 12 pass / 9 ignored; findings 8 / 6. Decisions Q30, Q31 (numbered past the WS4/WS7 Q22–Q25 pairs). |
| WS6 crypto core / verification | sbo-iye5 | Done 2026-11-04. 12 candidates: 9 confirmed, 2 partial (D3, D24), 1 read-only (D8). 5 new findings W6-1..W6-5. Tests: sbo-core 13 pass / 14 ignored, sbo-crypto 2 / 1 (+1 kzg), sbo-daemon 0 / 3. Live v5 genesis passes Q7 only under Q33 (a); fails Q8 either way. Decisions Q32, Q33. |
| WS7 supply chain / CI / secrets / logging | sbo-ip5k | Done 2026-11-04. No CI existed; `test.yml`, `supply-chain.yml` (cargo-audit, cargo-deny, gitleaks), dependabot added. 41 advisories, 34 after reasoned ignores, all closable by `cargo update` + dropping an unused `reqwest 0.11`. No secret ever committed (514 commits). 14 findings W7-1..14 (3 Medium). Decisions Q26–Q29. |
| WS8 PoCs | sbo-cka2 | Ordering list in the WS1 report §6. |
| WS9 ledger + remediation beans | sbo-q92z | Done 2026-11-04. `docs/security-audit-2026-11.md`: 2 Critical, 12 High, 29 Medium, 22 Low, 10 Info confirmed; 20+ leads refuted. 60 beans under the epic (48 remediation: 28 `todo`, 20 `draft` pending Q22–Q40; 12 spec-edit). Suite: 518 pass / 0 fail / 94 ignored after one WS3 generator fix. July epic sbo-f5wn closed, every open item carried. |

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

### Q30. `/v1/dnssec` after submit-side evidence refresh (WS5 W5-2, Medium)

`GET /v1/dnssec?domain=` runs a live DNSSEC chain walk through the node's
resolver for any caller and any domain (`needed_by` is caller-chosen, so the
"refresh needed" branch is always reachable). `/v1/submit` now refreshes
issuer evidence itself (`evidence.rs`), `mingo-web` never calls the route,
and the one remaining caller is `mingo-app`'s `appoint` CLI.

- (a) Remove the route; `appoint` posts its write and lets submit refresh.
- (b) Keep it behind the Q15 allowlist / bearer and the per-source limiter.

**Recommendation: (a).** One fewer unauthenticated amplifier, and the
submit path already does the job once.

### Q31. The `/auth` popup flow and sign-request IPC commands (WS5 W5-10, Low)

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

History (asked by Dan 2026-11-05): the six IPC commands landed 2025-12-18
(443da50) for a pre-browserid "sign request" login: an app submitted a
request, the user ran `sbo auth pending|approve|reject`, and the CLI signed
a nested-JWT assertion with the keyring; `sbo auth test-request|test-poll`
(f009007) was the only app-side caller. The three HTTP routes landed
2025-12-23 (2bc5dfe) from the web-auth demo design
(mingo `docs/plans/2024-12-22-web-auth-demo-design.md`): a planned
`navigator.sbo.request()` shim plus hidden iframe on `wallet.sandmill.org`
that would POST `/auth/request` and poll `/auth/status/:id`; the shim,
iframe and demo page were never built. On 2026-06-23 (4de7d7f, "delete
browserid-clone auth") the `sbo auth` CLI commands, the nested-JWT code and
the sbo-auth-demo crate were removed because browserid-ng owns auth; the
daemon-side queue and routes were left behind. Nothing has called them
since.

### Q32. Unknown headers versus a raw-bytes `object_hash` (WS6 W6-4, Medium)

The Wire spec says unknown headers are ignored, and the signature covers
only the modelled headers in canonical order. The State Commitment spec,
and Q18, say `object_hash = sha256(raw_sbo_bytes)`. Both cannot hold: a
relay can append `X-Relay: injected` to any signed message, every parser
accepts it, and the raw hash (hence the state root and every proof)
changes. Today the code hashes the reserialization, which quietly picks the
second rule and breaks the first spec. Test: `d2_unsigned_unknown_header_is_rejected`.

- (a) Fail closed: the parser rejects any header it does not model, and the
  signing content is the received header block minus the `Signature` line.
  Then every accepted message is canonical, raw and reserialized hashes
  coincide, and the spec text can keep `sha256(raw_sbo_bytes)`.
- (b) Keep "unknown headers are ignored" and amend the State Commitment and
  Genesis specs to define `object_hash` and `genesisHash` over the
  canonical serialization of the modelled headers.

- (c) Sign what was sent, ignore what you do not understand: the signing
  content is the received header block minus the `Signature` line, so an
  unknown header is accepted only if the signer put it there. Unknown
  headers sit after the modelled ones; a parser that does not model one
  keeps its bytes for hashing and ignores its meaning. A header whose
  meaning an old client must not skip is listed in a `Critical` header
  (X.509 style) and rejects on clients that do not know it; otherwise a
  semantics change is an `SBO-Version` bump.

**Recommendation: (c), revised 2026-11-05.** The defect is unsigned bytes
in a signed message, not the existence of unknown headers. (a) fixes it by
turning every new header into a de facto version bump: in a mixed fleet an
old node rejects every message that carries a new header, so a publisher
cannot use one until every consumer has upgraded, and several concurrent
experiments are impossible. (b) leaves experimental headers mutable in
flight. (c) keeps raw and reserialized hashes equal (so `sha256(raw_sbo_bytes)`
stands and `sbo-2tue` is safe), makes relay injection fail signature
verification, and lets old and new clients coexist. Experimental headers
use a reserved prefix (`X-`), are signed like any other, and are ignored by
clients that do not know them; several can be live at once. The ignored
test `d2_unsigned_unknown_header_is_rejected` already pins (c): it rejects
an *unsigned* unknown header, not an unknown header as such.

Follow-up (asked by Dan 2026-11-05): under (a), a mixed fleet means old
nodes drop every message with a new header, and concurrent experiments are
impossible; (c) was added in answer.

Reserialization (asked by Dan 2026-11-05): today it happens twice in every
consumer. Signature verification rebuilds the signing content from the
parsed struct (`canonical_signing_content()`), and `object_hash` is
`sha256(wire::serialize(msg))` after parse (`sync.rs:1122`,
`main.rs:728`); the parsed struct holds only modelled headers, so an
unknown header is dropped and a consumer that models a different subset
reserializes differently. Under (c) the rule is "bytes in, bytes out":
only the signer serializes, once, when signing; every consumer verifies
and hashes the bytes it received and forwards those same bytes to storage,
relays, snapshots and proofs. The parser keeps the raw bytes (bean
`sbo-xypz`), and `wire::serialize` is for producers only. Two clients that
understand different subsets of the headers then agree on signature and
hash by construction, because neither rebuilds anything. Canonical order
stays a producer rule, checked by consumers on the modelled headers only.

### Q33. Shape of the genesis batch under strict mode (WS6 D5)

Q7 (a) says only the genesis batch at the anchor is valid before a root
policy exists and `Genesis::validate` checks it structurally. The live v5
and v6 batches put nine community objects, policies and configs *before*
`/sys/policies/root`, which is the last of 14 messages. Under Q4 (b)
per-message state threading those nine writes are evaluated before any
policy exists.

- (a) The anchor submission is one structural unit: the mode objects must
  appear in their relative order (dnssec, domain, sys, root), the root
  policy may sit anywhere in the submission, and every other message in
  the submission is accepted without policy evaluation (today's lenient
  rule confined to the anchor submission). The live layout passes.
- (b) The mode objects come first, in order, and every message after the
  root policy is validated normally against the state it left (Q4). The
  live layout fails; the regenesis Dan already accepted (Q8, Q18) puts the
  root policy fourth and the community objects after it, where they get a
  real policy check.

**Recommendation: (b).** It is the only reading consistent with Q4, it
removes the last accept-all window, and the regenesis is already planned.

### Q34. `state_root` wire form in checkpoint objects (WS2 W2-4 / S18, Low)

The State Commitment spec writes `state_root` as `sha256:<hex>` in every
example; `trust::claim_from_message` and `bootstrap` decode bare hex only,
so a spec-shaped `checkpoint.v1` is silently not a claim and never counts
as a backer (vectors CP-01, CP-03). Whatever the live checkpointer emits
today is the form that works.

- (a) Spec form wins: code accepts `sha256:<hex>` (and, during migration,
  bare hex), and emits the prefixed form.
- (b) Spec examples move to bare hex.

**Recommendation: (a).** Every other hash on the wire carries its
algorithm prefix (`Content-Hash`, `Prev`, `genesisHash`); a bare hash is
the odd one out.

### Q35. Which bytes `genesisHash` covers (WS2, Genesis spec vs State Commitment)

The Genesis spec defines `genesisHash` over the *canonical
re-serialization* of the ordered genesis messages; the State Commitment
spec defines `object_hash` over the *raw received bytes* (Q18 (a)). The two
agree only when raw and canonical bytes coincide, which Q32 (a) makes
mandatory for accepted messages. Until Q32 lands, the daemon's
`genesis_hash_from_wire` and `object_hash` take different inputs.

- (a) After Q32 (a): define both over the bytes as included on chain and
  say in the Genesis spec that, because non-canonical messages are invalid,
  this equals the canonical serialization.
- (b) Keep two definitions.

**Recommendation: (a).** One hashing rule; it is what the generator and
every runner in `conformance/` already assume.

### Q36. Two identifier grammars (WS2 W2-1, Low)

`sbo-types` (`Id`, `Path`, `Action`, re-exported as `sbo_core::Id` and used
by the zkVM guest) predates `@`, `+` and `:`: it rejects every email-rooted
and agent identity sbo-core accepts, and its `Action::parse` folds case and
admits `create` / `update`, which are not wire actions (13 vectors).
Nothing on the wire path uses it today, which is why it has not bitten.

- (a) One grammar: move the sbo-core `message` grammar into `sbo-types`
  and have `sbo-core::message` re-export it (sbo-wasm follows by
  `#[path]`).
- (b) Delete the sbo-types grammar and the re-exports.

**Recommendation: (a).** The guest and the wasm kit then share one
definition by construction, and the conformance runner for sbo-types stays
meaningful.

### Q37. Percent-encoding versus the identifier charset (WS2 / S23, Info)

Core §Identifier Syntax says non-ASCII is not allowed directly and to use
percent-encoding (`café` → `caf%C3%A9`), but `%` is not in `id_char`, so
the example is not a valid id under the grammar on the same page
(vector ID-REJ-06; every implementation rejects it, agreeing with the
grammar and not the prose).

- (a) Drop the percent-encoding sentence: ids are ASCII only.
- (b) Add `%` to `id_char` with a normative percent-encoding rule, and
  define comparison (byte-exact on the encoded form).

**Recommendation: (a).** Nothing emits or decodes percent-encoded ids, and
(b) would reopen the normalization questions Q5 just closed.

Zoom-out (asked by Dan 2026-11-05: are paths user-facing, and should other
scripts be allowed?). Paths are user-facing in three places: community
and collection names (mingo's community id becomes the path segment),
identity references (`alice@example.com`, local part and domain), and the
`sbo://` URI. Post and comment ids in mingo are derived hashes and never
typed. Everything a reader *reads* (titles, community display names,
bodies) is payload and already UTF-8, so documents in other languages are
supported today; only the *address* is ASCII.

Three ways to internationalize addresses, in rising cost:

1. Display-name layer (no spec change). The app maps a Unicode name to an
   ASCII id (slug, hash or user choice) and shows the Unicode name from
   the payload. This is what mingo does for posts already. Collisions and
   confusables are an app problem, not a chain problem.
2. IDNA-style A-labels (spec note, no wire change). A Unicode segment is
   carried on chain as an `xn--` punycode A-label after UTS #46 mapping and
   NFC; clients render the U-label. Domains in identity references
   already work this way under Q5, so this extends an existing rule to
   local parts and path segments. Comparison stays byte-exact on ASCII,
   the trie, globs, proofs and old clients are untouched, and the URI
   needs no percent-encoding. Confusable policy (mixed-script, skeleton
   match) is a registry rule the owning collection's policy can apply.
3. Native UTF-8 identifiers (breaking). Requires: an `SBO-Version` bump
   (old clients reject non-ASCII header values); normative NFC and a
   prohibited-character table; a confusable policy or an explicit
   decision to accept aliasing of `(path, id)` by homoglyph; UTF-8
   validation in the wire parser; glob matching defined on code points
   rather than bytes; percent-encoding in `sbo://`; identity comparison
   reopened for local parts (RFC 6531 EAI, which browserid and most IdPs
   do not support); conformance vectors; zkvm cost for normalization.
   Roughly a spec cycle plus a wire version.

**Recommendation for the zoom-out: keep (a) now, and if internationalized
addresses are wanted, adopt (2) as a spec note in the Core and Identity
specs.** It gives readers their script, costs no wire change, and inherits
twenty years of IDNA practice on confusables. (3) buys only prettier raw
bytes on the wire, which no one reads, at the price of the normalization
and aliasing surface Q5 just closed.

### Q38. Glob matching: linear algorithm or wildcard cap (WS3 W3-1 / W3-2, High)

`PathPattern::match_parts`, `IdPattern::glob_match` and the warrant
`path:` glob in `scopes_authorize` all backtrack over every split of every
`**` (or `*`), so a pattern with k wildcards against an n-segment path costs
O(n^k). Policy patterns are authored by anyone with a `govern` grant on a
subtree (or via a `descendant_constraint` template) and evaluated by every
node on every write beneath; warrant scopes are authored by ANY wallet and
evaluated at the submit gate and on replay. Ten `**` against 24 segments
does not finish. Tests: `w3_1_path_pattern_matching_is_polynomial`,
`w3_1_id_pattern_matching_is_polynomial`, `w3_2_scope_path_glob_is_polynomial`.

- (a) Replace all three matchers with one memoised (dynamic-programming)
  matcher, O(k·n), shared by core policy and `authorize.rs`; no grammar change.
- (b) Keep the recursion and reject at write time any pattern with more
  than N wildcards (and any scope string with more than N) — a grammar
  change that also has to be stated in the Policy and Authorization specs.
- (c) Both: the linear matcher, plus a generous cap stated in the spec as a
  size bound (like the 256-char id limit).

**Recommendation: (c).** (a) alone leaves no spec statement a second
implementation can be held to; (b) alone leaves the quadratic-ish worst
case in place. The reference matchers in the WS3 tests and fuzz targets
are the oracle for (a).

### Q39. Unknown keys in policy documents (WS3 W3-3, Medium)

`Policy`, `Grant`, `Restriction` and `Requirements` deserialize without
`deny_unknown_fields`, so a restriction whose condition key is misspelled
(`max_sise`, `not_attestd`) is accepted as an EMPTY requirement and fails
open; an unknown grant key is dropped. Threat model I11 says unknown
condition keys reject at write time. Making the parser strict is
consensus-changing: any policy already on chain with a stray key would
become invalid on replay.

- (a) Strict parse (`deny_unknown_fields` on all four structs) from the
  Q18 regenesis; WS8/WS9 survey app 506's policies first.
- (b) Strict parse now behind the protocol version, lenient for existing
  chains.
- (c) Leave lenient; document that unknown keys are ignored.

**Recommendation: (a).**; it rides the same regenesis as Q2/Q6/Q8/Q13.

### Q40. A warrant with no scopes (WS3 observation, Info)

`scopes_authorize([])` is `true`: a warrant whose scope list is empty
authorizes every action on every path and schema for its audience. The
Authorization spec's scope grammar says a dimension with no scope is
unconstrained but never says whether an EMPTY list is "everything" or
"nothing". browserid warrants for a ledger audience carry `sign:sbo:*`
scopes today, so nothing emits an empty list. Pinned by
`empty_scopes_authorize_everything_today`.

- (a) Spec: an empty scope list is unconstrained (today's behaviour), stated
  explicitly.
- (b) Spec: a ledger warrant MUST carry at least one `action:`/`sign:sbo:`
  scope; an empty list authorizes nothing.

**Recommendation: (b)**; it matches the browserid "inert without a warrant"
posture, and the cost is one line in every signer.

## 3. Already settled by the spec text (no decision needed)

- S12, S17, S20, S21: pure documentation gaps; WS9 files one task bean each.
- S18: WS2 decides by vector (one side changes).
- July `sbo-vos1` and `sbo-4tka` confirmed fixed by reading.

## 4. Next

Audit phase complete. Dan answers Q22–Q40; each answer flips the named `draft` beans to `todo` and is recorded here and in the bean. Remediation proceeds in the ledger's §5 order; the PR from `audit-2026-11` opens when Dan says.
