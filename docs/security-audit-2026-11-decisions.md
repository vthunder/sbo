# Security audit 2026-11: open decisions

> **Status: open — WS1 decisions Q1–Q21 await Dan.** Product and design
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
| WS2 conformance vectors | sbo-5t0f | Blocked on Q1, Q4, Q5. |
| WS3 fuzz + proptest | sbo-qw0z | Blocked on Q5, Q9. |
| WS4 never-audited layers | sbo-f8cj | Ready (owns D7, D11, D12, D15–D17, D20–D23, D25–D28, D33, D34, D39, D55–D58). |
| WS5 HTTP / IPC surface | sbo-s4xl | Blocked on Q15 for the matrix expectations; D18, D19, D37, D38, D50, D52 otherwise ready. |
| WS6 crypto core / verification | sbo-iye5 | Blocked on Q7 (genesis shape) and Q19 (zkVM scope); D1–D6, D8–D10, D24, D30 otherwise ready. |
| WS7 supply chain / CI / secrets / logging | sbo-ip5k | Ready (D35, D36). |
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

### Q2. `brokers.v1` payload shape (S3)

Spec: `{ "brokers": ["broker.example"] }`. Code: a bare JSON array. A
spec-shaped object parses to no brokers (fail closed, every broker-certified
write rejected).

- (a) Code moves to the object form; the mingo genesis is regenerated.
- (b) Spec moves to the bare array.

**Recommendation: (b)** unless a regenesis is already planned for D3/D4
(Q18), in which case (a) rides along.

### Q3. Pinned root KSK (S4, D6, July `sbo-y5ek`)

`/sys/trust/dns-root` is the spec's single a-priori anchor; the code cannot
inject it into `dnssec-prover` and never reads the object.

- (a) Fork or patch `dnssec-prover` to accept trust anchors; read
  `/sys/trust/dns-root` at inclusion time; verify `valid_from/valid_until`.
- (b) Amend the spec: the IANA root as compiled into the validator is the
  anchor; `/sys/trust/dns-root` becomes an audit record; accept that a
  rollover can break replay of old evidence until the library updates.

**Recommendation: (a).** Durability of replay across the next IANA
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

### Q5. One identity-comparison rule (S6, D13, D54)

No SBO spec states how two identity references compare. Code compares
byte-exact everywhere and `Id` admits several `@`.

- (a) Adopt browserid-ng §5: exactly one `@`, domain compared as a
  lowercased A-label, local part byte-exact; the canonical on-chain form is
  lowercase-domain, and a header carrying an uppercase domain is invalid
  (so paths like `/u/alice@Example.com/` cannot alias).
- (b) Byte-exact everywhere, reject uppercase domains at parse.

**Recommendation: (a)** with the canonical-form rule, so comparison and
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

### Q8. Self-certification required for Mode B (S9)

- (a) Required for Mode B from the next genesis; plain self-signed domains
  only in Mode A.
- (b) Optional (current spec), with the hard reject of D7 when present.

**Recommendation: (b)** now, (a) at the next regenesis.

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

### Q10. Bridge spec status (S11, July `sbo-rx1z`)

- (a) Mark Status: Aspirational, not implemented; leave the text.
- (b) Remove the `import` action and bridge headers from the wire spec
  until implemented.

**Recommendation: (a).**

### Q11. D1 fix ordering

Two-line parser change plus the P2 pin keying fix, versus letting WS8 show
the payload swap and the pin confusion first.

- (a) Fix now on the branch; PoC against the parent commit.
- (b) PoC first, then fix.

**Recommendation: (b)**, as in browserid-ng Q1: the report should carry a
shown impact, and the audit rule is no production change on the branch.

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

### Q13. Owner fast-path versus policy (S13, D57)

- (a) Spec wins: owner updates, transfers and deletes evaluate `deny` and
  `restrictions` always, and `grants` as `to: owner` (so a policy without an
  owner grant denies the owner, as the spec allows).
- (b) Keep the fast-path for `grants` but apply `deny` and `restrictions`.

**Recommendation: (b).** It closes the bridge-lock and ban bypasses without
breaking every existing community policy that relies on the implicit owner
grant; revisit (a) with a spec note.

### Q14. Name claims under policy (S14, D56)

- (a) Evaluate the governing policy for `/sys/names/` creates and updates
  in addition to the anti-hijack check.
- (b) Keep name claims policy-free and amend the Identity/Genesis specs.

**Recommendation: (a).**

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

### Q16. `/sys/dnssec/` rollback (D33)

- (a) A refresh must not lower the current occupant's RRSIG expiration
  (monotonic freshness), and must carry the same or a newer DNSKEY set.
- (b) Accept rollback as the documented cost of permissionless refresh.

**Recommendation: (a)**; it is one comparison in the policy check.

### Q17. Role cycles (D10)

- (a) Both: a policy-validation pass on write (cycles, unknown keys,
  pattern syntax) and a visited-set + depth bound at evaluation.
- (b) Evaluation guard only.

**Recommendation: (a).**

### Q18. Root-changing fixes and regenesis (D3, D4, Q2)

Raw-bytes `object_hash` and trie domain separation each change every state
root and every proof.

- (a) Ship both together under a `state-commitment/v2` version, regenesis
  app 506, publish the migration note.
- (b) Ship separately.

**Recommendation: (a).**

### Q19. zkVM scope (D8, July `sbo-5rww`)

- (a) Mark `sbo-zkvm` experimental in README and specs, feature-gated,
  carrying no trust claim; no remediation this round beyond that note.
- (b) Remediate: bind witnesses to `actions_data`, run SBO validation in
  the guest.

**Recommendation: (a).**

### Q20. DA trust (D9, D39, July `sbo-7bl8`)

- (a) Document RPC trust as an accepted risk this round; fix only the
  silent-skip and zero-hash behaviours (never advance past unobtained data,
  cross-check the chain id).
- (b) Implement KZG and reorg handling now.

**Recommendation: (a).**

### Q21. Fuzzing cadence (Info)

- (a) Weekly launchd `make fuzz-smoke` on the dev box, like browserid-ng
  Q29.
- (b) Manual only.

**Recommendation: (a).**

## 3. Already settled by the spec text (no decision needed)

- S12, S17, S20, S21: pure documentation gaps; WS9 files one task bean each.
- S18: WS2 decides by vector (one side changes).
- July `sbo-vos1` and `sbo-4tka` confirmed fixed by reading.

## 4. Next

WS1 is done. Dan answers Q1–Q21 (Q1, Q4, Q5, Q7, Q9, Q15, Q19 unblock
WS2/3/5/6); WS4 and WS7 can start now. Decisions get recorded here and in
the affected beans as they arrive.
