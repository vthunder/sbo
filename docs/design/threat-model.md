<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# SBO threat model

> **Status: review draft, 2026-11-03.** Written for the 2026-11 security
> audit (epic `sbo-ax7t`, workstream WS1, bean `sbo-dl2l`). It names the
> adversaries, what each can see and send, the assets each is after, the
> trust boundaries the specs claim, and the invariants the rest of the audit
> tests. Section references are to the specs in `specs/`: *core* (SBO
> Specification), *wire*, *uri*, *policy*, *identity*, *authz*
> (Authorization), *attr* (Attribution), *attest* (Attestation), *community*,
> *content*, *indexer*, *genesis*, *bridge*, *state* (State Commitment),
> *nft*. Format follows `browserid-ng/docs/design/threat-model.md`.

## 1. The flows, and who touches what

Seven flows carry every object and every credential in the system. Each
line names the parties that see an artefact in transit; an adversary is
whichever of them is hostile. The one structural fact that shapes all of
them: **SBO is based.** Nothing SBO-aware gatekeeps inclusion on the DA
layer (core §Validity Layers). Every check that lives only at a daemon's
submit endpoint is a convenience; the check that matters is the one every
replayer performs on the bytes the chain carries.

**F1. Authoring and submission (wire, content §Write-Model, authz).** A
client builds an envelope (`sbo-wasm` kit, `sbo-cli`, or mingo-web), signs
it with an ephemeral `ed25519` key, attaches the attribution proof
(`Auth-Cert` presentation + `Auth-Evidence`), and either `POST`s it to a
daemon's `/v1/submit` or submits straight to TurboDA / an Avail node. The
daemon validates against confirmed+pending state, refreshes `/sys/dnssec/`
evidence ahead of the write, runs the fail-closed revocation check, stages
the object in the mempool overlay, and enqueues the bytes for a
finality-gated batch. Sees the bytes: client, daemon operator, TurboDA, the
Avail network, every node that follows the appId.

**F2. Replay and validation (core §Rules, wire §Batch, authz
§Verification).** Every full node reads each block's app data from an Avail
RPC (`sbo-rpc`, `avail-light`), splits the batch, parses each envelope,
verifies the signature over the reconstructed header block, checks the HLC
bound, resolves the owner to a controller, verifies attribution against the
block's inclusion time, evaluates the governing policy, applies LWW, and
writes the object to RocksDB, the filesystem mirror and the state trie.
Sees nothing new; this is where every invariant is decided.

**F3. Reads through a node (indexer, http).** A client asks a daemon for
`/v1/object`, `/v1/list`, `/v1/state-root`, optionally with an SBOQ
inclusion proof, and may verify the proof against a root it trusts. Reads
also serve the mempool tip (`confirmed: false`). Sees: the daemon operator;
any web origin, since CORS reflects `*`.

**F4. Attribution capture (attr §3–§5, authz §DNSSEC Evidence).** A client
or the daemon captures an RFC 9102 proof of `_browserid.<issuer>` from a
public resolver (`sbo-capture`, default `1.1.1.1:53`) and posts it as a
self-authorizing `dnssec.v1` object at `/sys/dnssec/<issuer>`, which any
later write references. The browserid certificate itself comes from the
issuer's IdP or the broker. Sees: the resolver, the IdP, anyone who reads
the chain (emails and provider domains are public).

**F5. Genesis, bootstrap and fast-sync (genesis, state §Checkpoints,
§Snapshots, §Attestations).** A repo is created by submitting a genesis
batch at `@firstBlock`; followers verify `genesisHash` against the `_sbo`
record or the URI. A fresh node may instead fetch a sync-point manifest
and a snapshot from a serving node, rebuild the trie, compare the root to a
checkpoint, and count attestations under its trust policy. Sees: the serving
node (untrusted by spec), the checkpoint authority, attestors.

**F6. Delegation via warrants (authz §Agent Warrant, attr §3a).** A human's
config key signs a warrant naming an agent, an `sbo+raw://` audience and
scopes; the agent mints access certs and presents
`access_cert~assertion~warrant~config_cert` in `Auth-Cert`. `as:<grantor>`
makes the write authorize as the human. Sees: the broker (status lists,
registry), the IdPs of both parties, everyone on chain.

**F7. DA submission and finality (content §Durability, submit_queue,
turbo).** The daemon batches queued bytes per appId and submits to TurboDA
with the operator's API key, then polls for finality before the next batch.
Sees: TurboDA (sees the key), the operator.

## 2. Adversaries

| # | Adversary | Position | Sees | Can send | Wants |
|---|---|---|---|---|---|
| A1 | Malicious writer | Anyone with an Avail account or a daemon in reach; needs no identity | The whole chain | Arbitrary bytes into the appId, directly or via `/v1/submit` | Occupy a slot, overwrite another's object, plant a policy, crash or fork replayers, exhaust node resources |
| A2 | Warrant-holding agent | Holds an agent access cert and a warrant from a human | The warrant, its scopes, the human's objects | Writes under the warrant, including `as:<grantor>` | Write outside its scopes, act as the human where not granted, keep acting after revocation or expiry |
| A3 | Malicious indexer / serving node | Runs a daemon others read from (`node=` in `_sbo`, da.sandmill.org) | All reads and submits that pass through it | Forged objects, proofs, manifests, snapshots, checkpoint lists; selective omission | A client that believes a state it never verified; censorship of reads; a forged fast-sync anchor |
| A4 | DA / RPC / TurboDA provider | Between the chain and every node | All submissions (TurboDA sees API keys) | Reordered, withheld, or fabricated block data; false finality | Reorder a create race, hide a write from one node, make two nodes diverge |
| A5 | Network / DNS attacker | Between a node and its resolver, IdPs, status-list hosts, other nodes | Plaintext DNS to `1.1.1.1`, TLS metadata | Forged or stale DNS answers, SERVFAIL, redirects on `https://` status and snapshot fetches | Capture a bad proof, steer an outbound fetch to an internal host, downgrade a primary to the broker path |
| A6 | Compromised or malicious IdP / broker | Controls `_browserid.<domain>` or the pinned broker | Its users' certs | Certs binding any key to any address in its domain, or (broker) in any no-primary domain | Impersonate its users on chain; the protocol accepts this as the email trust assumption and asks only that it be attributable and bounded |
| A7 | Daemon co-tenant | A second repo followed by the same daemon, or a second app on TurboDA | Shared pending pool, shared HTTP surface | `?repo=` selection, submits for the other repo | Spend the other repo's TurboDA credit, read or pollute its pending tip |
| A8 | Genesis forger / fast-sync backer | Can write a batch at some block, or sign a checkpoint / attestation | The real genesis | A second genesis at the same anchor, a forged checkpoint, an attestation under an unpinned key | A client syncs the wrong database or anchors on a forged root |
| A9 | Local attacker on the daemon host | Another user or process on the box | `~/.sbo`, the Unix socket, `/tmp/sbo-debug`, the filesystem mirror | IPC commands (`RepoAdd`, `RepoRemove`, `Shutdown`, approve sign requests), symlinks | The keyring, the TurboDA key, arbitrary file writes via the mirror, approving an auth request |
| A10 | Governance insider | Holds the `sys` key, a `govern` grant, or the checkpoint key | Everything | Policy edits, trust-anchor edits, checkpoints | Rewrite the rules retroactively; the audit asks only what stays auditable and what the pin/descendant-constraint model actually prevents |

A4 and A6 are not boundaries the protocol claims to hold; they are included
so the audit states what breaks and what remains detectable.

## 3. Assets, ranked

1. **The replay rule.** Every node must compute the same state from the same
   bytes. Anything that makes two correct nodes disagree (a parse that
   differs, a check that depends on wall clock or on an RPC's optional
   field, a panic on one input) is the top-ranked loss: it is a fork.
2. **Slot occupancy and ownership.** `(path, id)` is globally unique; the
   first valid write owns it. A write that lands in an occupied slot without
   authorization, or occupies a slot with no valid signature over its
   payload, breaks the object model.
3. **Policy objects and the `govern` chain.** The root policy, pins and
   descendant constraints decide who may write where. Planting, shadowing or
   cycling a policy captures a subtree or crashes every evaluator.
4. **Attribution evidence and trust anchors.** `/sys/dnssec/<domain>`,
   `/sys/trust/brokers`, `/sys/trust/dns-root`. A bad proof that validates,
   or an anchor that is never read, silently widens who may speak for an
   email.
5. **Genesis identity.** `firstBlock` + `genesisHash`. A client pointed at
   the wrong genesis replays an attacker's database.
6. **Checkpoint and attestation keys; snapshot roots.** A forged root that a
   client adopts is a forged database without replay.
7. **Operator secrets.** TurboDA API keys (per repo), the keyring at
   `~/.sbo/keys`, the checkpoint and attestor key files, the IPC socket.
8. **Node availability.** Replay must not stall on hostile bytes; the HTTP
   surface must not be a free amplifier (DNS captures, status fetches,
   snapshot streams, full-table lists).
9. **Metadata.** Emails and provider domains are public by design (T0/T1);
   the audit tracks only what leaks beyond that (logs, debug dumps).

## 4. Trust boundaries the specs claim

- **B1. Validity is decided on replay, by every client, from the bytes**
  (core §Validity Layers; indexer §Trust Model). No sequencer, checkpoint
  or daemon is an authority. Corollary: a submit-time gate is not a
  security boundary.
- **B2. The payload is bound to the signature only through `Content-Hash`**
  (core §Signature Scope; wire §Payload Integrity). A verifier MUST
  recompute it.
- **B3. The signed bytes are the canonical header block** (wire §Signature
  Computation, §Validation Rules): canonical order enforced, CRLF rejected,
  unknown headers ignored but never signed-around.
- **B4. One object per `(path, id)`, first valid write wins, by inclusion
  order** (core §Object Identity; state §Slot occupancy).
- **B5. Attribution is a deterministic function of the message, chain state
  and the pinned root KSK at inclusion time** (core §Attribution Capture;
  authz §Inclusion-Time Clock). No live network, no wall clock.
- **B6. An issuer vouches only for its own domain, or is a pinned broker**
  (authz §Verification step "Authority"; attr §4 step 6). Checked for the
  grantee and the grantor independently.
- **B7. An agent cert is inert without a warrant; the warrant names one
  `sbo+raw://` database; unknown scope dimensions fail closed; `as:` can only
  name the grantor and only with a `path:` scope** (authz §Agent Warrant).
- **B8. Policy only narrows down the hierarchy; `govern` is never implied by
  `*`; a pinned child cannot be reached by a later ancestor edit** (policy;
  policy-delegation model P1–P4 as implemented).
- **B9. Circular roles, unknown conditions and unknown actions make a
  policy invalid, and objects under an invalid policy are invalid** (policy
  §Validation Rules).
- **B10. Without a root policy, nothing is valid** (core §Policies; genesis
  §Validation). Genesis is validated structurally, in one block, first
  attempt wins, `genesisHash` verified.
- **B11. Indexer outputs are claims; proofs bind them to a root the client
  trusts; snapshots are verified against a checkpoint root; checkpoint trust
  is `{attestors, threshold}` over signed `(block, root)` claims** (indexer;
  state §Trust Mechanisms).
- **B12. `_sbo` DNS is discovery only, never a trust root** (uri §DNS TXT;
  identity §Repository Discovery).
- **B13. Ordering carries no authority** (content §HLC). A forged HLC can
  only demote the liar's own write, bounded by `ε` and the collection's `W`.
- **B14. A `dnssec.v1` object is self-authorizing but not trust-granting**
  (attr §3, §7): posting one proves only what the chain already validates.

## 5. Invariants to test

Phrased so WS2 (vectors), WS3 (properties), WS5 (authz matrix) and WS6
(verification tests) can each turn one into a check. Each names the
boundary it derives from.

**Envelope and signature (WS2, WS3, WS6)**
- I1. A message whose payload does not hash to `Content-Hash` is invalid
  (B2).
- I2. A message whose headers are not in canonical order, contain CR,
  duplicate a header, or carry a non-canonical `Content-Length`
  (`+5`, `007`), is invalid; the bytes verified are the bytes received, or
  the parser rejects anything the serializer would not reproduce (B3).
- I3. Every parser in the repo (`sbo-core` wire, `sbo-wasm` kit round trip,
  the batch splitter, the daemon's `extract_sbo_payload`) accepts and rejects
  the same inputs and yields the same `object_hash` (B1).
- I4. `object_hash` is the SHA-256 of the raw received bytes, so a message
  carrying a header the parser does not model (`Attestation`, `Origin`,
  `Proof`) hashes identically on every implementation (B1, state
  §Object Hash).
- I5. Unknown `Action`, `Type`, `SBO-Version`, key or hash algorithm, and
  any `Id` outside the grammar, reject; `..`, `.` and empty segments are not
  valid ids (B3, core §Identifier Syntax).
- I6. A batch is either applied as the spec says (all or nothing) or the
  spec is amended; every implementation does the same thing (B1, S5).
- I7. Both ed25519 wrappers accept exactly the same signatures (no
  strict/non-strict split) (B1).

**Ownership, slots and policy (WS3, WS4, WS6)**
- I8. A create into an occupied slot by a signer not authorized for the
  occupant is invalid; a transfer into an occupied slot is invalid; a delete
  or transfer-away vacates the slot (B4).
- I9. Every write that is not a `govern` write is evaluated against the
  governing policy's `deny`, `grants` and `restrictions`, including an
  update by the owner and a `/sys/names/` claim (B8, B9, core §post).
- I10. `govern` is granted only by name; a `*` or `post` grant never
  installs a policy; a policy write is authorized by the parent policy
  (B8).
- I11. A policy with a role cycle, an unknown condition key, an unknown
  action, or an invalid pattern is rejected at write time, and role
  resolution at evaluation time is bounded (B9).
- I12. A pinned child's governance resolves against the pinned version
  only; a child grant never exceeds the parent's `descendant_constraint`
  template; `forbid_pinning` is honoured (B8).
- I13. `not_attested` and `attested` fail closed on a state-read error and
  on an unknown inclusion time (B5, policy §Requirement Conditions).
- I14. `Creator` is immutable across updates and transfers; a declared
  `Creator` requires the signer to control it (authz §Creator integrity).
- I15. `Policy-Ref` may be set or changed only by the object's creator
  (core §post).

**Attribution (WS2, WS6)**
- I16. Attribution uses the inclusion time for every window: cert, warrant,
  RRSIG, root KSK, broker designation; a missing inclusion time is a hard
  reject, not a skipped check (B5).
- I17. The access cert's key equals the envelope `Public-Key`; the
  grantee's domain equals the access-cert issuer or that issuer is a pinned
  broker; the grantor's domain equals the config-cert issuer or that issuer
  is a pinned broker (B6).
- I18. An agent presentation whose audience is not a bare `sbo+raw://`
  reference identifying this database (authority; `@firstBlock` and
  `?genesis` if present) rejects; an `sbo://` audience always rejects (B7).
- I19. Scopes: OR within a dimension, AND across; an unrecognized
  dimension or an unrecognized `sign:` kind rejects; `as:` must equal the
  grantor, appear once, and travel with a `path:` scope (B7).
- I20. The pinned root KSK on chain, not a library constant, anchors
  validation; `/sys/trust/brokers` is read in the spec's shape (B5, S3,
  S4).
- I21. A `dnssec.v1` payload validates to the root and carries
  `_browserid.<id>` for exactly the id it is posted under; the write is
  otherwise invalid (B14).
- I22. The effective author of a write is the grantee, or the grantor under
  `as:`; owner, `Creator` and name-claim checks all use that identity
  (B7).
- I23. Identity comparison follows one rule everywhere (`resolve.rs`,
  `check_authority`, policy `canonical_name_ref`, `parse_email`): domain
  case-folded if the spec says so, local part byte-exact, one `@` (S6).

**Time and ordering (WS3)**
- I24. HLC arithmetic is checked: `T_b − W`, `T_b + ε`, `lag_s × 1000`,
  `physical / 1000` never overflow or wrap; a hostile `_config` cannot make
  the bound vacuous (B13).
- I25. The authoring instant used for any credential window is bounded by
  the spec's `W`, and `W` itself is bounded by a protocol maximum and set
  only by a party the policy authorizes (B13, S10).
- I26. LWW is a total order; the pending overlay and the confirmed path
  compute the same winner for the same pair (B13, content §Conflict
  Resolution).

**Genesis and bootstrap (WS4, WS6, WS8)**
- I27. Without a root policy no write is applied; the genesis batch is
  validated structurally (mode A/B object set, order, self/domain
  signatures, same block); a second genesis at the anchor is an error; a
  `genesisHash` mismatch stops sync (B10).
- I28. A snapshot is adopted only when its recomputed root equals a
  checkpoint root that the client's policy has actually verified (a signed
  `checkpoint.v1` under a pinned key, or `threshold` attestations under
  pinned keys), never a root asserted by the serving node's manifest;
  `policy_versions` in a snapshot are derived from covered objects, not
  loaded as given (B11).
- I29. The DA client never advances past a block whose data it did not
  obtain, never treats a zero block hash as real, and cross-checks the
  connected chain against the URI (B1, A4).
- I30. The state trie distinguishes leaves from internal nodes; an
  inclusion proof for an object cannot be re-interpreted as a subtree proof
  (state §State Tree Structure).

**HTTP, IPC and host (WS5, WS4)**
- I31. Every outbound fetch triggered by an unauthenticated request (status
  lists, snapshots, DNS captures) refuses redirects, refuses non-public
  addresses, caps the body, and is rate-limited per source; a cert's status
  URI host is the cert's issuer (A5, browserid-ng I9).
- I32. `/v1/submit` spends the node's TurboDA credit only for callers the
  operator has allowed; `?repo=` cannot reach a repo the caller is not
  allowed to write; CORS reflects `*` only when the bind is loopback (A1,
  A7).
- I33. On-chain `path`/`id` values map into the filesystem mirror without
  escaping the repo directory and without a file/directory collision
  stalling replay (A1, A9).
- I34. The IPC socket is `0600`; every mutating IPC command requires the
  socket, and a hostile `RepoAdd.path` cannot point the mirror at an
  arbitrary directory (A9).
- I35. A sign request id is ≥ 64 bits, expires, and its approval is
  delivered only to the opener origin the request named (A1).
- I36. No input from the chain, an RPC or an HTTP body can panic a replayer
  (`unwrap` on parsed paths, `(end - 1)` with `end == 0`, division by
  `cols == 0`, gzip bombs in snapshots) (asset 1, asset 8).

## 6. Accepted risks

- **The based design makes every submit-time check advisory.** Revocation
  (status lists), evidence freshness, rate limits and TurboDA key checks
  run at `/v1/submit` only; a writer with its own DA access bypasses them.
  The spec accepts this (core §Validity Layers); the audit therefore treats
  replay validation as the only boundary and submit-time checks as hygiene.
- **IdP and broker compromise** is the email trust assumption (authz
  §Security Considerations). Mitigation is attributability on chain plus
  the sovereignty upgrade; not a boundary.
- **DA inclusion and ordering are trusted from the RPC** until DA
  verification lands (July bean `sbo-7bl8`). The audit records what a lying
  RPC can do; closing it is a roadmap item.
- **Permissionless `/sys/dnssec/` refresh** (attr §5, resolved
  `mingo-jyzt`): any party may replace the proof with another valid one.
  The audit tests only that an invalid proof never lands and that the
  window read is the current object's.

## 7. Out of scope for this audit

Cryptanalysis of Ed25519, SHA-256 and the DNSSEC algorithms; the Avail
consensus and light-client sampling; the browserid-ng broker and IdP
internals (audited separately, `browserid-ng` 2026-11); the mingo
application layers (`mingo-app`, `mingo-idp`, `mingo-web`, `deploy/mingo/`),
which get their own audit; the RISC Zero proving system itself (the guest
program is in scope for what it proves, not for soundness of the VM).
