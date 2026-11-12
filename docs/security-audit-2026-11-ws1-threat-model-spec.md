<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS1: threat model and spec/design review

**Status:** complete, 2026-11-03. Epic `sbo-ax7t`, bean `sbo-dl2l`, branch
`audit-2026-11`. Scope: the fifteen specs in `specs/` and the two proposals
in `specs/proposals/`, read against every crate under `crates/`. Companion
documents: `docs/design/threat-model.md` (adversaries A1–A10, boundaries
B1–B14, invariants I1–I36) and `docs/security-audit-2026-11-decisions.md`
(Q1–Q21). Format follows the browserid-ng WS6 report.

**Method.** WS1 is the reviewer pass only. Every lead below is a *candidate*
with a pre-verification severity and an owning workstream whose skeptic
tries to refute it by reading more code or writing a test; nothing here is a
finding until that pass. Leads are `D1..Dn` (code), spec findings are
`S1..Sn` (spec gaps, contradictions, spec-vs-code disagreements with a
recommendation on which should move; the default is that the spec wins).
The twelve open items from the July 2026 review (`sbo-ix77`, epic
`sbo-f5wn`) were re-checked against today's tree (`30e267c`) and carried
forward where still present (§3). No production code or spec text was
changed.

## 1. Spec-by-spec review

Each entry: what the spec claims, what the code does, leads.

### 1.1 Core (SBO Specification)

Claims: `(path, id)` globally unique, first valid write wins; identifier
grammar (unreserved + `@ + :`, 1–256 chars, case-sensitive, no Unicode);
signature over canonical headers, payload bound via `Content-Hash`; batch
messages processed in order; absence of a root policy makes every message
invalid; only the owner may update "unless forbidden by the object's
policy"; `Policy-Ref` may be set only by the creator.

Code: `sbo-core/src/message/envelope.rs:97-118` implements the grammar but
accepts `.` and `..` as ids (D21); `sbo-daemon/src/validate.rs` (validate_post)
skips policy evaluation entirely when the signer controls the owner (D57) and
for all `/sys/names/` claims (D56); `message_to_stored_object` copies
`Policy-Ref` from any authorized updater (D12); genesis mode (`!root_policy_exists`)
accepts every post and every policy write (D5); the daemon's `run` loop logs
a `process_block` error and continues to the next block (D21b).

### 1.2 Wire Format

Claims: LF only; canonical header order is mandatory and non-canonical order
is invalid; `Content-Hash` MUST be verified; hex lowercase; unknown headers
ignored; batch is atomic ("if any message is invalid, the entire batch is
rejected"); `secp256k1`/`keccak256` listed as supported.

Code: `wire/parser.rs:123` collects headers into a `HashMap` (duplicates:
last wins; order discarded); `:169` skips `Content-Hash` ("Skip content hash
validation for now"); `message/validate.rs` verifies the signature over
`canonical_signing_content()` rebuilt from parsed fields, so any
byte-string that parses to the same fields verifies (D1, D2); unknown
headers (`Attestation`, `Origin`, `Proof`, …) are dropped and absent from
`wire::serialize`, so `object_hash` over re-serialized bytes differs from
the chain bytes (D3); `Content-Length` is parsed with Rust `usize::from_str`
which accepts `+5` and `007` (D2); the daemon applies valid messages of a
batch individually (S5); only `ed25519:` and `sha256:` parse (S21). The
canonical order in the spec has no `Auth-Warrant`; the serializer places it
after `Auth-Evidence` (S2).

### 1.3 URI

Claims: bare `repo=` rule; `@firstBlock` anchor; "MUST error if >1 genesis
at the anchor"; `as_of`, `content_hash` selectors; percent-encoding for
non-ASCII.

Code: `uri.rs` parses chain/appId/anchor/query; `dns.rs::parse_record`
enforces the bare rule; `as_of` is recognized and refused with 501
(`http.rs::reject_as_of`, fine); the >1-genesis rule is not implemented
(D5); no percent-decoding and `:` in an id mis-splits (D14, July
`sbo-zocd`).

### 1.4 Policy

Claims: evaluation order deny→grant→restriction→default-deny; roles may
nest and "circular role references are invalid (policy must be rejected)";
a validation pass with six rules; `attested`/`not_attested`; `fields`
conditions; identity forms; `$owner/$user/$email/$name` fail closed.

Code: `policy/evaluate.rs:342-380` resolves `Role` members recursively with
no visited set and no depth bound (D10); there is no policy-validation pass
anywhere (unknown action strings fail at serde, but cycles, bad patterns and
unknown `require` keys are accepted on write); `not_attested` reads
`list_objects_by_schema("attestation.v1").unwrap_or_default()`
(`validate.rs:2090`) so a RocksDB error un-bans everyone (D11), and the same
call scans every attestation in the database for every attested check
(D11b); the implemented `govern`, `pin`, `descendant_constraint`,
`forbid_pinning`, `dnssec_proof` and `require_payload_signed_by` are absent
from the spec (S12). The owner fast-path (D57) bypasses `deny` and
`restrictions`, which the spec says nothing can override.

### 1.5 Identity

Claims: email-rooted default; subaddressing downward only; owner reference
forms including bare key; `resolve_controller` with hop limit and cycle
detection; sovereignty upgrade on a primary domain; `domain.v1` self-cert
MUST reject on failure; `_sbo` is discovery only; name creation governed by
root policy; T1 operator can impersonate until the upgrade (noted in
Security Considerations only obliquely, July `sbo-0web`).

Code: `resolve.rs` matches the spec algorithm, including the primary-domain
override; bare keys resolve to `Controller::Key` (S7, July `sbo-4arq`); the
domain self-cert check is `tracing::warn!` only (`sync.rs:1305-1311`, D7);
name claims skip policy (D56); comparisons are byte-exact everywhere, no
case folding, and `Id` admits several `@` (D13, S6); the `e_<16 hex>`
creator fallback truncates the key to 64 bits (D55).

### 1.6 Authorization

Claims: `Auth-Cert` is a single browserid JWT with `principal.email`,
`public-key`, `iat/exp`; agent certs carry `Auth-Warrant`; recognized
brokers in `brokers.v1` `{ "brokers": [...] }`; `dns-root.v1` is "the only
key the protocol trusts a priori"; inclusion time for every window; audience
rule; scope grammar; `as:` guardrails; name-claim anti-hijack.

Code: the legacy single-cert verifier no longer exists; `attribution.rs`
keeps only the DNSSEC extraction and domain self-cert, and
`device_attribution.rs` verifies the four-object browserid device
presentation carried *in `Auth-Cert`*; the `Auth-Warrant` header is parsed
and serialized but never read (S1, S2). `TrustAnchors::root_ksk` is
"informational only" because `dnssec-prover` hardcodes the IANA root
(`attribution.rs:30-40`, D6, July `sbo-y5ek`); `/sys/trust/dns-root` is
never read. `/sys/trust/brokers` is parsed as a bare JSON array
(`validate.rs:97-106`), not the spec's object (S3). The audience and scope
rules match the spec (`authorize.rs`), with one addition: `sign:sbo:<act>`
is accepted as an action scope (S1 should document it). Presentation
expiries are judged at `authored_at` derived from the HLC
(`device_attribution.rs` module docs; `validate.rs::device_effective_email`),
not at the inclusion time the spec names (S10, D22). The name-claim
anti-hijack is implemented (`validate_name_claim`).

### 1.7 Attribution

Claims (this spec already describes the reference implementation): the
proof artefacts, evidence resolution order (`inline:`, `ref:`, conventional
`/sys/dnssec/<iss>`), §4 algorithm, §4a agent steps, §5 freshness with the
daemon's write-time refresh, and the `mingo-jyzt` resolution that any party
may refresh `/sys/dnssec/<domain>` in place.

Code matches §4/§4a closely. Leads: the permissionless refresh lets an
attacker replace a fresh proof with an older *valid* chain (lower
expiration, or a pre-rotation key still inside its RRSIG window), which is
accepted because validity is the only check (D33); `evidence.rs::refresh_wire`
signs with a throwaway key and no HLC, so `lww_admits` always lets it
overwrite (consistent with the resolution, noted for S/D33). The spec's §4
step 6 and the code's `check_authority` both compare the domain
byte-exact (S6).

### 1.8 Attestation

Claims: issuer is `Owner`; `type` grammar; `expires ≥ issued_at`; in-force
at inclusion time; stale is not invalid; anyone may attest anything.

Code: `schema/attestation.rs` validates the fields and the type regex;
`attested_subject_matches` resolves issuer and subject controllers and uses
`l2.inclusion_time.unwrap_or(0)` (D28: with an unknown inclusion time no
attestation is in force, so bans evaporate and memberships vanish). No
other gap.

### 1.9 Community

Claims: a thin descriptor; governance = attestation-defined roles + policy;
repository-per-community recommended; aggregated communities are not
sovereign because policies cascade.

Code: nothing community-specific in `sbo-core`/daemon beyond
`community.v1` schema presence; the sovereignty statement is honoured by
the P1–P4 delegation model (pins). No lead. Note for S12: the spec's
example policies use `can: ["create"]` on `/<issuer>/attestations/**` for
admins but never mention `govern`, so a reader cannot tell from the specs
that installing a community policy needs it.

### 1.10 Content

Claims: `HLC` bound `T_b − W ≤ physical ≤ T_b + ε`; `W` per collection via
`collection.v1` `_config`; "attribution is unchanged"; LWW total order by
HLC, signer key, object_hash; `Prev` advisory.

Code: `hlc.rs` and `validate.rs::check_hlc_bound` implement the bound;
`collection_max_lag_ms` reads `_config` from the write's own path with no
ceiling, and `within_bound` computes `t_b_ms - max_lag_ms` unchecked (D22:
an attacker who can create `_config` in a collection sets `W` to
`i64::MAX/1000`, which wraps the bound and, through `authored_at`, lets an
expired presentation verify); the LWW tie-break uses `owner` (the signing
key) on the stored side and `signing_key` on the new side, consistent;
`pending.rs::pending_still_wins` and `state_view::overlay_wins` return
different defaults when an HLC is missing (`false` vs `true`), a WS2 vector
(D17b).

### 1.11 Indexer and Client

Claims: indexer outputs are claims verified by inclusion and subtree proofs;
clients must distinguish tip from confirmed; completeness via subtree proof.

Code: `/v1/object?proof=1` serves an SBOQ inclusion proof; `/v1/list` serves
no completeness proof (S17); the pending tip is flagged `confirmed: false`.
The serving node is trusted far more than the spec allows in the bootstrap
path (D26, D27, §1.13).

### 1.12 Genesis

Claims: mode A/B object sets, order, same-block, first attempt wins, later
attempts rejected by policy; `genesisHash = sha256(concat(serialize(m)))`;
validation failure means "database is invalid"; trust anchors SHOULD be
established at genesis.

Code: `genesis.rs::Genesis::validate` is `todo!()`; `genesis_hash` matches
the spec's canonicalization; `main.rs:1706-1733` verifies the expected hash
at the anchor block and logs `GENESIS VERIFICATION FAILED` without stopping;
no same-block or first-wins logic exists; the daemon's "genesis mode" accepts
everything until `/sys/policies/root` appears, in any block (D5, July
`sbo-9d7l`). The spec's `concat(serialize(m))` is the reserialized form, so
the hash is only reproducible if every implementation serializes
identically (ties to D3/I4).

### 1.13 State Commitment

Claims: `object_hash = sha256(raw_sbo_bytes)`; sparse path trie, node hash
over canonical JSON of children; exclude-self checkpoint rule; snapshot
verified against a checkpoint root the client trusts; trust =
`{attestors, threshold}` over signed claims; attestations lag; liveness
fallback; manifest is "a convenience, never a trust root".

Code: `sync.rs:1122` hashes `wire::serialize(msg)` (D3); `sbo-crypto/src/trie.rs`
hashes a leaf as the bare object hash and an internal node as the JSON
document, so a 32-byte leaf is indistinguishable from a subtree hash
(D4, July `sbo-hedq`); `bootstrap.rs::evaluate_trust` inserts `sys-checkpointer`
as a backer whenever it is in the policy, without verifying that a
`checkpoint.v1` signed by any pinned key exists, and takes the checkpoint
root from the serving node's manifest (D26); `verify_and_load_payload` loads
`policy_versions` from the snapshot as given, outside the root check (D27);
`bootstrap_provisional` adopts the manifest's own `state_root` with
`RootTrust::ServingNode` when no checkpoint is listed (D26); `trust.rs`
has no liveness fallback (D15); checkpoint `state_root` is bare hex in
`trust.rs::claim_from_message` while the spec writes `sha256:...` (S18).

### 1.14 Bridge

Claims: lock/unlock/import with oracle attestations, verifier objects,
replay protection.

Code: `validate.rs` returns `Import action not yet implemented`; `Proof`,
`Proof-Type`, `Origin`, `Registry-Path`, `Object-Path`, `Attestation` are not
modelled by the parser (and so are dropped on re-serialization, D3). The
whole spec is aspirational (S11, July `sbo-rx1z`).

### 1.15 NFT schema

Claims: `nft.v1` payload shape with embedded media.

Code: no validator (`validate_schema` passes unknown schemas, which the
policy `schema` restriction can still gate). No lead; note that embedded
media makes `max_size` the only brake on payload bloat.

### 1.16 Proposals

*Domain self-certification*: applied to the specs; the implementation plan's
"warn-log then flip to hard reject" is still at warn-log (D7); the plan's
`ref:<path>#<creator>` form predates global uniqueness and the code reads the
single `/sys/dnssec/<domain>` slot (consistent with the later resolution).
Open question in the proposal (self-cert REQUIRED for Mode B?) is Q8.

*Global path/id uniqueness*: applied; `state_view::merge` implements the
"different creator → confirmed wins" rule; the reorg re-resolution text has
no implementation because there is no reorg handling at all (D39, July
`sbo-7bl8`).

## 2. Candidate leads

Pre-verification severities. "Owner" is the workstream whose skeptic pass
confirms or refutes.

| ID | Candidate | Sev | Where | Owner |
|---|---|---|---|---|
| D1 | `Content-Hash` is never verified against the payload; a signature-valid envelope accepts any payload. Compounds with P2 pins, which key a stored policy version by the *claimed* `Content-Hash` header (`sync.rs:1240`), so a malicious policy body can be filed under a benign policy's hash. July `sbo-d5nm`, still open. | Critical | `sbo-core/src/wire/parser.rs:169`; `message/validate.rs`; `sbo-daemon/src/sync.rs:1240` | WS6 (+WS8 PoC) |
| D2 | Signature verifies a reconstruction: headers into a `HashMap` (duplicates last-wins, order dropped), no canonical-order check, non-canonical `Content-Length` accepted, non-strict ed25519 verify. July `sbo-h75z`. | High | `parser.rs:123-130`, `envelope.rs::canonical_signing_content`, `crypto/ed25519.rs:61` | WS6 |
| D3 | `object_hash` and `genesisHash` are over `wire::serialize(msg)`, not the received bytes; unknown headers (`Attestation`, `Origin`, `Proof`, `Proof-Type`, `Registry-Path`, `Object-Path`) are dropped, so roots diverge across implementations and transfers carry a mutated object. July `sbo-2tue`. | High | `sync.rs:1122`, `genesis.rs::genesis_hash`, `wire/serializer.rs` | WS6, WS2 |
| D4 | State trie has no leaf/internal domain separation. July `sbo-hedq`. | High | `sbo-crypto/src/trie.rs` (`PartialNode::Leaf`, `TrieNode::hash`) | WS6 |
| D5 | Genesis: `Genesis::validate` is `todo!()`; no root policy ⇒ accept every write and every policy write; `genesisHash` mismatch only logs; no same-block / first-wins / >1-genesis rule. July `sbo-9d7l`. | Critical | `sbo-core/src/genesis.rs:13`, `validate.rs::validate_post` (`!root_policy_exists`), `main.rs:1706-1733` | WS6, WS4 |
| D6 | Pinned root KSK is decorative: `dnssec-prover` uses its compiled-in IANA root; `/sys/trust/dns-root` is never read. July `sbo-y5ek`. | High | `attribution.rs:30-62` | WS6 |
| D7 | Domain self-cert failure is `warn!` only; genesis verification failure is `error!` only. July `sbo-3gqo`. | High | `sync.rs:1294-1312`, `main.rs:1706-1733` | WS4 |
| D8 | zkVM guest proves header chain + DA + an independent trie witness; `_actions_hash` is discarded, witnesses are never derived from `actions_data`, `header_data: None` yields a zero `data_root`. July `sbo-5rww`. | Critical (scope Q19) | `sbo-zkvm/methods/guest/src/main.rs:124-200` | WS6 |
| D9 | `verify_kzg_proof` is a stub returning `Ok(true)`; DA client trusts RPC, zero block hash, "not available" advances height. July `sbo-7bl8`. | High | `sbo-crypto/src/kzg.rs`, `sbo-avail/src/client.rs:190-240` | WS6, WS4 |
| D10 | Role resolution recurses with no visited set or depth bound; no policy validation pass rejects cycles on write; a cyclic policy stack-overflows every evaluator. July `sbo-bynl`. | High | `policy/evaluate.rs:342-380` | WS3, WS6 |
| D11 | `not_attested` fails open on a state-read error; every attested check scans the whole `attestation.v1` set. July `sbo-zocd`. | Medium | `validate.rs:2079-2110` | WS4 |
| D12 | `Policy-Ref` set/update is not restricted to the creator. July `sbo-zocd`. | Medium | `validate.rs:2165` | WS4 |
| D13 | No identity normalization; `Id` admits multiple `@`; domain compared byte-exact in `resolve.rs`, `check_authority`, `canonical_name_ref`; `parse_email` uses `split_once` while `check_authority` uses `split('@').nth(1)`. July `sbo-zocd`. | Medium | `resolve.rs:70-90`, `device_attribution.rs:260-270`, `dns.rs::parse_email` | WS2, WS3 |
| D14 | URI percent-decoding absent; `:` in an id mis-splits. July `sbo-zocd`. | Low | `uri.rs:239-330` | WS3 |
| D15 | Trust gate has no bounded-wait / degrade fallback. July `sbo-zocd`. | Low | `trust.rs` | WS4 |
| D16 | `effective_owner_ref` falls back to the ephemeral signer key; `resolve_creator` falls back to `e_<first 16 hex>` (64-bit truncation) or the literal `unknown`. | Low | `validate.rs::effective_owner_ref`, `::resolve_creator` | WS4 |
| D17 | Mempool divergence (in-progress `sbo-hy4r`) and read-vs-validation policy disagreement during replay (`sbo-y757`); `pending_still_wins` and `overlay_wins` disagree on the missing-HLC default. | Medium | `pending.rs`, `state_view.rs`, `sync.rs` | WS4, WS2 |
| D18 | Submit-gate SSRF: a presentation's status refs name arbitrary `https://` URIs; `StatusChecker` fetches them with a default `reqwest` client (redirects followed, no address guard, uncapped body); `authority_key` performs a live DNS capture for any authority string before any on-chain check; the cert-status host is not bound to the cert issuer. Unauthenticated via `/v1/submit`. browserid-ng H1/W6-5 class. | High | `status.rs:60-80, 150-190`; `main.rs:690-720` | WS5 (+WS8) |
| D19 | Resource amplification without authentication or limits: `/v1/dnssec` does a live DNSSEC capture per request; `/v1/submit` captures evidence for every issuer the client names; `/v1/list?prefix=/` dumps the table; `/v1/snapshot` loads whole files into memory; `proof=1` per request; no 429 anywhere. | Medium | `http.rs` | WS5 |
| D20 | IPC: socket created with default umask; `RepoAdd.path` is any directory, `RepoRemove` runs `remove_dir_all`, `ApproveSignRequest` and `Shutdown` need only socket access. | Medium | `ipc.rs::run`, `main.rs::handle_request` | WS4, WS5 |
| D21 | Filesystem mirror traversal and stall: `Id::new("..")` is accepted, so `Path: /../../` + `ID: x` writes `wire_data` outside the repo directory; an object id that collides with a later collection name makes `create_dir_all` fail, `process_block` returns `Err`, and `run` skips the rest of the block on this node only (state fork). Also `with_extension("tmp")` collides ids `a.b` / `a.tmp`. | High | `envelope.rs:97-118`, `sync.rs:936-945, 1084-1110, 1321-1350` | WS4 (+WS8) |
| D22 | `W` is read from the collection's own `_config`, unbounded, writable by whoever has `create` there; `within_bound` subtracts unchecked (wrap at `i64::MAX`); `authored_at = physical/1000` feeds the presentation expiry check, so a hostile `_config` resurrects expired access certs and assertions. | Medium | `validate.rs::collection_max_lag_ms`, `hlc.rs::within_bound`, `device_attribution.rs::verify_device_attribution_with_provider_keys` | WS3, WS4 |
| D23 | Genesis mode is also live at the submit gate: a repo with no root policy accepts and forwards any write (ties to D5). | Medium | `validate.rs::validate_post` | WS4 |
| D24 | `require_payload_signed_by` only pattern-matches the issuer path; whether the domain-certified identity JWT signature is verified against the `/sys/domains/<d>` key on every replay needs confirming (`schema/mod.rs::validate_schema`). | Medium | `policy/evaluate.rs::check_payload_signed_by`, `schema/mod.rs` | WS6 |
| D25 | Transfer re-homes the object but keeps the original wire bytes (old `Owner`, `Path`, `ID` headers) in the mirror and in `object_hash`; readers re-parsing the mirror see a different owner than state; the source path's "must allow moving out" rule is not evaluated. | Low | `sync.rs::apply_transfer_or_delete`, `validate.rs::validate_transfer` | WS4 |
| D26 | Fast-sync trusts the serving node: `evaluate_trust` counts `sys-checkpointer` as a backer merely because it is in the policy; checkpoint roots come from the untrusted manifest; `bootstrap_provisional` adopts the manifest's own root (`RootTrust::ServingNode`). A malicious node forges a root and the client loads a forged database. | High | `bootstrap.rs:30-60, 150-260` | WS4 (+WS8) |
| D27 | Snapshot `policy_versions` (pinned historical policies) are loaded as given, outside the trie-root check; a forged pinned version rewrites a community's frozen governance. | High | `bootstrap.rs::verify_and_load_payload` | WS4 |
| D28 | With an unknown inclusion time (RPC `timestamp` missing is non-fatal, `rpc.rs:399-410`): attestations are evaluated at `t = 0` (bans not in force), attribution is impossible, the HLC bound is skipped. Nodes with and without the timestamp diverge. | Medium | `validate.rs:2085`, `::check_hlc_bound`, `::device_effective_email` | WS4, WS2 |
| D29 | Batch atomicity: the daemon validates and applies messages individually; the wire spec says an invalid message rejects the whole batch. Cross-implementation divergence (S5). | Medium | `sync.rs:720-800` | WS2 |
| D30 | Two ed25519 wrappers (`sbo-core/src/crypto`, `sbo-crypto`), both non-strict; two sha256 helpers; two `Id` grammars (`sbo-types` lacks `@ + :`). | Low | `sbo-core/src/crypto/ed25519.rs`, `sbo-crypto/src/ed25519.rs`, `sbo-types/src/id.rs` | WS2 |
| D31 | `Related` that fails to parse is silently dropped, so a message signed with a malformed `Related` fails signature verification (rejected), while a *well-formed* `Related` round-trips through serde with reordered keys and may change `object_hash` (D3 class). | Low | `envelope.rs::Related::parse_header` | WS2 |
| D32 | `Auth-Warrant` is parsed, serialized and signed but never consumed; a write carrying one is a plain write. | Info (S1) | `parser.rs:192`, `serializer.rs:90` | WS6 |
| D33 | `/sys/dnssec/<domain>` rollback: any party may replace the proof with an older valid chain or a pre-rotation key still inside its RRSIG window; only validity is checked, not monotonic freshness. | Medium | `validate.rs` dnssec policy path, `evidence.rs` | WS4 |
| D34 | Checkpoint `/sys/checkpoints/**` and attestation writes are ordinary policy-gated writes; the checkpoint key (`sys-checkpointer`) is a config string in `bootstrap.rs` while `trust.rs` pins public keys; a name/key mismatch means no backer ever counts. | Low | `bootstrap.rs:7`, `trust.rs::TrustPolicy::from_config` | WS4 |
| D35 | Secrets: TurboDA keys in `config.toml` plaintext and env; TurboDA request bodies logged at debug (first 200 bytes); webhook URL in config. | Low | `config.rs`, `turbo.rs:40` | WS7 |
| D36 | `/tmp/sbo-debug` fixed path, world-writable parent, symlink-followable writes when `save-raw-block` is on. | Low | `rpc.rs:243` | WS7 |
| D37 | Auth popup: `/auth/status/:id` returns the assertion to anyone holding the 64-bit id; no expiry sweep; `postMessage` target is the unvalidated `origin` query param. | Low | `http.rs::auth_popup_page`, `::get_auth_status` | WS5 |
| D38 | CORS reflects `*` and sets `Access-Control-Allow-Private-Network: true` on every response; with `SBO_HTTP_BIND=0.0.0.0` (da.sandmill.org) any web page can read state and `POST /v1/submit` using the node's TurboDA key and evidence capture. | High | `http.rs:300-345`, `main.rs::submit` | WS5 (Q15) |
| D39 | Avail light-client path: "app data not available" returns an empty block and advances; block hash hardcoded zero; no reorg/finality handling; URI chain id never cross-checked against the node's genesis. July `sbo-7bl8`. | High | `sbo-avail/src/client.rs:188-240`, `sbo-rpc/src/client.rs` | WS4 |
| D40 | `decode_app_data_from_rows` falls back to the raw bytes when extrinsic decoding fails; `extract_sbo_payload` heuristics; SBOP parser prints diagnostics to stderr and trusts `Receipt-Length`. | Low | `sbo-rpc/src/decode.rs`, `sync.rs::extract_sbo_payload`, `proof/sbop.rs` | WS3 |
| D49 | Guest `verify_app_completeness`: `(end - 1)` underflows when `end == 0`; `start / cols` divides by zero when `cols == 0`; prover-side `expect`s. | Low | `guest/src/main.rs:270-300` | WS3 |
| D50 | Snapshot decode inflates gzip without a cap (`read_to_end`), from an untrusted node; `fetch_snapshot` follows redirects with a default client. | Medium | `snapshot.rs::decode_snapshot_payload`, `bootstrap.rs::fetch_snapshot` | WS3, WS5 |
| D51 | Untrusted RFC 9102 bytes reach `dnssec_prover::parse_rr_stream` from the chain (`dnssec_proof` restriction), from `/v1/dnssec`, and from the submit gate; robustness unknown. | Info (fuzz) | `attribution.rs::extract_provider_key` | WS3 |
| D52 | Cert status URI host is not required to equal the cert issuer (browserid-ng W6-4 class); the warrant host is derived with a hand-rolled `uri_host`. | Low | `device_attribution.rs::presentation_status_refs` | WS5 |
| D54 | `Id` grammar allows several `@`; `check_authority` takes the segment after the first `@`, `resolve_controller` splits once: an identity `a@mingo.place@evil` is in domain `mingo.place` for one and `mingo.place@evil` for the other. | Low | `device_attribution.rs:262`, `resolve.rs:74` | WS2 |
| D55 | `resolve_creator` → `e_<16 hex>` / `unknown` sentinel ids as durable creators. | Low | `validate.rs::resolve_creator` | WS4 |
| D56 | `/sys/names/` claims never evaluate policy: the root policy's `/sys/names/*` grants, restrictions (`not_attested` bans) and `deny` are ignored; the spec says name creation is governed by policy and deployments may restrict it. | Medium | `validate.rs::validate_name_claim` | WS4 |
| D57 | Owner fast-path on update skips the whole policy: `deny` (bridge lock), `restrictions` (`max_size`, `schema`, `not_attested` bans), and `can: ["update"]` grants; the spec says "unless forbidden by the object's policy" and "no grants can override a deny". The same fast-path exists for transfer/delete. | Medium | `validate.rs::validate_post`, `::validate_transfer` | WS4 (+WS8) |
| D58 | `process_block` errors (filesystem, RocksDB) abort the block mid-way on one node and `run` continues to the next block: deterministic replay is not restartable from the failed message. | Medium | `sync.rs::run`, `::write_object` | WS4 |

Leads D41–D48 and D53 were considered and folded into the rows above (D53
into D18, D41–D48 refuted on reading: creator-string matching is guarded by
the creator-integrity check; `Path::parse(...).unwrap()` in policy
evaluation only sees already-validated paths; the zero-root sentinel in
`PartialTrie::new` is unreachable for a non-empty state).

## 3. July 2026 leads, re-checked

| July bean | Then | Now (30e267c) |
|---|---|---|
| sbo-d5nm Content-Hash unverified | Critical | **Still open** (D1); now compounded by P2 pins keyed on the claimed hash. |
| sbo-9d7l genesis fail-open | Critical | **Still open** (D5); `Genesis::validate` still `todo!()`; expected-hash check added but non-fatal (c0acdd7-era `verify_genesis`). |
| sbo-5rww zkVM proves no validity | Critical | **Still open** (D8); scope decision Q19. |
| sbo-h75z signature over reconstruction | High | **Still open** (D2). |
| sbo-bynl circular roles | High | **Still open** (D10); `Any` nesting adds a second recursion. |
| sbo-7bl8 DA trusted from RPC | High | **Still open** (D9, D39); finality-gated *submission* landed (f2fdb9f) but reads still trust the RPC. |
| sbo-3gqo self-cert warn-only | High | **Still open** (D7); evidence is now read from the object's own `Auth-Evidence: ref:` or the single slot, which closes the shadowing half under global uniqueness. |
| sbo-2tue object_hash over re-serialized bytes | High | **Still open** (D3). |
| sbo-y5ek pinned root KSK decorative | High | **Still open** (D6). |
| sbo-hedq trie domain separation | High | **Still open** (D4). |
| sbo-4arq bare-key owners | High | **Still open**; spec and code both accept bare keys (S7, Q6). |
| sbo-rx1z bridge unimplemented | High | **Still open** (S11). |
| sbo-zocd medium roundup | Medium | Policy-Ref (D12), not_attested fail-open (D11), normalization (D13), URI decoding (D14), trust-gate liveness (D15), legacy owner fallback (D16): **all still open**; bootstrap-proof anchor folded into D8/D26; KZG stub in D9. |
| sbo-0web docs/spec drift | Normal | **Still open**; superseded by S-items below. |
| sbo-vos1 unprivileged policy install | High | **Fixed** (4b28d8e, `govern`); re-verified by reading `require_govern` and the existing `member_create_grant_cannot_install_shadowing_policy` test. |
| sbo-4tka `/u/` attested lookup | High | **Fixed** (b6ac8ba); `attested_subject_matches` scans by schema regardless of path. |
| sbo-hy4r mempool order divergence | High, in progress | Partially addressed (f2fdb9f finality-gated batching); carried as D17. |

## 4. Spec findings

| ID | Finding | Which should move | Decision |
|---|---|---|---|
| S1 | Authorization spec describes a single-JWT `Auth-Cert` + separate `Auth-Warrant`; the code (and the Attribution spec §3) implement the four-object browserid device presentation inside `Auth-Cert`, with the warrant embedded; `Auth-Warrant` is dead on the wire; `sign:sbo:<action>` scopes are accepted but unspecified. | Spec moves to the device model; retire `Auth-Warrant` or define it. | Q1 |
| S2 | Wire canonical order omits `Auth-Warrant`; the serializer emits it after `Auth-Evidence`. | Follows Q1: either add it to the order or delete the header. | Q1 |
| S3 | `brokers.v1` payload: spec `{ "brokers": [...] }`, code bare array. | Whichever the live genesis emits; if code, amend spec. | Q2 |
| S4 | `dns-root.v1` is "the only a-priori key" but cannot be injected into `dnssec-prover`; the object is never read. | Code moves (fork/patch the validator to take anchors), or spec demotes the object to an audit record. | Q3 |
| S5 | Batch atomicity: spec all-or-nothing, code per-message; the daemon's evidence-refresh-ahead design assumes per-message. | Spec moves to per-message with explicit ordering text, or code moves and the refresh is a separate batch. | Q4 |
| S6 | Identity comparison rule is unstated for SBO: core says ids are case-sensitive; browserid-ng §5 lowercases the domain; code compares byte-exact everywhere and admits several `@`. | Spec gains one normative rule; code follows (D13). | Q5 |
| S7 | Bare-key `Owner` is a valid form in the Identity spec; bean `sbo-4arq` says reject it. | Decide; whichever way, spec and code must agree. | Q6 |
| S8 | "Absence of a root policy ⇒ invalid" vs genesis-mode accept-all; the spec never defines the bootstrap window precisely (what is valid *in* the genesis block before the root policy message is applied). | Spec gains a precise bootstrap rule; code implements `Genesis::validate` and fails closed (D5). | Q7 |
| S9 | Self-certification optional for Mode B (proposal's open question). | Decide. | Q8 |
| S10 | Content spec: "attribution is unchanged … valid at inclusion time"; code judges presentation expiries at the HLC-derived authoring instant bounded by `W`, and `W` is unbounded and unprivileged. | Spec moves to name the assertion as the one object judged at authoring time, with a protocol maximum for `W`; code bounds `W` and privileges `_config` (D22). | Q9 |
| S11 | Bridge spec is entirely unimplemented and reads as normative. | Mark Status: Aspirational / not implemented. | Q10 |
| S12 | Policy spec lacks `govern`, `pin`, `descendant_constraint`, `forbid_pinning`, `dnssec_proof`, `require_payload_signed_by`; the Community spec's examples cannot work without `govern`. | Spec moves (document what shipped in P1–P4). | no decision; WS9 task |
| S13 | Core/Policy say policy can forbid the owner and nothing overrides `deny`; code fast-paths owner updates past the policy. | Spec wins; code moves (D57). | Q13 |
| S14 | Identity/Genesis say name creation is governed by the root policy; code bypasses policy for name claims. | Spec wins; code moves (D56). | Q14 |
| S17 | Indexer spec promises completeness proofs; `/v1/list` serves none. | Document as a gap or add subtree proofs. | WS9 task |
| S18 | Checkpoint/attestation `state_root` is `sha256:`-prefixed in the spec examples, bare hex in `trust.rs` and `bootstrap.rs`. | Spec example or code; one of them. | WS2 vector |
| S19 | URI spec's ">1 genesis at the anchor MUST error" has no implementation. | Code (part of D5). | Q7 |
| S20 | The specs never state plainly that submit-time gates are advisory in a based design and that replay validation is the only boundary; the Attribution spec's §5 revocation note is the closest. | Add one paragraph to core §Validity Layers. | WS9 task |
| S21 | Wire spec lists `secp256k1` and `keccak256` as supported; code supports only `ed25519`/`sha256` and rejects the rest. | Spec: mark ed25519/sha256 REQUIRED, others reserved. | WS9 task |
| S22 | Encoding rules (lowercase hex, canonical integers) are stated but the parser accepts `+5`/`007` lengths and uppercase hex in some fields. | Code (part of D2). | — |

## 5. What needs Dan's decision

See `docs/security-audit-2026-11-decisions.md` Q1–Q21. The ones that block
other workstreams: Q1 (which attribution model the vectors encode), Q4
(batch atomicity, WS2 vectors), Q5 (identity comparison, WS2/WS3), Q7
(genesis fail-closed shape, WS6 tests), Q9 (authored-at vs inclusion time,
WS3 time properties), Q15 (HTTP exposure model, WS5 authz matrix
expectations), Q19 (zkVM scope).

## 6. Ordering for WS8 (High+ candidates to demonstrate)

1. D1 payload swap on a signature-valid message, plus the P2 pin confusion.
2. D21 filesystem escape with `Path: /../` and the collision stall.
3. D26/D27 forged manifest + snapshot adopted as `OnChainCheckpoint`.
4. D18 SSRF from a presentation's status ref through `/v1/submit`.
5. D5 genesis-mode acceptance (write before any root policy) and the
   non-fatal genesis-hash mismatch.
6. D2 duplicate/reordered header malleability.
7. D10 role-cycle crash of a replayer.
8. D57 owner update past a `deny` and past a `not_attested` ban.
9. D22 `_config` with a huge `W` resurrecting an expired assertion.
10. D38 cross-origin submit through a public bind (measure only).
