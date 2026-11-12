<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS6: crypto core and verification re-check

**Status:** skeptic pass complete, 2026-11-04. Epic `sbo-ax7t`, bean
`sbo-iye5`. Scope: the envelope signature and parser (`sbo-core/src/wire`,
`message`), both Ed25519 wrappers (`sbo-core/src/crypto`, `sbo-crypto`),
`object_hash` and `genesis_hash`, the state trie and proofs
(`sbo-crypto/src/trie.rs`), KZG (`sbo-crypto/src/kzg.rs`), identity JWTs
(`jwt.rs`), the device-presentation attribution verifier
(`device_attribution.rs`, `attribution.rs`, `dnssec-prover`), policy role
resolution and `require_payload_signed_by` (`policy/evaluate.rs`), genesis
(`genesis.rs`, the daemon's genesis mode), and the zkVM guest (read only,
Q19). Oracle: `docs/design/threat-model.md` I1, I2, I4, I7, I11, I16–I19,
I27, I30; decisions Q1, Q3, Q6, Q7, Q8, Q11, Q17, Q18, Q19.

**Method.** Reviewer pass over every file in scope, then a skeptic pass that
tried to refute each WS1 candidate by writing a Rust test. Every verdict
below is backed by a test that runs today. Tests encoding an invariant that
FAILS today are `#[ignore]`d with an `// AUDIT-2026-11 Dx: fails today`
comment and are the acceptance test for the fix; everything else passes
today and pins what the audit re-verified. No production code or spec text
was changed. No dependency was added: the tests use only existing
dependencies, and the one fixture is the live mingo genesis batch
(`crates/sbo-core/tests/fixtures/mingo-genesis-v5.wire`, public chain data).

| Crate | Test file | Pass | Ignored (fail today) |
|---|---|---|---|
| sbo-core | `crates/sbo-core/tests/audit_2026_11_ws6.rs` | 13 | 14 |
| sbo-crypto | `crates/sbo-crypto/tests/audit_2026_11_ws6.rs` | 2 | 1 (+1 under `--features kzg`) |
| sbo-daemon | `crates/sbo-daemon/tests/audit_2026_11_ws6.rs` | 0 | 3 |

Run the failing set with `cargo test -p <crate> --test audit_2026_11_ws6 -- --ignored`
(and `-p sbo-crypto --features kzg` for D9). All runs were done on the
localtest login: 15 pass, 19 ignored, 0 unexpected results.

## 1. Verdicts on the WS1 candidates

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| D1 | **CONFIRMED** | **Critical** | `sbo-core/src/wire/parser.rs:169` (`// Skip content hash validation`), `message/validate.rs::verify_message` (signature only), no caller recomputes it; `sbo-daemon/src/sync.rs:1240` keys P2 policy versions by the *claimed* hash | `d1_payload_swap_on_a_signature_valid_envelope_is_rejected`, `d1_payload_without_content_hash_is_rejected`, daemon `d1_daemon_rejects_a_payload_that_does_not_match_content_hash` |
| D2 | **CONFIRMED** | High | `parser.rs:123` (`HashMap` collect: duplicates last-wins, order dropped), `:159` (`usize::from_str` accepts `+2`, `002`), `crypto/ed25519.rs:61` and `sbo-crypto/src/ed25519.rs:70` (`verify`, not `verify_strict`), `hex::decode` everywhere (uppercase) | `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected`, `d2_uppercase_hex_is_rejected`, `d2_unsigned_unknown_header_is_rejected` |
| D3 | **PARTIAL** — reduces to D2 plus a spec conflict (Q32) | Medium | `sync.rs:1122` (`sha256(wire::serialize(msg))`), `genesis.rs::genesis_hash` | `d3_every_accepted_message_is_canonical` (ignored), `live_genesis_raw_and_reserialized_hashes_agree` (passes) |
| D4 | **CONFIRMED** | High | `sbo-crypto/src/trie.rs` `compute_hash`/`compute_node_hash`: `Leaf → object_hash` bare, internal → `sha256(json)` | `d4_leaf_and_internal_node_hashes_are_domain_separated` |
| D5 | **CONFIRMED** | **Critical** | `sbo-core/src/genesis.rs:13` (`todo!()`), `sbo-daemon/src/validate.rs:733,772` (genesis mode accepts every post and every policy write), `main.rs:1706-1733` (hash mismatch `error!` only) | `d5_genesis_validate_accepts_the_live_mode_b_batch`, `d5_genesis_validate_rejects_a_batch_without_a_root_policy`, daemon `d5_without_a_root_policy_*` (2) |
| D6 | **CONFIRMED** (by reading; see §1.6 for why no offline test exists) | High | `attribution.rs:30-62` (module doc admits it), `dnssec-prover-0.6.8/src/validation.rs:18` (`root_hints()` hardcoded, `verify_rr_stream` takes no anchors), `validate.rs::load_trust_anchors` never reads `/sys/trust/dns-root` | none possible today (W6-5) |
| D8 | **CONFIRMED** (read only, Q19 scopes it out) | Critical as a trust claim, Info for this round | `sbo-zkvm/methods/guest/src/main.rs:124-200` | — |
| D9 | **CONFIRMED** (KZG half) | High | `sbo-crypto/src/kzg.rs:116-157` (`Ok(true)` after the point-validity checks, "TODO: Add full pairing verification") | `d9_kzg_verify_rejects_a_proof_that_does_not_open_the_commitment` (`--features kzg`) |
| D10 | **CONFIRMED** | High | `policy/evaluate.rs:342-380` (`Role` and `Any` arms recurse with no visited set or depth bound); no validation pass on write | `d10_cyclic_role_policy_does_not_crash_the_evaluator` (child process), `d10_cyclic_role_policy_is_rejected_at_parse`; WS3 has the depth-bound tests |
| D24 | **PARTIAL** — the forged-issuer hole exists but is masked by a bug that makes the restriction deny everything (W6-3) | Low today, Medium once the path bug is fixed | `policy/evaluate.rs:253-300` (`check_payload_signed_by`: never verifies the JWT signature; `Path::parse("/sys/domains/<d>")` fails, so every payload is "Invalid issuer path") | `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer` |
| D30 | **CONFIRMED** (non-strict on both) | Low | both `verify` wrappers | `w6_1_small_order_public_key_universal_signature_is_rejected` (ignored), `i7_non_canonical_scalar_is_rejected_by_both_wrappers` (passes), `key_and_signature_lengths_and_algorithms_are_pinned` (passes) |
| D32 | **CONFIRMED** (Info) | Info | `parser.rs:192`, `serializer.rs:90` | `d32_auth_warrant_header_is_inert` (passes: a garbage `Auth-Warrant` changes nothing) |

### 1.1 D1 — the payload is not bound to the envelope (Critical)

Only `Content-Hash` ties the payload to the signed header block. The parser
checks `Content-Length` and parses the hash header but never compares it to
`sha256(payload)`; `verify_message` signs the canonical headers only; the
daemon's `validate_message` runs signature, schema, HLC, attribution,
state and policy checks and none of them recompute the hash. The test
swaps `{"amount":1}` for `{"amount":9}` under an untouched signature and
both `wire::parse` + `verify_message` and the daemon's `validate_message`
accept it. A payload may also be carried with no `Content-Hash` header at
all.

What the attacker gets: anyone relaying a signed write (the DA layer, a
node, a browser extension between the signer and `/v1/submit`) can replace
its payload with arbitrary bytes of the same length (`Content-Length` is
still checked), and every replayer accepts the message as signed by the
victim. Combined with P2 pins, which key a stored policy version by the
*claimed* `Content-Hash` (`sync.rs:1240`), a hostile policy body can be
filed under the hash a child policy pinned. Nothing in the current chain is
known to exploit it, but the integrity model the Core spec describes does
not exist in the implementation.

Remediation: in `parse_at`, when a payload is present require
`Content-Hash` and reject on `ContentHash::sha256(payload) != header`
(wire up the existing `ParseError::ContentHashMismatch`); require the
content headers for `Type: object`. Then un-ignore the three D1 tests.
Q11 (b): WS8 demonstrates the swap and the pin confusion against a local
daemon before the fix lands.

### 1.2 D2 — the signature verifies a reconstruction (High)

`parse_at` collects headers into a `HashMap` (duplicates: last wins; order
discarded), accepts `Content-Length: +2` and `002`, accepts uppercase hex
in `Public-Key`, `Signature` and `Content-Hash`, and `verify_message`
rebuilds the signing content from the parsed fields in canonical order. So
any byte string that parses to the same fields verifies: reordered
headers, a second `Path:` line (`/evil/` then `/audit/`: a last-wins parser
sees the signed path, a first-wins parser the attacker's), non-canonical
integers, and uppercase hex. The Wire spec says non-canonical order is
invalid and hex is lowercase. Five ignored tests cover these.

The unsigned-unknown-header case deserves its own note (Q32). The Wire spec
says unknown headers are ignored, and the canonical signing content only
covers modelled headers, so a relay can append `X-Relay: injected` to any
message and it still verifies (`d2_unsigned_unknown_header_is_rejected`).
That is harmless for the parsed object but, under the State Commitment
rule `object_hash = sha256(raw_sbo_bytes)` the audit decided to adopt
(Q18), it makes the object hash and therefore the state root malleable by
anyone on the path. The two rules cannot both stand.

Remediation: enforce the canonical order and uniqueness on parse (reject,
do not reorder), parse `Content-Length` as a canonical decimal, reject
non-lowercase hex, and either sign the received header block verbatim or
reject unknown headers (Q32). Switch both wrappers to `verify_strict`
(W6-1). Then every accepted message is byte-identical to its canonical
serialization and `sha256(raw)` equals `sha256(serialize(parse(raw)))`,
which is what `d3_every_accepted_message_is_canonical` pins.

### 1.3 D3 — `object_hash` over re-serialized bytes (Partial, Medium)

For canonical input the two hashes agree: the live v5 genesis batch
(14 messages) hashes to the documented
`sha256:ca27c611…` both as raw bytes and through
`genesis_hash_from_wire` (`live_genesis_raw_and_reserialized_hashes_agree`).
Every header the serializer does not model (`Attestation`, `Origin`,
`Proof`, …) is in the canonical signing order, so a signer that covered one
fails to verify after the parser drops it: there is no silent mutation of
a *signed* field. What remains is exactly the D2 set, where accepted bytes
are not canonical, plus the Q32 conflict. D3 therefore has no fix of its
own: the D2 parser rules make the raw and reserialized hashes coincide,
and Q18 chooses which one the spec names. Note that the Genesis spec
defines `genesisHash` over `serialize(m)` while the State Commitment spec
defines `object_hash` over raw bytes; after D2 they are the same bytes, and
the spec text should say so.

Also noted: `~/src/mingo/genesis.wire` is the **v5** batch (hash
`ca27c611…`), while `deploy/GENESIS.md` documents v6 (`fb64dc3b…`,
2026-09-18) as live. The v6 wire is not in the repo.

### 1.4 D4 — no leaf/internal domain separation (High)

A leaf hashes to its bare `object_hash`; an internal node hashes to
`sha256({"children":{…}})`. The test builds `/x/a`, `/x/b`, computes the
`/x` node hash `N`, then builds a second state with one object at `/x`
whose `object_hash` is `N`: both roots are equal. An object whose content
hashes to a chosen 32-byte value is not something an attacker can produce
(that is a SHA-256 preimage), but the structural property the State
Commitment spec claims, that an inclusion proof for an object cannot be
read as a subtree proof, does not hold, and an attacker who controls a leaf
value directly (none today; `object_hash` is always a SHA-256 of bytes)
would get a root collision. Fix: prefix leaf and internal preimages with
`0x00`/`0x01` (or hash leaves as `sha256("leaf" ‖ object_hash)`); ships
with Q18 as state-commitment v2, regenesis.

### 1.5 D5 — genesis is not validated and the bootstrap fails open (Critical)

`Genesis::validate` is `todo!()` and nothing calls it. The daemon's only
bootstrap rule is `root_policy_exists`: while false, `validate_post`
accepts every post (`validate.rs:772`) and every `policy.v2` write
(`:733`) from any key to any path, in any block, and a `genesisHash`
mismatch at the anchor logs `GENESIS VERIFICATION FAILED` and keeps
syncing. The daemon tests show a stranger's post to
`/communities/cooks/posts/` and a stranger's `policy.v2` at
`/communities/cooks/root` both `Valid` on an empty state. A node pointed
at the wrong anchor, or at a forged seed, builds a database the operator
never chose, and a repo followed without an expected hash never learns.

**Does the live genesis pass strict mode (Q7)?** The v5 batch is a plain
Mode B genesis: `/sys/domains/mingo.place`, `/sys/names/sys`
(domain-certified), `/sys/names/sys-checkpointer`, `/sys/trust/brokers`,
nine community objects/policies/configs, and `/sys/policies/root` **last**
(message 14 of 14); there is no `/sys/dnssec/mingo.place` object. So:

- Under Q7 (a) with the genesis batch defined as the whole anchor
  submission validated structurally (domain before sys before root, root
  present), it passes; `d5_genesis_validate_accepts_the_live_mode_b_batch`
  encodes that reading.
- Under Q4 (b) per-message state threading, the nine community objects are
  written *before* the root policy exists and would be rejected by an
  ordinary policy evaluation. Which reading applies is Q33.
- Under Q8 (a) (self-certification required for Mode B) it fails either
  way, so the regenesis Dan already accepted is needed; the new batch
  should put `/sys/dnssec/`, domain, sys, root first, then everything else.

Remediation: implement `Genesis::validate` (mode detection, object set,
relative order, JWT signatures: domain self-signed, sys signed by the
domain key, root policy signed by sys, all in one submission); call it from
the daemon at the anchor; make a `genesisHash` mismatch or a second genesis
at the anchor stop sync; remove genesis mode from `validate_post` and
`validate_transfer` so that with no root policy nothing is applied. Then
un-ignore the five D5 tests.

### 1.6 D6 — the pinned root KSK is decorative (High, confirmed by reading)

`dnssec-prover 0.6.8` validates against `root_hints()` (two IANA DS
records, plus the RFC 9102 test anchor under `cfg(test)`) and
`verify_rr_stream` has no anchor parameter. `TrustAnchors::root_ksk` is
documented as "informational only" and `load_trust_anchors` never reads
`/sys/trust/dns-root`. So a governance update to the on-chain anchor
changes nothing, and after the next IANA rollover old evidence stops
validating on a node whose library predates it while a node with a newer
library accepts it: the durability and convergence promise of the
Authorization spec is not implemented. Q3 (a) settles the direction (patch
or fork the validator to take anchors; read the on-chain history at
inclusion time; check the key windows).

Why there is no test: the repo has **no offline DNSSEC fixture**. Every
DNSSEC-dependent path (`extract_provider_key`, `verify_domain_self_cert`,
the `dnssec_proof` restriction, the submit-gate capture) is covered only by
`#[ignore]`d live tests. A synthetic chain cannot be built with the
project's own Ed25519 keys because `dnssec-prover` does not implement
algorithm 15 (`validation.rs:131`, `// TODO: 15 => ED25519`), so a fixture
needs an RSA or P-256 signer. That is W6-5, and it is the first thing the
Q3 remediation must add, because the acceptance test for D6 is "a chain
rooted at a *non-IANA* key validates when that key is the pinned anchor and
is rejected when it is not".

### 1.7 D8 — the zkVM guest (read only)

Confirmed as WS1 and July described: the guest verifies the header chain,
the raw-cells hash, app completeness and the trie witness; `_actions_hash`
is computed and discarded; the witness is an independent input never
derived from `actions_data`; `header_data: None` makes
`verify_data_availability` return a zero `data_root` without asserting
anything; `is_first_proof` accepts any `prev_state_root` as trusted. A
"validity proof" proves that *some* trie transition happened over
*some* data. Q19 (a): `sbo-zkvm` is to be marked experimental with no
trust claim; no test was written and the risc0 build was not attempted.

### 1.8 D9 — the KZG verifier is a stub (High)

`verify_kzg_proof` decompresses both points, checks they are in G1 and not
the identity, then returns `Ok(true)`. The test passes the G1 generator as
both commitment and proof with arbitrary `(x, y)` and gets `Ok(true)`. No
pairing is ever computed, so `verify_cell` validates nothing about the
data. The light-client read path does not call it (that trust question is
Q20, settled as accepted risk), so the practical impact today is confined
to anything that believes `verify_cell`: the zkVM DA step (D8) and any
future client. The fix needs Avail's SRS (`srs_data.rs` ships G1 points
for the prover side) and a G2 element for the pairing; until then the
function should return `Err(KzgError::Unsupported)` rather than `Ok(true)`.

### 1.9 D10 — role cycles (High)

`identity_matches` recurses through `Role` members and `Any` lists with no
visited set and no depth bound, and no validation pass runs when a
`policy.v2` is written. The test deserializes `a → b → a` without error
and evaluates a grant to `role:a` in a child process, which dies with a
stack overflow. A policy like that on chain crashes every node that
evaluates a write it governs: a deterministic, chain-wide denial of
service that a `govern` grantee (or anyone, before D5 is fixed) can plant.
Q17 (a): reject cycles, unknown identity kinds and bad patterns at write
time, and bound role resolution at evaluation. WS3 carries the depth-bound
property tests; the write-time half is `d10_cyclic_role_policy_is_rejected_at_parse`.

### 1.10 D24 — `require_payload_signed_by` (Partial)

Two problems, one masking the other. `check_payload_signed_by` maps the
JWT's `iss` to `/sys/domains/<d>` and `Path::parse`s it; the path has no
trailing slash, so parsing fails and the restriction denies **every**
payload with "Invalid issuer path", legitimate or forged (W6-3, fail
closed, so Low). Behind that bug, the check only pattern-matches the
issuer *string*: it never loads the issuer object or verifies the JWT
signature against its key, so once the path is fixed any signer satisfies
the restriction by writing `iss: domain:mingo.place`. The live root policy
does not use the restriction (zero occurrences in the genesis batch).
Related: `schema::validate_schema` verifies self-signed `identity.v1`
JWTs but leaves domain-certified ones to "the caller", and no caller
verifies them on replay, so a domain-certified `iss` is decorative; the
anti-hijack rule uses browserid attribution instead, which is why this is
not a takeover. The acceptance test requires both halves: the domain-signed
JWT is allowed and the forged one denied.

## 2. New findings

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| W6-1 | **CONFIRMED** | Low | both `verify` wrappers use `ed25519_dalek::Verifier::verify`, not `verify_strict`: the identity point as a public key with `R = identity, S = 0` verifies every message. Self-inflicted (an owner would have to publish that key), but it is the one place the two wrappers can disagree with a strict verifier elsewhere (I7). | `w6_1_small_order_public_key_universal_signature_is_rejected` (ignored) |
| W6-2 | Informational | Low | `dnssec-prover 0.6.8` has no Ed25519 (algorithm 15) verification; a primary domain whose zone is signed with alg 15 can never be attributed (fail closed, availability only). Worth knowing before pinning anchors (Q3). | — |
| W6-3 | **CONFIRMED** | Low | `require_payload_signed_by` is unusable: `issuer_to_path` yields `/sys/domains/<d>` without a trailing slash and `Path::parse` rejects it, so the restriction denies all payloads. | `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer` (ignored; first half) |
| W6-4 | **CONFIRMED** (spec conflict) | Medium | Wire spec "unknown headers are ignored" + signing content over modelled headers only, versus State Commitment `object_hash = sha256(raw_sbo_bytes)`: a relay-appended header is accepted and changes the raw hash. | `d2_unsigned_unknown_header_is_rejected` (ignored); decision Q32 |
| W6-5 | Informational | Info | No offline DNSSEC fixture or synthetic chain builder exists; every DNSSEC path is covered only by ignored live tests. Blocks any deterministic test of D6, the self-cert rule, and the `dnssec_proof` restriction. | — (remediation item under Q3) |

## 3. Invariants re-verified (passing tests)

- **I2 / signature scope**: tampering any modelled header (`Path`, `ID`,
  `Action`, `Type`) fails verification; a signer that covered an unmodelled
  header in the canonical order (`Origin`) fails to verify rather than
  being silently stripped (`signature_covers_every_modelled_header`).
- **I7 (partial)**: both wrappers reject a non-canonical scalar `S + L`
  (ed25519-dalek 2.2 canonical check), and both pin 32-byte keys, 64-byte
  signatures, the `ed25519:` prefix and lowercase-or-uppercase hex of the
  right length; unknown key and hash algorithms reject
  (`i7_non_canonical_scalar_is_rejected_by_both_wrappers`,
  `key_and_signature_lengths_and_algorithms_are_pinned`,
  `ed25519_wrapper_pins_lengths`). The strict/non-strict split is W6-1.
- **I4 for canonical input**: the live genesis batch hashes identically as
  raw bytes and reserialized, and to the documented identity; all 14
  messages verify (`live_genesis_raw_and_reserialized_hashes_agree`).
- **JWT alg pin**: `alg: none`, `HS256`, `ES256`, an empty signature, and a
  signature by another key all reject on `verify_domain`
  (`jwt_alg_is_pinned_to_eddsa_and_signature_length_to_64`).
- **I17**: the envelope key must equal the access cert's key
  (`KeyMismatch`); the grantee's issuer must be its domain or a pinned
  broker, and the same for the grantor's issuer; a broker pinned in
  `TrustAnchors` is accepted (`device::i17_*`).
- **I16**: an inclusion time outside the DNSSEC window rejects
  (`device::i16_*`).
- **I18**: a presentation for another database's audience rejects
  (`device::i18_wrong_audience_rejects`).
- **I19**: `as:` must name the grantor, appear once, and travel with a
  `path:` scope; otherwise the grantee authors (`device::i19_as_scope_rules`).
- **Cross-issuer**: a delegated grant whose grantor issuer has no DNSSEC
  evidence fails closed (`MissingIssuerEvidence`).
- **Subaddressing**: a config cert for `alice@d` covers a warrant whose
  grantor is `alice+bot@d` (browserid-ng §4.6 authorization half); the
  authentication half (browserid-ng D1) lives in the IdP's mint, not in sbo.
- **Trie proofs**: inclusion and non-existence proofs verify; a changed
  object hash or state root is detected
  (`inclusion_proof_verifies_and_tampering_is_detected`).
- **D32**: `Auth-Warrant` is inert (`d32_auth_warrant_header_is_inert`).

## 4. July 2026 findings touching these crates, re-verified

| July bean | Then | Now (30e267c) |
|---|---|---|
| sbo-d5nm Content-Hash never verified | Critical, open | **Still open** (D1), now with the P2 pin-keying compounding. Three ignored tests. |
| sbo-h75z signature over reconstruction | High, open | **Still open** (D2): order, duplicates, `+N`/`00N`, uppercase hex, non-strict verify, all reproduced. |
| sbo-2tue object_hash over re-serialized bytes | High, open | **Partial** (D3): identical for canonical input (live genesis pinned); differs only on the D2 inputs; spec conflict Q32. |
| sbo-hedq trie domain separation | High, open | **Still open** (D4), root collision demonstrated. |
| sbo-y5ek pinned root KSK decorative | High, open | **Still open** (D6); library has no anchor injection and no alg 15. |
| sbo-3gqo self-cert warn-only | High, open | Not re-tested here (WS4 D7); the verifier half (`verify_domain_self_cert`, `check_domain_binding`) is sound by reading and by its unit tests. |
| sbo-9d7l genesis unimplemented / fail-open | Critical, open | **Still open** (D5), reproduced at the daemon's gate; live genesis layout analysed (§1.5). |
| sbo-bynl circular roles | High, open | **Still open** (D10), crash reproduced in a child process. |
| sbo-5rww zkVM proves no validity | Critical, open | **Still open** (D8); scoped out by Q19. |
| sbo-7bl8 KZG stub | High, open | **Still open** (D9), `Ok(true)` reproduced. The DA-trust half is Q20 (accepted). |

## 5. What needs Dan's decision

1. **Q32 — unknown headers versus a raw-bytes `object_hash`.** Either the
   signature covers the received header block verbatim and unknown headers
   are rejected (fail closed, matches B5), or unknown headers stay ignored
   and `object_hash` is defined over the canonical serialization (the code's
   current behaviour, contradicting the State Commitment spec and Q18).
2. **Q33 — the shape of the genesis batch under strict mode.** Whether the
   anchor submission is validated as one structural unit (root policy may
   sit last, as in the live v5/v6 batches) or the mode objects must come
   first and everything after the root policy is validated normally (Q4
   per-message semantics; the live layout then fails and the planned
   regenesis reorders it).

Both are appended to `docs/security-audit-2026-11-decisions.md`.

## 6. High+ list for WS8

In the order WS6 recommends demonstrating them against a local daemon:

1. D1 payload swap on a signature-valid write through `/v1/submit`, and the
   P2 pin confusion (a hostile `policy.v2` filed under a benign hash).
2. D5 a stranger's writes and a planted governing policy on a node whose
   root policy has not arrived (and a forged seed with a mismatching
   `genesisHash` that keeps syncing).
3. D10 a cyclic-role policy that crashes every node evaluating a governed
   write (needs D5 or a `govern` grant to plant it).
4. D2 duplicate-`Path` message read differently by a first-wins parser
   (WS2 cross-implementation vector) and a relay-appended header changing
   the raw object hash (Q32).
5. D4 root collision (demonstration only; no attacker-chosen leaf exists).
