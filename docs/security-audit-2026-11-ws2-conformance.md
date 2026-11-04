<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS2: cross-implementation conformance vectors

**Status:** complete, 2026-11-04. Epic `sbo-ax7t`, bean `sbo-5t0f`. Scope:
every check this repo implements more than once, pitted against one vector
suite whose expected verdicts are the spec's. Oracle:
`docs/design/threat-model.md` I1–I7 (envelope and signature), I13, I16,
I23, I26, I30; decisions Q1, Q2, Q4, Q5 (settled 2026-11-04); Core
§Identifier Syntax, §Signature Scope; Wire §Encoding Rules, §Batch
Submissions, §Validation; State Commitment §Object Hash, §State Tree
Structure; Content §Conflict Resolution, §Confirmed vs Tip; Genesis
§`genesisHash` canonicalization.

**Method.** Enumerate the duplicate implementations (§1), write one vector
suite per check under `conformance/` with the spec's verdict on every
vector (135 vectors, 8 suites; the five signed suites are generated from a
fixed seed by `sbo-core/tests/audit_2026_11_ws2_generate.rs` and CI checks
they regenerate byte-identically), then one runner per implementation
(`crates/<crate>/tests/audit_2026_11_ws2_*.rs`, 19 tests) that judges every
vector and carries an `EXPECTED_FAIL` table naming the finding that owns
each disagreement. A runner fails on any unlisted disagreement and on any
listed vector that starts agreeing, so removing a table entry is the
acceptance test for the fix and the tables are the open ledger for these
layers. CI: `.github/workflows/conformance.yml` (SHA-pinned actions). No
production code or spec text changed; one dev-dependency added
(`sbo-crypto`: serde_json).

| Crate | Runner | Tests | Vector verdicts agreeing | Expected-fail entries |
|---|---|---|---|---|
| sbo-types | `audit_2026_11_ws2_types.rs` | 1 | 37 | 13 |
| sbo-crypto | `audit_2026_11_ws2_crypto.rs` | 2 | 18 | 2 |
| sbo-core | `audit_2026_11_ws2_core.rs` | 6 | 103 | 38 |
| sbo-wasm | `audit_2026_11_ws2_wasm.rs` | 4 | 71 | 24 |
| sbo-daemon | `audit_2026_11_ws2_daemon.rs` | 6 | 36 | 7 |

Run everything with the five `cargo test -p <crate> --test
audit_2026_11_ws2_<crate>` lines in `conformance.yml`.

## 1. Duplicate implementations

Confirmed by reading; the bean's starting list minus the pairs that turned
out to be one code path.

| Check | Implementations | Shared code? | Suite |
|---|---|---|---|
| Wire parse + signature verify | `sbo-core::wire` + `message::verify_message`; `sbo-wasm` (`#[path]`-includes the same source, compiled separately for the browser kit) | same source, two compilations | `wire.json` |
| `object_hash` | spec: `sha256(raw bytes)`; daemon `sync.rs:1122`: `sha256(wire::serialize(parsed))`; `sbo-wasm::kit::object_hash`: sha256 of the bytes it assembled | three rules | `wire.json` (`object_hash_raw`) |
| Batch split | `sbo-core::wire::parse_batch`; daemon `extract_sbo_payload` + the per-message loop in `process_block` (private; mirrored with the public `validate_message` / `message_to_stored_object` pair) | one splitter | `batch.json` |
| Identifier grammar | `sbo-types::{Id, Path, Action}` (re-exported as `sbo_core::Id` etc., used by the zkVM guest); `sbo-core::message::{Id, Path, Action}` (the wire path; also sbo-wasm) | **two grammars** | `identifiers.json` |
| Identity comparison | `resolve::resolve_controller` (primary-domain match), `dns::parse_email`, policy `canonical_name_ref` (private), `device_attribution` `check_authority` (closure) | four byte-exact sites, no shared helper | `identity.json` |
| ed25519 verify | `sbo-core::crypto::ed25519` (std); `sbo-crypto::ed25519` (no_std, the guest's) | two wrappers over the same dalek call | `ed25519.json` |
| sha256 | `sbo-core::crypto::hash`, `sbo-crypto::hash` (+ the risc0 precompile under `zkvm`) | two wrappers, one digest | covered via trie/object_hash |
| State trie root | `sbo-crypto::SparseTrie` (builder), `PartialTrie::compute_node_hash` (verifier; the guest's `verify_state_transition` path), `compute_trie_root` (helper), daemon `StateDb::compute_trie_state_root` (segment mapping + helper) | two hashers | `trie.json` |
| Last-writer-wins | daemon `validate::lww_admits` (confirmed path), `pending::overlay_wins` (read merge), `pending_still_wins` (reconcile, via `reconcile_applied`) | three functions over `hlc::lww_wins` | `lww.json` |
| Policy in force | `StateDb::resolve_policy` (confirmed) vs `Overlay` (tip reads see pending objects; tip validation resolves from the confirmed column family) | one resolver, two views | daemon runner `POL-01` |
| Checkpoint claim | spec `sha256:<hex>`; daemon `trust::claim_from_message` bare hex | one parser, two forms | `checkpoint.json` |
| Inclusion time | daemon `L2Context.inclusion_time: Option<i64>`: attribution fails closed on `None`, attested checks run at `t = 0` | one context, two rules | daemon runner `TIME-01` |

Not duplicates after reading: the zkVM guest never parses SBO messages (it
verifies a trie witness with the sbo-crypto code above, so `trie.json`
covers it); `sbo-rpc::decode` and `extract_sbo_payload` are framing, not
parsing (WS3 fuzzes them); SBOP/SBOQ proofs are serializations of
`TrieProof` (WS3).

## 2. Cross-implementation disagreements (new findings)

| ID | Verdict | Severity | Where | Vectors / test |
|---|---|---|---|---|
| W2-1 | **CONFIRMED** | Low | `sbo-types/src/id.rs:30` (charset lacks `@ + :`), `action.rs:30` (`to_lowercase`, admits `create`/`update`) vs `sbo-core/src/message/envelope.rs:97` | ID-OK-03..06, PATH-OK-03, ACT-REJ-01..04 (`identifier_vectors_sbo_types_grammar`, 13 expected-fail) |
| W2-2 | **CONFIRMED** (= WS4 D17 half) | Low | `pending.rs:246` `overlay_wins` returns `true` on a missing/unparseable HLC; `pending.rs:142` `pending_still_wins` and `validate.rs:484` `lww_admits` treat the chain as authoritative | LWW-06..08 (`lww_vectors_…`, 3 expected-fail). Decision Q25 (a) aligns them. |
| W2-3 | **CONFIRMED** (= WS4 D17 / `sbo-y757`) | Medium | `state_view.rs:170-180`: `Overlay::resolve_policy` delegates to the confirmed DB while `Overlay::get_object` serves the pending policy object | POL-01 (`policy_in_force_agrees_…`, 1 expected-fail): the tip shows a policy the tip does not enforce |
| W2-4 | **CONFIRMED** | Low | `trust.rs:91-103` decodes `state_root` as bare hex; spec examples are `sha256:<hex>` (S18) | CP-01, CP-03 (`checkpoint_claim_vectors`, 2 expected-fail). Decision Q34. |

Everything else the vectors flagged is the stack agreeing with itself
against the spec, which confirms WS1 leads owned by other workstreams:

| Lead | Confirmed by | Implementations that agree with each other and disagree with the spec |
|---|---|---|
| D1 Content-Hash never verified | W-CH-01 | core, wasm |
| D2 signature over a reconstruction | W-ORD-01, W-DUP-01/02, W-CL-01/02, W-HEX-01/02, W-INJ-01/02 | core, wasm |
| D3 object_hash over re-serialized bytes; import headers unverifiable | W-OK-05 (a correctly signed message carrying `Attestation` fails verification), 9 object_hash vectors (daemon rule ≠ raw) | core, wasm, daemon rule |
| D4 no leaf/internal domain separation | TRIE-03 root == TRIE-01 root | SparseTrie, PartialTrie, compute_trie_root, StateDb |
| D13 / D54 / Q5 no identity grammar; byte-exact domains | W-ID-03/04, ID-REJ-09..12, IDC-02/06, IDD-02/04, IDR-02 | core, wasm; `resolve_controller`, `parse_email` |
| D21 `.` / `..` accepted | W-ID-01/02, ID-REJ-07/08, PATH-REJ-04/05 | sbo-types, core, wasm |
| D28 missing inclusion time admits a banned writer | TIME-01: with the block timestamp the post is rejected (Policy), without it the ban is "not yet in force" at `t = 0` and the post is **Valid** | daemon (two nodes on the same chain data disagree). Decision Q23. |
| D30 both ed25519 wrappers non-strict | ED-REJ-04 (identity-point key, R = identity, S = 0 verifies for any message) | core, sbo-crypto, wasm. Refuted half: a non-canonical S (S + L) **is** rejected by dalek (ED-REJ-03 agrees), so only the small-order case stands. |

Batch rules (Q4): rules 1, 2, 3 and 5 hold today in both the splitter and
the sequential application (B-01..B-06, no expected-fail). Rule 1
(parse-as-unit) is exactly `parse_batch`'s behaviour; rule 5 (lower index
wins a slot) falls out of global uniqueness.

## 3. Invariants re-verified (agreeing vectors)

- **I1** is not held (D1); **I2** is not held (D2); recorded above.
- **I3** holds between the two compilations of the parser: sbo-core and
  sbo-wasm return identical verdicts on all 37 wire vectors and both
  expected-fail tables are identical by construction. The kit assembles the
  canonical vector byte-for-byte from its `EnvelopeSpec` and its signing
  bytes equal core's `canonical_signing_content`
  (`kit_reproduces_the_canonical_vector_and_hashes_raw_bytes`).
- **I5** holds for enumerations: `Type`, `Action`, `SBO-Version`, key and
  hash algorithm prefixes, signature length, missing required headers,
  missing blank line, `Name:value` without the space, empty input
  (W-ENUM-01..06, W-SIG-02/04, W-STR-01..04) reject everywhere. Fails for
  `.`/`..` (D21).
- **I7** holds between the two wrappers (identical verdicts on all 7
  vectors); the shared gap is D30.
- **I23** `parse_email` and `resolve_controller` agree with each other on
  every pair; both are byte-exact (D13).
- **I26** holds whenever both sides carry an HLC (LWW-01..05: confirmed
  path, overlay and reconcile agree, including the signer and object_hash
  tiebreaks and the idempotent replay); fails only on a missing HLC (W2-2).
- **I30** fails (D4).
- Batch rules 1, 2, 3, 5 hold (above). Content-Length mismatch in either
  direction rejects (W-CL-03/04). A tampered signature or a signature by
  another key rejects (W-SIG-01/03).
- Trie: all four implementations reproduce the same root on every vector,
  including the daemon's `[path…, id]` segment mapping.

## 4. July 2026 leads touching these layers

| July | Now |
|---|---|
| `sbo-d5nm` Content-Hash unverified | **Open** (W-CH-01). |
| `sbo-h75z` signature over reconstruction, duplicates last-wins, non-canonical lengths/hex | **Open**, every sub-item reproduced (W-ORD/DUP/CL/HEX/INJ). |
| `sbo-2tue` object_hash over re-serialized bytes | **Open** (9 object_hash vectors). |
| `sbo-hedq` trie domain separation | **Open** (TRIE-03). |
| `sbo-zocd` no email/name normalization | **Open** (identity suite). |
| `sbo-y757` reads vs validation policy | **Open** (POL-01). |

## 5. What needs Dan's decision

Appended to `docs/security-audit-2026-11-decisions.md` §2:

1. **Q34** `state_root` form in checkpoint objects (W2-4 / S18): spec
   `sha256:<hex>` wins, code accepts both during migration.
2. **Q35** which bytes `genesisHash` covers: one rule with `object_hash`
   once Q32 (a) makes raw == canonical.
3. **Q36** two identifier grammars (W2-1): one grammar in `sbo-types`,
   re-exported by `sbo-core::message`.
4. **Q37** percent-encoding sentence vs the `id_char` set (S23): drop the
   sentence; ids are ASCII only.

Already covered by other workstreams' items: W2-2 by Q25, D28 by Q23,
unlisted headers by Q32.
