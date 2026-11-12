# Conformance vectors (security audit 2026-11, WS2)

Cross-implementation vectors for every check this repo implements more than
once. Each file is a JSON suite whose expected verdicts are the **spec's**
(Core, Wire, State Commitment, Genesis, Content; threat-model invariants
I1–I7, I23, I26, I30; decisions Q4, Q5), never what any implementation does
today. One runner per implementation judges the vectors and keeps an
`EXPECTED_FAIL` table naming the audit finding (`AUDIT-2026-11 <id>`) that
owns each disagreement. A runner fails if an implementation disagrees with
the spec anywhere else, **or** if a listed vector starts agreeing: removing
the table entry is the acceptance test for the fix. The tables therefore
double as the open ledger for these layers.

| File | What | Vectors | Judged by |
|---|---|---|---|
| `wire.json` | one wire message as received: parse + signature verdict, `object_hash` over the raw bytes | 37 | sbo-core, sbo-wasm (parser + verifier), daemon object_hash rule |
| `batch.json` | a DA submission: parse-as-unit, sequential apply (Q4 rules 1, 2, 3, 5) | 6 | sbo-core `parse_batch`, daemon sequential validate + apply |
| `identifiers.json` | id / path / action / type grammar | 50 | sbo-types, sbo-core `message`, sbo-wasm |
| `identity.json` | identity comparison and domain extraction (Q5) | 18 | sbo-core `resolve_controller`, `dns::parse_email` |
| `ed25519.json` | signature acceptance (canonical S, small-order keys, lengths) | 7 | sbo-core wrapper, sbo-crypto wrapper, sbo-wasm |
| `trie.json` | state-trie roots (v2: domain separation, object-versus-container) | 5 | sbo-crypto `SparseTrie`, `PartialTrie`, `compute_trie_root`; daemon `StateDb` |
| `lww.json` | last-writer-wins pairs incl. missing HLC | 8 | daemon `lww_admits`, `overlay_wins`, `reconcile_applied` |
| `checkpoint.json` | `checkpoint.v1` claim parsing (`state_root` form) | 5 | daemon `claim_from_message` |

Runners: `crates/<crate>/tests/audit_2026_11_ws2_*.rs`. CI:
`.github/workflows/conformance.yml`.

Regenerate the signed suites (fixed seed, byte-reproducible; the CI job
checks `git diff` is empty afterwards):

    cargo test -p sbo-core --test audit_2026_11_ws2_generate -- --ignored

`identifiers.json`, `identity.json` and `lww.json` are hand-authored.
