<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS3: property tests and fuzz targets

**Status:** complete, 2026-11-04. Epic `sbo-ax7t`, bean `sbo-qw0z`. Scope:
every parser in the Rust tree (wire envelope and batch splitter, identifier
grammar, URI, `_sbo` TXT, policy JSON and patterns, HLC, attestation /
collection / content schemas, SBOP / SBOQ proof messages, trie proofs, JWT
identity objects, device presentations, RFC 9102 evidence, Avail app-data
decoding, snapshot and IPC framing), every sign→verify path (envelope
signature, both ed25519 wrappers, JWT, device attribution, domain
self-certification, trie inclusion / non-existence / state-transition
witnesses), every narrowing and composition rule (deny / grant /
restriction composition, action coverage, descendant-constraint templates,
role resolution, warrant scopes and the `as:` selector, the audience rule)
and all time arithmetic (HLC bound, last-writer-wins order, attestation
windows, DNSSEC and certificate windows, the authoring-instant clock).
Oracle: `docs/design/threat-model.md` I1–I7, I9–I12, I19, I22–I26; WS1
leads routed to WS3: D10, D13, D14, D40, D49, D50, D51, S22; decisions
Q5, Q9, Q17, Q21.

**Method.** Reviewer pass over each parser and rule, then a property for
every invariant that should hold, written against a reference
implementation where one is cheap (memoised glob matcher, SCALE compact
encoder, spec intervals). Every property that FAILS today is an
`#[ignore]`d test with an `// AUDIT-2026-11 <id>: fails today` comment and
is the acceptance test for the fix; the rest pass and pin what was
re-verified. Each ignored test was run on its own to confirm it fails for
the stated reason (§4). Twelve cargo-fuzz targets then ran for 90 s each
(§3). No production code or spec text was changed; only dev-dependencies
(`proptest`) in four manifests, the standalone `fuzz/` workspace, the
`Makefile` fuzz targets and `.github/workflows/fuzz-smoke.yml`.

| Crate | Test files | Pass | Ignored (fail today) |
|---|---|---|---|
| sbo-core | `tests/audit_2026_11_ws3_{wire,policy,role_cycle,time_scopes,uri_identity,proofs}.rs` (+ `audit_2026_11_ws3_support/`) | 47 | 22 |
| sbo-crypto | `tests/audit_2026_11_ws3_trie.rs` | 5 | 3 |
| sbo-rpc | `tests/audit_2026_11_ws3_decode.rs` | 3 | 1 |
| sbo-daemon | `tests/audit_2026_11_ws3_daemon.rs` | 3 | 1 |

Run the failing set with `cargo test -p <crate> --test <file> -- --ignored`.
`audit_2026_11_ws3_role_cycle` is its own binary because its ignored tests
abort the process (stack overflow), so run them one at a time with
`--exact`.

## 1. New findings

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| W3-1 | **CONFIRMED** | High | `policy/path.rs::match_parts` (and `glob_match`): `**` / `*` matching backtracks over every split, O(n^k) in the number of wildcards; policy-author controlled, evaluated by every node on every write under the subtree | `w3_1_path_pattern_matching_is_polynomial`, `w3_1_id_pattern_matching_is_polynomial` (10 `**` vs 24 segments does not finish) |
| W3-2 | **CONFIRMED** | High | `authorize.rs::path_glob_matches`: same recursion on the warrant `path:` scope; WALLET authored (any user), evaluated at the submit gate and on replay | `w3_2_scope_path_glob_is_polynomial` |
| W3-3 | **CONFIRMED** | Medium | `policy/types.rs`: `Policy`, `Grant`, `Restriction`, `Requirements` have no `deny_unknown_fields`; a misspelled condition key is an empty requirement that fails OPEN (I11) | `w3_3_unknown_policy_keys_are_rejected` |
| W3-4 | **CONFIRMED** | Medium | `sbo-crypto/src/trie.rs::insert_into`: an object at a strict prefix of another object's segments evicts (or is evicted by) the subtree; both writes are legal under `segments = path ++ [id]`, so one object silently leaves every state root and can never be proven — order dependent | `w3_4_prefix_paths_coexist_in_the_commitment` |
| W3-5 | Informational | Info | `sbo-crypto/src/merkle.rs` is not declared in `lib.rs` (dead code); its `generate_proof` and `DataProof::verify` disagree for leaf counts that are not a power of two (odd-level promotion vs hashing). Delete or fix before anything uses it. | none (uncompilable from outside the crate) |
| W3-6 | **CONFIRMED** | Low (SBOP) / Medium (SBOQ) | `proof/sbop.rs`: `((Receipt-Length + 2) / 3) * 4` unchecked; `proof/sboq.rs`: `obj_start + Object-Length` unchecked — wraps in release so the bounds check passes and `data[obj_start..obj_end]` panics. SBOQ is what an untrusted indexer serves for `?proof=1`, so a hostile indexer crashes the client. | `w3_6_sbop_huge_receipt_length_does_not_panic`, `w3_6_sboq_huge_object_length_does_not_panic` |
| W3-7 | **CONFIRMED** | Medium | `sbo-rpc/src/decode.rs::extract_data_from_encoded_extrinsic`: gzip-flagged chain data is inflated with `read_to_end` and no cap; a ~100 KiB submission inflates to GiB on every syncing node before SBO parsing can reject it (D50 class, on the chain-read path) | `w3_7_gzip_inflation_is_capped` |
| W3-8 | **CONFIRMED** | Medium | `sbo-crypto/src/trie.rs:1246` `verify_nonexistence_proof` indexes `path_segments[idx]` unchecked; `parse_sboq` derives `path_segments` from the steps' `segment` fields, so the proof an indexer returns for a MISSING object (`"segment": null` first) reaches it with an empty list and panics the verifying client. Found by `trie_verifier_is_total` on its first run. | `w3_8_nonexistence_verifier_rejects_short_path_segments` |
| W3-9 | **CONFIRMED** (found by `proof_parse`) | Medium | `proof/sbop.rs:113`: the header loop leaves `pos = len + 1` when the image has no blank line and no trailing newline, then `&bytes[pos..]` panics; SBOP is read off the chain by every light-mode node, so one DA submission panics every light node's sync task | `w3_9_sbop_without_blank_line_does_not_panic` |
| W3-10 | **CONFIRMED** (found by `wire_parse`) | Medium | `wire/parser.rs:75`: the batch splitter computes `end_pos = pos + Content-Length` unchecked; `Content-Length: 18446744073709551615` overflows (debug) or wraps past the bounds check into a slice panic (release). One DA submission kills the sync task of every node on the app id; `/v1/submit` parses the same way. | `w3_10_huge_content_length_does_not_panic` |
| W3-11 | Informational (found by `jwt`) | Info | `jwt.rs`: `IdentityClaims` and `DomainClaims` carry no kind claim and are mutually decodable, so `verify_domain` accepts a self-signed identity token and `verify_self_signed_identity` accepts a domain token. Schema validation keys off `sub`, so the impact is a confused object, not a forged one. | pinned inside the `jwt` fuzz target |

### 1.1 W3-1 / W3-2 — exponential glob matching (High)

Three copies of the same backtracking matcher: `PathPattern::match_parts`
tries every split for every `**`, `IdPattern::glob_match` every split for
every `*`, and `authorize.rs::path_glob_matches` is `match_parts` again for
warrant scopes. With k wildcards and n segments the work is O(n^k); the
tests use k = 10 against n = 24 and give up after 200 ms (the real run is
minutes to hours). Who controls the pattern decides the severity:

- a policy pattern needs a `govern` grant on the subtree, or lands via a
  parent's `descendant_constraint` template. A community admin, or anyone
  who captures a subtree, installs one pattern and every node that replays
  a write beneath it stalls — deterministic, chain-wide, and permanent
  until the policy is replaced (W3-1);
- a warrant scope needs nothing but a wallet. The scope string is the
  user's to write; the submit gate evaluates it on the way in and every
  node evaluates it again on replay (W3-2). This is the one an outsider can
  use.

Remediation (Q38): one memoised matcher for all three, O(k·n), plus a
stated wildcard cap in the Policy and Authorization specs so a second
implementation has a bound to meet. The reference matchers in
`audit_2026_11_ws3_policy.rs` (`reference_match`) and
`fuzz/fuzz_targets/path_glob.rs` are the oracle. The fuzz targets
`policy_json` and `path_glob` currently skip patterns with more than 3–4
wildcards so the smoke run stays green; lift the guard with the fix.

### 1.2 W3-3 — unknown policy keys fail open (Medium)

`serde_json::from_value::<Policy>({"restrictions":[{"on":"/**","require":{"max_sise":5}}]})`
succeeds and the restriction requires nothing. Same for a grant with an
unknown key, and for a `Requirements` with a typo in `not_attested`. The
threat model (I11) and the spec's fail-closed posture (B5) say an unknown
condition key rejects. Strict parsing is consensus-changing for any policy
already on chain with a stray key, so it is a decision (Q39) and rides the
regenesis. `unknown_action_name_rejects` pins the one place serde already
fails closed (an unknown action name in `can`).

### 1.3 W3-4 — prefix paths cannot coexist in the trie (Medium)

`SparseTrie::insert` of `[x, a]` after `[x, a, b]` replaces the branch at
`a` with a leaf; the opposite order replaces the leaf with a branch. The
daemon maps an object to `path segments ++ [id]`, so an object `a` at `/x/`
and an object `b` at `/x/a/` are two legal writes whose commitments collide
on the segment `a`. Whichever is inserted second wins the root; the other
is absent from every state root, every snapshot root and every proof, and
`verify_state_transition` will disagree with a host that applied both. The
daemon rebuilds the trie from a sorted object list each block, so which
object is lost is deterministic per node but still means a live object
that cannot be proven. Related to D21 (id / collection name collision stalls
`process_block`) and to D4 (no leaf / internal domain separation): the
State Commitment spec needs a rule for the object-versus-container case
(forbid it at validation, or key leaves distinctly), and that rule is part of
the Q18 `state-commitment/v2` work.

### 1.4 W3-6 — unchecked length arithmetic in the proof parsers

SBOP: `Receipt-Length: 18446744073709551614` panics on `+ 2` in a debug
build and wraps in release; harmless in release except that the computed
"expected base64 length" is nonsense. SBOQ is worse: `obj_start +
Object-Length` wraps in release to a small number, the `obj_end > data.len()`
check passes, and `data[obj_start..obj_end]` panics with `obj_end <
obj_start` — in release. SBOQ is the format the daemon serves for
`/v1/object?proof=1` and the CLI verifies, so a hostile indexer or a
man-in-the-middle on a plain-HTTP indexer crashes the client. Checked
arithmetic and an upper bound on both headers.

### 1.5 W3-7 — gzip bomb on the chain-read path (Medium)

`extract_data_from_encoded_extrinsic` sniffs `1f 8b` and inflates with
`read_to_end`. Avail bounds a submission to a few MiB, gzip bounds nothing
below ~1000:1, so 100 KiB in, ~100 MiB out; 2 MiB in, ~2 GiB out, on every
node that syncs the app id, before `parse_batch` sees a byte. The daemon's
snapshot decoder has the same shape (D50, `d50_snapshot_inflation_is_capped`,
untrusted serving node). One `Take`-capped reader for both, cap tied to the
largest legal submission.

### 1.6 W3-8 — non-existence proof verification panics (Medium)

(For W3-9, the SBOP header-terminator panic, see the fuzz section: it is the
one crash the smoke run produced in real code; the other four were harness
over-approximations, corrected and documented in §3.)

Found by the totality property on its first run (`index out of bounds: the
len is 0 but the index is 0`, `trie.rs:1246`). `verify_nonexistence_proof`
finds the divergence step (first `segment: None`) and reads
`proof.path_segments[idx]`. `parse_sboq` builds `path_segments` by
collecting the `Some` segments, so a proof whose FIRST step is the
divergence (an object missing at the top level — the common non-existence
answer) arrives with `path_segments = []` and panics. Any client that asks
an indexer for a proof of absence and verifies the reply can be crashed by
that indexer. Fix: `path_segments.get(idx)` → `InvalidProof`, and a
length check `proof.len() <= path_segments.len() + 1` up front. The
`trie_proof` fuzz target pads `path_segments` to cover the steps for now.

## 2. Invariants re-verified (passing properties)

**Envelope and signature (I1–I5, I7).** `serialize ∘ parse` is the identity
on the parser's own output and the batch splitter returns exactly the
messages that were concatenated (`serialize_parse_roundtrip_is_identity`,
`batch_split_is_exact`); the parser, splitter and header-line parser are
total on arbitrary bytes and a truncated payload is an error
(`parser_is_total`, `truncated_payload_rejects`); any change to a signed
header value breaks verification (`header_bit_flip_breaks_signature`); the
two ed25519 wrappers return the same verdict on every (key, message,
signature) and both reject a non-canonical `S` (`two_ed25519_wrappers_agree`,
`non_canonical_s_is_rejected_by_both` — I7 holds; D30 is a code-duplication
note, not a behavioural split); the identifier grammar admits exactly the
documented character set and every path of valid ids round-trips
(`id_grammar_and_path_roundtrip`, `id_rejects_out_of_grammar`);
`sbo-types::Id` is a strict subset of `sbo-core::Id` (`sbo_types_id_is_subset_of_core_id`, D30 / WS2 W2-1).

**Policy composition (I9, I10, I12).** `PathPattern` agrees with a memoised
reference on every `*` / `**` / literal interaction over a small alphabet
(`path_pattern_matches_reference`); an undefined `$owner` fails closed
(`undefined_variable_fails_closed`); `IdPattern` literal / `*` / prefix
semantics (`id_pattern_semantics`); the action lattice: reflexive, `*`
covers all but `govern`, `post` ⇒ create + update, `govern` only by
`govern` (`action_coverage_lattice`); `deny` beats every grant for every
actor and action (`deny_beats_grant`); a grant is necessary and sufficient
(`grant_is_necessary_and_sufficient`); `max_size` and `not_attested`
restrictions narrow exactly (`restrictions_narrow_grants`); a child grant is
covered iff recipient and path are byte-equal and every action is covered,
and an identical child always passes (`descendant_constraint_is_a_narrowing`);
mandated restrictions are byte-exact, looser OR tighter both reject
(`mandated_restriction_must_be_verbatim`); policy JSON round-trips stably and
junk never panics (`policy_json_roundtrip_and_totality`); an acyclic role
tree resolves (`acyclic_roles_resolve`).

**Time and ordering (I24–I26).** `Hlc::parse ∘ to_wire` is the identity and
parse accepts exactly the canonical form (`hlc_wire_roundtrip`,
`hlc_parse_rejects_non_canonical`); the bound is the spec interval for
non-overflowing inputs (`hlc_bound_is_the_spec_interval`); the LWW key is a
strict total order and a replayed duplicate never wins
(`lww_is_a_strict_total_order`); attestation freshness is `issued_at ≤ t <
expires` with no self-expiry when absent (`attestation_in_force_interval`);
domain self-cert binding is inclusive at both window ends and compares the
key in either encoding (`domain_binding_window_is_inclusive`); the device
attribution window is the intersection of the access-cert window and every
DNSSEC window, inclusion outside any DNSSEC window rejects
(`attribution_window_is_the_intersection`); expiries are judged at
`authored_at` when supplied, never the wall clock — an assertion expired at
inclusion but live at authoring verifies, one expired at authoring does not
(`expiries_are_judged_at_the_authoring_instant`, the Q9 rule).

**Scopes and audience (I18, I19, I22).** `scopes_authorize` agrees with a
reference on literal scopes: OR within a dimension, AND across, `sign:sbo:x`
≡ `action:x`, unknown dimension or unknown `sign:` kind fails closed
(`scopes_are_or_within_and_across`); adding a scope in a new dimension never
widens (`adding_a_scope_never_widens`); `effective_author` is the grantee
without `as:`, the grantor with exactly one `as:<grantor>` plus a `path:`
scope, and rejects every other shape (`effective_author_rules`); the
audience rule: same `chain:appId`, bare path, anchor and `?genesis` must
match when present, `sbo://` never (`audience_identifies_exactly_this_db`).

**URI and DNS.** parse ↔ render is a fixed point in both renderings, the
parser is total and `sbo://` yields the DNS-needed error
(`uri_render_parse_is_a_fixed_point`, `uri_parser_is_total`); alias
resolution is idempotent and alias-invariant for `is_avail`
(`chain_alias_resolution_is_idempotent`); `compose` inherits the anchor and
drops the query (`compose_inherits_anchor_and_drops_query`); `_sbo` TXT
parsing requires `v=sbo1` and a bare `repo=`, ignores unknown keys, and a
duplicated key takes the LAST value (`dns_record_parsing` — pinned; same
class as browserid-ng W2-6, WS2 decides); the two email-split rules agree
on one `@` (`email_split_rules_agree_on_one_at`).

**Proofs and JWT.** SBOP / SBOQ serialize → parse recover every field and
the parsers are total (`sbop_roundtrip_and_totality`,
`sboq_roundtrip_and_totality`); `genesis_hash_from_wire ≡ genesis_hash ∘
parse_batch` and is order-sensitive (`genesis_hash_is_over_the_ordered_batch`);
JWT create → verify, tampered payload rejects, domain-certified verifies
under the domain key only (`jwt_sign_verify`); `Proof-Length` is advisory
(`sboq_proof_length_header_is_advisory_today`, observation).

**Trie.** The root is a pure function of the object set
(`trie_root_is_order_independent`); every object has a verifying inclusion
proof, every absent path a verifying non-existence proof, a wrong root, a
tampered sibling or a wrong object hash all fail
(`trie_proofs_are_sound_and_complete`); a witness built from real proofs
yields exactly the rebuilt root after create / update / delete and a
witness against the wrong previous root is rejected
(`state_transition_witness_matches_rebuilt_root`); the verifier is total on
unstructured proofs whose `path_segments` covers the steps
(`trie_verifier_is_total`, guarded for W3-8); empty-trie conventions
(`empty_trie_conventions`).

**Avail decoding, snapshot, IPC.** `decode_compact` inverts a reference
SCALE encoder in every mode (`compact_roundtrip_and_totality`); unpadding
removes exactly the `0x80 0*` suffix (`unpad_removes_only_the_marker`); a
well-formed unsigned extrinsic yields its blob and every decoder is total
on junk (`extrinsic_unwrap_and_totality`); IPC request parsing is total and
an unknown `cmd` never becomes a default command
(`ipc_request_parsing_is_total`); `required_issuers` is total and empty for a
key-rooted write (`required_issuers_is_total`); snapshot decoding is total
(`snapshot_decode_is_total`).

## 3. Fuzz targets

Standalone workspace `fuzz/` (cargo-fuzz 0.13, nightly, libFuzzer + ASAN),
seeds committed under `fuzz/seeds/<target>/`, `make fuzz-smoke` runs every
target for `FUZZ_SECS` (default 60). Targets and what they assert are in
`fuzz/README.md`. Three targets carry a documented guard that masks a
finding already encoded as an ignored test (W3-1/W3-2 wildcard count,
W3-6 length headers, I24 arithmetic range, W3-8 segment padding) so the
smoke run is green until the fix lands.

Smoke run 2026-11-04 on the dev box (`FUZZ_SECS=90`, ASAN, one worker). The first pass crashed five targets; two were real (W3-9 SBOP, W3-10 Content-Length, both encoded as ignored tests with the crash input as a committed seed), three were harness over-approximations (batch splitter fails on ANY later message; non-ASCII ids; identity/domain JWT mutual decodability, kept as W3-11) and were corrected. Second pass, all targets:

| target | executions / 90 s | result |
|---|---|---|
| `wire_parse` | 1,498,795 | clean (after W3-10 guard) |
| `wire_build` | 316,892 | clean |
| `uri_dns` | 1,432,002 | clean |
| `policy_json` | 4,525,814 | clean (wildcard guard) |
| `path_glob` | 2,262,867 | clean (wildcard guard) |
| `proof_parse` | 4,011,575 | clean (after W3-9 guard) |
| `hlc_lww` | 7,926,632 | clean (range guard) |
| `trie_proof` | 533,106 | clean (W3-8 padding) |
| `schema_json` | 803,021 | clean |
| `presentation` | 939,534 | clean |
| `dnssec_rr` | 3,841,560 | clean — no panic in `dnssec-prover`, no spurious `Ok` (D51 refuted as a crash) |
| `jwt` | 315,835 | clean |

~28M executions, 0 crashes with the documented guards; every guard names the ignored test that owns the masked finding.

Weekly run: `make fuzz-smoke-install` installs
`scripts/launchd/org.sandmill.sbo-fuzz-smoke.plist` (Sundays 14:00, after
the browserid-ng run; log `/tmp/sbo-fuzz-smoke.log`) — decision Q21. CI:
`.github/workflows/fuzz-smoke.yml` builds every target on nightly and runs
each for 30 s on a weekly schedule, on changes under `fuzz/`, and on demand;
SHA-pinned actions matching WS7's `test.yml`.

## 4. WS1 leads routed to WS3, and the ignored tests confirmed to fail today

Every ignored test was run alone (`-- --ignored --exact`) on 2026-11-04 and failed for the stated reason; the three `d10_*` tests abort the process with `fatal runtime error: stack overflow` (SIGABRT), which is the finding.

| WS1 lead / invariant | Verdict | Severity | Test (ignored, fails today) |
|---|---|---|---|
| D1 Content-Hash never verified | **CONFIRMED** (property: a one-byte payload change keeps the signature valid and parses) | Critical (WS6 owns) | `d1_swapped_payload_is_rejected` |
| D2 signature over a reconstruction | **CONFIRMED** three ways: reordered headers, duplicate header (last wins), `+5`/`007` Content-Length | High (WS6 owns) | `d2_non_canonical_header_order_is_rejected`, `d2_duplicate_header_is_rejected`, `d2_non_canonical_content_length_is_rejected` |
| D3 unknown headers dropped | **CONFIRMED** for `Attestation`, `Origin`, `Proof`, `Proof-Type`, `Registry-Path`, `Object-Path` | High (WS6 owns) | `d3_unknown_header_survives_or_rejects` |
| D4 trie domain separation | **CONFIRMED** (one object whose hash equals a subtree hash commits to the same root) | High (WS6 owns) | `d4_leaf_and_subtree_commit_to_different_roots` |
| D10 role cycles | **CONFIRMED** (cycle, self-reference, and a 200k-deep acyclic chain all abort) | High | `d10_cyclic_roles_terminate`, `d10_self_referencing_role_terminates`, `d10_role_chain_depth_is_bounded` |
| D13 / Q5 identity comparison | **CONFIRMED** (uppercase domains accepted) | Medium | `d13_uppercase_domain_is_not_a_valid_identity_reference` |
| D14 URI `:` ids / percent-decoding | **CONFIRMED** (`role:mod` parsed as creator `role`) | Low | `d14_colon_ids_round_trip_through_the_uri` |
| D21 dot segments | **CONFIRMED** (`.`, `..`, `...` are valid ids and path segments) | High (WS4 owns) | `d21_dot_segments_are_rejected` |
| D22 / I25 `W` unbounded | **CONFIRMED** (`max_authoring_lag_s = i64::MAX` validates) | Medium | `d22_max_authoring_lag_has_a_protocol_maximum` |
| D50 snapshot inflation | **CONFIRMED** (a 256 KiB gzip inflating to 96 MiB decodes) | Medium | `d50_snapshot_inflation_is_capped` |
| D54 several `@` | **CONFIRMED** (and the two split rules disagree on exactly those ids) | Low → Q5 | `d54_identity_has_exactly_one_at` |
| I24 HLC arithmetic | **CONFIRMED** (`within_bound` panics on overflow in debug) | Low | `i24_hlc_bound_arithmetic_is_checked` |
| D40 SBOP parser trusts `Receipt-Length` | **CONFIRMED** as W3-6 and W3-9 | Low / Medium | `w3_6_*`, `w3_9_*` |
| D49 zkVM guest arithmetic | Not reached: the guest crate needs the risc0 toolchain and is scoped out (Q19) | — | — |
| D51 RFC 9102 bytes into `dnssec-prover` | **REFUTED as a crash**: 3.8M executions, no panic, no spurious `Ok` | Info | `dnssec_rr` target |
| S22 encoding rules | **CONFIRMED** (part of D2) | — | `d2_non_canonical_content_length_is_rejected` |
| I7 two ed25519 wrappers | **REFUTED**: identical verdicts, both reject non-canonical `S` | — | passing |
| I26 LWW total order | **REFUTED**: strict total order holds | — | passing |

## 5. What needs Dan's decision

See the decisions doc Q38 (glob matcher: linear algorithm and/or wildcard
cap), Q39 (strict policy parsing is consensus-changing; ride the regenesis)
and Q40 (an empty warrant scope list authorizes everything today).

## 6. Notes for other workstreams

- WS6 / WS9: W3-4 belongs with D4 and D21 in the `state-commitment/v2`
  fix group (Q18): one rule for object-versus-container collisions, domain
  separation, and raw-bytes `object_hash` change the root together.
- WS5 / WS8: W3-2 is the externally reachable DoS of this set (one warrant
  from any wallet); W3-8 and W3-6 (SBOQ) are client-side crashes from a
  hostile indexer and belong in the Indexer & Client spec's threat text.
- WS2: `dns_record_parsing` pins last-wins on duplicate `_sbo` keys and
  `sbo_types_id_is_subset_of_core_id` pins the two-grammar relationship;
  both flip deliberately when WS2's vectors settle the rule.
- `sbo-crypto/src/merkle.rs` is dead code with a latent prover/verifier
  mismatch (W3-5); delete it or wire it in with a fix.
