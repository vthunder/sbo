# Fuzz targets (security audit 2026-11, WS3)

cargo-fuzz (libFuzzer + ASAN) targets for every parser, every sign→verify
path and every narrowing rule in the Rust tree. Standalone workspace:
nothing here is built by `cargo build --workspace`, the `test` CI job, or the
mingo-side Dockerfile. `sbo-core` is built with `default-features = false`
(no rocksdb).

| target | exercises |
|---|---|
| `wire_parse` | `wire::parse` / `parse_batch` / `split_message` on bytes; accepted input survives serialize → parse with the same signature verdict; batch splitter agrees with the single parser |
| `wire_build` | structured envelopes (grammar-valid ids/paths, payloads, optional headers) built, signed, serialized, parsed back identical; a bit flip in a signed header value is always detected |
| `uri_dns` | `SboRawUri` parse ↔ render fixed point (friendly + canonical), `ChainId`, `_sbo` TXT `parse_record` (Ok ⇒ bare repo), `parse_email`, `audience_identifies_db` |
| `policy_json` | `Policy` deserialize on text, serialize round trip, `evaluate` verdict stable across the round trip, `deny` wins, `check_descendant_constraint` |
| `path_glob` | `PathPattern`, `IdPattern` and the warrant `path:` glob against memoised reference matchers; `scopes_authorize` fail-closed and OR/AND shape |
| `proof_parse` | SBOP / SBOQ parse totality + serialize round trip; `verify_trie_proof` on parsed proofs |
| `hlc_lww` | `Hlc::parse` ↔ `to_wire`, canonical-form acceptance, LWW strict total order, the validity interval |
| `trie_proof` | sparse-trie inclusion / non-existence proofs on arbitrary prefix-free sets, order-independent root, state-transition witnesses vs a rebuilt trie, verifier totality |
| `schema_json` | `attestation.v1` / `collection.v1` / `post.v1` / `comment.v1` / `reaction.v1` parsers and `validate_schema` on (schema, payload) pairs; attestation invariants when Ok |
| `presentation` | device-presentation attribution on byte-edited valid bundles and arbitrary text; whatever verifies is the fixture identity, key, audience, inside the DNSSEC window |
| `dnssec_rr` | `extract_provider_key` / `verify_dnssec_proof_for_domain` / `verify_domain_self_cert` on arbitrary RFC 9102 bytes (D51); any `Ok` is a finding |
| `jwt` | identity / domain JWT verifiers on edited valid tokens and arbitrary text; a verified self-signed token carries its signer's key |

Three targets carry a documented **guard** that masks a finding already
encoded as an `#[ignore]`d `AUDIT-2026-11` test, so the smoke run stays green
until the fix lands; remove the guard with the fix:

- `policy_json`, `path_glob`: patterns with more than 3–4 wildcards are
  skipped (W3-1 / W3-2: `**` matching is exponential).
- `proof_parse`: `Receipt-Length` / `Object-Length` above 2^40 are skipped
  (W3-6: unchecked length arithmetic), and an SBOP image with no blank
  line is skipped (W3-9: the parser slices past the end — found by this
  target on its first run; seed `crash-w3-9`).
- `wire_parse`: a declared `Content-Length` longer than 12 digits is skipped
  (W3-10: the batch splitter adds it unchecked — found by this target;
  seed `crash-w3-10`).
- `trie_proof`: `path_segments` is padded to cover the steps (W3-8: the
  non-existence verifier indexes it unchecked).
- `hlc_lww`: bound arithmetic is exercised on |x| < 2^53 (I24: unchecked
  `t_b − W` / `t_b + ε`).

## Running

```sh
rustup toolchain install nightly --profile minimal   # once
cargo install cargo-fuzz                             # once
make fuzz-smoke                                      # 60 s per target
FUZZ_SECS=900 scripts/fuzz-smoke.sh wire_parse       # one target, longer
cd fuzz && cargo +nightly fuzz run policy_json corpus/policy_json seeds/policy_json -- -max_total_time=3600 -jobs=4 -workers=4
```

On the dev box wrap every command in `ssh localtest '…'` (macOS Gatekeeper
stalls fresh binaries). `cargo +nightly fuzz list` prints the targets;
`cargo +nightly fuzz fmt <target> <artifact>` pretty-prints an `Arbitrary`
input from a crash file.

## Weekly run on the dev box

Decision Q21 of the audit: the smoke run is scheduled, not just available.
`make fuzz-smoke-install` copies
`scripts/launchd/org.sandmill.sbo-fuzz-smoke.plist` into
`~/Library/LaunchAgents/` and bootstraps it; every Sunday at 14:00 (after
the browserid-ng run at 13:00) launchd runs `ssh localtest 'make
fuzz-smoke'` with `FUZZ_SECS=60` from `~/src/sbo`, output appended to
`/tmp/sbo-fuzz-smoke.log`. Every run ends in a `fuzz-smoke: OK` or
`fuzz-smoke: FAILED (exit N)` line, so `tail -1 /tmp/sbo-fuzz-smoke.log` is
the weekly check and `grep FAILED /tmp/sbo-fuzz-smoke.log` the history; a
failure's crash inputs are under `fuzz/artifacts/<target>/`.

```sh
make fuzz-smoke-install
launchctl print gui/$(id -u)/org.sandmill.sbo-fuzz-smoke | head -3
launchctl kickstart gui/$(id -u)/org.sandmill.sbo-fuzz-smoke
tail -3 /tmp/sbo-fuzz-smoke.log
```

## CI

`.github/workflows/fuzz-smoke.yml` builds every target on nightly and runs
each for a short budget (weekly schedule, on changes under `fuzz/`, and on
demand). It is a build-and-smoke gate, not the long run.

Layout: `seeds/<target>/` is the committed seed corpus (regenerate with
`cargo run --release --bin gen_seeds`); `corpus/<target>/` is the growing run
corpus and `artifacts/<target>/` holds crashes — both ignored. A crash that
reproduces gets minimised (`cargo +nightly fuzz tmin`), copied into
`seeds/<target>/crash-<id>`, and an `#[ignore]`d regression test in the
owning crate's `tests/audit_2026_11_ws3_*.rs`.
