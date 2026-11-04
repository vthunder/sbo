#!/usr/bin/env bash
# Run every cargo-fuzz target for a short budget (security audit 2026-11 WS3).
#
#   scripts/fuzz-smoke.sh             # 60 s per target
#   FUZZ_SECS=600 scripts/fuzz-smoke.sh
#   scripts/fuzz-smoke.sh wire_parse  # one target
#
# Needs: `rustup toolchain install nightly --profile minimal` and
# `cargo install cargo-fuzz`. On the dev box run it through `ssh localtest`
# (Gatekeeper stalls fresh test binaries otherwise). Seeds are read from
# fuzz/seeds/<target> (committed); new inputs land in fuzz/corpus/<target>
# (ignored); crashes in fuzz/artifacts/<target>.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"

SECS="${FUZZ_SECS:-60}"
JOBS="${FUZZ_JOBS:-1}"
TARGETS=(wire_parse wire_build uri_dns policy_json path_glob proof_parse hlc_lww trie_proof schema_json presentation dnssec_rr jwt)
[ $# -gt 0 ] && TARGETS=("$@")

if [ ! -d seeds/wire_parse ]; then
  cargo run --release --bin gen_seeds
fi

status=0
for t in "${TARGETS[@]}"; do
  mkdir -p "corpus/$t"
  echo "=== $t (${SECS}s)"
  if ! cargo +nightly fuzz run "$t" "corpus/$t" "seeds/$t" -- \
        -max_total_time="$SECS" -jobs="$JOBS" -workers="$JOBS" \
        -rss_limit_mb=2048 -timeout=20 -max_len=16384 2>&1 | tail -6; then
    echo "!!! $t: crash/timeout — see fuzz/artifacts/$t"
    status=1
  fi
done
exit $status
