#!/usr/bin/env bash
# The fast local equivalent of .github/workflows/release-candidate.yml: the
# same tests on the same pinned toolchain, the conformance vectors, the
# supply-chain gates and the fuzz seed replay. Prints one line per step and
# exits non-zero if any step failed or the run left the tree dirty.
#
#   scripts/release-check.sh                                # repo root, clean tree
#   RELEASE_CHECK_SKIP="fuzz" scripts/release-check.sh      # space-separated step names to skip (dev only)
#
# It does NOT qualify a submission: the release-candidate workflow on the
# staging mirror does (sandmill-infra/ip-approval/PLAN.md). Two things only
# CI does: the production image build + smoke (rc / image sbo-daemon, no
# docker here) and the network-less sandbox around the tests.
#
# On the dev box run it through `ssh localtest` so cargo's test binaries are
# not stalled by Gatekeeper. Needs: rustup, cargo-audit, cargo-deny,
# gitleaks, cargo-fuzz, curl.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
WF=.github/workflows/release-candidate.yml
LOGDIR="${RELEASE_CHECK_LOGDIR:-/tmp/sbo-release-check}"
mkdir -p "$LOGDIR"
SKIP=" ${RELEASE_CHECK_SKIP:-} "
declare -a RESULTS=()
FAILED=0

if [ -n "$(git status --porcelain)" ]; then
  echo "refusing: the tree is dirty (commit or stash first, so the result describes a commit)"
  git status --short
  exit 2
fi

step() {
  local name="$1"; shift
  if [[ "$SKIP" == *" $name "* ]]; then RESULTS+=("skip  $name"); return 0; fi
  local log="$LOGDIR/$name.log"
  printf '==> %s\n' "$name"
  if "$@" >"$log" 2>&1; then
    RESULTS+=("ok    $name")
  else
    RESULTS+=("FAIL  $name  (log: $log)")
    FAILED=1
    tail -40 "$log" | sed 's/\x1b\[[0-9;]*m//g'
    return 1
  fi
}

wf_env() { sed -nE "s/^  $1: *\"?([^\" #]+)\"?.*/\1/p" "$WF" | head -1; }
MINGO_DEPLOY_REV="$(wf_env MINGO_DEPLOY_REV)"
FUZZ_TOOLCHAIN="$(wf_env FUZZ_TOOLCHAIN)"

# The toolchain the daemon image builds with (FROM rust:X in mingo's
# deploy/sbo-daemon/Dockerfile at the pinned rev), which the workflow must
# also pin. Every cargo step below uses it, never rustup's stable.
TC=""
rust_pinned() {
  local df v
  df="$(curl -sfL "https://raw.githubusercontent.com/vthunder/mingo/$MINGO_DEPLOY_REV/deploy/sbo-daemon/Dockerfile")" \
    || { echo "could not fetch mingo deploy/sbo-daemon/Dockerfile at $MINGO_DEPLOY_REV"; return 1; }
  v="$(sed -nE 's/^FROM rust:([0-9.]+)-.*/\1/p' <<<"$df" | head -1)"
  [ -n "$v" ] || { echo "no FROM rust:<version> in the daemon Dockerfile"; return 1; }
  grep -qE "rust-toolchain@[0-9a-f]{40} # $v(\.[0-9]+)?$" "$WF" || { echo "$WF pins a different toolchain than the daemon Dockerfile ($v)"; return 1; }
  rustup toolchain install "$v" --profile minimal >/dev/null 2>&1 || return 1
  TC="$v"
  echo "daemon image and CI build with rust $v: $(cargo "+$TC" --version)"
}
cargo_tc() { [ -n "$TC" ] || { echo "no pinned toolchain (rust-pinned failed or was skipped)"; return 1; }; cargo "+$TC" "$@"; }

rust_workspace() { cargo_tc test --locked; }
audit_pins() { cargo_tc test --locked -- audit_2026_11; }
conformance() {
  cargo_tc test --locked -p sbo-types  --test audit_2026_11_ws2_types &&
  cargo_tc test --locked -p sbo-crypto --test audit_2026_11_ws2_crypto &&
  cargo_tc test --locked -p sbo-core   --test audit_2026_11_ws2_core &&
  cargo_tc test --locked -p sbo-wasm   --test audit_2026_11_ws2_wasm &&
  cargo_tc test --locked -p sbo-daemon --test audit_2026_11_ws2_daemon
}
conformance_repro() {
  cargo_tc test --locked -p sbo-core --test audit_2026_11_ws2_generate -- --ignored &&
  git diff --exit-code -- conformance/
}
cargo_audit() { command -v cargo-audit >/dev/null || { echo "cargo-audit not installed"; return 1; }; cargo audit; }
cargo_deny() { command -v cargo-deny >/dev/null || { echo "cargo-deny not installed"; return 1; }; cargo deny check; }
gitleaks_scan() { command -v gitleaks >/dev/null || { echo "gitleaks not installed"; return 1; }; gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts=HEAD .; }
fuzz_replay() {
  rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal >/dev/null 2>&1 || return 1
  FUZZ_REPLAY=1 FUZZ_TOOLCHAIN="$FUZZ_TOOLCHAIN" scripts/fuzz-smoke.sh
}

step rust-pinned        rust_pinned
step rust-workspace     rust_workspace
step audit-pins         audit_pins
step conformance        conformance
step conformance-repro  conformance_repro
step cargo-audit        cargo_audit
step cargo-deny         cargo_deny
step gitleaks           gitleaks_scan
step fuzz               fuzz_replay

echo
echo "release-check summary ($(git rev-parse --short HEAD)):"
printf '  %s\n' "${RESULTS[@]}"
echo "  (CI only: rc / image sbo-daemon, and the offline sandbox around the tests)"
if [ -z "$(git status --porcelain)" ]; then
  echo "  tree clean after the run"
else
  echo "  FAIL  the run left the tree dirty:"; git status --short | sed 's/^/    /'; FAILED=1
fi
exit $FAILED
