# sbo — standard targets (same vocabulary in browserid-ng, mingo, browserid-bsky):
#
#   make build            compile the workspace
#   make test             run the test suite
#   make fuzz-smoke       run every cargo-fuzz target for FUZZ_SECS (default 60) — see fuzz/README.md
#   make fuzz-smoke-install  (dev box) install the weekly launchd agent org.sandmill.sbo-fuzz-smoke
#   make push             push HEAD to origin
#   make watch            watch CI runs for HEAD until they all finish
#   make deploy           see below — sbo has no deployable of its own
#
# Deploy model: this repo ships as a LIBRARY + the sbo-daemon BINARY, but the
# daemon's deployable lives in the mingo repo (deploy/sbo-daemon/Dockerfile
# clones vthunder/sbo at a pinned SBO_REV and layers mingo's app config on
# top). To ship daemon changes:
#   1. push here, note the new sha
#   2. bump SBO_REV in mingo: deploy/sbo-daemon/Dockerfile (and keep the
#      sbo-core git pin in mingo's Cargo.toml in sync)
#   3. push mingo (paths under deploy/sbo-daemon/** auto-trigger the deploy)
# `make deploy` triggers the mingo-side workflow for a rebuild at the
# CURRENTLY PINNED rev — it does not bump the pin for you.

SHA := $(shell git rev-parse HEAD)

.PHONY: build test fuzz-smoke fuzz-smoke-install push watch deploy

build:
	cargo build --workspace

test:
	cargo test --workspace

# cargo-fuzz smoke run (security audit 2026-11 WS3). Standalone workspace under
# fuzz/ — nothing here is built by `make build`/CI-test/Docker. On the dev box:
# ssh localtest 'make fuzz-smoke'.
fuzz-smoke:
	scripts/fuzz-smoke.sh

# Dev-box only (audit 2026-11 Q21): weekly fuzz-smoke via launchd, Sundays
# 14:00 (after the browserid-ng run at 13:00), through `ssh localtest`, log
# /tmp/sbo-fuzz-smoke.log. Check with `launchctl print gui/$$(id -u)/org.sandmill.sbo-fuzz-smoke`;
# kick one off now with `launchctl kickstart gui/$$(id -u)/org.sandmill.sbo-fuzz-smoke`.
FUZZ_PLIST = org.sandmill.sbo-fuzz-smoke.plist
fuzz-smoke-install:
	cp scripts/launchd/$(FUZZ_PLIST) $(HOME)/Library/LaunchAgents/$(FUZZ_PLIST)
	-launchctl bootout gui/$$(id -u)/org.sandmill.sbo-fuzz-smoke 2>/dev/null
	launchctl bootstrap gui/$$(id -u) $(HOME)/Library/LaunchAgents/$(FUZZ_PLIST)
	launchctl print gui/$$(id -u)/org.sandmill.sbo-fuzz-smoke | head -3

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@# Runs take a few seconds to register after a push — wait for them to
	@# APPEAR before waiting for them to finish, or this exits instantly.
	@until gh run list --commit $(SHA) --json status -q '.[].status' | grep -q .; do sleep 5; done
	@while gh run list --commit $(SHA) --json status -q '.[].status' \
	    | grep -qE 'in_progress|queued|requested|waiting'; do sleep 15; done
	@gh run list --commit $(SHA)

deploy:
	@echo "sbo deploys via the mingo repo (SBO_REV pin) — see the header of this Makefile."
	gh workflow run deploy-daemon.yml -R vthunder/mingo
