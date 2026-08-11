# sbo — standard targets (same vocabulary in browserid-ng, mingo, browserid-bsky):
#
#   make build            compile the workspace
#   make test             run the test suite
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

.PHONY: build test push watch deploy

build:
	cargo build --workspace

test:
	cargo test --workspace

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@while gh run list --commit $(SHA) --json status -q '.[].status' \
	    | grep -qE 'in_progress|queued|requested|waiting'; do sleep 15; done
	@gh run list --commit $(SHA)

deploy:
	@echo "sbo deploys via the mingo repo (SBO_REV pin) — see the header of this Makefile."
	gh workflow run deploy-daemon.yml -R vthunder/mingo
