---
# sbo-y757
title: 'Daemon: reads and validation disagree about which policy is in force while replaying'
status: todo
type: bug
priority: normal
created_at: 2026-09-16T21:35:30Z
updated_at: 2026-09-16T21:35:30Z
---

A daemon replaying the chain (e.g. after a redeploy) validates writes against its **confirmed state plus the mempool**, while `/v1/object` serves the **pending overlay**. Between a policy leaving the mempool and being replayed from the chain, it is in neither: reads show the NEW policy, validation applies the OLD one, and nothing tells a client which is in force.

Observed 2026-09-16 publishing the browserid-pay contribution floor (`browserid-pay-er8j`). The daemon was ~3,700 blocks behind after a redeploy. `/v1/object` reported the new policy — first from the overlay at a provisional block, then briefly reverting to the old one when pending flushed — while writes that the new policy forbids were accepted for ~20 minutes. Cost three wrong diagnoses (suspected a cached Docker layer, then a logic bug, then a stale binary) before the sync lag showed up in the daemon log.

Consequences:

- A published policy silently does not apply until replay catches up, with no error and no signal.
- A client cannot distinguish "the policy is in force" from "the daemon has not seen it yet".
- Mixed daemon versions or sync positions disagree about which writes are valid.

Ideas, not yet decided:

- [ ] report sync height and confirmed-vs-pending provenance on `/v1/object` (and a head/lag field on a status endpoint)
- [ ] have `/v1/submit` refuse, or warn, while the node is materially behind the chain head
- [ ] make policy resolution during validation prefer the newest *confirmed-on-chain* version, rather than whatever the replay has reached
- [ ] document the window in the Policy Specification: publishing is not enforcing

Workaround documented in browserid-pay `deploy/GENESIS.md`: watch `Processed block N` in the daemon log and wait for it to pass the block `policy-update` reported before trusting a probe.
