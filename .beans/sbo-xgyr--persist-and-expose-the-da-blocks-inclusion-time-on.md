---
# sbo-xgyr
title: Persist and expose the DA block's inclusion time on stored objects
status: todo
type: feature
priority: high
created_at: 2026-09-18T13:02:01Z
updated_at: 2026-09-18T13:02:01Z
---

The daemon reads the DA block's real inclusion time but never persists it, so a reader can learn *which block* an object landed in but not *when*. Height gives ordering; it does not give deadlines.

**What exists today:**

- `sync.rs:571` — `let block_timestamp = data.timestamp;` (the block's `timestamp.set` inherent, UNIX seconds)
- `sync.rs:781` — threaded into `L2Context::for_block(block_timestamp, ..)` and used for attribution windows and the HLC validity bound
- `StoredObject` (`sbo-core/src/state/objects.rs:29`) persists `block_number: u64` — **but no timestamp**
- `sbo-daemon/src/main.rs:276` — the object JSON exposes `block: obj.block_number`

So the value is in hand at sync time and then dropped.

**Why it matters.** Any consumer that needs a trustworthy time has only two options today: a self-asserted HLC (bounded by `W`, but still the author's claim) or a payload field (bounded by nothing). Inclusion time is the one time no party controls, and it is unavailable to readers.

The immediate consumer is browserid-pay's adjudicator, which rules on whether a delivery met a deadline (`browserid-pay-e1ou`, critical — obligation timing currently derives from an unverified payload timestamp). Approximating from height × block time drifts and is not acceptable for something money hangs on.

- [ ] persist the block timestamp on `StoredObject` alongside `block_number`
- [ ] expose it in the object JSON next to `block` (`/v1/get`, `/v1/list`)
- [ ] what to do for objects already stored without one — backfill from the DA layer, or leave null and let readers handle absent?
- [ ] `inclusion_time` is `Option<i64>` because a block may carry no usable timestamp; the stored field inherits that, so readers must handle null rather than assume
- [ ] confirm this is the block's inherent and not the daemon's receipt clock, for every path that writes an object (sync replay vs. local submit — `main.rs:680` uses `Some(now)`, which is NOT block time)
