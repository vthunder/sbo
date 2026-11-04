---
# sbo-prqd
title: 'Fix D15: trust gate degrade fallback after the bounded wait'
status: todo
type: bug
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Low.** `trust.rs` / `main.rs:1690-1700`: `timeout_blocks` bounds the wait but stops sync and keeps reads refused; the spec's degrade fallback is unimplemented. July `sbo-zocd`.

- [ ] Implement the spec's bounded-wait/degrade rule (or document the stop as the chosen behaviour)
- [ ] Extend `d15_enforcing_gate_stays_gated_without_claims`
