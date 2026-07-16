---
# sbo-hy4r
title: Single-node mempool order can diverge from on-chain order (optimistic model consistency gap)
status: in-progress
type: bug
priority: high
created_at: 2026-07-16T19:33:24Z
updated_at: 2026-07-16T20:23:38Z
---

## Problem
The SBO daemon validates writes OPTIMISTICALLY at /v1/submit against its mempool (confirmed+pending) overlay, then re-validates at APPLY time in canonical DA (Avail) block order. These two orders can DIVERGE, so a write that passes optimistic submit can be DISREGARDED at apply — silently.

Root cause: the daemon submits each mempool change as a SEPARATE DA transaction. Avail has its own mempool and can order/batch those txs differently than the SBO node's mempool order. So the canonical block order ≠ the node's intended order.

## Expected vs actual
Expectation (dan): in a single-node deployment — all clients submit through ONE node with its mempool, no other nodes, no clients submitting independently to the DA — the node's order should ALWAYS match the on-chain order. Today it does not, because per-change separate DA txs get reordered by Avail's mempool.

## Observed (2026-07-16, two_writer_collision harness, block 3622818)
A membership attestation and a dependent post were submitted back-to-back. Both landed in the SAME Avail block, but the POST was ordered BEFORE its membership. At apply-time replay the author was not yet a confirmed member → member:create grant did not match → 'policy:✗ (No matching grant)' → the post was disregarded, even though /v1/submit had accepted it (the membership was pending-visible in the overlay at submit time). Daemon log:
  [3622818/0] Post …/collision-test-… → policy:✗ (No matching grant)
  [3622818/0] Post …/control-…        → policy:✗ (No matching grant)
  [3622818/0] Post …/membership-cooks (a) → applied
  [3622818/0] Post …/membership-cooks (b) → applied

## Impact
- Any dependency-ordered writes are at risk (post depends on membership; content depends on a policy/dnssec; etc.). An optimistically-accepted write silently drops if a dependency is reordered after it in the canonical block.
- UX: a user who JOINS and IMMEDIATELY POSTS can see the first post show pending then vanish. Normal spacing (membership confirms in an earlier block) is fine.
- Not caused by the (path,id)-uniqueness change (sbo-qv95) — pre-existing property of optimistic submit vs canonical replay; surfaced by the harness.

## Candidate fixes (from dan)
1. BATCHING (preferred long-term): the node takes changes from its mempool, orders them into batches, and submits batches SEQUENTIALLY to the DA, waiting for each batch to confirm before submitting the next. Guarantees single-node consistency (writes from OTHER nodes/clients can still interleave between batches, but a single node's own order is preserved). Cost: no batching support today; complicates the SBO wire format (needs a multi-change batch envelope).
2. Per-tx confirm-inclusion (REJECTED): submit each tx and wait for its inclusion before the next. Avail blocks are ~20s and finality ~40-60s → far too slow for interactive use. Not workable.

## Interim client-side mitigation (does not fix the root cause)
The mingo SPA could wait for a membership to CONFIRM (not just go pending) before enabling posting, and/or re-submit a post that drops. Avoids the vanishing-first-post race for the common case without touching the node.

## Severity: high — it's a correctness/consistency gap in the core optimistic model that most SBO deployments (single trusted node) would assume holds.

## Decision (2026-07-16): implement batching, finality-gated
Root cause CONFIRMED: TurboDA uses a pool of accounts + multithreaded submission and does NOT support pinning to a single account/thread — so separate per-write submissions reorder. Preconfirmations (~300ms) only guarantee submission, NOT order (nice future TurboDA feature idea, but not soon). Dropping TurboDA (direct Avail SDK + nonces) would fix it but costs its benefits (preconfirmations, retries, fallback RPCs, DA pre-payment, TEE) — not worth it.

Chosen approach: the daemon assembles pending mempool writes (in order) into an ORDERED BATCH (one DA tx — the multi-message payload format genesis already uses, parse_batch on the read side, so ~no wire-format change), submits ONE batch at a time, and WAITS FOR FINALITY before submitting the next. Inter-batch barrier via TurboDA's submission-status query endpoint (poll get_submission_info until on-chain). Intra-batch order = array order (guaranteed, one tx→one block); inter-batch order = enforced by the finality wait. This restores single-node order == on-chain order (other nodes/clients still interleave between batches, as expected).

Rejected: order-tolerant apply (non-monotonic bans/not_attested make block-as-a-set ill-defined); concurrent independent batches (dependency-independence analysis too error-prone).

## Implementation scope (daemon submission side only)
- Ordered mempool → batch assembly (preserve submission order; not a HashMap).
- One-batch-in-flight scheduler: accumulate while a batch finalizes; on finality, submit the next accumulated batch.
- turbo client: add submission-status polling (get_submission_info → on-chain) for the barrier.
- No wire-format change (multi-message payload already supported); no validation/trie change.
