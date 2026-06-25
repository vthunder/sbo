# Plan — daemon-side mempool overlay (shared optimistic tip)

**Date:** 2026-06-25
**Goal:** Hide Avail's ~20s block latency by serving a **validated-but-unconfirmed**
overlay on top of confirmed state, visible to **all** clients of a daemon — not
just the author (today's optimism is client-local only). Honest about trust: the
overlay is a *mempool*, never proof-backed; `state-root` stays at the last
confirmed block and pending objects are flagged `confirmed: false`.

## Decisions (locked)
- **Full validation at submit**, pending-aware (validate against `confirmed + pending`).
- **Polling first** (overlay alone cuts perceived latency to ~1s); SSE/WebSocket push later.
- **TTL-only eviction** (~60s / ~3 blocks); no dependency-cascade handling for now.
- **In-memory** pending pool (transient; lost on restart, which is fine).
- Single-daemon assumption (all Mingo writes route through mingo's daemon). Multi-daemon
  mempool gossip is out of scope.

## Context (current state)
- `sbo-daemon` `submit()` (`main.rs:332`) just forwards wire bytes to TurboDA — no
  validation, no readable staging. Validation only happens later, on block replay
  (`validate.rs::validate_message`). So a bad write is silently filtered, and a good
  write is invisible for ~20s.
- Optimism today is **client-local** (mingo-web: pending-post placeholder, optimistic
  vote) — only the author sees it; other users wait for the block.
- Reads: `http.rs` → `RepoApi::{get_object,list_objects,state_root}` →
  `main.rs::{read_object_view,read_object_list}` → `StateDb` (confirmed only).

## Architecture

### 1. `StateView` trait (sbo-core or sbo-daemon) — the overlay substrate
`validate_message` / `l2_authorize` / `resolve_policy` currently take `&StateDb`.
Introduce a `StateView` trait exposing the read methods they need
(`get_first_object_at_path_id`, `list_objects_by_schema`,
`list_objects_by_path_prefix`, `resolve_policy`, name lookup, `has_objects`, …).
- `impl StateView for &StateDb` — confirmed only (unchanged behavior).
- `struct Overlay<'a> { db: &'a StateDb, pending: &'a PendingPool }` — checks pending
  first (LWW by HLC), falls through to `db`; list methods concatenate + dedup.
This is the meatiest refactor. It is reused by BOTH submit-validation and read-merge,
so it's worth doing once. (Scope valve: if too large, fall back to confirmed-only
validation + confirmed-only membership gating in the SPA — see "Phasing".)

### 2. `PendingPool` (new, `sbo-daemon/src/pending.rs`)
In-memory, `Arc<RwLock<…>>` (shared like `shared_state_db`). Entry:
`{ msg: Message, wire: Vec<u8>, data_hash: [u8;32], submitted_at: i64 }`.
Indexed for the overlay by `(path, id)` and by `data_hash` (reconciliation).
Methods: `insert`, `remove_by_hash`, `objects_under_prefix`, `objects_by_schema`,
`object_at`, `sweep_expired(now, ttl)`.

### 3. Submit path (`submit()` + `submit_v1`)
1. `wire::parse(data)` → `Message` (reject 400 on parse error).
2. Build `L2Context { inclusion_time: now, anchors: load_trust_anchors(db) }`.
3. `validate_message(&msg, Overlay{db, pending}, repo_path, &l2)`.
4. On `Invalid` → return **400 with stage+reason** (real accept/reject; far better UX
   than today's silent filtering).
5. On `Valid` → `pending.insert(...)`, then `turbo.submit_raw(&data)`, return
   `{ accepted: true, pending: true, hash, submission_id }`.

### 4. Read-merge (`read_object_view`, `read_object_list`)
Merge `pending` over `confirmed`, dedup by `(path,id)`, LWW by HLC (pending wins only
if newer). Tag results with `confirmed: bool` (new `ObjectView` field, default true).
`state_root` is unchanged (confirmed only — the overlay has no root/proofs).
Proof requests (`?proof=1`) only ever serve confirmed objects.

### 5. Reconciliation (in the sync loop, `main.rs` after `process_block`)
- For each applied write in the block: `pending.remove_by_hash(data_hash)` (the write
  is now confirmed; drop the shadow).
- Each tick: `pending.sweep_expired(now, TTL)` — evict writes that never landed
  (failed submission, or lost an LWW race). TTL ≈ 60s.

### 6. mingo-web changes (simplify)
- **Remove** client-local optimism (pending-post placeholder, optimistic vote) — the
  server overlay now covers it *and* makes it cross-user.
- After a successful submit, re-render after ~1s (overlay reflects it); keep a short
  poll to flip the item's style when it becomes `confirmed: true`.
- Render `confirmed: false` items with a subtle "pending" affordance (muted/spinner)
  that clears on confirmation.
- On submit **400**, surface the reason immediately (e.g. "not a member" → show Join).
- Membership gating (`hasMembership`) stays **confirmed-only** so Join shows
  "Joining…" until the membership actually confirms (avoids the show-as-member /
  post-rejected mismatch). Phase B relaxes this.

## Phasing
- **Phase A (core mempool):** PendingPool + read-merge + reconcile + TTL; submit
  validates against **confirmed** state (`inclusion_time=now`) and returns accept/reject.
  Already delivers instant shared posts/comments/votes for existing members (the common
  case). Ship the SPA simplification here.
- **Phase B (pending-aware validation):** the `Overlay` `StateView` so submit validates
  against `confirmed + pending` → join→post and other chained writes go optimistic; relax
  SPA membership gating to count pending memberships.
- **Phase C (push):** SSE/WebSocket endpoint streaming pending+confirm events so other
  users' writes appear instantly without polling.

## Critical files
- New: `sbo-daemon/src/pending.rs`.
- `sbo-daemon/src/main.rs` — `submit()`, `read_object_view`, `read_object_list`, sync loop.
- `sbo-daemon/src/http.rs` — `submit_v1` response shape, `ObjectView { confirmed }`.
- `sbo-daemon/src/validate.rs` + `sbo-core` policy/authorize — `StateView` abstraction.
- `reference_impl/mingo-web/app.js` — remove local optimism, render `confirmed` flag, 400 handling.

## Verification
1. Two browsers signed in as different handles, both on the same daemon: A posts →
   appears in **B's** feed within ~1–2s, marked pending → flips to confirmed in ~20s.
2. Invalid write (non-member posts) → submit returns 400 with reason; nothing shown.
3. Vote toggling reflects instantly (overlay LWW) and matches confirmed count after the block.
4. `state-root` block stays at last confirmed; `?proof=1` only returns confirmed objects.
5. Kill+restart daemon mid-pending → pending lost (acceptable), confirmed intact; TTL
   evicts a submission that never lands.
6. `cargo test -p sbo-core -p sbo-daemon`.

## Risks / notes
- Spam: only validated (attribution-gated) writes enter the pool; TTL bounds it; add a
  per-identity rate cap if needed.
- Dependency cascade (pending membership evicted but dependent post lingers) is accepted
  for the demo; TTL cleans it up. Revisit if it causes visible glitches.
- The `StateView` refactor is the main effort/risk; Phase A keeps it optional.
