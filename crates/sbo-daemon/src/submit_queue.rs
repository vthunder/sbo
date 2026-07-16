//! Finality-gated batched DA submission (bean sbo-hy4r).
//!
//! # Why
//!
//! TurboDA submits through a *pool* of accounts / multithreaded workers and
//! cannot be pinned to a single account, so two independent `submit_raw` calls
//! can land in **different** blocks in an order unrelated to the order we called
//! them. That reorders a node's own writes on-chain: a write that was valid at
//! submit-time because its dependency was pending-visible (e.g. a post whose
//! group membership was staged in the same window) can be applied *before* that
//! dependency in canonical block order and get disregarded ("No matching
//! grant").
//!
//! # The fix
//!
//! Decouple accept-and-stage (synchronous, optimistic — unchanged) from
//! DA-submit (background, batched, finality-gated). Accepted writes are pushed —
//! **in submission order** — onto an ordered queue. A single background
//! scheduler drains the whole queue into ONE ordered batch (the exact
//! multi-message concatenation format `sbo_core::wire::parse_batch` splits back
//! into ordered messages — the same format genesis uses), submits it, and then
//! BARRIERS on that submission finalizing on-chain before draining the next
//! batch. One batch in flight at a time ⇒ this node's submission order == its
//! on-chain order. Writes submitted together in one finality window land in the
//! SAME batch ⇒ the SAME block ⇒ dependency ordering is preserved.
//!
//! Writes from other nodes/clients may still interleave *between* our batches —
//! that is acceptable; the guarantee is only about a single node not reordering
//! its own dependent writes.
//!
//! # Durability (flagged, intentionally not solved here)
//!
//! Writes sit in this **in-memory** queue between accept and DA-submit. A crash
//! (or a shutdown mid-batch) in that window loses the un-submitted bytes — the
//! client re-submits on non-confirmation. This is the *same durability class* as
//! the existing in-memory pending pool (`pending::PendingPool`); we deliberately
//! do NOT add queue persistence (a durable WAL) now. If stronger durability is
//! wanted, persist the queue to disk on enqueue and replay on startup.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};

/// Ordered DA submission queue: accepted writes' wire bytes in submission order.
///
/// Strict FIFO (a `VecDeque`, never a map) — order is the whole point. Each
/// entry is one accepted write's *wire bytes*, which may itself be a multi-
/// message batch; because the batch format is plain concatenation, draining and
/// concatenating entries yields a single valid `parse_batch` payload whose
/// messages come back out in enqueue order.
pub struct SubmitQueue {
    inner: Mutex<VecDeque<Vec<u8>>>,
    /// Wakes the scheduler when the queue transitions from empty → non-empty, so
    /// the idle case awaits instead of busy-spinning.
    notify: Notify,
}

impl SubmitQueue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        })
    }

    /// Enqueue one accepted write's wire bytes at the tail (submission order).
    pub async fn enqueue(&self, wire: Vec<u8>) {
        self.inner.lock().await.push_back(wire);
        // notify_one stores a permit if no waiter is parked, so a wakeup racing
        // an enqueue is never lost.
        self.notify.notify_one();
    }

    /// Drain the ENTIRE queue, in order, into a single batch payload: the ordered
    /// concatenation of every queued write's wire bytes. Returns `None` if empty.
    ///
    /// The result is a valid multi-message batch: `parse_batch` splits it back
    /// into the same messages in the same order (see the round-trip unit test).
    pub async fn drain_batch(&self) -> Option<Vec<u8>> {
        let mut q = self.inner.lock().await;
        if q.is_empty() {
            return None;
        }
        let mut batch = Vec::new();
        for wire in q.drain(..) {
            batch.extend_from_slice(&wire);
        }
        Some(batch)
    }

    /// Current queued entry count (not byte size). For tests/metrics.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Await the next enqueue notification (used by the scheduler's idle wait).
    async fn wait(&self) {
        self.notify.notified().await;
    }
}

/// Result of polling a DA submission's on-chain status for the finality barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityStatus {
    /// True once the submission is finalized on-chain (state `Finalized` with a
    /// concrete block number).
    pub finalized: bool,
    /// The finalizing block number, when known.
    pub block_number: Option<u64>,
}

/// The two DA operations the scheduler needs, factored behind a trait so the
/// loop is testable with a fake submitter (no network). `TurboDaClient`
/// implements it below.
pub trait DaSubmitter: Send + Sync + 'static {
    /// Submit a batch, returning its submission id on success.
    fn submit_batch(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<String, String>> + Send;

    /// Poll a submission's on-chain finality status.
    fn poll_status(
        &self,
        submission_id: &str,
    ) -> impl std::future::Future<Output = Result<FinalityStatus, String>> + Send;
}

/// Timing knobs for the scheduler. Defaults are production values; tests inject
/// tiny durations so the finality barrier runs fast.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// How often to poll `poll_status` while waiting for finalization.
    pub poll_interval: Duration,
    /// Initial retry backoff after a failed submit.
    pub initial_backoff: Duration,
    /// Cap on the (doubling) submit-retry backoff.
    pub max_backoff: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            // ~6s between finality polls; Avail blocks are ~20s and finality lags
            // a few blocks, so a batch typically finalizes in ~40–60s.
            poll_interval: Duration::from_secs(6),
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// Background batch scheduler loop. Runs until `shutdown` is notified (or the
/// task is aborted). Invariant: at most ONE batch is in flight — the single
/// serialization point that guarantees batch N's block < batch N+1's block.
///
/// Steps, repeated:
///  1. Drain the whole queue into one ordered batch (idle-wait if empty).
///  2. Submit it (retry with backoff on error — never drop or advance).
///  3. BARRIER: poll until finalized on-chain, then loop. Everything enqueued
///     during the barrier goes out in the next batch.
pub async fn run_scheduler<S: DaSubmitter>(
    queue: Arc<SubmitQueue>,
    submitter: S,
    config: SchedulerConfig,
    shutdown: Arc<Notify>,
) {
    loop {
        // (1) Get the next batch, idling on the notify while empty (no spin).
        let batch = loop {
            if let Some(b) = queue.drain_batch().await {
                break b;
            }
            tokio::select! {
                _ = queue.wait() => {}
                _ = shutdown.notified() => return,
            }
        };

        // (2)+(3) Submit and barrier on finality. If shutdown fires mid-batch we
        // drop this (un-confirmed) batch and exit — the client re-submits on
        // non-confirmation (see the durability note at the top of this module).
        tokio::select! {
            _ = submit_and_await_finalized(&submitter, &batch, &config) => {}
            _ = shutdown.notified() => return,
        }
    }
}

/// Submit one batch and block until it is finalized on-chain. Retries submit
/// errors with doubling backoff and treats poll errors as transient (keeps
/// polling) — never advances until finalization is observed.
async fn submit_and_await_finalized<S: DaSubmitter>(
    submitter: &S,
    batch: &[u8],
    config: &SchedulerConfig,
) {
    // Submit, retrying forever with backoff until accepted.
    let mut backoff = config.initial_backoff;
    let submission_id = loop {
        match submitter.submit_batch(batch).await {
            Ok(id) => {
                tracing::info!(
                    "DA batch submitted ({} bytes), submission_id={id}; awaiting finality",
                    batch.len()
                );
                break id;
            }
            Err(e) => {
                tracing::error!("DA batch submit failed: {e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(config.max_backoff);
            }
        }
    };

    // Barrier: poll until finalized. Poll errors are transient — keep polling.
    loop {
        tokio::time::sleep(config.poll_interval).await;
        match submitter.poll_status(&submission_id).await {
            Ok(status) if status.finalized => {
                tracing::info!(
                    "DA batch {submission_id} finalized in block {:?}",
                    status.block_number
                );
                return;
            }
            Ok(_) => { /* not finalized yet — keep waiting */ }
            Err(e) => {
                tracing::warn!("DA status poll for {submission_id} failed: {e}; will retry");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TurboDaClient adapter
// ---------------------------------------------------------------------------

impl DaSubmitter for crate::turbo::TurboDaClient {
    async fn submit_batch(&self, data: &[u8]) -> Result<String, String> {
        self.submit_raw(data)
            .await
            .map(|r| r.submission_id)
            .map_err(|e| e.to_string())
    }

    async fn poll_status(&self, submission_id: &str) -> Result<FinalityStatus, String> {
        let v = self
            .get_submission_status(submission_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(parse_finality(&v))
    }
}

/// Extract finality from a TurboDA `GET /v1/submission/{id}` JSON body.
///
/// Observed shape (matches genesis-submission polling): a `state` string that
/// reads `"Finalized"` once on-chain, with a non-null `block_number`. We treat
/// the submission as final only when BOTH hold. Fields are also looked up under
/// a `data` wrapper defensively, since some TurboDA responses nest the payload.
fn parse_finality(v: &serde_json::Value) -> FinalityStatus {
    // TurboDA `GET /v1/get_submission_info?submission_id=<id>` returns:
    //   { "state": "Finalized", "data": { "block_number": <n>, ... }, ... }
    // `state` is TOP-LEVEL; `block_number` is nested under `data`. Read each from
    // its real location, with defensive fallbacks to the other level in case the
    // service ever moves them.
    let state = v
        .get("state")
        .and_then(|s| s.as_str())
        .or_else(|| v.get("data").and_then(|d| d.get("state")).and_then(|s| s.as_str()));
    let block_number = v
        .get("data")
        .and_then(|d| d.get("block_number"))
        .and_then(|b| b.as_u64())
        .or_else(|| v.get("block_number").and_then(|b| b.as_u64()))
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("blockNumber"))
                .and_then(|b| b.as_u64())
        });
    let finalized = matches!(state, Some(s) if s.eq_ignore_ascii_case("finalized"))
        && block_number.is_some();
    FinalityStatus {
        finalized,
        block_number,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A minimal, valid SBO 0.5 wire message with a distinct ID and body, so we
    // can assert parse_batch round-trips the batch back into ordered messages.
    fn wire_msg(id: &str, body: &str) -> Vec<u8> {
        let content_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pk = "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sig = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        format!(
            "SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: {id}\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: {}\n\
Content-Hash: {content_hash}\n\
Public-Key: {pk}\n\
Signature: {sig}\n\
\n\
{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn drain_batch_preserves_order_and_round_trips_parse_batch() {
        let q = SubmitQueue::new();
        // Enqueue N messages in a known order.
        let ids = ["first", "second", "third", "fourth"];
        for (i, id) in ids.iter().enumerate() {
            q.enqueue(wire_msg(id, &format!("{{\"n\":{i}}}"))).await;
        }
        assert_eq!(q.len().await, 4);

        // Drain the whole queue into one batch.
        let batch = q.drain_batch().await.expect("non-empty");
        assert!(q.is_empty().await, "drain must empty the queue");

        // The batch is the exact multi-message format parse_batch splits: the
        // messages come back out in the SAME order they were enqueued.
        let messages = sbo_core::wire::parse_batch(&batch).expect("batch parses");
        let got: Vec<&str> = messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(got, ids, "parse_batch order must match enqueue order");
    }

    #[tokio::test]
    async fn drain_batch_returns_none_when_empty() {
        let q = SubmitQueue::new();
        assert!(q.drain_batch().await.is_none());
    }

    #[tokio::test]
    async fn multi_message_entries_concatenate_into_one_batch() {
        // An entry may itself be a batch of >1 message (a single /v1/submit body
        // with join+post). Draining across entries must still yield one ordered
        // batch that round-trips.
        let q = SubmitQueue::new();
        let mut entry_a = wire_msg("a1", "{\"x\":1}");
        entry_a.extend_from_slice(&wire_msg("a2", "{\"x\":2}")); // 2-message entry
        q.enqueue(entry_a).await;
        q.enqueue(wire_msg("b1", "{\"y\":1}")).await;

        let batch = q.drain_batch().await.unwrap();
        let messages = sbo_core::wire::parse_batch(&batch).unwrap();
        let ids: Vec<&str> = messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["a1", "a2", "b1"]);
    }

    /// Fake submitter that records batches and finalizes after `polls_until_final`
    /// status polls, so we can drive the scheduler without a network.
    struct FakeSubmitter {
        submitted: Arc<Mutex<Vec<Vec<u8>>>>,
        polls: Arc<AtomicUsize>,
        polls_until_final: usize,
        /// Notified once the first batch has finalized (so the test can proceed).
        finalized_once: Arc<Notify>,
    }

    impl DaSubmitter for FakeSubmitter {
        async fn submit_batch(&self, data: &[u8]) -> Result<String, String> {
            self.submitted.lock().await.push(data.to_vec());
            Ok("fake-submission".to_string())
        }
        async fn poll_status(&self, _submission_id: &str) -> Result<FinalityStatus, String> {
            let n = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            if n >= self.polls_until_final {
                self.finalized_once.notify_one();
                Ok(FinalityStatus { finalized: true, block_number: Some(100) })
            } else {
                Ok(FinalityStatus { finalized: false, block_number: None })
            }
        }
    }

    #[tokio::test]
    async fn scheduler_drains_and_barriers_on_finality() {
        let q = SubmitQueue::new();
        // Enqueue two entries BEFORE the scheduler runs: they must drain into a
        // single batch (one batch at a time), in order.
        q.enqueue(wire_msg("m1", "{\"a\":1}")).await;
        q.enqueue(wire_msg("m2", "{\"a\":2}")).await;

        let submitted = Arc::new(Mutex::new(Vec::new()));
        let finalized_once = Arc::new(Notify::new());
        let fake = FakeSubmitter {
            submitted: submitted.clone(),
            polls: Arc::new(AtomicUsize::new(0)),
            polls_until_final: 3, // must poll 3× before advancing (barrier holds)
            finalized_once: finalized_once.clone(),
        };
        let shutdown = Arc::new(Notify::new());
        // Fast timings so the 3-poll barrier completes quickly.
        let cfg = SchedulerConfig {
            poll_interval: Duration::from_millis(5),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        };
        let handle = tokio::spawn(run_scheduler(q.clone(), fake, cfg, shutdown.clone()));

        // Wait until the first batch finalized.
        finalized_once.notified().await;
        shutdown.notify_waiters();
        let _ = handle.await;

        // Exactly one batch was submitted, containing both messages in order.
        let batches = submitted.lock().await;
        assert_eq!(batches.len(), 1, "both entries drain into ONE batch");
        let messages = sbo_core::wire::parse_batch(&batches[0]).unwrap();
        let ids: Vec<&str> = messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["m1", "m2"]);
    }

    #[test]
    fn parse_finality_matches_finalized_state() {
        // The REAL TurboDA shape: `state` top-level, `block_number` nested in `data`.
        let finalized = serde_json::json!({
            "state": "Finalized",
            "data": { "block_number": 42 }
        });
        assert_eq!(
            parse_finality(&finalized),
            FinalityStatus { finalized: true, block_number: Some(42) }
        );

        // Pending (block_number null under data) → not final.
        let pending = serde_json::json!({ "state": "Pending", "data": { "block_number": null } });
        assert!(!parse_finality(&pending).finalized);

        // Finalized state but no block number yet → not final (conservative).
        let no_block = serde_json::json!({ "state": "Finalized", "data": {} });
        assert!(!parse_finality(&no_block).finalized);

        // Defensive fallback: everything nested under `data`.
        let nested = serde_json::json!({ "data": { "state": "finalized", "block_number": 7 } });
        assert_eq!(parse_finality(&nested).block_number, Some(7));
        assert!(parse_finality(&nested).finalized);
    }
}
