//! Phase 3 verification: fast-sync backer counting against the live node.
//!
//! Runs the REAL `bootstrap_with_policy` path against da.sandmill.org:
//!  1. Positive: a threshold-2 policy trusting {sys-checkpointer, attestor2}
//!     must bootstrap with 2 distinct backers (RootTrust::Attested{backers:2}).
//!  2. Negative control: threshold-2 trusting {sys-checkpointer, UNKNOWN} must
//!     FAIL — proving the count is real, not rubber-stamped.
//!
//! Run: cargo run -p sbo-daemon --example fastsync_backers

use sbo_core::state::StateDb;
use sbo_daemon::bootstrap::{bootstrap_with_policy, RootTrust, TrustPolicy, SYS_AUTHORITY};
use std::path::Path;

const NODE: &str = "https://da.sandmill.org";
const ATTESTOR2: &str = "ed25519:a7cfa800d359e889ed98a2e2faa2b45903921205288a0283f2f5a1f33d32dc6b";
const UNKNOWN: &str = "ed25519:0000000000000000000000000000000000000000000000000000000000000000";
const DBROOT: &str = "/private/tmp/claude-501/-Users-thunder-src-browserid-ng/917e2196-7719-44f6-af29-0b1398fccba2/scratchpad";

#[tokio::main]
async fn main() {
    // Positive: two distinct trusted backers must satisfy threshold 2.
    run(
        "threshold-2 {sys-checkpointer, attestor2}",
        TrustPolicy { attestors: vec![SYS_AUTHORITY.to_string(), ATTESTOR2.to_string()], threshold: 2 },
        &format!("{DBROOT}/fs-pos"),
        true,
    )
    .await;

    // Negative control: attestor2 replaced by an unknown key → only 1 real
    // backer (the checkpoint) → threshold 2 unmet → must error.
    run(
        "threshold-2 {sys-checkpointer, UNKNOWN}  (expected FAIL)",
        TrustPolicy { attestors: vec![SYS_AUTHORITY.to_string(), UNKNOWN.to_string()], threshold: 2 },
        &format!("{DBROOT}/fs-neg"),
        false,
    )
    .await;
}

async fn run(label: &str, policy: TrustPolicy, db_path: &str, expect_ok: bool) {
    let _ = std::fs::remove_dir_all(db_path);
    let db = StateDb::open(Path::new(db_path)).expect("open temp state db");
    println!("\n=== {label} ===");
    match bootstrap_with_policy(&db, NODE, &policy).await {
        Ok(r) => {
            let backers = match r.trust {
                RootTrust::Attested { backers } => backers,
                other => {
                    println!("  bootstrapped but trust = {other:?} (not Attested)");
                    0
                }
            };
            println!(
                "  OK: block {} | {} objects | trust {:?}",
                r.block, r.object_count, r.trust
            );
            println!(
                "  => {}",
                if expect_ok && backers >= 2 { "PASS (2+ distinct backers counted)" } else { "UNEXPECTED" }
            );
        }
        Err(e) => {
            println!("  ERR: {e}");
            println!("  => {}", if expect_ok { "UNEXPECTED FAILURE" } else { "PASS (correctly rejected — count is real)" });
        }
    }
}
