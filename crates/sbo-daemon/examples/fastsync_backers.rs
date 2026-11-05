//! Fast-sync backer counting against the live node.
//!
//! Runs the REAL `bootstrap_with_policy` path against da.sandmill.org under a
//! key-pinned policy (the checkpoint authority is just a pinned key, D34):
//!  1. Positive: threshold-1 pinning the sys-checkpointer key must bootstrap as
//!     `RootTrust::SignedCheckpoints{backers:1}` once the node's manifest carries
//!     the signed checkpoint wire; until it does, the result is `Provisional`
//!     (gated, to be confirmed by `start`'s walk-forward).
//!  2. Negative control: pinning an UNKNOWN key must never yield
//!     `SignedCheckpoints` — proving the count is real, not rubber-stamped.
//!
//! Run: cargo run -p sbo-daemon --example fastsync_backers

use sbo_core::state::StateDb;
use sbo_daemon::bootstrap::{bootstrap_with_policy, RootTrust, TrustPolicy};
use std::path::Path;

const NODE: &str = "https://da.sandmill.org";
/// The mingo `sys-checkpointer` key (see the mingo genesis fixture).
const CHECKPOINTER: &str = "ed25519:937fc1e8073a1d3939bb59fa744e4fd2d7ff365c2cd573ca8a931b47e7949c00";
const UNKNOWN: &str = "ed25519:0000000000000000000000000000000000000000000000000000000000000000";

#[tokio::main]
async fn main() {
    let root = std::env::temp_dir().join("sbo-fastsync-backers");
    run("threshold-1 {sys-checkpointer}", &[CHECKPOINTER], &root.join("pos"), true).await;
    run("threshold-1 {UNKNOWN}  (SignedCheckpoints must NOT appear)", &[UNKNOWN], &root.join("neg"), false).await;
}

async fn run(label: &str, keys: &[&str], db_path: &Path, expect_signed: bool) {
    let _ = std::fs::remove_dir_all(db_path);
    let db = StateDb::open(db_path).expect("open temp state db");
    let policy = TrustPolicy::from_config(&keys.iter().map(|k| k.to_string()).collect::<Vec<_>>(), 1).unwrap();
    println!("\n=== {label} ===");
    match bootstrap_with_policy(&db, NODE, &policy).await {
        Ok(r) => {
            println!("  block {} | {} objects | trust {:?}", r.block, r.object_count, r.trust);
            let signed = matches!(r.trust, RootTrust::SignedCheckpoints { .. });
            println!(
                "  => {}",
                match (expect_signed, signed) {
                    (true, true) => "PASS (signed checkpoint by the pinned key counted)",
                    (true, false) => "PROVISIONAL (manifest carried no signed wire; walk-forward will confirm)",
                    (false, false) => "PASS (unknown key never counts)",
                    (false, true) => "UNEXPECTED",
                }
            );
        }
        Err(e) => println!("  ERR: {e}"),
    }
}
