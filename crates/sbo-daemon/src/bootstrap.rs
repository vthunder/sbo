//! Fast-sync client bootstrap (State Commitment §Bootstrap and Fast-Sync).
//!
//! Fetch a snapshot + a trusted checkpoint root from a serving node, verify the
//! snapshot reconstructs that root, and load it into a state DB — reaching a
//! recent height without replaying from genesis. Trust is selectable: an on-chain
//! `checkpoint.v1` object (authority-signed) when the node advertises one at the
//! snapshot's height, else the serving node's own advertised root (trust-the-node).

use std::io::Read;

use anyhow::{anyhow, Context, Result};

use sbo_core::state::{StateDb, StoredObject};

use crate::http::SyncPointsView;
use crate::snapshot;

/// The author id of the checkpoint authority's `checkpoint.v1` claim. In the
/// unified trust model (State Commitment §Trust Mechanisms) the authority
/// checkpoint is just one signed `(block, root)` claim; a client's [`TrustPolicy`]
/// includes this id to count it. `{attestors:[SYS_AUTHORITY], threshold:1}`
/// reproduces the legacy "trust the on-chain checkpoint" behaviour. This is the
/// deployment's checkpoint-authority identity — `sys-checkpointer` in the default
/// mingo genesis (the `sys`-delegated checkpoint key, not `sys` itself).
pub const SYS_AUTHORITY: &str = "sys-checkpointer";

/// A client's local trust policy over signed `(block, state_root)` claims. The
/// root is accepted once `threshold` distinct trusted attestors (the authority
/// checkpoint counting as [`SYS_AUTHORITY`]) agree on it.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub attestors: Vec<String>,
    pub threshold: usize,
}

impl Default for TrustPolicy {
    /// Legacy behaviour: trust the on-chain checkpoint authority alone.
    fn default() -> Self {
        Self { attestors: vec![SYS_AUTHORITY.to_string()], threshold: 1 }
    }
}

/// How the root a snapshot was verified against was obtained — i.e. what the
/// bootstrap ultimately trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootTrust {
    /// The authority `checkpoint.v1` alone backed the root (policy `{[sys],1}`).
    OnChainCheckpoint,
    /// `n` distinct trusted attestors agreed on the root (web-of-trust).
    Attested { backers: usize },
    /// The serving node's advertised snapshot root (trust that node).
    ServingNode,
}

/// Count how many of `policy`'s trusted attestors back `root` at `block`: the
/// authority checkpoint counts as [`SYS_AUTHORITY`], plus each matching on-chain
/// attestation. Returns the distinct backer count, or `None` if `< threshold`.
pub fn evaluate_trust(
    policy: &TrustPolicy,
    block: u64,
    checkpoint_root: &str,
    attestations: &[crate::http::AttestationView],
) -> Option<usize> {
    use std::collections::HashSet;
    let trusted: HashSet<&str> = policy.attestors.iter().map(|s| s.as_str()).collect();
    let mut backers: HashSet<&str> = HashSet::new();
    if trusted.contains(SYS_AUTHORITY) {
        backers.insert(SYS_AUTHORITY);
    }
    for a in attestations {
        if a.block == block && a.state_root == checkpoint_root && trusted.contains(a.attestor.as_str())
        {
            backers.insert(a.attestor.as_str());
        }
    }
    (backers.len() >= policy.threshold).then_some(backers.len())
}

#[derive(Debug)]
pub struct BootstrapResult {
    pub block: u64,
    pub state_root: [u8; 32],
    pub object_count: usize,
    pub trust: RootTrust,
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).context("decode hex root")?;
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow!("state root is not 32 bytes"))
}

/// Verify `objects` reconstruct `trusted_root`, then load them into `db`. The
/// verification (rebuild the trie → compare root) happens BEFORE any write, so a
/// mismatched/forged snapshot never touches the DB.
pub fn verify_and_load(
    db: &StateDb,
    objects: &[StoredObject],
    trusted_root: [u8; 32],
) -> Result<()> {
    let root = snapshot::compute_snapshot_root(objects);
    if root != trusted_root {
        return Err(anyhow!(
            "snapshot root {} does not match trusted root {} — refusing to load",
            hex::encode(root),
            hex::encode(trusted_root)
        ));
    }
    for o in objects {
        db.put_object(o).map_err(|e| anyhow!("put_object: {e}"))?;
    }
    Ok(())
}

/// Fetch the sync-point manifest from a serving node.
pub async fn fetch_manifest(node_url: &str) -> Result<SyncPointsView> {
    let url = format!("{}/v1/sync-points", node_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET {url} -> {}", resp.status()));
    }
    resp.json::<SyncPointsView>()
        .await
        .with_context(|| format!("decode {url}"))
}

/// Download + decompress the snapshot at `block` into its object set.
pub async fn fetch_snapshot(node_url: &str, block: u64) -> Result<Vec<StoredObject>> {
    let url = format!("{}/v1/snapshot?block={}", node_url.trim_end_matches('/'), block);
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET {url} -> {}", resp.status()));
    }
    let gz = resp.bytes().await?.to_vec();
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut json = Vec::new();
    dec.read_to_end(&mut json).context("decompress snapshot")?;
    serde_json::from_slice(&json).context("parse snapshot")
}

/// End-to-end bootstrap into `db` from a serving node: pick the newest snapshot,
/// determine a trusted root (an on-chain checkpoint at that height if advertised,
/// else the node's own root), verify the snapshot against it, and load. Returns
/// the height reached — the caller sets the repo head to it and tails from `head+1`.
pub async fn bootstrap(db: &StateDb, node_url: &str) -> Result<BootstrapResult> {
    bootstrap_with_policy(db, node_url, &TrustPolicy::default()).await
}

/// Bootstrap under an explicit [`TrustPolicy`]. Selects the **freshest snapshot
/// whose checkpoint root already satisfies the policy** (§Checkpoint Attestations
/// — freshest already-attested), so trust is established immediately with no
/// wait. Falls back to a trust-the-node bootstrap only for the default sys-only
/// policy when no checkpoint is published at all.
pub async fn bootstrap_with_policy(
    db: &StateDb,
    node_url: &str,
    policy: &TrustPolicy,
) -> Result<BootstrapResult> {
    let manifest = fetch_manifest(node_url).await?;
    if manifest.snapshots.is_empty() {
        return Err(anyhow!("node advertises no snapshots"));
    }

    // Snapshots are newest-first; take the freshest one whose checkpoint root is
    // backed by enough trusted attestors.
    let mut chosen: Option<(u64, String, RootTrust)> = None;
    for snap in &manifest.snapshots {
        let Some(cp) = manifest.checkpoints.iter().find(|c| c.block == snap.block) else {
            continue; // no on-chain root to agree on at this height
        };
        if let Some(backers) = evaluate_trust(policy, snap.block, &cp.state_root, &manifest.attestations) {
            let trust = if backers == 1 && policy.attestors == [SYS_AUTHORITY] {
                RootTrust::OnChainCheckpoint
            } else {
                RootTrust::Attested { backers }
            };
            chosen = Some((snap.block, cp.state_root.clone(), trust));
            break;
        }
    }

    let (block, root_hex, trust) = match chosen {
        Some(c) => c,
        // No checkpoint satisfies the policy. Only the default sys-only policy may
        // degrade to trusting the serving node's own root; a stricter policy that
        // is unmet is an error rather than a silent downgrade.
        None if policy.attestors == [SYS_AUTHORITY] && policy.threshold <= 1 => {
            let snap = &manifest.snapshots[0];
            (snap.block, snap.state_root.clone(), RootTrust::ServingNode)
        }
        None => {
            return Err(anyhow!(
                "no checkpoint satisfies trust policy (need {} of {:?}) at any advertised snapshot height",
                policy.threshold,
                policy.attestors
            ));
        }
    };

    let trusted_root = hex_to_32(&root_hex)?;
    let objects = fetch_snapshot(node_url, block).await?;
    verify_and_load(db, &objects, trusted_root)?;

    Ok(BootstrapResult {
        block,
        state_root: trusted_root,
        object_count: objects.len(),
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::AttestationView;

    fn att(block: u64, attestor: &str, root: &str) -> AttestationView {
        AttestationView { block, attestor: attestor.to_string(), state_root: root.to_string() }
    }

    // The unified verifier: the authority checkpoint counts as SYS_AUTHORITY, and
    // the default sys-only policy accepts on the checkpoint alone.
    #[test]
    fn default_policy_accepts_on_checkpoint_alone() {
        let p = TrustPolicy::default();
        assert_eq!(evaluate_trust(&p, 100, "aa", &[]), Some(1));
    }

    // Web-of-trust: threshold 2 needs a peer agreeing on the SAME root; a peer on
    // a different root does not count, and an untrusted attestor is ignored.
    #[test]
    fn threshold_counts_only_trusted_agreeing_attestors() {
        let p = TrustPolicy {
            attestors: vec![SYS_AUTHORITY.into(), "alice".into(), "bob".into()],
            threshold: 2,
        };
        // sys + alice agree on "aa" → 2 backers, meets threshold.
        assert_eq!(
            evaluate_trust(&p, 100, "aa", &[att(100, "alice", "aa")]),
            Some(2)
        );
        // alice attests a DIFFERENT root → only sys backs "aa" → below threshold.
        assert_eq!(evaluate_trust(&p, 100, "aa", &[att(100, "alice", "bb")]), None);
        // untrusted attestor "mallory" agreeing doesn't count → only sys → below.
        assert_eq!(evaluate_trust(&p, 100, "aa", &[att(100, "mallory", "aa")]), None);
        // wrong block → doesn't count.
        assert_eq!(evaluate_trust(&p, 100, "aa", &[att(99, "alice", "aa")]), None);
        // duplicate attestor counted once (still needs a distinct 2nd backer).
        assert_eq!(
            evaluate_trust(&p, 100, "aa", &[att(100, "alice", "aa"), att(100, "alice", "aa")]),
            Some(2)
        );
    }

    // A policy that excludes the authority trusts only independent attestors.
    #[test]
    fn policy_without_authority_ignores_checkpoint() {
        let p = TrustPolicy { attestors: vec!["alice".into(), "bob".into()], threshold: 2 };
        // Only alice → below threshold (checkpoint/sys not trusted).
        assert_eq!(evaluate_trust(&p, 5, "rr", &[att(5, "alice", "rr")]), None);
        // alice + bob → meets threshold, authority irrelevant.
        assert_eq!(
            evaluate_trust(&p, 5, "rr", &[att(5, "alice", "rr"), att(5, "bob", "rr")]),
            Some(2)
        );
    }

    // Bootstrap's core: a snapshot loads only if it reconstructs the trusted root,
    // and a wrong root is refused before any write.
    #[test]
    fn verify_and_load_accepts_matching_rejects_forged() {
        let src = tempfile::tempdir().unwrap();
        let src_db = StateDb::open(src.path()).unwrap();
        for (path, creator, id, hash) in [
            ("/communities/cooks/", "sys@mingo.place", "community", [7u8; 32]),
            ("/u/dan@mingo.place/", "dan@mingo.place", "profile", [8u8; 32]),
        ] {
            src_db
                .put_object(&StoredObject {
                    path: sbo_core::message::Path::parse(path).unwrap(),
                    id: sbo_core::message::Id::new(id).unwrap(),
                    creator: sbo_core::message::Id::new(creator).unwrap(),
                    owner: sbo_core::message::Id::new(creator).unwrap(),
                    content_type: "application/json".into(),
                    content_hash: sbo_core::crypto::ContentHash::sha256(b"{}"),
                    payload: b"{}".to_vec(),
                    policy_ref: None,
                    content_schema: Some("x.v1".into()),
                    owner_ref: None,
                    block_number: 5,
                    object_hash: hash,
                    hlc: None,
                    prev: None,
                })
                .unwrap();
        }
        let root = src_db.compute_trie_state_root().unwrap();
        let objects = src_db.list_objects_by_path_prefix("/").unwrap();

        // Fresh target DB, correct root → loads, root matches, objects present.
        let dst = tempfile::tempdir().unwrap();
        let dst_db = StateDb::open(dst.path()).unwrap();
        verify_and_load(&dst_db, &objects, root).unwrap();
        assert_eq!(dst_db.compute_trie_state_root().unwrap(), root);
        assert_eq!(dst_db.list_objects_by_path_prefix("/").unwrap().len(), objects.len());

        // Wrong root → refused, and (since verify precedes writes) nothing loaded.
        let dst2 = tempfile::tempdir().unwrap();
        let dst2_db = StateDb::open(dst2.path()).unwrap();
        assert!(verify_and_load(&dst2_db, &objects, [0u8; 32]).is_err());
        assert!(dst2_db.list_objects_by_path_prefix("/").unwrap().is_empty());
    }
}
