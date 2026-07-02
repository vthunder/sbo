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

/// How the root a snapshot was verified against was obtained — i.e. what the
/// bootstrap ultimately trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootTrust {
    /// An on-chain `checkpoint.v1` object (authority-signed) at the snapshot height.
    OnChainCheckpoint,
    /// The serving node's advertised snapshot root (trust that node).
    ServingNode,
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
    let manifest = fetch_manifest(node_url).await?;
    let snap = manifest
        .snapshots
        .first()
        .ok_or_else(|| anyhow!("node advertises no snapshots"))?;
    let block = snap.block;

    // Prefer an on-chain checkpoint at this exact height (authority-signed). Its
    // root is the trust anchor. If none is published, fall back to the node's own
    // snapshot root — a trust-the-node bootstrap (still verified for internal
    // consistency, just anchored on the serving node rather than the chain).
    let (root_hex, trust) = match manifest.checkpoints.iter().find(|c| c.block == block) {
        Some(cp) => (cp.state_root.clone(), RootTrust::OnChainCheckpoint),
        None => (snap.state_root.clone(), RootTrust::ServingNode),
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
