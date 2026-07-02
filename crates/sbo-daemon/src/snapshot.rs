//! State snapshots for fast client bootstrap (State Commitment spec §Snapshots).
//!
//! A snapshot is the full confirmed object set as of a checkpoint height, stored
//! compact + gzip-compressed, plus a small metadata sidecar. It is *self-verifying*:
//! a client rebuilds the trie from the objects and requires the resulting state
//! root to equal the matching checkpoint's `state_root` (obtained + trusted on
//! chain). The bytes are non-canonical — only the root is.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use sbo_core::state::{StateDb, StoredObject};

/// Snapshot wire format id (bump on incompatible changes).
pub const FORMAT: &str = "sbo-snapshot/json+gzip/1";

/// Metadata sidecar written next to each snapshot file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub format: String,
    /// Checkpoint height this snapshot is taken at.
    pub block: u64,
    /// Claimed state root at `block` (hex sha256). MUST equal the checkpoint's root.
    pub state_root: String,
    pub object_count: usize,
    pub created_at: i64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    /// sha256 of the compressed snapshot file (transport integrity only).
    pub content_sha256: String,
    /// Snapshot file name (relative to the snapshots dir).
    pub file: String,
}

pub fn snapshot_file_name(block: u64) -> String {
    format!("snapshot-{block}.json.gz")
}
pub fn meta_file_name(block: u64) -> String {
    format!("snapshot-{block}.meta.json")
}

/// Hex sha256 of raw bytes.
fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(sbo_core::sha256(bytes))
}

/// Write a snapshot (gzip-compressed object set) + metadata sidecar for `block`.
/// `state_root` is the hex root the daemon already recorded for this height.
pub fn write_snapshot(
    dir: &Path,
    block: u64,
    state_root: &str,
    objects: &[StoredObject],
    now: i64,
) -> Result<SnapshotMeta> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec(objects)?;
    let uncompressed_bytes = json.len() as u64;

    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&json)?;
    let gz = enc.finish()?;
    let compressed_bytes = gz.len() as u64;
    let content_sha256 = hex_sha256(&gz);

    let file = snapshot_file_name(block);
    // Write to a temp name then rename, so a partial write is never served.
    let tmp = dir.join(format!("{file}.tmp"));
    std::fs::write(&tmp, &gz)?;
    std::fs::rename(&tmp, dir.join(&file))?;

    let meta = SnapshotMeta {
        format: FORMAT.to_string(),
        block,
        state_root: state_root.to_string(),
        object_count: objects.len(),
        created_at: now,
        uncompressed_bytes,
        compressed_bytes,
        content_sha256,
        file,
    };
    std::fs::write(dir.join(meta_file_name(block)), serde_json::to_vec_pretty(&meta)?)?;
    Ok(meta)
}

/// Read + decompress a snapshot file into its object set.
pub fn read_snapshot_objects(path: &Path) -> Result<Vec<StoredObject>> {
    let gz = std::fs::read(path)?;
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut json = Vec::new();
    dec.read_to_end(&mut json)?;
    Ok(serde_json::from_slice(&json)?)
}

/// Compute the state root a set of snapshot objects reconstructs to — the client's
/// verification primitive. Uses the canonical trie over `(segments, object_hash)`,
/// so it matches `StateDb::compute_trie_state_root` exactly. Returns `[0u8;32]` for
/// an empty set (matching the daemon's empty-tree convention).
pub fn compute_snapshot_root(objects: &[StoredObject]) -> [u8; 32] {
    if objects.is_empty() {
        return [0u8; 32];
    }
    let entries: Vec<(Vec<String>, [u8; 32])> = objects
        .iter()
        .map(|o| (StateDb::object_to_segments(&o.path, &o.creator, &o.id), o.object_hash))
        .collect();
    sbo_core::compute_trie_root(&entries)
}

/// List available snapshot metas in `dir`, newest block first.
pub fn list_snapshot_metas(dir: &Path) -> Vec<SnapshotMeta> {
    let mut metas = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_meta = p
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.ends_with(".meta.json"));
            if is_meta {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(m) = serde_json::from_slice::<SnapshotMeta>(&bytes) {
                        metas.push(m);
                    }
                }
            }
        }
    }
    metas.sort_by(|a, b| b.block.cmp(&a.block));
    metas
}

#[cfg(test)]
mod tests {
    use super::*;

    // A snapshot must round-trip AND reconstruct the exact same state root the
    // daemon computes from its DB — otherwise a client's verify would never match.
    #[test]
    fn snapshot_roundtrips_and_reproduces_root() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();

        // Populate a few objects across paths/creators.
        for (path, creator, id, hash) in [
            ("/communities/cooks/", "sys@mingo.place", "community", [1u8; 32]),
            ("/communities/cooks/spaces/general/", "dan@mingo.place", "p-1", [2u8; 32]),
            ("/sys/names/", "sys@mingo.place", "sys", [3u8; 32]),
        ] {
            db.put_object(&StoredObject {
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
                block_number: 10,
                object_hash: hash,
                hlc: None,
                prev: None,
            })
            .unwrap();
        }

        let db_root = db.compute_trie_state_root().unwrap();
        let objects = db.list_objects_by_path_prefix("/").unwrap();

        let snap_dir = dir.path().join("snapshots");
        let meta = write_snapshot(&snap_dir, 10, &hex::encode(db_root), &objects, 0).unwrap();
        assert_eq!(meta.object_count, objects.len());

        // Read back and recompute the root from the snapshot alone.
        let read = read_snapshot_objects(&snap_dir.join(&meta.file)).unwrap();
        assert_eq!(read.len(), objects.len());
        assert_eq!(compute_snapshot_root(&read), db_root, "snapshot must reproduce the DB root");

        // Listing finds it.
        let metas = list_snapshot_metas(&snap_dir);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].block, 10);
    }
}
