//! Security audit 2026-11, WS8 — PoC for D26/D27: a hostile serving node hands
//! a fast-syncing client a forged state root and forged pinned policy versions.
//!
//! Loopback only: an in-process axum server plays the hostile serving node and
//! answers `/v1/sync-points` and `/v1/snapshot` with a snapshot the attacker
//! built. No production host, no Avail, fake keys. Backs
//! `docs/security-audit-2026-11-ws8-pocs.md`. **Inverted by `sbo-syib`**: each
//! PoC now asserts the hole is closed, and runs in CI.

use sbo_core::crypto::ContentHash;
use sbo_core::message::{Id, Path};
use sbo_core::policy::Policy;
use sbo_core::state::{StateDb, StoredObject};
use sbo_core::crypto::SigningKey;
use sbo_daemon::bootstrap::{evaluate_trust, RootTrust, TrustPolicy};
use sbo_daemon::snapshot::{compute_snapshot_root, SnapshotMeta, SnapshotPayload};
use tempfile::tempdir;

fn obj(path: &str, id: &str, hash: u8, schema: Option<&str>, payload: &[u8]) -> StoredObject {
    StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/json".into(),
        content_hash: ContentHash::sha256(payload),
        payload: payload.to_vec(),
        policy_ref: None,
        related: None,
        content_schema: schema.map(|s| s.to_string()),
        owner_ref: None,
        block_number: 100,
        object_hash: [hash; 32],
        hlc: None,
        prev: None,
    }
}

/// D26 (inverted): a root the serving node simply asserts, with no signed
/// `checkpoint.v1` read, is backed by nobody — under the default policy and
/// under a pinned one alike.
#[test]
fn poc_d26_forged_root_with_no_checkpoint_is_backed_by_nobody() {
    let forged_root = "de".repeat(32);
    assert_eq!(evaluate_trust(&TrustPolicy::default(), 999_999, &forged_root, &[]), None);
    let pinned = TrustPolicy { attestors: vec![SigningKey::generate().public_key()], threshold: 1 };
    assert_eq!(evaluate_trust(&pinned, 999_999, &forged_root, &[]), None, "D26 REGRESSION — a forged root was backed");
}

/// D27: a fast-sync client loads `policy_versions` from the snapshot payload
/// without checking that each key is the policy's own content hash. A hostile
/// node files an all-grants policy under the hash a child community pinned, so
/// the client's frozen governance is silently rewritten.
///
/// We build a snapshot whose OBJECT set reconstructs a root (so the root check
/// passes), then attach a forged `(hash, all-grants-policy)` version whose key
/// is NOT that policy's content hash, and load it with `verify_and_load_payload`.
#[test]
fn poc_d27_forged_policy_version_does_not_load_into_a_fast_sync_client() {
    // The honest object set and its true root.
    let objects = vec![
        obj("/communities/cooks/", "community", 7, Some("x.v1"), b"{}"),
        obj("/communities/cooks/", "root", 8, Some("policy.v2"),
            br#"{"grants":[{"to":"owner","can":["update"],"on":"/communities/cooks/**"}]}"#),
    ];
    let root = compute_snapshot_root(&objects);

    // The attacker's forged pinned version: an all-grants policy filed under a
    // hash the victim's child policy pins (here just a label the client trusts).
    let forged: Policy = serde_json::from_value(serde_json::json!({
        "grants": [{"to": "*", "can": ["*"], "on": "/**"}]
    }))
    .unwrap();
    let pinned_hash = "sha256:00000000000000000000000000000000000000000000000000000000deadbeef";
    let payload = SnapshotPayload {
        objects,
        policy_versions: vec![(pinned_hash.to_string(), forged.clone())],
    };

    let dst = tempdir().unwrap();
    let db = StateDb::open(dst.path()).unwrap();
    let res = sbo_daemon::bootstrap::verify_and_load_payload(&db, &payload, root);

    // The snapshot root matches (objects are honest) so the load succeeds, but
    // the forged version — backed by no covered object — is dropped.
    assert!(res.is_ok(), "snapshot root check unexpectedly failed: {res:?}");
    assert!(
        db.get_policy_version(pinned_hash).unwrap().is_none(),
        "D27 REGRESSION — a forged policy version loaded under the pinned hash",
    );
}

/// Serve `manifest` + `gz` from an in-process node; returns its base URL.
async fn serve(manifest: sbo_daemon::http::SyncPointsView, gz: Vec<u8>) -> String {
    use axum::routing::get;
    let manifest_json = serde_json::to_string(&manifest).unwrap();
    let app = axum::Router::new()
        .route("/v1/sync-points", get(move || {
            let m = manifest_json.clone();
            async move { ([("content-type", "application/json")], m) }
        }))
        .route("/v1/snapshot", get(move || {
            let b = gz.clone();
            async move { b }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn gzip(payload: &SnapshotPayload) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&serde_json::to_vec(payload).unwrap()).unwrap();
    e.finish().unwrap()
}

fn manifest(root_hex: &str, gz_len: usize, checkpoints: Vec<sbo_daemon::http::CheckpointView>) -> sbo_daemon::http::SyncPointsView {
    sbo_daemon::http::SyncPointsView {
        format: "sbo-syncpoints/1".into(),
        genesis: sbo_daemon::http::GenesisView { first_block: Some(1), genesis_hash: None },
        head: 100,
        latest_state_root: sbo_daemon::http::StateRootView { block: 100, state_root: root_hex.to_string() },
        snapshots: vec![SnapshotMeta {
            format: "sbo-snapshot/2".into(),
            block: 100,
            state_root: root_hex.to_string(),
            object_count: 1,
            created_at: 0,
            uncompressed_bytes: 0,
            compressed_bytes: gz_len as u64,
            content_sha256: String::new(),
            file: "snapshot-100.json.gz".into(),
        }],
        checkpoints,
        attestations: vec![],
    }
}

/// A signed `checkpoint.v1` for `(block, root)` as base64 wire.
fn checkpoint_wire(signer: &SigningKey, block: u64, root_hex: &str) -> String {
    use base64::Engine as _;
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Message, ObjectType};
    let payload = serde_json::to_vec(&serde_json::json!({ "block": block, "state_root": root_hex })).unwrap();
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/checkpoints/").unwrap(),
        id: Id::new(&format!("block-{block}")).unwrap(),
        object_type: ObjectType::Object,
        signing_key: signer.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".into()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("checkpoint.v1".into()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None,
        extra_headers: Vec::new(),
    };
    msg.sign(signer);
    base64::engine::general_purpose::STANDARD.encode(sbo_core::wire::serialize(&msg))
}

/// D26 end-to-end (inverted): a hostile in-process node serves a manifest whose
/// snapshot reconstructs the root it advertises, with no signed checkpoint. A
/// client with no pinned keys cannot bootstrap at all (only the explicit
/// `--trust-serving-node` path adopts that root); a client with pinned keys
/// loads it only PROVISIONALLY — gated until the on-chain walk-forward confirms.
#[tokio::test]
async fn poc_d26_hostile_node_root_is_not_adopted_end_to_end() {
    let objects = vec![obj("/x/", "a", 1, None, b"{}")];
    let root_hex = hex::encode(compute_snapshot_root(&objects));
    let payload = SnapshotPayload { objects, policy_versions: vec![] };
    let gz = gzip(&payload);
    // No on-chain checkpoint object at all — the node just asserts the root.
    let node = serve(manifest(&root_hex, gz.len(), vec![]), gz).await;

    let dst = tempdir().unwrap();
    let db = StateDb::open(dst.path()).unwrap();
    let err = sbo_daemon::bootstrap::bootstrap_with_policy(&db, &node, &TrustPolicy::default()).await.unwrap_err();
    assert!(err.to_string().contains("trust-serving-node"), "{err}");
    assert!(db.list_objects_by_path_prefix("/").unwrap().is_empty(), "nothing loaded without a policy");

    let pinned = TrustPolicy { attestors: vec![SigningKey::generate().public_key()], threshold: 1 };
    let out = sbo_daemon::bootstrap::bootstrap_with_policy(&db, &node, &pinned).await.unwrap();
    assert_eq!(out.trust, RootTrust::Provisional, "D26 REGRESSION — the hostile node's root was trusted: {:?}", out.trust);

    // The explicit opt-in is the only way to adopt the node's root as trusted.
    let dst2 = tempdir().unwrap();
    let db2 = StateDb::open(dst2.path()).unwrap();
    let out = sbo_daemon::bootstrap::bootstrap_trust_serving_node(&db2, &node).await.unwrap();
    assert_eq!(out.trust, RootTrust::ServingNode);
}

/// D26 positive path: the manifest carries the signed `checkpoint.v1`; the
/// client re-verifies it and counts it only when the signer is pinned.
#[tokio::test]
async fn signed_checkpoint_in_manifest_counts_only_from_a_pinned_key() {
    let objects = vec![obj("/x/", "a", 1, None, b"{}")];
    let root_hex = hex::encode(compute_snapshot_root(&objects));
    let payload = SnapshotPayload { objects, policy_versions: vec![] };
    let gz = gzip(&payload);
    let checkpointer = SigningKey::generate();
    let cp = sbo_daemon::http::CheckpointView {
        id: "block-100".into(),
        block: 100,
        state_root: root_hex.clone(),
        wire: Some(checkpoint_wire(&checkpointer, 100, &root_hex)),
    };
    let node = serve(manifest(&root_hex, gz.len(), vec![cp]), gz).await;

    let pinned = TrustPolicy { attestors: vec![checkpointer.public_key()], threshold: 1 };
    let dst = tempdir().unwrap();
    let db = StateDb::open(dst.path()).unwrap();
    let out = sbo_daemon::bootstrap::bootstrap_with_policy(&db, &node, &pinned).await.unwrap();
    assert_eq!(out.trust, RootTrust::SignedCheckpoints { backers: 1 });
    assert_eq!(db.list_objects_by_path_prefix("/").unwrap().len(), 1);

    let other = TrustPolicy { attestors: vec![SigningKey::generate().public_key()], threshold: 1 };
    let dst2 = tempdir().unwrap();
    let db2 = StateDb::open(dst2.path()).unwrap();
    let out = sbo_daemon::bootstrap::bootstrap_with_policy(&db2, &node, &other).await.unwrap();
    assert_eq!(out.trust, RootTrust::Provisional, "an unpinned signer must not count");
}
