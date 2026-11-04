//! Security audit 2026-11, WS2 — conformance RUNNER for `sbo-daemon`
//! (last-writer-wins on the confirmed path vs the read overlay vs
//! reconciliation; batch application rules; the state-trie root as the daemon
//! computes it from its segment mapping; checkpoint-claim parsing; the
//! inclusion-time rule; policy-in-force agreement between reads and
//! validation).
//!
//! Vectors: `conformance/*.json`. Expected-fail tables name the finding that
//! owns each disagreement (`AUDIT-2026-11 <id>`); removing an entry is the
//! acceptance test for the fix.

use sbo_core::crypto::{sha256, ContentHash, PublicKey, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::pending::{overlay_wins, PendingPool};
use sbo_daemon::state_view::{Overlay, StateView};
use sbo_daemon::trust::claim_from_message;
use sbo_daemon::validate::{lww_admits, message_to_stored_object, validate_message, L2Context, ValidationResult};
use serde_json::Value;
use std::path::PathBuf;
use tempfile::tempdir;

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

fn judge(suite: &str, results: Vec<(String, bool, bool, String)>, expected_fail: &[(&str, &str)]) {
    let mut unexpected = Vec::new();
    let mut fixed = Vec::new();
    let mut agree = 0;
    for (id, expected, actual, detail) in &results {
        let listed = expected_fail.iter().find(|(v, _)| v == id);
        match (expected == actual, listed) {
            (true, None) => agree += 1,
            (true, Some((_, finding))) => fixed.push(format!("{id} ({finding}) now agrees with the spec — remove it from EXPECTED_FAIL")),
            (false, Some(_)) => {}
            (false, None) => unexpected.push(format!("{id}: spec {expected}, impl {actual} — {detail}")),
        }
    }
    eprintln!("{suite}: {agree} agree, {} expected-fail, {} unexpected", expected_fail.len(), unexpected.len());
    assert!(unexpected.is_empty(), "{suite}: unexpected disagreements:\n{}", unexpected.join("\n"));
    assert!(fixed.is_empty(), "{suite}:\n{}", fixed.join("\n"));
}

fn stored(path: &str, id: &str, owner_key: &str, hlc: Option<&str>, object_hash: [u8; 32], payload: &[u8], schema: Option<&str>) -> StoredObject {
    StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new("x").unwrap(),
        owner: Id::new(owner_key).unwrap(),
        content_type: "application/json".into(),
        content_hash: ContentHash::sha256(payload),
        payload: payload.to_vec(),
        policy_ref: None,
        related: None,
        content_schema: schema.map(|s| s.to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash,
        hlc: hlc.map(|s| s.to_string()),
        prev: None,
    }
}

fn hash32(short_hex: &str) -> [u8; 32] {
    let mut h = [0u8; 32];
    let b = hex::decode(short_hex).unwrap();
    h[32 - b.len()..].copy_from_slice(&b);
    h
}

fn put_root_policy(db: &StateDb, policy: Value) {
    let policy: sbo_core::policy::Policy = serde_json::from_value(policy).unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    db.put_object(&stored("/sys/policies/", "root", "sys", None, [0u8; 32], b"{}", Some("policy.v2"))).unwrap();
}

fn put_key_rooted_name(db: &StateDb, name: &str, key: &SigningKey) {
    let jwt = sbo_core::jwt::create_self_signed_identity(key, name, None).unwrap();
    let payload = jwt.into_bytes();
    let mut o = stored("/sys/names/", name, name, None, [0u8; 32], &payload, Some("identity.v1"));
    o.creator = Id::new(name).unwrap();
    o.content_type = "application/jwt".into();
    db.put_object(&o).unwrap();
}

// ------------------------------------------------------------------ LWW ----

const LWW_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D17: with a missing or unparseable HLC the read overlay lets
    // the pending shadow beat the on-chain value (`overlay_wins` → true) while
    // reconciliation and the confirmed path treat the chain as authoritative.
    ("LWW-06/overlay_wins", "D17"),
    ("LWW-07/overlay_wins", "D17"),
    ("LWW-08/overlay_wins", "D17"),
];

#[test]
fn lww_vectors_confirmed_path_overlay_and_reconciliation_agree() {
    let doc = load("lww.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let new = &v["new"];
        let old = &v["old"];
        let new_hash = hash32(new["hash"].as_str().unwrap());
        let old_hash = hash32(old["hash"].as_str().unwrap());
        let old_obj = stored("/x/", "y", old["signer"].as_str().unwrap(), old["hlc"].as_str(), old_hash, b"{}", None);
        let new_obj = stored("/x/", "y", new["signer"].as_str().unwrap(), new["hlc"].as_str(), new_hash, b"{}", None);

        // Confirmed path: an incoming message against the stored value.
        let msg = Message {
            action: Action::Post,
            path: Path::parse("/x/").unwrap(),
            id: Id::new("y").unwrap(),
            object_type: ObjectType::Object,
            signing_key: PublicKey::parse(new["signer"].as_str().unwrap()).unwrap(),
            signature: Signature([0u8; 64]),
            content_type: None,
            content_hash: None,
            payload: Some(b"{}".to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: new["hlc"].as_str().map(|s| s.to_string()),
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        let admits = lww_admits(&msg, Some(&old_obj), &new_hash);
        let overlay = overlay_wins(&new_obj, &old_obj);
        let mut pool = PendingPool::new();
        pool.insert(new_obj.clone(), new_hash, 0);
        pool.reconcile_applied(&old_obj);
        let reconcile_keeps = pool.object_at(&new_obj.path, &new_obj.id).is_some();

        match v["new_wins"].as_bool() {
            Some(w) => {
                results.push((format!("{id}/lww_admits"), w, admits, "confirmed path".into()));
                results.push((format!("{id}/overlay_wins"), w, overlay, "read overlay".into()));
                results.push((format!("{id}/reconcile"), w, reconcile_keeps, "pending kept after confirmation".into()));
            }
            None => {
                results.push((format!("{id}/lww_admits"), v["confirmed_applies"].as_bool().unwrap(), admits, "confirmed path with missing HLC".into()));
                results.push((format!("{id}/overlay_wins"), v["pending_beats_confirmed"].as_bool().unwrap(), overlay, "read overlay with missing HLC".into()));
                results.push((format!("{id}/reconcile"), v["pending_beats_confirmed"].as_bool().unwrap(), reconcile_keeps, "reconciliation with missing HLC".into()));
            }
        }
    }
    judge("lww/daemon", results, LWW_EXPECTED_FAIL);
}

// ---------------------------------------------------------------- batch ----

/// Q4 rules 2, 3 and 5 as the daemon applies them: sequential validate +
/// apply, a rejected message invisible to later ones, lower index wins a slot.
/// (`SyncEngine::process_block` needs a light client; this mirrors its loop
/// with the public `validate_message` / `message_to_stored_object` pair.)
#[test]
fn batch_vectors_daemon_sequential_application() {
    let doc = load("batch.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let bytes = v["wire"].as_str().unwrap().as_bytes();
        let expected: Vec<usize> = v["applied"].as_array().unwrap().iter().map(|i| i.as_u64().unwrap() as usize).collect();
        let dir = tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        put_root_policy(&db, serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/communities/**"}]
        }));
        let mut applied = Vec::new();
        if let Ok(msgs) = sbo_core::wire::parse_batch(bytes) {
            for (i, m) in msgs.iter().enumerate() {
                let l2 = L2Context::for_block(Some(1_703_001_234), &db); // the vectors' HLC instant
                if let ValidationResult::Valid { .. } = validate_message(m, &db, dir.path(), &l2) {
                    let h = sha256(&sbo_core::wire::serialize(m));
                    if let Some(o) = message_to_stored_object(m, 1, Some(&db), h, &l2) {
                        db.put_object(&o).unwrap();
                        applied.push(i);
                    }
                }
            }
        }
        results.push((id, true, applied == expected, format!("applied {applied:?}, spec {expected:?}")));
    }
    judge("batch-apply/daemon", results, &[]);
}

// ----------------------------------------------------------------- trie ----

#[test]
fn trie_vectors_daemon_state_root_from_segment_mapping() {
    let doc = load("trie.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let dir = tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        for o in v["objects"].as_array().unwrap() {
            let segs: Vec<&str> = o["segments"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
            let (path, oid) = segs.split_at(segs.len() - 1);
            let path = if path.is_empty() { "/".to_string() } else { format!("/{}/", path.join("/")) };
            let h: [u8; 32] = hex::decode(o["object_hash"].as_str().unwrap()).unwrap().try_into().unwrap();
            db.put_object(&stored(&path, oid[0], "sys", None, h, b"{}", None)).unwrap();
        }
        let root = hex::encode(db.compute_trie_state_root().unwrap());
        let expected = v["root"].as_str().unwrap();
        results.push((format!("{id}/StateDb"), true, root == expected, format!("{root} vs {expected}")));
    }
    judge("trie/daemon", results, &[]);
}

// ----------------------------------------------------------- checkpoint ----

const CP_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 S18 (Q22): the spec writes `state_root` as `sha256:<hex>`;
    // `claim_from_message` decodes bare hex only, so a spec-shaped checkpoint
    // is silently not a claim and never counts as a backer.
    ("CP-01", "S18"),
    ("CP-03", "S18"),
];

#[test]
fn checkpoint_claim_vectors() {
    let doc = load("checkpoint.json");
    let mut results = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap().to_string();
        let payload = serde_json::to_vec(&v["payload"]).unwrap();
        let msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/checkpoints/").unwrap(),
            id: Id::new("c").unwrap(),
            object_type: ObjectType::Object,
            signing_key: SigningKey::from_bytes(&[1u8; 32]).public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("application/json".into()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: v["schema"].as_str().map(|s| s.to_string()),
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        let got = claim_from_message(&msg).map(|c| (c.block, hex::encode(c.state_root)));
        let expected = v["claim"].as_object().map(|c| (c["block"].as_u64().unwrap(), c["state_root"].as_str().unwrap().to_string()));
        results.push((id, true, got == expected, format!("got {got:?}, spec {expected:?}")));
    }
    judge("checkpoint/daemon", results, CP_EXPECTED_FAIL);
}

// -------------------------------------------------------- inclusion time ----

const TIME_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D28: with no inclusion time the attested checks run at
    // t = 0, so a ban issued at any real time is "not yet in force" and the
    // banned writer is admitted; a node that has the timestamp rejects.
    ("TIME-01/no-timestamp", "D28"),
];

/// I13 / I16: a missing inclusion time is a hard reject, never a skipped
/// check; nodes with and without the block timestamp must agree.
#[test]
fn inclusion_time_vectors_nodes_with_and_without_timestamp_agree() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let issuer = SigningKey::from_bytes(&[5u8; 32]);
    let alice = SigningKey::from_bytes(&[6u8; 32]);
    put_key_rooted_name(&db, "cooks", &issuer);
    put_key_rooted_name(&db, "alice", &alice);
    put_root_policy(&db, serde_json::json!({
        "grants": [{"to": "*", "can": ["post"], "on": "/spaces/**"}],
        "restrictions": [{"on": "/spaces/**", "require": {"not_attested": {"type": "ban", "by": "cooks"}}}]
    }));
    // The ban, issued at a real wall-clock time.
    let ban = serde_json::to_vec(&serde_json::json!({"subject": "alice", "type": "ban", "value": true, "issued_at": 1_700_000_000})).unwrap();
    let mut b = stored(&sbo_core::schema::storage_path("cooks", "alice"), "ban", "cooks", None, [0u8; 32], &ban, Some("attestation.v1"));
    b.creator = Id::new("cooks").unwrap();
    b.owner_ref = Some("cooks".into());
    db.put_object(&b).unwrap();

    let payload = b"{}".to_vec();
    let mut post = Message {
        action: Action::Post,
        path: Path::parse("/spaces/general/").unwrap(),
        id: Id::new("p1").unwrap(),
        object_type: ObjectType::Object,
        signing_key: alice.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".into()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None,
    };
    post.sign(&alice);

    let with_ts = validate_message(&post, &db, dir.path(), &L2Context::for_block(Some(1_800_000_000), &db));
    let without_ts = validate_message(&post, &db, dir.path(), &L2Context::for_block(None, &db));
    let results = vec![
        ("TIME-01/with-timestamp".to_string(), false, matches!(with_ts, ValidationResult::Valid { .. }), format!("{with_ts:?}")),
        ("TIME-01/no-timestamp".to_string(), false, matches!(without_ts, ValidationResult::Valid { .. }), format!("{without_ts:?}")),
    ];
    judge("inclusion-time/daemon", results, TIME_EXPECTED_FAIL);
}

// ------------------------------------------------------ policy in force ----

const POLICY_EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 D17 (sbo-y757): the overlay serves a pending policy object
    // to readers but validation resolves policies from the confirmed column
    // family only, so the tip shows a policy that the tip does not enforce.
    ("POL-01/validation-sees-pending-policy", "D17"),
];

/// Content spec §Confirmed vs Tip: both views are computed by the same rules
/// and differ only in which writes are eligible — a policy visible in the tip
/// governs tip validation.
#[test]
fn policy_in_force_agrees_between_tip_reads_and_tip_validation() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({
        "grants": [{"to": "*", "can": ["create"], "on": "/spaces/**"}]
    }));
    // A newer root policy that denies /spaces/** sits in the mempool (signed,
    // accepted at the submit gate, not yet replayed from the chain).
    let new_policy = serde_json::to_vec(&serde_json::json!({
        "deny": ["/spaces/**"],
        "grants": [{"to": "*", "can": ["create"], "on": "/elsewhere/**"}]
    })).unwrap();
    let pending_root = stored("/sys/policies/", "root", "sys", Some("1703001234567.0"), sha256(&new_policy), &new_policy, Some("policy.v2"));
    let overlay = Overlay::new(&db, vec![pending_root.clone()]);

    let tip_read = overlay.get_object(&Path::parse("/sys/policies/").unwrap(), &Id::new("root").unwrap()).unwrap().unwrap();
    let tip_shows_new = tip_read.payload == new_policy;
    let in_force = overlay.resolve_policy(&Path::parse("/spaces/general/").unwrap()).unwrap().unwrap();
    let validation_sees_new = !in_force.deny.is_empty();

    let results = vec![
        ("POL-01/tip-read-shows-pending-policy".to_string(), true, tip_shows_new, "overlay.get_object".into()),
        ("POL-01/validation-sees-pending-policy".to_string(), true, validation_sees_new, format!("overlay.resolve_policy deny = {:?}", in_force.deny)),
    ];
    judge("policy-in-force/daemon", results, POLICY_EXPECTED_FAIL);
}
