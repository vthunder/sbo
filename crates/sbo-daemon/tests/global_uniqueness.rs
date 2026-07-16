//! Global `(path, id)` uniqueness (sbo-qv95): object identity is `(path, id)`,
//! globally unique across creators. First-valid-write-wins; `creator` is an
//! immutable attribute, not part of the state-trie key. These tests exercise the
//! create-race, the global transfer destination-collision, delete-frees-slot
//! recycling, self-authorizing single-slot updates, and proof round-trips under
//! the new `[path, id]` keying.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::validate::{
    message_to_stored_object, validate_message, L2Context, ValidationResult, ValidationStage,
};
use tempfile::tempdir;

fn ctx(db: &StateDb) -> L2Context {
    L2Context::for_block(None, db)
}

/// Root policy granting `create`+`update` to everyone on `/shared/*` and only
/// `create` (no update) to everyone on `/pub/*`, plus first-come name claims.
fn put_root_policy(db: &StateDb) {
    let policy: sbo_core::policy::Policy = serde_json::from_value(serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/pub/*"},
            {"to": "*", "can": ["create", "update"], "on": "/shared/**"},
            {"to": "*", "can": ["create", "delete", "transfer"], "on": "/pub/**"}
        ]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy)
        .unwrap();
    db.put_object(&StoredObject {
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        content_schema: Some("policy.v2".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
}

fn signed_post(key: &SigningKey, path: &str, id: &str) -> Message {
    let payload = b"{}".to_vec();
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature::parse(&"0".repeat(128)).unwrap(),
        content_type: Some("application/json".to_string()),
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
    msg.sign(key);
    msg
}

fn signed_transfer(key: &SigningKey, path: &str, id: &str, new_path: &str, new_id: &str) -> Message {
    let mut msg = signed_post(key, path, id);
    msg.action = Action::Transfer {
        new_owner: None,
        new_path: Some(Path::parse(new_path).unwrap()),
        new_id: Some(Id::new(new_id).unwrap()),
    };
    msg.sign(key);
    msg
}

/// Validate a create and, if valid, persist it as the slot's occupant (as the
/// sync apply path would), so a subsequent write sees the incumbent.
fn create_and_store(db: &StateDb, msg: &Message) -> ValidationResult {
    let l2 = ctx(db);
    let res = validate_message(msg, db, std::path::Path::new("/tmp"), &l2);
    if matches!(res, ValidationResult::Valid { .. }) {
        let obj = message_to_stored_object(msg, 2, Some(db), [7u8; 32], &l2).unwrap();
        db.put_object(&obj).unwrap();
    }
    res
}

#[test]
fn two_creators_same_slot_second_create_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let alice = SigningKey::generate();
    let bob = SigningKey::generate();

    // Alice creates /pub/p1 first — she occupies the slot.
    let a = create_and_store(&db, &signed_post(&alice, "/pub/", "p1"));
    assert!(matches!(a, ValidationResult::Valid { .. }), "first create wins: {a:?}");

    // Bob's create into the SAME (path, id) slot is a create into an occupied
    // slot by a different creator → resolves to the update path → rejected (no
    // `update` grant on /pub/*), so the incumbent stands.
    let b = validate_message(
        &signed_post(&bob, "/pub/", "p1"),
        &db,
        std::path::Path::new("/tmp"),
        &ctx(&db),
    );
    assert!(
        matches!(b, ValidationResult::Invalid { stage: ValidationStage::Policy, .. }),
        "second creator's create into an occupied slot must be invalid, got {b:?}"
    );

    // Alice still owns the slot with her creator attribute.
    let occ = db.get_object(&Path::parse("/pub/").unwrap(), &Id::new("p1").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(occ.creator.as_str(), alice_creator(&alice));
}

#[test]
fn transfer_into_slot_occupied_by_different_creator_is_rejected() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let alice = SigningKey::generate();
    let bob = SigningKey::generate();

    // Alice occupies /pub/dest; Bob occupies /pub/src.
    create_and_store(&db, &signed_post(&alice, "/pub/", "dest"));
    create_and_store(&db, &signed_post(&bob, "/pub/", "src"));

    // Bob transfers his /pub/src into /pub/dest — a slot occupied by ALICE.
    // The destination-collision check is GLOBAL, so this is rejected regardless
    // of creator.
    let res = validate_message(
        &signed_transfer(&bob, "/pub/", "src", "/pub/", "dest"),
        &db,
        std::path::Path::new("/tmp"),
        &ctx(&db),
    );
    assert!(
        matches!(res, ValidationResult::Invalid { stage: ValidationStage::State, .. }),
        "transfer into a globally-occupied slot must be rejected, got {res:?}"
    );
}

#[test]
fn delete_frees_slot_for_another_creator() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let alice = SigningKey::generate();
    let bob = SigningKey::generate();
    let path = Path::parse("/pub/").unwrap();
    let id = Id::new("p1").unwrap();

    create_and_store(&db, &signed_post(&alice, "/pub/", "p1"));
    assert!(db.get_object(&path, &id).unwrap().is_some());

    // Free the slot (as the sync apply path does on a delete).
    db.delete_object(&path, &id).unwrap();
    assert!(db.get_object(&path, &id).unwrap().is_none(), "delete frees the slot");

    // Bob can now create at the recycled (path, id).
    let res = create_and_store(&db, &signed_post(&bob, "/pub/", "p1"));
    assert!(matches!(res, ValidationResult::Valid { .. }), "recreate after delete: {res:?}");
    let occ = db.get_object(&path, &id).unwrap().unwrap();
    assert_eq!(occ.creator.as_str(), alice_creator(&bob), "new creator now occupies the slot");
}

#[test]
fn different_signer_updates_self_authorizing_slot_no_fork() {
    // The /sys/dnssec analog: a path whose policy grants create+update to
    // everyone (self-authorizing) holds a SINGLE slot. A first writer creates it;
    // a DIFFERENT signer updates the same slot (no fork — global uniqueness means
    // one object, not a per-creator pair). Freshest write is current (LWW/latest).
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let first = SigningKey::generate();
    let second = SigningKey::generate();
    let path = Path::parse("/shared/").unwrap();
    let id = Id::new("evidence").unwrap();

    let a = create_and_store(&db, &signed_post(&first, "/shared/", "evidence"));
    assert!(matches!(a, ValidationResult::Valid { .. }), "first writer creates: {a:?}");

    // A different signer updates the SAME slot — allowed by the update-to-all
    // grant; there is exactly one slot, so no grindable fork.
    let b = validate_message(
        &signed_post(&second, "/shared/", "evidence"),
        &db,
        std::path::Path::new("/tmp"),
        &ctx(&db),
    );
    assert!(matches!(b, ValidationResult::Valid { .. }), "different signer update: {b:?}");

    // Still one object at the slot.
    assert!(db.get_object(&path, &id).unwrap().is_some());
}

#[test]
fn update_by_different_signer_preserves_immutable_creator() {
    // Regression (the subtle one): `creator` is IMMUTABLE, so a self-authorizing
    // update by a DIFFERENT signer must keep the incumbent's creator — not flip to
    // the new writer's. If it flipped, the pending overlay's create-race merge
    // would mistake the valid update for a losing create and DROP it, and the
    // /sys/dnssec refresh (the very thing this change fixes) would break in the
    // mempool window.
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let first = SigningKey::generate();
    let second = SigningKey::generate();
    let path = Path::parse("/shared/").unwrap();
    let id = Id::new("evidence").unwrap();

    create_and_store(&db, &signed_post(&first, "/shared/", "evidence"));
    let incumbent = db.get_object(&path, &id).unwrap().unwrap();

    // Build the stored object for the second signer's update exactly as the apply
    // path does (with confirmed state present) and confirm it carries the
    // incumbent's creator, not the second signer's own.
    let upd = signed_post(&second, "/shared/", "evidence");
    let res = validate_message(&upd, &db, std::path::Path::new("/tmp"), &ctx(&db));
    assert!(matches!(res, ValidationResult::Valid { .. }), "different-signer update valid: {res:?}");
    let updated = message_to_stored_object(&upd, 3, Some(&db), [9u8; 32], &ctx(&db)).unwrap();
    assert_eq!(
        updated.creator.as_str(),
        incumbent.creator.as_str(),
        "update must preserve the immutable incumbent creator"
    );

    // Sanity: the second signer's OWN resolved creator (on a fresh slot) really is
    // different — so the equality above is preservation, not coincidence.
    let owns_fresh = message_to_stored_object(
        &signed_post(&second, "/shared/", "other"), 3, Some(&db), [9u8; 32], &ctx(&db),
    )
    .unwrap();
    assert_ne!(
        owns_fresh.creator.as_str(),
        incumbent.creator.as_str(),
        "the two signers must resolve to different creators for this test to be meaningful"
    );
}

#[test]
fn proof_round_trips_with_path_id_segments() {
    // Trie proofs are keyed on `[path…, id]` (no creator segment). Generate a
    // proof for the occupant and confirm its segments and that it verifies.
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let mk = |path: &str, id: &str, creator: &str, h: u8| StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new(creator).unwrap(),
        owner: Id::new(creator).unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        content_schema: None,
        owner_ref: None,
        block_number: 1,
        object_hash: [h; 32],
        hlc: None,
        prev: None,
    };
    db.put_object(&mk("/sys/names/", "alice", "user123", 1)).unwrap();
    db.put_object(&mk("/sys/names/", "bob", "user456", 2)).unwrap();

    let (creator, proof) = db
        .generate_trie_proof_auto(&Path::parse("/sys/names/").unwrap(), &Id::new("alice").unwrap())
        .unwrap()
        .expect("proof for existing object");

    // creator is carried as an attribute, but the trie segments are [path…, id]
    // with NO creator level.
    assert_eq!(creator.as_str(), "user123");
    assert_eq!(proof.path_segments, vec!["sys".to_string(), "names".to_string(), "alice".to_string()]);
    assert_eq!(proof.object_hash, Some([1u8; 32]), "proof binds the occupant's hash");

    let root = db.compute_trie_state_root().unwrap();
    assert_eq!(proof.state_root, root, "proof state root matches the computed trie root");
}

/// The creator id `resolve_creator` derives for a bare key-rooted signer:
/// `e_<first16hex>` of the ed25519 key (matching validate.rs's fallback).
fn alice_creator(key: &SigningKey) -> String {
    let pk = key.public_key().to_string();
    let hex = pk.strip_prefix("ed25519:").unwrap();
    format!("e_{}", &hex[..16])
}
