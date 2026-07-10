//! Tier 2 integration tests: `Action::transfer` (move / rename / re-own) and
//! delete validation in `validate::validate_message`.
//!
//! Covers the rules from SBO Specification.md §transfer:
//! - the current owner may transfer/delete their object;
//! - a non-owner may only if the object's (source) policy grants it — this is
//!   the sys/admin-override path;
//! - relocation checks the destination policy and the same-creator collision
//!   rule. Creator is invariant across a move.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult, ValidationStage};
use tempfile::tempdir;

fn ctx(db: &StateDb) -> L2Context {
    L2Context::for_block(None, db)
}

fn is_valid(r: &ValidationResult) -> bool {
    matches!(r, ValidationResult::Valid { .. })
}

/// Register a key-rooted `identity.v1` name and index its pubkey→name mapping so
/// `resolve_creator` resolves the signer to the name (not a key-hash id).
fn put_name(db: &StateDb, name: &str, key: &SigningKey) {
    let jwt = sbo_core::jwt::create_self_signed_identity(key, name, None).unwrap();
    let payload = jwt.into_bytes();
    db.put_object(&StoredObject {
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        creator: Id::new(name).unwrap(),
        owner: Id::new(name).unwrap(),
        content_type: "application/jwt".to_string(),
        content_hash: ContentHash::sha256(&payload),
        payload,
        policy_ref: None,
        content_schema: Some("identity.v1".to_string()),
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
    db.put_name_claim(&key.public_key().to_string(), name).unwrap();
}

/// Install the root policy: owner-controls-own-namespace, plus an `admin` role
/// (membership = the registered name `root`) granted transfer/delete/create on
/// everything. Mirrors the mingo root-policy shape.
fn put_root_policy(db: &StateDb) {
    let policy: sbo_core::policy::Policy = serde_json::from_value(serde_json::json!({
        "roles": { "admin": ["root"] },
        "grants": [
            {"to": "owner", "can": ["*"], "on": "/$owner/**"},
            {"to": {"role": "admin"}, "can": ["transfer", "delete", "create"], "on": "/**"}
        ]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    // Genesis check looks for the root-policy object itself.
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

/// Store an object owned by the name `owner` (creator == owner), at `path`/`id`.
fn put_owned(db: &StateDb, path: &str, id: &str, owner: &str) {
    db.put_object(&StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new(owner).unwrap(),
        owner: Id::new(owner).unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        content_schema: None,
        owner_ref: Some(owner.to_string()),
        block_number: 1,
        object_hash: [7u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn signed_transfer(
    key: &SigningKey,
    path: &str,
    id: &str,
    new_path: Option<&str>,
    new_id: Option<&str>,
    new_owner: Option<&str>,
) -> Message {
    let placeholder_sig = Signature::parse(&"0".repeat(128)).unwrap();
    let mut msg = Message {
        action: Action::Transfer {
            new_owner: new_owner.map(|o| Id::new(o).unwrap()),
            new_path: new_path.map(|p| Path::parse(p).unwrap()),
            new_id: new_id.map(|i| Id::new(i).unwrap()),
        },
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: placeholder_sig,
        content_type: None,
        content_hash: None,
        payload: None,
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

struct World {
    _dir: tempfile::TempDir,
    db: StateDb,
    alice: SigningKey,
    admin: SigningKey,
    bob: SigningKey,
}

fn world() -> World {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    let admin = SigningKey::generate();
    let bob = SigningKey::generate();
    put_name(&db, "alice", &alice);
    put_name(&db, "root", &admin);
    put_name(&db, "bob", &bob);
    put_root_policy(&db);
    put_owned(&db, "/alice/items/", "x", "alice");
    World { _dir: dir, db, alice, admin, bob }
}

#[test]
fn owner_moves_object_within_own_namespace() {
    let w = world();
    let msg = signed_transfer(&w.alice, "/alice/items/", "x", Some("/alice/archive/"), None, None);
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(is_valid(&r), "owner should be able to move within own namespace: {:?}", r);
}

#[test]
fn admin_moves_user_object_via_policy_override() {
    let w = world();
    // `root` (admin role) is neither the owner nor in alice's namespace.
    let msg = signed_transfer(&w.admin, "/alice/items/", "x", Some("/archive/"), Some("x"), None);
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(is_valid(&r), "admin role should be granted transfer over /**: {:?}", r);
}

#[test]
fn stranger_cannot_transfer_anothers_object() {
    let w = world();
    let msg = signed_transfer(&w.bob, "/alice/items/", "x", Some("/bob/x/"), None, None);
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(
        matches!(r, ValidationResult::Invalid { stage: ValidationStage::Policy, .. }),
        "non-owner non-admin must be denied at policy stage: {:?}", r
    );
}

#[test]
fn transfer_to_existing_destination_is_a_collision() {
    let w = world();
    put_owned(&w.db, "/alice/archive/", "x", "alice"); // destination already taken by same creator
    let msg = signed_transfer(&w.alice, "/alice/items/", "x", Some("/alice/archive/"), None, None);
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(
        matches!(r, ValidationResult::Invalid { stage: ValidationStage::State, .. }),
        "collision at destination must be rejected: {:?}", r
    );
}

#[test]
fn owner_can_delete_via_null_owner() {
    let w = world();
    let msg = signed_transfer(&w.alice, "/alice/items/", "x", None, None, Some("null:"));
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(is_valid(&r), "owner should be able to delete own object: {:?}", r);
}

#[test]
fn cannot_transfer_nonexistent_object() {
    let w = world();
    let msg = signed_transfer(&w.alice, "/alice/items/", "ghost", Some("/alice/archive/"), None, None);
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(
        matches!(r, ValidationResult::Invalid { stage: ValidationStage::State, .. }),
        "transfer of missing object must be rejected: {:?}", r
    );
}

#[test]
fn owner_can_chown_to_another_identity() {
    let w = world();
    // Re-owning without moving: no destination check, owner authorizes.
    let msg = signed_transfer(&w.alice, "/alice/items/", "x", None, None, Some("bob"));
    let r = validate_message(&msg, &w.db, w._dir.path(), &ctx(&w.db));
    assert!(is_valid(&r), "owner should be able to transfer ownership: {:?}", r);
}
