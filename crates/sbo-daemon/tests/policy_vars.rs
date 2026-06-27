//! Phase 1 integration: the `/u/<owner>/` container layout works end-to-end via
//! the de-circularized `$owner` (declared `Owner` header, not path segment 0).

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult, ValidationStage};
use tempfile::tempdir;

fn ctx(db: &StateDb) -> L2Context {
    L2Context::for_block(None, db)
}

fn put_key_name(db: &StateDb, name: &str, key: &SigningKey) {
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

/// Root policy: the `/u/<owner>/` container — owner may do anything in their own
/// `/u/$owner/**` namespace. Plus first-come name claims (so resolution works).
fn put_root_policy(db: &StateDb) {
    let policy: sbo_core::policy::Policy = serde_json::from_value(serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["*"], "on": "/u/$owner/**"}
        ]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
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

fn signed_post(key: &SigningKey, path: &str, id: &str, owner: Option<&str>) -> Message {
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
        owner: owner.map(|o| Id::new(o).unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(key);
    msg
}

fn signed_post_creator(
    key: &SigningKey,
    path: &str,
    id: &str,
    owner: Option<&str>,
    creator: Option<&str>,
) -> Message {
    let mut msg = signed_post(key, path, id, owner);
    msg.creator = creator.map(|c| Id::new(c).unwrap());
    msg.sign(key);
    msg
}

#[test]
fn declared_creator_must_be_controlled_by_signer() {
    // Phase 2: the Creator reference sets the object's trie identity, so the
    // signer must control it even when Owner is something the signer DOES control.
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    let bob = SigningKey::generate();
    put_key_name(&db, "alice", &alice);
    put_key_name(&db, "bob", &bob);
    put_root_policy(&db);

    // Alice writes in her own namespace (Owner: alice, which she controls) but
    // declares Creator: bob, which she does NOT control → rejected at attribution.
    let forged = signed_post_creator(&alice, "/u/alice/notes/", "n1", Some("alice"), Some("bob"));
    assert!(
        matches!(
            validate_message(&forged, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }
        ),
        "a Creator the signer does not control must be rejected"
    );

    // Declaring Creator: alice (self, controlled) is fine.
    let ok = signed_post_creator(&alice, "/u/alice/notes/", "n2", Some("alice"), Some("alice"));
    assert!(
        matches!(validate_message(&ok, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "a self-controlled Creator should be allowed"
    );
}

#[test]
fn u_namespace_create_authorized_by_declared_owner() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    put_key_name(&db, "alice", &alice);
    put_root_policy(&db);

    // Alice writes under /u/alice/ declaring Owner: alice → $owner = "alice",
    // path matches /u/$owner/**, signer controls "alice" → allowed.
    let ok = signed_post(&alice, "/u/alice/notes/", "n1", Some("alice"));
    assert!(
        matches!(validate_message(&ok, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "owner write under /u/<owner>/ with declared Owner should be allowed"
    );
}

#[test]
fn u_namespace_create_denied_without_declared_owner() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    put_key_name(&db, "alice", &alice);
    put_root_policy(&db);

    // No Owner header → $owner undefined → `/u/$owner/**` cannot match
    // (it is NOT back-derived as the container segment "u"). Denied at policy.
    let no_owner = signed_post(&alice, "/u/alice/notes/", "n2", None);
    assert!(
        matches!(
            validate_message(&no_owner, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Policy, .. }
        ),
        "create without a declared Owner must fail closed under /u/$owner/**"
    );
}

#[test]
fn u_namespace_forged_owner_denied() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    let bob = SigningKey::generate();
    put_key_name(&db, "alice", &alice);
    put_key_name(&db, "bob", &bob);
    put_root_policy(&db);

    // Bob declares Owner: alice to write under /u/alice/ — path matches, but he
    // does not control "alice", so the `to: owner` check (signer_is_owner) fails.
    let forged = signed_post(&bob, "/u/alice/notes/", "n3", Some("alice"));
    assert!(
        matches!(
            validate_message(&forged, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { .. }
        ),
        "declaring someone else's Owner must not grant access to their namespace"
    );
}
