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

/// Register the repo's primary domain object at `/sys/domains/<domain>`.
fn put_domain(db: &StateDb, domain: &str) {
    db.put_object(&StoredObject {
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain).unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: "application/jwt".to_string(),
        content_hash: ContentHash::sha256(b"domain"),
        payload: b"domain".to_vec(),
        policy_ref: None,
        content_schema: Some("domain.v1".to_string()),
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

fn signed_name_claim(key: &SigningKey, name: &str) -> Message {
    let jwt = sbo_core::jwt::create_self_signed_identity(key, name, None).unwrap();
    let payload = jwt.into_bytes();
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature::parse(&"0".repeat(128)).unwrap(),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
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

#[test]
fn name_claim_on_primary_domain_requires_controlling_the_email() {
    // Phase 4 anti-hijack: on a repo whose primary domain is mingo.place, a
    // stranger with no attribution to alice@mingo.place cannot claim
    // /sys/names/alice (which would govern that identity).
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_domain(&db, "mingo.place");
    put_root_policy(&db);

    let stranger = SigningKey::generate();
    let claim = signed_name_claim(&stranger, "alice");
    assert!(
        matches!(
            validate_message(&claim, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }
        ),
        "claiming a primary-domain name without controlling the email must be denied"
    );
}

#[test]
fn name_claim_without_primary_domain_is_first_come() {
    // No /sys/domains/* → no primary domain → name claims are first-come (a
    // no-DNS sbo+raw:// repo, where names are key-rooted from the start).
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);

    let anyone = SigningKey::generate();
    let claim = signed_name_claim(&anyone, "alice");
    assert!(
        matches!(validate_message(&claim, &db, dir.path(), &ctx(&db)), ValidationResult::Valid { .. }),
        "without a primary domain, a name claim should be first-come"
    );
}

#[test]
fn sovereignty_lifecycle_control_flips_browserid_to_key() {
    // Phase 6 demo: the same key-signed write by alice flips from unauthorized to
    // authorized the moment she publishes her key-rooted /sys/names/alice record —
    // control moves from the domain's browserid onramp to her own key, with her
    // namespace and creator identity unchanged.
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_domain(&db, "mingo.place");
    put_root_policy(&db);
    let alice = SigningKey::generate();

    // BEFORE: no key record yet. alice@mingo.place is browserid-rooted; a key-only
    // signer with no attribution cannot act as it.
    let before = signed_post(&alice, "/u/alice@mingo.place/notes/", "n1", Some("alice@mingo.place"));
    assert!(
        matches!(
            validate_message(&before, &db, dir.path(), &ctx(&db)),
            ValidationResult::Invalid { stage: ValidationStage::Attribution, .. }
        ),
        "before the key record, a key-only signer must not control the email identity"
    );

    // Alice publishes her key-rooted name record (the sovereignty upgrade).
    put_key_name(&db, "alice", &alice);

    // AFTER: the identical write is authorized — alice@mingo.place now resolves
    // through the record to her key, and her creator stays the canonical email.
    let after = signed_post(&alice, "/u/alice@mingo.place/notes/", "n2", Some("alice@mingo.place"));
    match validate_message(&after, &db, dir.path(), &ctx(&db)) {
        ValidationResult::Valid { creator } => assert_eq!(creator, "alice@mingo.place"),
        other => panic!("after the key record, the key should control the identity: {other:?}"),
    }
}

#[test]
fn sovereign_key_write_under_u_namespace_with_canonical_email() {
    // Phase 3 sovereignty: alice published a key-rooted /sys/names/alice on a
    // repo whose primary domain is mingo.place. She now signs with her key (no
    // browserid). Her email identity alice@mingo.place resolves THROUGH the key
    // record, so she controls her /u/alice@mingo.place/ namespace, and her
    // creator segment canonicalizes back to the email (stable across the upgrade).
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let alice = SigningKey::generate();
    put_key_name(&db, "alice", &alice); // identity.v1 record + pubkey->name index
    put_domain(&db, "mingo.place"); // makes mingo.place the primary domain
    put_root_policy(&db); // grants owner /u/$owner/**

    let w = signed_post(&alice, "/u/alice@mingo.place/notes/", "n1", Some("alice@mingo.place"));
    match validate_message(&w, &db, dir.path(), &ctx(&db)) {
        ValidationResult::Valid { creator } => assert_eq!(
            creator, "alice@mingo.place",
            "sovereign-key writer's creator should canonicalize to the email"
        ),
        other => panic!("expected Valid for sovereign-key write, got {other:?}"),
    }
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
