//! Security audit 2026-11, WS6 — daemon side: genesis fail-open (D5) and the
//! Content-Hash gap as seen by `validate_message` (D1). `#[ignore]`d tests fail
//! today and are the acceptance tests for their fix. No production code changed.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::StateDb;
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult};
use tempfile::tempdir;

fn signed(key: &SigningKey, path: &str, id: &str, schema: Option<&str>, payload: &[u8]) -> Message {
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(payload)),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: schema.map(|s| s.to_string()),
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

/// Q7 (a): without a root policy, nothing outside the genesis batch at the
/// anchor is valid. Today an empty state is "genesis mode": every post by
/// anyone to any path is accepted with no policy evaluation at all.
#[test]
#[ignore] // AUDIT-2026-11 D5: fails today — validate_post allows any post when no root policy exists
fn d5_without_a_root_policy_an_ordinary_write_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let mallory = SigningKey::generate();
    let msg = signed(&mallory, "/communities/cooks/posts/", "hello", None, b"{}");
    let r = validate_message(&msg, &db, dir.path(), &L2Context::for_block(Some(1_700_000_000), &db));
    assert!(matches!(r, ValidationResult::Invalid { .. }), "accepted in genesis mode: {r:?}");
}

/// Same hole for policy objects: a `policy.v2` write anywhere is accepted
/// before a root policy exists, so a stranger can plant governing policies.
#[test]
#[ignore] // AUDIT-2026-11 D5: fails today — policy writes bypass `govern` in genesis mode
fn d5_without_a_root_policy_a_policy_write_outside_genesis_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let mallory = SigningKey::generate();
    let policy = br#"{"grants":[{"to":"*","can":["*"],"on":"/**"}]}"#;
    let msg = signed(&mallory, "/communities/cooks/", "root", Some("policy.v2"), policy);
    let r = validate_message(&msg, &db, dir.path(), &L2Context::for_block(Some(1_700_000_000), &db));
    assert!(matches!(r, ValidationResult::Invalid { .. }), "policy planted in genesis mode: {r:?}");
}

/// D1 at the daemon's gate: a message whose payload does not hash to its
/// `Content-Hash` must be rejected before any state check.
#[test]
#[ignore] // AUDIT-2026-11 D1: fails today — no layer recomputes Content-Hash
fn d1_daemon_rejects_a_payload_that_does_not_match_content_hash() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let key = SigningKey::generate();
    let mut msg = signed(&key, "/audit/", "obj", None, b"{\"amount\":1}");
    // Signature-valid envelope, swapped payload of equal length.
    msg.payload = Some(b"{\"amount\":9}".to_vec());
    assert!(sbo_core::message::verify_message(&msg).is_ok());
    let r = validate_message(&msg, &db, dir.path(), &L2Context::for_block(Some(1_700_000_000), &db));
    assert!(
        matches!(r, ValidationResult::Invalid { .. }),
        "swapped payload passed validate_message: {r:?}"
    );
}
