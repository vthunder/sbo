//! Security audit 2026-11 remediation, daemon level: a `/sys/dnssec/<domain>`
//! refresh is monotonic (`sbo-uv8a`, D33, Q16 (a)) — never lowers the
//! incumbent's RRSIG expiration nor carries an older DNSKEY set. Offline,
//! over synthetic chains from `sbo_core::dnssec_fixture`, through
//! `validate_message`.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::dnssec_fixture::{browserid_txt_for_sbo_key, ChainSpec, SyntheticRoot, ZoneKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::policy::Policy;
use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult};
use tempfile::tempdir;

const T0: i64 = 1_700_000_000;
const T1: i64 = 1_700_100_000;
const T2: i64 = 1_700_200_000;
const DOMAIN: &str = "example.test";

fn ctx(db: &StateDb, t: i64) -> L2Context {
    L2Context::for_block(Some(t), db)
}

fn is_valid(r: &ValidationResult) -> bool {
    matches!(r, ValidationResult::Valid { .. })
}

fn reason(r: &ValidationResult) -> String {
    match r {
        ValidationResult::Valid { .. } => "valid".into(),
        ValidationResult::Invalid { reason, .. } => reason.clone(),
    }
}

fn put_obj(db: &StateDb, path: &str, id: &str, schema: Option<&str>, content_type: &str, payload: &[u8]) {
    db.put_object(&StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new("sys").unwrap(),
        owner: Id::new("sys").unwrap(),
        content_type: content_type.to_string(),
        content_hash: ContentHash::sha256(payload),
        payload: payload.to_vec(),
        policy_ref: None,
        related: None,
        content_schema: schema.map(|s| s.to_string()),
        owner_ref: Some("sys".to_string()),
        block_number: 1,
        object_hash: [7u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
}

/// Root policy: anyone may create/update `/sys/domains/**`, and `/sys/dnssec/**`
/// is self-authorizing (the `dnssec_proof` restriction).
fn put_root_policy(db: &StateDb) {
    let policy: Policy = serde_json::from_value(serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create", "update"], "on": "/sys/dnssec/**"},
            {"to": "*", "can": ["create"], "on": "/sys/domains/**"}
        ],
        "restrictions": [{
            "on": "/sys/dnssec/**",
            "require": {"schema": "dnssec.v1", "content_type": "application/octet-stream", "dnssec_proof": true}
        }]
    }))
    .unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    put_obj(db, "/sys/policies/", "root", Some("policy.v2"), "application/json", b"{}");
}

fn pin_root(db: &StateDb, root: &SyntheticRoot) {
    put_obj(db, "/sys/trust/", "dns-root", Some("dns-root.v1"), "application/json", &root.dns_root_v1(0, None));
}

fn post(key: &SigningKey, path: &str, id: &str, schema: &str, content_type: &str, payload: &[u8]) -> Message {
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some(content_type.to_string()),
        content_hash: Some(ContentHash::sha256(payload)),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some(schema.to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None,
        extra_headers: Vec::new(),
    };
    msg.sign(key);
    msg
}

fn dnssec_write(key: &SigningKey, proof: &[u8]) -> Message {
    post(key, "/sys/dnssec/", DOMAIN, "dnssec.v1", "application/octet-stream", proof)
}

fn validate(db: &StateDb, msg: &Message, t: i64) -> ValidationResult {
    validate_message(msg, db, std::path::Path::new("/tmp"), &ctx(db, t))
}

// ───────────────────────── D33 ─────────────────────────

/// AUDIT-2026-11 D33 (Q16 (a)): a refresh whose RRSIG expiration is older than
/// the incumbent's is rejected; equal or newer is accepted.
#[test]
fn d33_refresh_cannot_lower_the_incumbent_rrsig_expiration() {
    let root = SyntheticRoot::generate();
    let txt = browserid_txt_for_sbo_key(&SigningKey::generate().public_key());
    let k = SigningKey::generate();
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);
    pin_root(&db, &root);

    // Incumbent: a valid chain expiring at T2, planted as the current occupant.
    put_obj(&db, "/sys/dnssec/", DOMAIN, Some("dnssec.v1"), "application/octet-stream", &root.browserid_chain(DOMAIN, &txt, T0, T2));

    let older = dnssec_write(&k, &root.browserid_chain(DOMAIN, &txt, T0, T2 - 1));
    let r = validate(&db, &older, T1);
    assert!(!is_valid(&r), "older expiration must be rejected, got {r:?}");
    assert!(reason(&r).contains("rollback"), "{}", reason(&r));

    let same = dnssec_write(&k, &root.browserid_chain(DOMAIN, &txt, T0, T2));
    assert!(is_valid(&validate(&db, &same, T1)), "equal expiration is an idempotent refresh");
    let newer = dnssec_write(&k, &root.browserid_chain(DOMAIN, &txt, T0, T2 + 1));
    assert!(is_valid(&validate(&db, &newer, T1)), "newer expiration refreshes");
    // Any other party may refresh (permissionless), subject to the same rule.
    let stranger = SigningKey::generate();
    assert!(is_valid(&validate(&db, &dnssec_write(&stranger, &root.browserid_chain(DOMAIN, &txt, T0, T2 + 1)), T1)));
    assert!(!is_valid(&validate(&db, &dnssec_write(&stranger, &root.browserid_chain(DOMAIN, &txt, T0, T2 - 1)), T1)));
}

/// AUDIT-2026-11 D33 (Q16 (a)): a pre-rotation DNSKEY set — still inside its
/// window, with a later expiration — cannot replace the rotated incumbent.
#[test]
fn d33_refresh_cannot_carry_a_pre_rotation_dnskey_set() {
    let root = SyntheticRoot::generate();
    let txt = browserid_txt_for_sbo_key(&SigningKey::generate().public_key());
    let k = SigningKey::generate();
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);
    pin_root(&db, &root);

    let rotated = ChainSpec::new(DOMAIN, &txt)
        .window(T0, T2)
        .leaf_key(ZoneKey::generate(&format!("{DOMAIN}.")))
        .leaf_dnskey_window(T1, T2)
        .build(&root);
    put_obj(&db, "/sys/dnssec/", DOMAIN, Some("dnssec.v1"), "application/octet-stream", &rotated);

    let pre_rotation = ChainSpec::new(DOMAIN, &txt)
        .window(T0, T2 + 100)
        .leaf_key(ZoneKey::generate(&format!("{DOMAIN}.")))
        .leaf_dnskey_window(T0, T2 + 100)
        .build(&root);
    let r = validate(&db, &dnssec_write(&k, &pre_rotation), T1 + 1);
    assert!(!is_valid(&r), "pre-rotation key set must be rejected, got {r:?}");
    assert!(reason(&r).contains("DNSKEY"), "{}", reason(&r));

    // The first write into an empty slot is not a refresh: no incumbent, no rule.
    let dir2 = tempdir().unwrap();
    let db2 = StateDb::open(dir2.path()).unwrap();
    put_root_policy(&db2);
    pin_root(&db2, &root);
    assert!(is_valid(&validate(&db2, &dnssec_write(&k, &pre_rotation), T1 + 1)));
}
