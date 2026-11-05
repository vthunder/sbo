//! Security audit 2026-11 remediation, daemon level: `/sys/trust/dns-root` is
//! read at inclusion time and anchors every DNSSEC check (`sbo-evne`, D6/S4).
//! All offline, over synthetic chains from `sbo_core::dnssec_fixture`.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::dnssec_fixture::{browserid_txt_for_sbo_key, SyntheticRoot};
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

// ───────────────────────── D6 ─────────────────────────

/// AUDIT-2026-11 D6: a self-authorizing `/sys/dnssec/<domain>` write rooted at a
/// non-IANA key is accepted only when `/sys/trust/dns-root` pins that key.
#[test]
fn d6_dnssec_write_is_verified_against_the_pinned_root() {
    let root = SyntheticRoot::generate();
    let txt = browserid_txt_for_sbo_key(&SigningKey::generate().public_key());
    let chain = root.browserid_chain(DOMAIN, &txt, T0, T2);
    let k = SigningKey::generate();
    let msg = dnssec_write(&k, &chain);

    // Not pinned: library IANA anchors → rejected.
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);
    let r = validate(&db, &msg, T1);
    assert!(!is_valid(&r), "unpinned root must reject the synthetic chain, got {r:?}");
    assert!(reason(&r).contains("dnssec_proof"), "{}", reason(&r));

    // Pinned: accepted.
    pin_root(&db, &root);
    let r = validate(&db, &msg, T1);
    assert!(is_valid(&r), "pinned root must accept, got {r:?}");

    // Pinned to a different root: rejected again.
    let other = SyntheticRoot::generate();
    pin_root(&db, &other);
    assert!(!is_valid(&validate(&db, &msg, T1)));
}

/// AUDIT-2026-11 D6: the history's `valid_from`/`valid_until` are checked
/// against the write's inclusion time.
#[test]
fn d6_dns_root_history_window_is_checked_at_inclusion_time() {
    let old_root = SyntheticRoot::generate();
    let new_root = SyntheticRoot::generate();
    let txt = browserid_txt_for_sbo_key(&SigningKey::generate().public_key());
    let old_chain = old_root.browserid_chain(DOMAIN, &txt, T0, T2);
    let new_chain = new_root.browserid_chain(DOMAIN, &txt, T0, T2);
    let k = SigningKey::generate();

    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);
    let history = sbo_core::dnssec_fixture::dns_root_v1(&[old_root.root_ksk(0, Some(T1 - 1)), new_root.root_ksk(T1, None)]);
    put_obj(&db, "/sys/trust/", "dns-root", Some("dns-root.v1"), "application/json", &history);

    assert!(is_valid(&validate(&db, &dnssec_write(&k, &old_chain), T1 - 10)));
    assert!(!is_valid(&validate(&db, &dnssec_write(&k, &old_chain), T1 + 10)), "retired root");
    assert!(is_valid(&validate(&db, &dnssec_write(&k, &new_chain), T1 + 10)));
    assert!(!is_valid(&validate(&db, &dnssec_write(&k, &new_chain), T1 - 10)), "root not yet active");
}

/// AUDIT-2026-11 D6 + D7: a self-certifying `domain.v1` verifies its evidence
/// against the pinned root at inclusion time.
#[test]
fn d6_domain_self_cert_uses_pinned_root() {
    let root = SyntheticRoot::generate();
    // The domain key IS the provider key (Mode B self-certifying genesis).
    let domain_key = SigningKey::generate();
    let chain = root.browserid_chain(DOMAIN, &browserid_txt_for_sbo_key(&domain_key.public_key()), T0, T2);

    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db);
    put_obj(&db, "/sys/dnssec/", DOMAIN, Some("dnssec.v1"), "application/octet-stream", &chain);
    let jwt = sbo_core::jwt::create_domain(&domain_key, DOMAIN).unwrap();
    let mut msg = post(&domain_key, "/sys/domains/", DOMAIN, "domain.v1", "application/jwt", jwt.as_bytes());
    msg.auth_evidence = Some(format!("ref:/sys/dnssec/{DOMAIN}"));
    msg.sign(&domain_key);

    let r = validate(&db, &msg, T1);
    assert!(!is_valid(&r), "unpinned: self-cert must fail, got {r:?}");
    pin_root(&db, &root);
    let r = validate(&db, &msg, T1);
    assert!(is_valid(&r), "pinned: self-cert must pass, got {r:?}");
    let r = validate(&db, &msg, T2 + 1);
    assert!(!is_valid(&r), "outside the RRSIG window at inclusion time, got {r:?}");
}
