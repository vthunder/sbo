//! Security audit 2026-11 — the strict bootstrap window as the daemon applies
//! it (sbo-3q6x; Genesis Spec §Bootstrap Window, decisions Q7 (a), Q33 (b)).
//!
//! The sync path (`sync.rs::genesis_gate`) validates the mode-object prefix of
//! the anchor submission with `sbo_core::Genesis`, applies those objects
//! structurally (creator and owner `sys`), and then validates every later
//! message of the submission by the ordinary rules against the state the
//! prefix left. This test replays the post-regenesis v6 fixture through the
//! same two steps against a `StateDb` and checks that every post-root message
//! is admitted by the root policy — the property Q33 (b) demands of a genesis
//! layout (and which the pre-regenesis v5 layout does not have).

use sbo_core::message::{Id, Message, Path};
use sbo_core::policy::Policy;
use sbo_core::state::StateDb;
use sbo_daemon::validate::{message_to_stored_object, validate_message, L2Context, ValidationResult};
use tempfile::tempdir;

const V6_GENESIS: &[u8] = include_bytes!("../../sbo-core/tests/fixtures/mingo-genesis-v6.wire");
const T_B: i64 = 1_784_246_720;

/// Store a validated message the way the sync path does: object, policy
/// index for `policy.v2`, pubkey→name index for `identity.v1`.
fn apply(db: &StateDb, m: &Message, l2: &L2Context) {
    let hash = sbo_core::sha256(&sbo_core::wire::serialize(m));
    let stored = message_to_stored_object(m, 1, Some(db), hash, l2).expect("stored object");
    db.put_object(&stored).unwrap();
    match m.content_schema.as_deref() {
        Some("policy.v2") => {
            let policy: Policy = serde_json::from_slice(m.payload.as_deref().unwrap()).unwrap();
            db.put_policy(&m.path, &policy).unwrap();
        }
        Some("identity.v1") => {
            db.put_name_claim(&m.signing_key.to_string(), m.id.as_str()).unwrap();
        }
        _ => {}
    }
}

#[test]
fn v6_genesis_prefix_applies_structurally_and_the_rest_validates_under_the_root() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let msgs = sbo_core::wire::parse_batch(V6_GENESIS).unwrap();

    // Before the prefix is applied nothing at all is valid — not even the
    // genesis objects themselves through the ordinary gate (D23).
    let l2 = L2Context::for_block(Some(T_B), &db);
    for m in &msgs {
        assert!(
            matches!(validate_message(m, &db, dir.path(), &l2), ValidationResult::Invalid { .. }),
            "{}{} must not pass the ordinary gate with no root policy",
            m.path, m.id
        );
    }

    // The mode-object prefix: validated structurally, applied as sys's.
    let info = sbo_core::Genesis::validate_at(&msgs, Some(T_B), &l2.anchors).unwrap();
    assert_eq!(info.prefix_len, 2);
    for m in &msgs[..info.prefix_len] {
        let mut m = m.clone();
        m.creator = Some(Id::new(&info.sys_identity).unwrap());
        m.owner = Some(Id::new("sys").unwrap());
        apply(&db, &m, &l2);
    }
    assert!(sbo_daemon::validate::root_policy_present(&db));
    let sys = db.get_object(&Path::parse("/sys/names/").unwrap(), &Id::new("sys").unwrap()).unwrap().unwrap();
    assert_eq!(sys.creator.as_str(), "sys");
    assert_eq!(sys.owner_ref.as_deref(), Some("sys"));

    // Everything after the root policy is an ordinary write under it.
    for m in &msgs[info.prefix_len..] {
        let l2 = L2Context::for_block(Some(T_B), &db);
        let r = validate_message(m, &db, dir.path(), &l2);
        assert!(matches!(r, ValidationResult::Valid { .. }), "{}{} rejected under the root policy: {r:?}", m.path, m.id);
        apply(&db, m, &l2);
    }
    assert_eq!(db.list_objects_by_path_prefix("/").unwrap().len(), msgs.len());

    // After genesis a stranger cannot take a mode-object slot: a second
    // `/sys/names/sys` is an ordinary write into an occupied slot whose
    // controller the stranger does not hold (Genesis Spec §Genesis Detection,
    // conflict resolution).
    let stranger = sbo_core::crypto::SigningKey::generate();
    let jwt = sbo_core::jwt::create_self_signed_identity(&stranger, "sys", None).unwrap();
    let mut takeover = msgs[0].clone();
    takeover.signing_key = stranger.public_key();
    takeover.content_hash = Some(sbo_core::crypto::ContentHash::sha256(jwt.as_bytes()));
    takeover.payload = Some(jwt.into_bytes());
    takeover.sign(&stranger);
    let l2 = L2Context::for_block(Some(T_B), &db);
    assert!(matches!(validate_message(&takeover, &db, dir.path(), &l2), ValidationResult::Invalid { .. }));
}
