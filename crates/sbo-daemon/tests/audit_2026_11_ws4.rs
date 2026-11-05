//! Security audit 2026-11, WS4: layers never audited before (daemon
//! validation glue, mempool overlay, fast-sync trust, IPC, host).
//!
//! Every test here backs a verdict in
//! `docs/security-audit-2026-11-ws4-layers.md`. Tests that encode an
//! invariant which FAILS today are `#[ignore]`d with an
//! `// AUDIT-2026-11 <id>: fails today` comment; un-ignoring one is the
//! acceptance test for its fix. Everything else passes today and pins what
//! the audit re-verified. No production code was changed.
//!
//! Run the failing set: `cargo test -p sbo-daemon --test audit_2026_11_ws4 -- --ignored`.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::error::DbError;
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::policy::Policy;
use sbo_core::state::{PolicyEntry, StateDb, StoredObject};
use sbo_daemon::state_view::StateView;
use sbo_daemon::validate::{
    message_to_stored_object, resolve_creator, validate_message, L2Context, ValidationResult,
};
use tempfile::tempdir;

const T_B: i64 = 1_700_000_000; // inclusion time used by the timed contexts

fn ctx(db: &StateDb) -> L2Context {
    L2Context::for_block(Some(T_B), db)
}

fn is_valid(r: &ValidationResult) -> bool {
    matches!(r, ValidationResult::Valid { .. })
}

fn validate(db: &dyn StateView, msg: &Message, l2: &L2Context) -> ValidationResult {
    validate_message(msg, db, std::path::Path::new("/tmp"), l2)
}

/// Install a root policy (index + the `/sys/policies/root` object that takes the
/// daemon out of genesis mode).
fn put_root_policy(db: &StateDb, policy: serde_json::Value) {
    let policy: Policy = serde_json::from_value(policy).unwrap();
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &policy).unwrap();
    put_obj(db, "/sys/policies/", "root", "sys", Some("policy.v2"), b"{}");
}

fn put_obj(db: &StateDb, path: &str, id: &str, owner_ref: &str, schema: Option<&str>, payload: &[u8]) {
    db.put_object(&StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new(owner_ref).unwrap_or_else(|_| Id::new("sys").unwrap()),
        owner: Id::new(owner_ref).unwrap_or_else(|_| Id::new("sys").unwrap()),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(payload),
        payload: payload.to_vec(),
        policy_ref: None,
        related: None,
        content_schema: schema.map(|s| s.to_string()),
        owner_ref: Some(owner_ref.to_string()),
        block_number: 1,
        object_hash: [7u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
}

fn post(key: &SigningKey, path: &str, id: &str, payload: &[u8]) -> Message {
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature::parse(&"0".repeat(128)).unwrap(),
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(payload)),
        payload: Some(payload.to_vec()),
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

fn key_ref(key: &SigningKey) -> String {
    key.public_key().to_string()
}

// ───────────────────────────── D57 / Q13: owner fast-path ─────────────────────────────

/// AUDIT-2026-11 D57: fails today. `deny` is absolute ("no grants can override
/// a deny", Policy spec) yet the owner fast-path in `validate_post` never
/// evaluates the policy, so an owner updates an object under a denied path.
#[test]
#[ignore]
fn d57_owner_update_under_denied_path_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "deny": ["/locked/**"], "grants": [] }));
    let alice = SigningKey::generate();
    put_obj(&db, "/locked/", "x", &key_ref(&alice), None, b"{}");

    let r = validate(&db, &post(&alice, "/locked/", "x", b"{\"v\":2}"), &ctx(&db));
    assert!(!is_valid(&r), "owner update under a denied path must be invalid, got {r:?}");
}

/// AUDIT-2026-11 D57: fails today. `restrictions` (here `max_size`) are
/// skipped for the owner as well.
#[test]
#[ignore]
fn d57_owner_update_ignores_restrictions() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(
        &db,
        serde_json::json!({
            "grants": [{"to": "*", "can": ["create", "update"], "on": "/r/**"}],
            "restrictions": [{"on": "/r/**", "require": {"max_size": 1}}]
        }),
    );
    let alice = SigningKey::generate();
    put_obj(&db, "/r/", "x", &key_ref(&alice), None, b"{}");

    // Sanity (passes today): a non-owner is held to the restriction.
    let bob = SigningKey::generate();
    let r = validate(&db, &post(&bob, "/r/", "x", b"{\"big\":true}"), &ctx(&db));
    assert!(!is_valid(&r), "non-owner must hit max_size, got {r:?}");

    let r = validate(&db, &post(&alice, "/r/", "x", b"{\"big\":true}"), &ctx(&db));
    assert!(!is_valid(&r), "owner update must hit max_size too, got {r:?}");
}

/// AUDIT-2026-11 D57 / D25: fails today. The source path's policy is only
/// evaluated for non-owners, so an owner moves an object out of a path whose
/// policy denies everything (a "bridge lock" written as `deny`).
#[test]
#[ignore]
fn d57_owner_transfer_out_of_denied_path_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(
        &db,
        serde_json::json!({
            "deny": ["/locked/**"],
            "grants": [{"to": "*", "can": ["create"], "on": "/free/**"}]
        }),
    );
    let alice = SigningKey::generate();
    put_obj(&db, "/locked/", "x", &key_ref(&alice), None, b"{}");

    let mut msg = post(&alice, "/locked/", "x", b"{}");
    msg.action = Action::Transfer {
        new_owner: None,
        new_path: Some(Path::parse("/free/").unwrap()),
        new_id: None,
    };
    msg.sign(&alice);
    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "transfer out of a denied path must be invalid, got {r:?}");
}

// ───────────────────────────── D56 / Q14: name claims ─────────────────────────────

/// AUDIT-2026-11 D56: fails today. `/sys/names/` claims take a dedicated path
/// that never evaluates the root policy: a `deny` on `/sys/names/**` does not
/// stop a claim.
#[test]
#[ignore]
fn d56_name_claim_evaluates_root_policy() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "deny": ["/sys/names/**"], "grants": [] }));
    let bob = SigningKey::generate();
    let jwt = sbo_core::jwt::create_self_signed_identity(&bob, "bob", None).unwrap();
    let mut msg = post(&bob, "/sys/names/", "bob", jwt.as_bytes());
    msg.content_type = Some("application/jwt".into());
    msg.content_schema = Some("identity.v1".into());
    msg.sign(&bob);

    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "name claim under a denied path must be invalid, got {r:?}");
}

// ───────────────────────────── D12: Policy-Ref ─────────────────────────────

/// AUDIT-2026-11 D12: fails today. Core spec: `Policy-Ref` may be set only by
/// the object's creator. A non-creator with an `update` grant repoints it.
#[test]
#[ignore]
fn d12_policy_ref_is_not_changed_by_a_non_creator() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(
        &db,
        serde_json::json!({ "grants": [{"to": "*", "can": ["create", "update"], "on": "/shared/**"}] }),
    );
    let alice = SigningKey::generate();
    put_obj(&db, "/shared/", "doc", &key_ref(&alice), None, b"{}");

    let bob = SigningKey::generate();
    let mut msg = post(&bob, "/shared/", "doc", b"{\"v\":2}");
    msg.policy_ref = Some("/evil/policy".into());
    msg.sign(&bob);
    let l2 = ctx(&db);
    let r = validate(&db, &msg, &l2);
    if is_valid(&r) {
        let stored = message_to_stored_object(&msg, 2, Some(&db), [1u8; 32], &l2).unwrap();
        assert_eq!(stored.policy_ref, None, "non-creator update must not repoint Policy-Ref");
    }
}

// ───────────────────────────── D11 / D28: attestations ─────────────────────────────

fn ban_policy() -> serde_json::Value {
    serde_json::json!({
        "grants": [{"to": "*", "can": ["create", "update"], "on": "/posts/**"}],
        "restrictions": [{"on": "/posts/**", "require": {"not_attested": {"type": "ban"}}}]
    })
}

fn put_ban(db: &StateDb, subject: &str, issued_at: i64) {
    let payload = serde_json::json!({
        "subject": subject, "type": "ban", "value": true, "issued_at": issued_at
    });
    put_obj(
        db,
        "/u/mod/attestations/",
        "ban-1",
        "mod",
        Some("attestation.v1"),
        &serde_json::to_vec(&payload).unwrap(),
    );
}

/// A StateView whose attestation listing fails, as a RocksDB read error would.
struct FailingSchemaList<'a>(&'a StateDb);

impl StateView for FailingSchemaList<'_> {
    fn get_object(&self, p: &Path, i: &Id) -> Result<Option<StoredObject>, DbError> {
        self.0.get_object(p, i)
    }
    fn resolve_policy(&self, p: &Path) -> Result<Option<Policy>, DbError> {
        self.0.resolve_policy(p)
    }
    fn resolve_policy_entry(&self, p: &Path) -> Result<Option<PolicyEntry>, DbError> {
        self.0.resolve_policy_entry(p)
    }
    fn get_policy_version(&self, h: &str) -> Result<Option<Policy>, DbError> {
        self.0.get_policy_version(h)
    }
    fn list_objects_by_path_prefix(&self, p: &str) -> Result<Vec<StoredObject>, DbError> {
        self.0.list_objects_by_path_prefix(p)
    }
    fn list_objects_by_schema(&self, _s: &str) -> Result<Vec<StoredObject>, DbError> {
        Err(DbError::RocksDb("simulated read failure".into()))
    }
    fn get_name_for_pubkey(&self, k: &str) -> Result<Option<String>, DbError> {
        self.0.get_name_for_pubkey(k)
    }
}

/// Passes today: with a healthy state read, an in-force ban blocks the write.
#[test]
fn d11_ban_is_enforced_with_healthy_state() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, ban_policy());
    let banned = SigningKey::generate();
    put_ban(&db, &key_ref(&banned), 1);

    let r = validate(&db, &post(&banned, "/posts/", "p1", b"{}"), &ctx(&db));
    assert!(!is_valid(&r), "banned writer must be rejected, got {r:?}");
}

/// AUDIT-2026-11 D11: fails today. `attested_subject_matches` does
/// `list_objects_by_schema(..).unwrap_or_default()`, so a state-read error
/// makes `not_attested` treat a banned writer as un-banned.
#[test]
#[ignore]
fn d11_not_attested_fails_closed_on_state_read_error() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, ban_policy());
    let banned = SigningKey::generate();
    put_ban(&db, &key_ref(&banned), 1);

    let view = FailingSchemaList(&db);
    let l2 = L2Context::for_block(Some(T_B), &db);
    let r = validate(&view, &post(&banned, "/posts/", "p1", b"{}"), &l2);
    assert!(!is_valid(&r), "a state-read error must fail closed, got {r:?}");
}

/// AUDIT-2026-11 D28: fails today. With no block timestamp the attestation
/// clock is `t = 0`, so a ban issued at `t = 1` is "not yet in force" and the
/// banned writer is admitted; a node that has the timestamp rejects it (fork).
#[test]
#[ignore]
fn d28_unknown_inclusion_time_does_not_lift_a_ban() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, ban_policy());
    let banned = SigningKey::generate();
    put_ban(&db, &key_ref(&banned), 1);

    let l2 = L2Context::for_block(None, &db);
    let r = validate(&db, &post(&banned, "/posts/", "p1", b"{}"), &l2);
    assert!(!is_valid(&r), "unknown inclusion time must not lift a ban, got {r:?}");
}

/// AUDIT-2026-11 D28: fails today. With no block timestamp the HLC validity
/// bound is skipped entirely, so a write authored in 1970 is admitted.
#[test]
#[ignore]
fn d28_unknown_inclusion_time_does_not_skip_the_hlc_bound() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "grants": [{"to": "*", "can": ["create"], "on": "/posts/**"}] }));
    let k = SigningKey::generate();
    let mut msg = post(&k, "/posts/", "p1", b"{}");
    msg.hlc = Some("1000.0".into());
    msg.sign(&k);

    let l2 = L2Context::for_block(None, &db);
    let r = validate(&db, &msg, &l2);
    assert!(!is_valid(&r), "HLC far outside any bound must be invalid, got {r:?}");
}

// ───────────────────────────── D22 / Q9: W is unbounded ─────────────────────────────

fn w_policy() -> serde_json::Value {
    serde_json::json!({ "grants": [{"to": "*", "can": ["create"], "on": "/posts/**"}] })
}

/// Passes today: under the default `W` (5 min) a write authored an hour before
/// inclusion is rejected.
#[test]
fn d22_default_w_rejects_an_hour_old_authoring_instant() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, w_policy());
    let k = SigningKey::generate();
    let mut msg = post(&k, "/posts/", "p1", b"{}");
    msg.hlc = Some(format!("{}.0", (T_B - 3600) * 1000));
    msg.sign(&k);
    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "default W must reject, got {r:?}");
}

/// AUDIT-2026-11 D22: fails today. A collection `_config` sets `W` with no
/// protocol maximum, so whoever can write `_config` makes the bound vacuous: a
/// write authored 50 years before inclusion is admitted (and, for attributed
/// writes, presentation expiries are judged at that instant).
#[test]
#[ignore]
fn d22_collection_w_is_capped_by_a_protocol_maximum() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, w_policy());
    let cfg = serde_json::json!({ "max_authoring_lag_s": 3_153_600_000_i64 }); // 100 years
    put_obj(&db, "/posts/", "_config", "sys", Some("collection.v1"), &serde_json::to_vec(&cfg).unwrap());
    let k = SigningKey::generate();
    let mut msg = post(&k, "/posts/", "p1", b"{}");
    msg.hlc = Some(format!("{}.0", (T_B - 50 * 365 * 86_400) * 1000));
    msg.sign(&k);
    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "W beyond the protocol maximum must not admit, got {r:?}");
}

// ───────────────────────────── D23 / Q7: genesis mode ─────────────────────────────

/// AUDIT-2026-11 D23: fails today. A repo with no root policy accepts any write
/// from any key with no policy check at all (genesis mode), at the submit gate
/// and on replay. Q7 (strict genesis) makes only the genesis batch valid here.
#[test]
#[ignore]
fn d23_no_root_policy_rejects_ordinary_writes() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let k = SigningKey::generate();
    let r = validate(&db, &post(&k, "/anything/", "x", b"{}"), &ctx(&db));
    assert!(!is_valid(&r), "no root policy must mean no ordinary write is valid, got {r:?}");
}

// ───────────────────────────── Q6: bare-key owners (daemon side) ─────────────────────────────

/// AUDIT-2026-11 Q6: fails today. An explicit bare-key `Owner:` literal is
/// accepted as an identity (decision: reject; an identity is a name or an email).
#[test]
#[ignore]
fn q6_explicit_bare_key_owner_is_rejected() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "grants": [{"to": "*", "can": ["create"], "on": "/u/**"}] }));
    let k = SigningKey::generate();
    let mut msg = post(&k, "/u/", "x", b"{}");
    msg.owner = Some(Id::new(key_ref(&k)).unwrap());
    msg.sign(&k);
    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "bare-key Owner must be rejected, got {r:?}");
}

/// AUDIT-2026-11 Q6: fails today. With no `Owner`/`Creator` the signer key is
/// the owner (signer fallback). Decision: every post-genesis write names an
/// owner that is a name or an email.
#[test]
#[ignore]
fn q6_signer_fallback_owner_is_rejected_after_genesis() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "grants": [{"to": "*", "can": ["create"], "on": "/u/**"}] }));
    let k = SigningKey::generate();
    let r = validate(&db, &post(&k, "/u/", "x", b"{}"), &ctx(&db));
    assert!(!is_valid(&r), "owner-less write must be rejected after genesis, got {r:?}");
}

// ───────────────────────────── D16 / D55: creator fallback ─────────────────────────────

/// Passes today (pins the Low finding): an unnamed, unattributed signer gets a
/// durable creator id made of 64 bits of its key.
#[test]
fn d16_unnamed_signer_creator_is_a_truncated_key() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let k = SigningKey::generate();
    let msg = post(&k, "/x/", "y", b"{}");
    let creator = resolve_creator(&msg, Some(&db), &ctx(&db));
    let hex = key_ref(&k).trim_start_matches("ed25519:").to_string();
    assert_eq!(creator.as_str(), format!("e_{}", &hex[..16]));
}

// ───────────────────────────── D17: overlay vs reconcile ─────────────────────────────

fn hlc_less(path: &str, id: &str, hash: u8) -> StoredObject {
    StoredObject {
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        creator: Id::new("a").unwrap(),
        owner: Id::new("a").unwrap(),
        content_type: "application/json".into(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        related: None,
        content_schema: None,
        owner_ref: None,
        block_number: 1,
        object_hash: [hash; 32],
        hlc: None,
        prev: None,
    }
}

/// Passes today (documents D17): for an HLC-less pair the read merge says the
/// pending value wins, while reconciliation on confirmation drops it. The two
/// rules disagree only until the confirming write lands, after which reads
/// converge on the confirmed value — so this is a tip-visibility wobble, not a
/// state divergence.
#[test]
fn d17_overlay_and_reconcile_disagree_on_missing_hlc() {
    let pending = hlc_less("/p/", "x", 1);
    let confirmed = hlc_less("/p/", "x", 2);
    assert!(sbo_daemon::pending::overlay_wins(&pending, &confirmed));
    let mut pool = sbo_daemon::pending::PendingPool::new();
    pool.insert(pending.clone(), [1u8; 32], 0);
    pool.reconcile_applied(&confirmed);
    assert!(pool.object_at(&pending.path, &pending.id).is_none(), "reconcile drops the HLC-less pending value");
}

// ───────────────────────────── D26 / D27 / D34 / D15: fast-sync trust ─────────────────────────────

/// AUDIT-2026-11 D26: fails today. `evaluate_trust` under the default policy
/// counts the checkpoint authority as a backer of ANY root at ANY height with
/// no signed `checkpoint.v1` ever read, so a serving node's forged manifest
/// root is "trusted" with one backer.
#[test]
#[ignore]
fn d26_authority_does_not_back_a_root_without_a_signed_checkpoint() {
    use sbo_daemon::bootstrap::{evaluate_trust, TrustPolicy};
    let forged = "ff".repeat(32);
    assert_eq!(
        evaluate_trust(&TrustPolicy::default(), 12345, &forged, &[]),
        None,
        "no signed checkpoint was observed; the authority must not count"
    );
}

/// AUDIT-2026-11 D27: fails today. Snapshot `policy_versions` are loaded as
/// given, outside the trie-root check and without checking that the key is the
/// policy's content hash. A forged pinned version rewrites frozen governance.
#[test]
#[ignore]
fn d27_snapshot_policy_versions_are_verified_against_their_hash() {
    use sbo_daemon::bootstrap::verify_and_load_payload;
    use sbo_daemon::snapshot::{compute_snapshot_root, SnapshotPayload};
    let src = tempdir().unwrap();
    let src_db = StateDb::open(src.path()).unwrap();
    put_obj(&src_db, "/c/", "o", "a", None, b"{}");
    let objects = src_db.list_objects_by_path_prefix("/").unwrap();
    let root = compute_snapshot_root(&objects);

    let forged: Policy = serde_json::from_value(serde_json::json!({
        "grants": [{"to": "*", "can": ["*"], "on": "/**"}]
    }))
    .unwrap();
    let payload = SnapshotPayload { objects, policy_versions: vec![("sha256:not-the-hash".into(), forged)] };

    let dst = tempdir().unwrap();
    let dst_db = StateDb::open(dst.path()).unwrap();
    let res = verify_and_load_payload(&dst_db, &payload, root);
    let loaded = dst_db.get_policy_version("sha256:not-the-hash").unwrap();
    assert!(res.is_err() || loaded.is_none(), "a policy version whose key is not its content hash must not load");
}

/// Passes today (pins D34, Low): the legacy bootstrap names the authority by
/// the string `sys-checkpointer`, while the trustless gate pins public keys and
/// rejects that string, so the two trust models cannot share a config value.
#[test]
fn d34_legacy_authority_name_is_not_a_pinnable_key() {
    assert_eq!(sbo_daemon::bootstrap::SYS_AUTHORITY, "sys-checkpointer");
    assert!(sbo_daemon::trust::TrustPolicy::from_config(&["sys-checkpointer".to_string()], 1).is_err());
}

/// Passes today (pins D15, Low): an enforcing anchor with no observed claims
/// stays gated; the only exit is the config `timeout_blocks`, which stops sync
/// and keeps reads refused (no degrade path).
#[test]
fn d15_enforcing_gate_stays_gated_without_claims() {
    use sbo_daemon::trust::{PendingAnchor, TrustGate};
    let dir = tempdir().unwrap();
    let k = SigningKey::generate();
    let anchor = PendingAnchor {
        block: 10,
        state_root: "aa".repeat(32),
        attestors: vec![k.public_key().to_string()],
        threshold: 1,
    };
    let gate = TrustGate::with_anchor(dir.path().to_path_buf(), anchor).unwrap();
    assert!(gate.is_gated());
}

// ───────────────────────────── D20: IPC socket mode ─────────────────────────────

/// AUDIT-2026-11 D20 (Q22 a): the IPC socket is chmod 0600 right after the
/// bind (it used to inherit the process umask, typically 0755), so only the
/// daemon's own uid can issue commands (`RepoAdd` to any directory,
/// `Shutdown`, `Submit`).
#[tokio::test]
async fn d20_ipc_socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let server = sbo_daemon::ipc::IpcServer::new(sock.clone());
    let task = tokio::spawn(async move {
        let _ = server.run(|_req| async { sbo_daemon::ipc::Response::error("n/a") }).await;
    });
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    task.abort();
    assert_eq!(mode, 0o600, "IPC socket mode is {mode:o}, expected 0600");
}

// ───────────────────────────── D7: domain self-cert ─────────────────────────────

/// AUDIT-2026-11 D7: fails today. Identity spec Rule 4: a `domain.v1` whose
/// self-certification evidence is present but does not verify MUST be
/// rejected. Validation never looks at it (the sync path only logs a warning),
/// so the write is valid.
#[test]
#[ignore]
fn d7_domain_with_failing_self_cert_is_invalid() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    put_root_policy(&db, serde_json::json!({ "grants": [{"to": "*", "can": ["create"], "on": "/sys/domains/**"}] }));
    // Evidence object present, but garbage: the self-cert cannot verify.
    put_obj(&db, "/sys/dnssec/", "example.com", "sys", Some("dnssec.v1"), b"not-a-proof");

    let k = SigningKey::generate();
    let jwt = sbo_core::jwt::create_domain(&k, "example.com").unwrap();
    let mut msg = post(&k, "/sys/domains/", "example.com", jwt.as_bytes());
    msg.content_type = Some("application/jwt".into());
    msg.content_schema = Some("domain.v1".into());
    msg.auth_evidence = Some("ref:/sys/dnssec/example.com".into());
    msg.sign(&k);

    let r = validate(&db, &msg, &ctx(&db));
    assert!(!is_valid(&r), "domain.v1 with failing self-cert must be invalid, got {r:?}");
}

/// Passes today: `verify_genesis` does report a mismatch; the finding (D7
/// second half) is that `main.rs` only logs the `Err` and keeps syncing.
#[test]
fn d7_genesis_mismatch_is_reported_by_verify_genesis() {
    use sbo_daemon::repo::Repo;
    let uri = sbo_core::uri::SboRawUri::parse("sbo+raw://avail:turing:9@1/").unwrap();
    let mut repo = Repo::new("sbo+raw://avail:turing:9/".into(), uri, dir_path(), None);
    repo.expected_genesis = Some("sha256:deadbeef".into());
    let k = SigningKey::generate();
    let wire = sbo_core::wire::serialize(&post(&k, "/sys/test/", "a", b"{}"));
    assert!(repo.verify_genesis(&wire).unwrap_err().contains("mismatch"));
}

fn dir_path() -> std::path::PathBuf {
    std::env::temp_dir().join("sbo-audit-ws4-repo")
}
