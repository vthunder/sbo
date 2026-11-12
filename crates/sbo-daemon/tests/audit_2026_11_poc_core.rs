//! Security audit 2026-11, WS8 — working PoCs for the post-verification
//! High/Critical findings, demonstrated against in-process harnesses only.
//!
//! No production host, no Avail, no TurboDA, no real keys: every test builds
//! its own `StateDb` in a tempdir, drives `validate_message` / the mirror-write
//! path / `bootstrap` against loopback, and mocks any DA submitter. Each PoC is
//! `#[ignore]`d with an `// AUDIT-2026-11 <id> PoC` tag so it does not run in
//! CI; run the set with
//! `cargo test -p sbo-daemon --test audit_2026_11_poc_core -- --ignored`.
//!
//! These back `docs/security-audit-2026-11-ws8-pocs.md`. Where the fix lands,
//! the matching WS4/WS5/WS6 `#[ignore]`d acceptance test flips to green; these
//! PoCs document the *impact* that is live today, so they assert the broken
//! behaviour (and will need updating when the fix inverts it — intentional, so
//! a reader is never left with a green PoC of a closed hole).

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::state::StateDb;
use sbo_daemon::validate::{validate_message, L2Context, ValidationResult};
use sbo_core::state::StoredObject;
use tempfile::tempdir;

const T_B: i64 = 1_700_000_000;

fn ctx(db: &StateDb) -> L2Context {
    L2Context::for_block(Some(T_B), db)
}

fn is_valid(r: &ValidationResult) -> bool {
    matches!(r, ValidationResult::Valid { .. })
}

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
        owner: Some(Id::new(&q6_name_for(key)).unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: schema.map(|s| s.to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None, extra_headers: Vec::new(),
    };
    msg.sign(key);
    msg
}

/// A deterministic local name for a test key: every write names an owner that
/// is a name or an email (audit 2026-11 Q6, no signer-key fallback).
fn q6_name_for(key: &SigningKey) -> String {
    let pk = key.public_key().to_string();
    format!("n{}", &pk.trim_start_matches("ed25519:")[..12])
}

/// Register the key-rooted `identity.v1` record `q6_name_for(key)` resolves to.
fn q6_register(db: &StateDb, key: &SigningKey) {
    let name = q6_name_for(key);
    let jwt = sbo_core::jwt::create_self_signed_identity(key, &name, None).unwrap();
    db.put_object(&StoredObject {
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new(&name).unwrap(),
        creator: Id::new(&name).unwrap(),
        owner: Id::new(&name).unwrap(),
        content_type: "application/jwt".to_string(),
        content_hash: ContentHash::sha256(jwt.as_bytes()),
        payload: jwt.into_bytes(),
        policy_ref: None,
        related: None,
        content_schema: Some("identity.v1".to_string()),
        owner_ref: Some(name.clone()),
        block_number: 1,
        object_hash: [6u8; 32],
        hlc: None,
        prev: None,
    })
    .unwrap();
    db.put_name_claim(&key.public_key().to_string(), &name).unwrap();
}

// ===========================================================================
// PoC-1 (D1, Critical): payload swap on a signature-valid envelope, and the
// P2 pin confusion that keys a stored policy version by the *claimed* hash.
// ===========================================================================

/// The write is signed over the header block only; `Content-Hash` is never
/// recomputed. A relay swaps the payload for equal-length bytes and the daemon
/// still accepts it as authored by the victim. Impact measured: a 12-byte JSON
/// body `{"amount":1}` becomes `{"amount":9}` under an untouched signature.
/// Inverted after the fix (sbo-xd6u): the swap is rejected at the daemon gate
/// and at the parser.
#[test]
fn poc_d1_payload_swap_is_rejected_by_the_daemon_gate() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let victim = SigningKey::generate();
    q6_register(&db, &victim);

    // Victim signs {"amount":1}. A relay keeps the headers (and signature) and
    // substitutes the payload — same length, so Content-Length still matches.
    let mut msg = signed(&victim, "/audit/", "invoice", None, br#"{"amount":1}"#);
    msg.payload = Some(br#"{"amount":9}"#.to_vec());

    // The envelope signature still verifies (it never covered the payload) —
    // the payload is bound only through Content-Hash.
    assert!(
        sbo_core::message::verify_message(&msg).is_ok(),
        "precondition: the envelope signature is still valid after the swap",
    );

    // The daemon's full validation rejects it.
    let r = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(!is_valid(&r), "the daemon accepted a swapped payload: {r:?}");
    // And so does the parser, before any state check.
    let bytes = sbo_core::wire::serialize(&msg);
    assert!(matches!(
        sbo_core::wire::parse(&bytes),
        Err(sbo_core::error::ParseError::ContentHashMismatch)
    ));
}

/// P2 pin confusion: a child policy pins an ancestor by `{ancestor, hash}`.
/// The daemon indexes a policy version under the *header* `Content-Hash`, which
/// D1 lets a writer choose independently of the body. So a hostile policy body
/// can be filed under the benign hash a child pinned. This PoC shows the two
/// ingredients compose: a policy message whose header hash does not match its
/// body is accepted (D1), and the index keys on the header hash.
/// Inverted after the fix (sbo-xd6u): a policy whose header hash does not
/// match its body is rejected by the parser and by the daemon gate, and the
/// policy index keys versions by the hash of the body (sync.rs), so no child
/// pin can resolve to a body other than the one hashed.
#[test]
fn poc_d1_policy_version_with_a_mismatched_hash_is_rejected() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let sys = SigningKey::generate();
    q6_register(&db, &sys);

    let benign = br#"{"grants":[{"to":"owner","can":["update"],"on":"/c/**"}]}"#;
    let benign_hash = ContentHash::sha256(benign).to_string();

    // A policy write whose BODY grants everyone everything, but whose header
    // Content-Hash is the benign policy's hash (the value a child pin trusts).
    let hostile_body = br#"{"grants":[{"to":"*","can":["*"],"on":"/**"}]}"#;
    let mut msg = signed(&sys, "/c/", "root", Some("policy.v2"), hostile_body);
    msg.content_hash = Some(ContentHash::parse(&benign_hash).unwrap());
    msg.sign(&sys);
    assert_ne!(
        ContentHash::sha256(hostile_body).to_string(),
        benign_hash,
        "sanity: the hostile body does not actually hash to the benign hash",
    );

    let bytes = sbo_core::wire::serialize(&msg);
    assert!(matches!(
        sbo_core::wire::parse(&bytes),
        Err(sbo_core::error::ParseError::ContentHashMismatch)
    ));
    let r = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(!is_valid(&r), "the daemon accepted a policy whose header hash != body hash: {r:?}");
}

// ===========================================================================
// PoC-2 (D5/D23, Critical): with no root policy the daemon accepts every write
// and every policy write from any key (genesis mode = accept-all).
// ===========================================================================

/// Inverted by sbo-3q6x (Q7 (a)): a node pointed at a repo whose root policy
/// has not arrived (a forged seed, a wrong anchor, or simply before genesis
/// replays) applies NOTHING — not a stranger's root policy, not a stranger's
/// write. The bootstrap window is the genesis prefix at the anchor, applied
/// structurally by the sync path, never through `validate_message`.
#[test]
fn poc_d5_stranger_takes_over_a_rootless_repo() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let mallory = SigningKey::generate();
    q6_register(&db, &mallory);

    // 1. A stranger's root policy granting themselves everything is refused.
    let planted = br#"{"grants":[{"to":"*","can":["*"],"on":"/**"}]}"#;
    let policy = signed(&mallory, "/sys/policies/", "root", Some("policy.v2"), planted);
    assert!(
        !is_valid(&validate_message(&policy, &db, dir.path(), &ctx(&db))),
        "a stranger's root policy was accepted on an empty repo",
    );

    // 2. And an ordinary stranger write is refused too.
    let post = signed(&mallory, "/communities/cooks/posts/", "hello", None, b"{}");
    assert!(
        !is_valid(&validate_message(&post, &db, dir.path(), &ctx(&db))),
        "a stranger post was accepted on an empty repo",
    );
}

// ===========================================================================
// PoC-3 (D7, High): a domain.v1 whose DNSSEC self-cert evidence is present but
// does not verify is accepted (validation never reads it), so it can go on to
// certify `sys` — a forged trust root.
// ===========================================================================

#[test] // AUDIT-2026-11 D7: inverted by `sbo-c46r`; the failing self-cert is now rejected
fn poc_d7_failing_self_cert_domain_is_rejected() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    // Permit domain creation so we isolate the self-cert gap, not policy. The
    // root is installed directly in state: there is no genesis mode through
    // which a write could plant it (sbo-3q6x).
    let sys = SigningKey::generate();
    q6_register(&db, &sys);
    let planted =
        br#"{"grants":[{"to":"*","can":["create","update"],"on":"/sys/**"}]}"#;
    db.put_policy(&Path::parse("/sys/policies/").unwrap(), &serde_json::from_slice(planted).unwrap()).unwrap();
    let pol = signed(&sys, "/sys/policies/", "root", Some("policy.v2"), planted);
    let stored = sbo_daemon::validate::message_to_stored_object(&pol, 1, Some(&db), [1u8; 32], &ctx(&db)).unwrap();
    db.put_object(&stored).unwrap();

    // Evidence object present but garbage: the self-cert cannot verify. (Planted
    // directly in state: the write gate itself would refuse the garbage proof.)
    let ev = signed(&sys, "/sys/dnssec/", "evil.example", Some("dnssec.v1"), b"not-a-proof");
    let stored = sbo_daemon::validate::message_to_stored_object(&ev, 1, Some(&db), [7u8; 32], &ctx(&db)).unwrap();
    db.put_object(&stored).unwrap();

    let attacker = SigningKey::generate();
    q6_register(&db, &attacker);
    let jwt = sbo_core::jwt::create_domain(&attacker, "evil.example").unwrap();
    let mut dom = signed(&attacker, "/sys/domains/", "evil.example", Some("domain.v1"), jwt.as_bytes());
    dom.content_type = Some("application/jwt".into());
    dom.auth_evidence = Some("ref:/sys/dnssec/evil.example".into());
    dom.sign(&attacker);

    let r = validate_message(&dom, &db, dir.path(), &ctx(&db));
    assert!(
        !is_valid(&r),
        "D7 REGRESSION — the domain with failing self-cert was accepted: {r:?}",
    );
}

// ===========================================================================
// PoC-4 (D21, High) — INVERTED after the fix (Q24, sbo-vu8s): an on-chain
// `Path: /../` used to escape the filesystem mirror because the grammar
// admitted dot segments and the mirror join was verbatim. Now the grammar
// rejects `.` / `..` at parse, and the mirror layout (`sbo_daemon::mirror`)
// keeps every write under the repo root.
// ===========================================================================

#[test]
fn poc_d21_path_dotdot_escapes_the_mirror() {
    // The grammar rejects the hostile path and ids (the root cause is gone).
    assert!(Path::parse("/../../").is_err(), "grammar must reject /../");
    assert!(Path::parse("/a/../").is_err());
    assert!(Path::parse("/./").is_err());
    assert!(Id::new("..").is_err());
    assert!(Id::new(".").is_err());
    assert!(Id::new("pwned").is_ok());

    // Every mirror path the daemon can compute from grammar-valid input stays
    // inside the repo root.
    let root = tempdir().unwrap();
    let repo_mirror = root.path().join("repo");
    std::fs::create_dir_all(&repo_mirror).unwrap();
    for (p, id) in [("/", "...x"), ("/a/", "..a"), ("/x.d/", "y"), ("/u/alice@example.com/", "n1")] {
        let path = Path::parse(p).unwrap();
        let file = sbo_daemon::mirror::write_object(&repo_mirror, &path, id, b"ok").unwrap();
        let canon = file.canonicalize().unwrap();
        assert!(canon.starts_with(repo_mirror.canonicalize().unwrap()), "{p}{id} escaped: {canon:?}");
    }
}

/// D58 companion — INVERTED after the fix: an object `/c/x` and a collection
/// `/c/x/` no longer claim one filesystem entry (collections live in `<seg>.d/`
/// directories), so a nested write after an object write succeeds, and the
/// mirror is best-effort anyway (a failure logs; `process_block` goes on).
#[test]
fn poc_d58_id_collection_collision_blocks_the_mirror() {
    let root = tempdir().unwrap();
    let mirror = root.path().join("repo");
    let c = Path::parse("/c/").unwrap();
    let cx = Path::parse("/c/x/").unwrap();
    // Object /c/x — a file; then object /c/x/y — needs a collection dir for x.
    sbo_daemon::mirror::write_object(&mirror, &c, "x", b"obj").unwrap();
    sbo_daemon::mirror::write_object(&mirror, &cx, "y", b"nested").unwrap();
    // And an object literally named `x.d` next to the `x.d/` collection dir.
    sbo_daemon::mirror::write_object(&mirror, &c, "x.d", b"dotd").unwrap();
    assert_eq!(std::fs::read(sbo_daemon::mirror::object_file(&mirror, &c, "x")).unwrap(), b"obj");
    assert_eq!(std::fs::read(sbo_daemon::mirror::object_file(&mirror, &cx, "y")).unwrap(), b"nested");
    assert_eq!(std::fs::read(sbo_daemon::mirror::object_file(&mirror, &c, "x.d")).unwrap(), b"dotd");
    // `a.b` and `a.tmp` no longer share a temp file.
    assert_ne!(
        sbo_daemon::mirror::temp_file(&sbo_daemon::mirror::object_file(&mirror, &c, "a.b")),
        sbo_daemon::mirror::temp_file(&sbo_daemon::mirror::object_file(&mirror, &c, "a.tmp")),
    );
}

// ===========================================================================
// PoC-5 (D10, High): a cyclic-role policy used to crash every evaluator.
// INVERTED under `sbo-sla3`: the cyclic document is rejected at parse, and a
// cyclic policy built in code evaluates to a denial in bounded time. Still run
// in a child process so a regression (stack overflow) cannot take the test
// runner with it.
// ===========================================================================

#[test]
fn poc_d10_role_cycle_crashes_the_evaluator() {
    // Re-exec this test binary targeting the inner helper; it must exit cleanly.
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--ignored", "--exact", "poc_d10_inner_evaluate_cycle"])
        .env("SBO_POC_D10_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "evaluating a cyclic-role policy crashed the child ({}); stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Inner helper: only runs its body in the re-exec'd child. The cyclic document
/// (a → b → a) must fail to parse; the same policy built in code must evaluate
/// to a denial without overflowing. Not a standalone finding; the parent drives it.
#[test]
#[ignore]
fn poc_d10_inner_evaluate_cycle() {
    if std::env::var("SBO_POC_D10_CHILD").is_err() {
        return; // only the re-exec'd child runs the body
    }
    use sbo_core::policy::{evaluate, ActionType, Grant, Identity, PathPattern, Policy, PolicyResult, PolicyVars};
    let parsed = serde_json::from_str::<Policy>(
        r#"{"roles":{"a":[{"role":"b"}],"b":[{"role":"a"}]},
            "grants":[{"to":{"role":"a"},"can":["post"],"on":"/x/**"}]}"#,
    );
    assert!(parsed.is_err(), "a cyclic-role policy parsed");
    let policy = Policy {
        roles: [
            ("a".to_string(), vec![Identity::Role { role: "b".into() }]),
            ("b".to_string(), vec![Identity::Role { role: "a".into() }]),
        ]
        .into_iter()
        .collect(),
        deny: vec![],
        grants: vec![Grant {
            to: Identity::Role { role: "a".into() },
            can: vec![ActionType::Post],
            on: PathPattern::new("/x/**"),
            id: None,
        }],
        restrictions: vec![],
        pin: None,
        descendant_constraint: None,
    };
    let key = SigningKey::generate();
    let msg = signed(&key, "/x/", "p", None, b"{}");
    let actor = Id::new("mallory").unwrap();
    let r = evaluate(
        &policy,
        &actor,
        ActionType::Create,
        "/x/",
        &PolicyVars::default(),
        false,
        &|_| false,
        &msg,
        None,
    );
    assert!(matches!(r, PolicyResult::Denied(_)), "nobody is a member of a cyclic role: {r:?}");
}
