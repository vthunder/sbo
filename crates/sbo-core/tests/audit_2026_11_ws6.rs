//! Security audit 2026-11, WS6 (crypto core and verification), sbo-core side.
//!
//! Tests tagged `AUDIT-2026-11 <id>: fails today` are `#[ignore]`d; un-ignoring
//! them is the acceptance criterion for the fix. Everything else passes today and
//! pins what the audit re-verified. Run the failing set with
//! `cargo test -p sbo-core --test audit_2026_11_ws6 -- --ignored`.
//!
//! No production code is changed by this file. Fake keys only; no network.

use sbo_core::crypto::{ContentHash, PublicKey, Signature, SigningKey};
use sbo_core::message::{verify_message, Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

const LIVE_GENESIS: &[u8] = include_bytes!("fixtures/mingo-genesis-v5.wire");
/// `~/src/mingo/deploy/GENESIS.md`, "v5 canonical identity".
const LIVE_GENESIS_HASH: &str =
    "sha256:ca27c61143c18786fc9ffee4fee25b458e7881390601e2ab55e0d9df9dc585bc";

fn signed(key: &SigningKey, payload: &[u8]) -> Message {
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/audit/").unwrap(),
        id: Id::new("obj").unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
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
        extra_headers: Vec::new(),
    };
    msg.sign(key);
    msg
}

/// Parse then verify: what the daemon does with chain bytes.
fn accepts(bytes: &[u8]) -> bool {
    match wire::parse(bytes) {
        Ok(msg) => verify_message(&msg).is_ok(),
        Err(_) => false,
    }
}

fn replace_line(wire_bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let s = String::from_utf8(wire_bytes.to_vec()).unwrap();
    assert!(s.contains(from), "wire does not contain {from:?}");
    s.replacen(from, to, 1).into_bytes()
}

// ---------------------------------------------------------------------------
// D1: Content-Hash binds nothing (July sbo-d5nm)
// ---------------------------------------------------------------------------

/// The payload is bound to the signed headers only through `Content-Hash`.
/// Swapping the payload for other bytes of the same length must be rejected,
/// at parse or at verification.
#[test]
fn d1_payload_swap_on_a_signature_valid_envelope_is_rejected() {
    let key = SigningKey::generate();
    let msg = signed(&key, br#"{"amount":1}"#);
    let mut bytes = wire::serialize(&msg);
    let swapped = br#"{"amount":9}"#;
    let n = bytes.len();
    bytes[n - swapped.len()..].copy_from_slice(swapped);
    assert!(
        !accepts(&bytes),
        "a payload that does not hash to Content-Hash was accepted"
    );
}

/// Wire Format spec: a `Type: object` message with a payload carries the
/// content headers; the hash is REQUIRED when a payload is present.
#[test]
fn d1_payload_without_content_hash_is_rejected() {
    let key = SigningKey::generate();
    let mut msg = signed(&key, b"{}");
    msg.content_hash = None;
    msg.sign(&key);
    let bytes = wire::serialize(&msg);
    assert!(!accepts(&bytes), "payload with no Content-Hash header was accepted");
}

// ---------------------------------------------------------------------------
// D2: the signature verifies a reconstruction (July sbo-h75z)
// ---------------------------------------------------------------------------

#[test]
fn d2_non_canonical_header_order_is_rejected() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    let s = String::from_utf8(bytes).unwrap();
    // Swap the Path and ID lines.
    let reordered = s
        .replacen("Path: /audit/\nID: obj\n", "ID: obj\nPath: /audit/\n", 1)
        .into_bytes();
    assert!(!accepts(&reordered), "non-canonical header order was accepted");
}

/// Two `Path` lines: the HashMap parse keeps the last one, so the signer's
/// `/audit/` verifies while a first-wins parser reads `/evil/`.
#[test]
fn d2_duplicate_header_is_rejected() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    let dup = replace_line(&bytes, "Path: /audit/\n", "Path: /evil/\nPath: /audit/\n");
    assert!(!accepts(&dup), "duplicate Path header was accepted (last wins)");
}

/// Encoding rules: `Content-Length` is a canonical decimal integer.
#[test]
fn d2_non_canonical_content_length_is_rejected() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    for bad in ["+2", "002"] {
        let b = replace_line(&bytes, "Content-Length: 2\n", &format!("Content-Length: {bad}\n"));
        assert!(!accepts(&b), "Content-Length: {bad} was accepted");
    }
}

/// Encoding rules: hex is lowercase. Uppercase hex re-serializes to lowercase,
/// so the signature still verifies while the raw bytes differ.
#[test]
fn d2_uppercase_hex_is_rejected() {
    let key = SigningKey::generate();
    let msg = signed(&key, b"{}");
    let bytes = wire::serialize(&msg);
    let pk = key.public_key().to_string(); // ed25519:<hex>
    let pk_upper = format!("ed25519:{}", pk["ed25519:".len()..].to_uppercase());
    let b = replace_line(&bytes, &format!("Public-Key: {pk}\n"), &format!("Public-Key: {pk_upper}\n"));
    assert!(!accepts(&b), "uppercase Public-Key hex was accepted");

    let sig = msg.signature.to_hex();
    let b = replace_line(&bytes, &format!("Signature: {sig}\n"), &format!("Signature: {}\n", sig.to_uppercase()));
    assert!(!accepts(&b), "uppercase Signature hex was accepted");
}

/// A relay appends a header the parser does not model. Under Q32 (c) the
/// signature covers the received header block, so an unknown header is valid
/// only if the signer put it there; one injected on the path fails to verify.
#[test]
fn d2_unsigned_unknown_header_is_rejected() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    let b = replace_line(&bytes, "Public-Key: ", "X-Relay: injected\nPublic-Key: ");
    assert!(!accepts(&b), "an unsigned unknown header was accepted");
}

/// Mirror of the previous test for the daemon's `object_hash` input: for every
/// accepted message the received bytes must equal the canonical serialization,
/// otherwise `sha256(raw)` (spec) and `sha256(serialize(parse(raw)))` (code)
/// disagree across implementations.
#[test]
fn d3_every_accepted_message_is_canonical() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    let variants = [
        replace_line(&bytes, "Public-Key: ", "X-Relay: injected\nPublic-Key: "),
        replace_line(&bytes, "Content-Length: 2\n", "Content-Length: 02\n"),
    ];
    for v in variants {
        if let Ok(msg) = wire::parse(&v) {
            if verify_message(&msg).is_ok() {
                assert_eq!(
                    wire::serialize(&msg),
                    v,
                    "accepted message is not canonical: raw-bytes and reserialized object_hash differ"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// D2 / I7: strict Ed25519 verification
// ---------------------------------------------------------------------------

/// The identity point as a public key with an all-zero S and R = identity
/// satisfies `[S]B = R + [k]A` for every message. Non-strict verification
/// accepts it; `verify_strict` rejects small-order keys.
#[test]
fn w6_1_small_order_public_key_universal_signature_is_rejected() {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = 1; // the identity point, compressed
    let mut sig = [0u8; 64];
    sig[0] = 1; // R = identity, S = 0
    let pk = PublicKey { bytes: pk_bytes };
    let r = sbo_core::crypto::verify(&pk, b"anything at all", &Signature(sig));
    assert!(r.is_err(), "sbo-core wrapper accepted a universal forgery under a small-order key");

    let pk2 = sbo_core::ed25519_new::PublicKey { bytes: pk_bytes };
    let r2 = sbo_core::ed25519_new::verify(&pk2, b"anything at all", &sbo_core::ed25519_new::Signature(sig));
    assert!(r2.is_err(), "sbo-crypto wrapper accepted a universal forgery under a small-order key");
}

/// Both wrappers must agree on a non-canonical S (S + L). ed25519-dalek 2.x
/// rejects it; this pins that neither wrapper re-admits it.
#[test]
fn i7_non_canonical_scalar_is_rejected_by_both_wrappers() {
    let key = SigningKey::generate();
    let m = b"msg";
    let good = key.sign(m);
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut bad = good.0;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = bad[32 + i] as u16 + l[i] as u16 + carry;
        bad[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert!(sbo_core::crypto::verify(&key.public_key(), m, &good).is_ok());
    let a = sbo_core::crypto::verify(&key.public_key(), m, &Signature(bad)).is_err();
    let pk2 = sbo_core::ed25519_new::PublicKey { bytes: key.public_key().bytes };
    let b = sbo_core::ed25519_new::verify(&pk2, m, &sbo_core::ed25519_new::Signature(bad)).is_err();
    assert!(a && b, "S+L accepted (core rejects: {a}, crypto rejects: {b})");
}

#[test]
fn key_and_signature_lengths_and_algorithms_are_pinned() {
    for bad in ["ed25519:", &format!("ed25519:{}", "ab".repeat(31)), &format!("ed25519:{}", "ab".repeat(33)), &format!("bls12-381:{}", "ab".repeat(32)), &format!("ed25519:{}", "zz".repeat(32))] {
        assert!(PublicKey::parse(bad).is_err(), "accepted key {bad}");
        assert!(sbo_core::ed25519_new::PublicKey::parse(bad).is_err(), "sbo-crypto accepted key {bad}");
    }
    for bad in ["", &"ab".repeat(63), &"ab".repeat(65), &"zz".repeat(64)] {
        assert!(Signature::parse(bad).is_err());
        assert!(sbo_core::ed25519_new::Signature::parse(bad).is_err());
    }
    assert!(ContentHash::parse(&format!("keccak256:{}", "ab".repeat(32))).is_err());
    assert!(ContentHash::parse(&format!("sha256:{}", "ab".repeat(31))).is_err());
}

#[test]
fn signature_covers_every_modelled_header() {
    let key = SigningKey::generate();
    let msg = signed(&key, b"{}");
    assert!(verify_message(&msg).is_ok());
    let bytes = wire::serialize(&msg);
    for (from, to) in [
        ("Path: /audit/\n", "Path: /other/\n"),
        ("ID: obj\n", "ID: other\n"),
        ("Action: post\n", "Action: delete\n"),
        ("Type: object\n", "Type: collection\n"),
    ] {
        let b = replace_line(&bytes, from, to);
        assert!(!accepts(&b), "tampered {from:?} still verified");
    }
    // A listed header the Message does not model (`Origin`), covered by the
    // signer in its canonical slot: under Q32 (c) the parser keeps it in place
    // and the received block verifies (it used to be dropped at parse and the
    // message rejected; changed by sbo-zom8). Unsigned, it still rejects.
    let mut with_origin = msg.clone();
    with_origin.signature = Signature([0u8; 64]);
    let mut content = with_origin.canonical_signing_content();
    let marker = b"Public-Key: ";
    let at = content.windows(marker.len()).position(|w| w == marker).unwrap();
    content.splice(at..at, b"Origin: x\n".iter().copied());
    with_origin.signature = key.sign(&content);
    let b = replace_line(&wire::serialize(&with_origin), "Public-Key: ", "Origin: x\nPublic-Key: ");
    assert!(accepts(&b), "a signed, listed-but-unmodelled header must verify");
    let parsed = wire::parse(&b).unwrap();
    assert_eq!(parsed.extra_headers, vec![("Origin".to_string(), "x".to_string())]);
    assert_eq!(wire::serialize(&parsed), b, "bytes in, bytes out");
    let unsigned = replace_line(&bytes, "Public-Key: ", "Origin: x\nPublic-Key: ");
    assert!(!accepts(&unsigned));
}

/// Q32 (c): a `Critical` header names headers a consumer must understand. One
/// naming a header this implementation does not model rejects at parse; one
/// naming only modelled headers is carried like any extension header.
#[test]
fn critical_header_rejects_unknown_names_and_x_headers_are_carried() {
    let key = SigningKey::generate();
    let mut msg = signed(&key, b"{}");
    msg.auth_cert = Some("cert".to_string());
    msg.extra_headers = vec![
        ("X-Zeta".to_string(), "2".to_string()),
        ("Critical".to_string(), "Content-Hash".to_string()),
        ("X-Experiment".to_string(), "1".to_string()),
    ];
    msg.sign(&key);
    let bytes = wire::serialize(&msg);
    let text = String::from_utf8(bytes.clone()).unwrap();
    // Slot 26 `Critical`, slot 27 unknown headers in byte order, then Auth-Cert.
    assert!(text.contains("\nCritical: Content-Hash\nX-Experiment: 1\nX-Zeta: 2\nAuth-Cert: cert\nPublic-Key: "), "{text}");
    assert!(accepts(&bytes));
    let parsed = wire::parse(&bytes).unwrap();
    assert_eq!(parsed.extra_headers, vec![
        ("Critical".to_string(), "Content-Hash".to_string()),
        ("X-Experiment".to_string(), "1".to_string()),
        ("X-Zeta".to_string(), "2".to_string()),
    ]);
    assert_eq!(wire::serialize(&parsed), bytes);
    assert!(sbo_core::message::verify_received(&parsed, &bytes).is_ok());

    let b = replace_line(&bytes, "Critical: Content-Hash\n", "Critical: Content-Hash,X-Experiment\n");
    assert!(matches!(wire::parse(&b), Err(sbo_core::error::ParseError::UnknownCriticalHeader(n)) if n == "X-Experiment"));

    // Unknown headers belong in slot 27: before a modelled header, or out of
    // byte order among themselves, is non-canonical (§Validation 15).
    let b = replace_line(&bytes, "Action: post\n", "Action: post\nX-Early: 1\n");
    assert!(matches!(wire::parse(&b), Err(sbo_core::error::ParseError::HeaderOrder(_))));
    let b = replace_line(&bytes, "X-Experiment: 1\nX-Zeta: 2\n", "X-Zeta: 2\nX-Experiment: 1\n");
    assert!(matches!(wire::parse(&b), Err(sbo_core::error::ParseError::HeaderOrder(_))));
    let b = replace_line(&bytes, "X-Zeta: 2\nAuth-Cert: cert\n", "Auth-Cert: cert\nX-Zeta: 2\n");
    assert!(matches!(wire::parse(&b), Err(sbo_core::error::ParseError::HeaderOrder(_))));
}

/// §Size Bounds: the bounds are checked, never wrapped or allocated.
#[test]
fn size_bounds_reject_before_any_slice() {
    let key = SigningKey::generate();
    let bytes = wire::serialize(&signed(&key, b"{}"));
    let b = replace_line(&bytes, "Content-Length: 2\n", &format!("Content-Length: {}\n", wire::MAX_MESSAGE_BYTES + 1));
    assert!(wire::parse(&b).is_err());
    let big = vec![b'x'; wire::MAX_SUBMISSION_BYTES + 1];
    assert!(wire::parse_batch(&big).is_err());
    let mut huge_header = b"SBO-Version: 0.5\nAction: post\nPath: /a/\nID: x\nType: object\nContent-Type: ".to_vec();
    huge_header.extend(std::iter::repeat(b'a').take(wire::MAX_HEADER_BLOCK_BYTES));
    huge_header.extend_from_slice(b"\n\n");
    assert!(wire::parse(&huge_header).is_err());
}

/// Q32 (c): the signing content of a received message is its header block
/// minus the `Signature` line, and it is what the signer produced.
#[test]
fn signing_content_of_received_bytes_equals_what_the_signer_signed() {
    let key = SigningKey::generate();
    let msg = signed(&key, b"{}");
    let bytes = wire::serialize(&msg);
    assert_eq!(wire::signing_content(&bytes).unwrap(), msg.canonical_signing_content());
    let parsed = wire::parse(&bytes).unwrap();
    assert!(sbo_core::message::verify_received(&parsed, &bytes).is_ok());
    let tampered = replace_line(&bytes, "ID: obj\n", "ID: other\n");
    assert!(sbo_core::message::verify_received(&parsed, &tampered).is_err());
}

// ---------------------------------------------------------------------------
// D3 / D5: the live genesis (mingo v5, app 506)
// ---------------------------------------------------------------------------

/// For canonical input the raw-bytes hash (State Commitment spec) and the
/// reserialized hash (code, Genesis spec) agree, and both equal the documented
/// v5 identity. The divergence is only for non-canonical accepted input (D2).
#[test]
fn live_genesis_raw_and_reserialized_hashes_agree() {
    let raw = ContentHash::sha256(LIVE_GENESIS).to_string();
    let reserialized = sbo_core::genesis_hash_from_wire(LIVE_GENESIS).unwrap().to_string();
    assert_eq!(raw, LIVE_GENESIS_HASH);
    assert_eq!(reserialized, LIVE_GENESIS_HASH);
    let msgs = wire::parse_batch(LIVE_GENESIS).unwrap();
    assert_eq!(msgs.len(), 14);
    for m in &msgs {
        assert!(verify_message(m).is_ok());
        assert_eq!(wire::serialize(m).len(), wire::serialize(m).len());
    }
}

/// Q7 (a): the genesis batch at the anchor is validated structurally. The live
/// batch is a plain Mode B genesis (domain, sys, root policy present, no
/// `/sys/dnssec/` object) and must pass `Genesis::validate`.
#[test]
#[ignore] // AUDIT-2026-11 D5: fails today — Genesis::validate is todo!()
fn d5_genesis_validate_accepts_the_live_mode_b_batch() {
    let msgs = wire::parse_batch(LIVE_GENESIS).unwrap();
    sbo_core::Genesis::validate(&msgs).expect("the live genesis batch is a valid Mode B genesis");
}

/// A batch with no root policy at all is not a genesis.
#[test]
#[ignore] // AUDIT-2026-11 D5: fails today — Genesis::validate is todo!()
fn d5_genesis_validate_rejects_a_batch_without_a_root_policy() {
    let msgs: Vec<Message> = wire::parse_batch(LIVE_GENESIS)
        .unwrap()
        .into_iter()
        .filter(|m| !(m.path.to_string() == "/sys/policies/" && m.id.as_str() == "root"))
        .collect();
    assert!(sbo_core::Genesis::validate(&msgs).is_err());
}

// ---------------------------------------------------------------------------
// D10: role cycles (July sbo-bynl)
// ---------------------------------------------------------------------------

fn cyclic_policy_eval() {
    use sbo_core::policy::{evaluate, ActionType, Grant, Identity, PathPattern, Policy, PolicyVars};
    // Built in code, not parsed: the validation pass (D10 fix) rejects this
    // document at parse time, and the evaluator's own bound is what is under
    // test here — a cyclic policy that reached it by any route must terminate.
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
    let msg = signed(&key, b"{}");
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

/// A policy whose roles reference each other is on chain (nothing rejects it
/// at write time) and every evaluator that touches it must terminate. Runs the
/// evaluation in a child process so a stack overflow does not take the test
/// runner down.
#[test]
fn d10_cyclic_role_policy_does_not_crash_the_evaluator() {
    if std::env::var_os("AUDIT_WS6_CHILD").is_some() {
        cyclic_policy_eval();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args(["--exact", "d10_cyclic_role_policy_does_not_crash_the_evaluator", "--nocapture"])
        .env("AUDIT_WS6_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "evaluating a cyclic role policy crashed: {status}");
}

/// Q17 (a): a cyclic policy must also be rejected when it is parsed for a write.
#[test]
fn d10_cyclic_role_policy_is_rejected_at_parse() {
    let r = serde_json::from_str::<sbo_core::policy::Policy>(
        r#"{"roles":{"a":[{"role":"b"}],"b":[{"role":"a"}]},"grants":[]}"#,
    );
    assert!(r.is_err(), "a policy with a role cycle deserialized without error");
}

// ---------------------------------------------------------------------------
// D24 / W6-3: require_payload_signed_by
// ---------------------------------------------------------------------------

/// Today the restriction denies EVERY payload, legitimate or forged: the issuer
/// path `/sys/domains/<d>` has no trailing slash, so `Path::parse` fails and
/// `check_payload_signed_by` answers "Invalid issuer path". Once that is fixed,
/// the check must also verify the JWT signature against the issuer object's key,
/// otherwise any signer satisfies it by writing `iss: domain:<d>`. The fix must
/// make both halves of this test hold.
#[test]
fn d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer() {
    use sbo_core::policy::{evaluate_with, ActionType, Policy, PolicyResult, PolicyVars};
    let policy: Policy = serde_json::from_str(
        r#"{"grants":[{"to":"*","can":["post"],"on":"/sys/names/**"}],
            "restrictions":[{"on":"/sys/names/**","require":{"require_payload_signed_by":{"path":"/sys/domains/*"}}}]}"#,
    )
    .unwrap();
    let domain = SigningKey::generate();
    let user = SigningKey::generate();
    // The on-chain `/sys/domains/mingo.place` object's key, as the daemon
    // supplies it from state (`SignerKeyLookup`).
    let domain_pk = domain.public_key();
    let signer_key = |path: &Path, id: &Id| -> Option<sbo_core::crypto::PublicKey> {
        (path.to_string() == "/sys/domains/" && id.as_str() == "mingo.place").then(|| domain_pk.clone())
    };
    let run = |jwt: String| {
        let mut msg = signed(&user, jwt.as_bytes());
        msg.path = Path::parse("/sys/names/").unwrap();
        msg.id = Id::new("victim").unwrap();
        msg.content_schema = Some("identity.v1".to_string());
        msg.sign(&user);
        evaluate_with(&policy, &Id::new("user").unwrap(), ActionType::Create, "/sys/names/",
            &PolicyVars::default(), false, &|_| false, &signer_key, &msg, None)
    };
    // Signed by the domain key: must be allowed.
    let legit = sbo_core::jwt::create_domain_certified_identity(
        &domain, "mingo.place", "victim.place", &user.public_key(), None).unwrap();
    let r = run(legit);
    assert!(matches!(r, PolicyResult::Allowed), "domain-signed identity denied: {r:?}");
    // Signed by the user's own key but claiming the domain issuer: must be denied.
    let forged = sbo_core::jwt::create_domain_certified_identity(
        &user, "mingo.place", "victim.place", &user.public_key(), None).unwrap();
    let r = run(forged);
    assert!(matches!(r, PolicyResult::Denied(_)), "forged issuer satisfied require_payload_signed_by: {r:?}");
}

// ---------------------------------------------------------------------------
// JWT and device-presentation pins (passing)
// ---------------------------------------------------------------------------

#[test]
fn jwt_alg_is_pinned_to_eddsa_and_signature_length_to_64() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key = SigningKey::generate();
    let token = sbo_core::jwt::create_domain(&key, "example.com").unwrap();
    assert!(sbo_core::jwt::verify_domain(&token).is_ok());
    let parts: Vec<&str> = token.split('.').collect();
    for alg in ["none", "HS256", "ES256"] {
        let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#));
        let t = format!("{}.{}.{}", header, parts[1], parts[2]);
        assert!(sbo_core::jwt::verify_domain(&t).is_err(), "alg {alg} accepted");
        let t = format!("{}.{}.", header, parts[1]);
        assert!(sbo_core::jwt::verify_domain(&t).is_err(), "alg {alg} with empty signature accepted");
    }
    // Signature by a different key over the same claims.
    let other = SigningKey::generate();
    let forged = sbo_core::jwt::create_domain(&other, "example.com").unwrap();
    let fp: Vec<&str> = forged.split('.').collect();
    let t = format!("{}.{}.{}", parts[0], parts[1], fp[2]);
    assert!(sbo_core::jwt::verify_domain(&t).is_err());
}

mod device {
    use sbo_core::attribution::{AttributionError, TrustAnchors};
    use sbo_core::browserid_core::device::{
        AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
    };
    use sbo_core::browserid_core::{Assertion, KeyPair};
    use sbo_core::device_attribution::{
        effective_author, verify_device_attribution, verify_device_attribution_with_provider_key,
    };
    use chrono::Duration;

    const AUD: &str = "sbo+raw://avail:turing:506/";

    struct Fx {
        pres: AccessPresentation,
        idp: KeyPair,
        access: KeyPair,
    }

    fn fixture(iss: &str, grantee: &str, grantor: &str, config_identities: Vec<String>) -> Fx {
        let idp = KeyPair::generate();
        let access = KeyPair::generate();
        let config = KeyPair::generate();
        let access_cert = AccessCert::create(iss, grantee, Holder::new("svc.a").unwrap(), &access.public_key(), Duration::hours(24), &idp, None).unwrap();
        let config_cert = DeviceCert::create(iss, &config.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(), config_identities, Duration::days(90), &idp, None).unwrap();
        let warrant = Warrant::create(grantor, grantee, HolderMatcher::new("svc.a").unwrap(), AUD, vec!["action:post".into()], Duration::days(90), &config, None).unwrap();
        let assertion = Assertion::create(AUD, Duration::days(1), &access).unwrap();
        Fx { pres: AccessPresentation { access_cert, assertion, warrant, config_cert }, idp, access }
    }

    fn verify(fx: Fx, pk: &str, aud: &str, now: i64, win: (i64, i64), anchors: &TrustAnchors) -> Result<sbo_core::device_attribution::DeviceAttribution, AttributionError> {
        verify_device_attribution_with_provider_key(pk, fx.pres, &fx.idp.public_key(), win.0, win.1, aud, now, None, anchors)
    }

    #[test]
    fn i17_envelope_key_must_equal_the_access_cert_key() {
        let now = chrono::Utc::now().timestamp();
        let fx = fixture("d.example", "alice@d.example", "alice@d.example", vec!["alice@d.example".into()]);
        let pk = fx.access.public_key().to_base64();
        let other = KeyPair::generate().public_key().to_base64();
        let fx2 = fixture("d.example", "alice@d.example", "alice@d.example", vec!["alice@d.example".into()]);
        assert!(verify(fx, &pk, AUD, now, (now - 10, now + 10), &TrustAnchors::default()).is_ok());
        assert!(matches!(verify(fx2, &other, AUD, now, (now - 10, now + 10), &TrustAnchors::default()), Err(AttributionError::KeyMismatch)));
    }

    #[test]
    fn i17_issuer_must_be_authoritative_for_grantee_and_grantor_or_a_pinned_broker() {
        let now = chrono::Utc::now().timestamp();
        // Issuer `broker.example` vouches for `alice@other.example`.
        let fx = fixture("broker.example", "alice@other.example", "alice@other.example", vec!["alice@other.example".into()]);
        let pk = fx.access.public_key().to_base64();
        let r = verify(fx, &pk, AUD, now, (now - 10, now + 10), &TrustAnchors::default());
        assert!(matches!(r, Err(AttributionError::IssuerNotAuthorized { .. })), "{r:?}");
        let fx = fixture("broker.example", "alice@other.example", "alice@other.example", vec!["alice@other.example".into()]);
        let pk = fx.access.public_key().to_base64();
        assert!(verify(fx, &pk, AUD, now, (now - 10, now + 10), &TrustAnchors::with_brokers(vec!["broker.example".into()])).is_ok());
    }

    #[test]
    fn i16_inclusion_time_outside_the_dnssec_window_rejects() {
        let now = chrono::Utc::now().timestamp();
        let fx = fixture("d.example", "alice@d.example", "alice@d.example", vec!["alice@d.example".into()]);
        let pk = fx.access.public_key().to_base64();
        let r = verify(fx, &pk, AUD, now, (now + 100, now + 200), &TrustAnchors::default());
        assert!(matches!(r, Err(AttributionError::EvidenceWindowMismatch { .. })), "{r:?}");
    }

    #[test]
    fn i18_wrong_audience_rejects() {
        let now = chrono::Utc::now().timestamp();
        let fx = fixture("d.example", "alice@d.example", "alice@d.example", vec!["alice@d.example".into()]);
        let pk = fx.access.public_key().to_base64();
        let r = verify(fx, &pk, "sbo+raw://avail:turing:507/", now, (now - 10, now + 10), &TrustAnchors::default());
        assert!(matches!(r, Err(AttributionError::DevicePresentation(_))), "{r:?}");
    }

    /// browserid-ng §4.6: a config cert for `alice@d` signs warrants for
    /// `alice+bot@d` (authorization subaddressing). The access cert is minted
    /// for the exact grantee by the IdP, which is where the browserid-ng D1 rule
    /// lives; sbo only consumes the presentation.
    #[test]
    fn subaddressed_grantor_is_covered_by_the_base_config_cert() {
        let now = chrono::Utc::now().timestamp();
        let fx = fixture("d.example", "bot@d.example", "alice+bot@d.example", vec!["alice@d.example".into()]);
        let pk = fx.access.public_key().to_base64();
        let a = verify(fx, &pk, AUD, now, (now - 10, now + 10), &TrustAnchors::default()).unwrap();
        assert_eq!(a.grantor, "alice+bot@d.example");
        assert_eq!(a.email, "bot@d.example", "the grantee authors by default");
    }

    #[test]
    fn i19_as_scope_rules() {
        assert_eq!(effective_author("g@d", "a@d", &["path:/x/**".into(), "as:g@d".into()]).unwrap(), "g@d");
        assert!(effective_author("g@d", "a@d", &["as:g@d".into()]).is_err(), "as: without path:");
        assert!(effective_author("g@d", "a@d", &["path:/x/**".into(), "as:other@d".into()]).is_err());
        assert!(effective_author("g@d", "a@d", &["path:/x/**".into(), "as:g@d".into(), "as:g@d".into()]).is_err());
        assert_eq!(effective_author("g@d", "a@d", &["action:post".into()]).unwrap(), "a@d");
    }

    /// Cross-issuer delegation: the grantor's issuer needs its own DNSSEC
    /// evidence; without it the write fails closed.
    #[test]
    fn cross_issuer_grant_without_grantor_evidence_fails_closed() {
        let idp_a = KeyPair::generate();
        let idp_b = KeyPair::generate();
        let access = KeyPair::generate();
        let config = KeyPair::generate();
        let access_cert = AccessCert::create("a.example", "svc@a.example", Holder::new("svc.a").unwrap(), &access.public_key(), Duration::hours(24), &idp_a, None).unwrap();
        let config_cert = DeviceCert::create("b.example", &config.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(), vec!["dan@b.example".into()], Duration::days(90), &idp_b, None).unwrap();
        let warrant = Warrant::create("dan@b.example", "svc@a.example", HolderMatcher::new("svc.a").unwrap(), AUD, vec!["action:post".into()], Duration::days(90), &config, None).unwrap();
        let assertion = Assertion::create(AUD, Duration::days(1), &access).unwrap();
        let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
        let now = chrono::Utc::now().timestamp();
        let r = verify_device_attribution(&access.public_key().to_base64(), &pres.encode(), |_iss| None, AUD, now, None, &TrustAnchors::default());
        assert!(matches!(r, Err(AttributionError::MissingIssuerEvidence(_))), "{r:?}");
    }
}

/// D32 (Info): `Auth-Warrant` is carried and signed but never consumed. A
/// garbage value does not affect signature verification or parsing.
#[test]
fn d32_auth_warrant_header_is_inert() {
    let key = SigningKey::generate();
    let mut msg = signed(&key, b"{}");
    msg.auth_warrant = Some("not-a-jws".to_string());
    msg.sign(&key);
    let bytes = wire::serialize(&msg);
    assert!(String::from_utf8_lossy(&bytes).contains("Auth-Warrant: not-a-jws\n"));
    assert!(accepts(&bytes));
}

