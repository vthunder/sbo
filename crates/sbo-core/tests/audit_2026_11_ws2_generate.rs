//! Security audit 2026-11, WS2 — conformance-vector GENERATOR.
//!
//! Writes `conformance/{wire,batch,ed25519,trie,checkpoint}.json` from a fixed
//! seed key so the vectors are reproducible byte-for-byte. Run with
//!
//!     cargo test -p sbo-core --test audit_2026_11_ws2_generate -- --ignored
//!
//! The expected verdicts recorded here are the SPEC's verdicts (Core, Wire,
//! State Commitment, Genesis; threat-model I1–I7, I30; decisions Q4, Q5),
//! never what any implementation does today. The runners
//! (`audit_2026_11_ws2_*.rs` in each crate) compare each implementation
//! against them and keep an expected-fail table per finding.
//!
//! Report: docs/security-audit-2026-11-ws2-conformance.md.

use sbo_core::crypto::{sha256, ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path, Related};
use sbo_core::wire;
use serde_json::{json, Value};
use std::path::PathBuf;

const SEED: [u8; 32] = [0x42; 32];
const SEED_B: [u8; 32] = [0x43; 32];

fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn write(name: &str, v: &Value) {
    let path = out_dir().join(name);
    std::fs::write(&path, serde_json::to_string_pretty(v).unwrap() + "\n").unwrap();
    eprintln!("wrote {}", path.display());
}

fn base_message(key: &SigningKey) -> Message {
    let payload = br#"{"body":"hello"}"#.to_vec();
    let mut m = Message {
        action: Action::Post,
        path: Path::parse("/communities/cooks/spaces/general/").unwrap(),
        id: Id::new("p1").unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".into()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: Some(Id::new("alice@example.com").unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: Some("post.v1".into()),
        policy_ref: None,
        related: None,
        hlc: Some("1703001234567.0".into()),
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None, extra_headers: Vec::new(),
    };
    m.sign(key);
    m
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("vectors are ASCII")
}

/// Sign an arbitrary header block (every header except `Signature`, in the
/// order given) and assemble the wire: used for header sets `Message` cannot
/// model (import headers, injected headers).
fn sign_raw(key: &SigningKey, header_lines: &[(&str, &str)], payload: &[u8]) -> String {
    let mut signing = String::new();
    for (n, v) in header_lines {
        signing.push_str(n);
        signing.push_str(": ");
        signing.push_str(v);
        signing.push('\n');
    }
    signing.push('\n');
    let sig = key.sign(signing.as_bytes());
    let mut w = String::new();
    for (n, v) in header_lines {
        w.push_str(n);
        w.push_str(": ");
        w.push_str(v);
        w.push('\n');
    }
    w.push_str("Signature: ");
    w.push_str(&sig.to_hex());
    w.push_str("\n\n");
    w.push_str(&text(payload));
    w
}

fn header_lines_of(wire_text: &str) -> Vec<(String, String)> {
    wire_text
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .map(|l| {
            let (n, v) = l.split_once(": ").unwrap();
            (n.to_string(), v.to_string())
        })
        .collect()
}

fn vec_entry(id: &str, desc: &str, w: &str, valid: bool, spec_ref: &str) -> Value {
    json!({
        "id": id,
        "description": desc,
        "wire": w,
        "spec": { "valid": valid, "ref": spec_ref },
        // State Commitment §Object Hash: sha256 of the raw received bytes.
        "object_hash_raw": hex::encode(sha256(w.as_bytes())),
    })
}

#[test]
#[ignore]
fn generate_conformance_vectors() {
    let key = SigningKey::from_bytes(&SEED);
    let key_b = SigningKey::from_bytes(&SEED_B);
    let base = base_message(&key);
    let base_wire = text(&wire::serialize(&base));
    let payload = base.payload.clone().unwrap();
    let hdrs = header_lines_of(&base_wire);
    let hdr_refs: Vec<(&str, &str)> = hdrs.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let without_sig: Vec<(&str, &str)> = hdr_refs.iter().copied().filter(|(n, _)| *n != "Signature").collect();

    let mut vectors = Vec::new();

    // ---- accepted ----
    vectors.push(vec_entry("W-OK-01", "canonical post with payload", &base_wire, true, "Wire §Parsing"));

    let mut transfer = base.clone();
    transfer.action = Action::Transfer { new_owner: Some(Id::new("bob@example.com").unwrap()), new_path: None, new_id: None };
    transfer.payload = None;
    transfer.content_hash = None;
    transfer.content_type = None;
    transfer.content_schema = None;
    transfer.hlc = None;
    transfer.sign(&key);
    vectors.push(vec_entry("W-OK-02", "canonical transfer, no payload, no Content-Length", &text(&wire::serialize(&transfer)), true, "Wire §Conditionally Required Headers"));

    let mut rel = base.clone();
    rel.related = Some(vec![Related { rel: "license".into(), reference: "sbo+raw://avail:mainnet:13/licenses/cc-by".into() }]);
    rel.prev = Some("0000000000000000000000000000000000000000000000000000000000000001".into());
    rel.sign(&key);
    vectors.push(vec_entry("W-OK-03", "canonical post with Related, HLC and Prev", &text(&wire::serialize(&rel)), true, "Core §Related Objects"));

    let mut coll = base.clone();
    coll.object_type = ObjectType::Collection;
    coll.sign(&key);
    vectors.push(vec_entry("W-OK-04", "canonical collection", &text(&wire::serialize(&coll)), true, "Core §Object Types"));

    // Import headers (Attestation / Origin / Registry-Path / Object-Path) have a
    // canonical position and are signed; a verifier that cannot reproduce them
    // cannot verify the message (D3 / S2 class).
    let mut with_att: Vec<(&str, &str)> = Vec::new();
    for (n, v) in &without_sig {
        with_att.push((n, v));
        if *n == "Content-Hash" {
            with_att.push(("Attestation", "bridge-attestation-opaque"));
        }
    }
    vectors.push(vec_entry("W-OK-05", "signed message carrying the canonical `Attestation` header (bridge/import header in its canonical slot)", &sign_raw(&key, &with_att, &payload), true, "Wire §Canonical Header Order; §Encoding Rules (unknown headers ignored does not apply: Attestation is a listed header)"));

    // ---- Content-Hash binding (I1) ----
    let swapped = base_wire.replacen(r#"{"body":"hello"}"#, r#"{"body":"EVIL!"}"#, 1);
    assert_eq!(swapped.len(), base_wire.len());
    vectors.push(vec_entry("W-CH-01", "payload swapped for one of equal length; headers and signature untouched", &swapped, false, "Core §Signature Scope: payload is bound only via Content-Hash; Wire §Validation 5"));

    let hash_line = hdrs.iter().find(|(n, _)| n == "Content-Hash").unwrap().1.clone();
    let mut flipped = hash_line.clone();
    let last = flipped.pop().unwrap();
    flipped.push(if last == '0' { '1' } else { '0' });
    let bad_hash = base_wire.replacen(&hash_line, &flipped, 1);
    vectors.push(vec_entry("W-CH-02", "Content-Hash header altered (signature then fails)", &bad_hash, false, "Wire §Validation 5, 6"));

    // ---- canonical form (I2) ----
    let reordered = base_wire.replacen("SBO-Version: 0.5\nAction: post\n", "Action: post\nSBO-Version: 0.5\n", 1);
    assert_ne!(reordered, base_wire);
    vectors.push(vec_entry("W-ORD-01", "two headers swapped out of canonical order", &reordered, false, "Wire §Validation 2: headers not in canonical order"));

    let dup_same = base_wire.replacen("Owner: alice@example.com\n", "Owner: alice@example.com\nOwner: alice@example.com\n", 1);
    vectors.push(vec_entry("W-DUP-01", "a header repeated with the identical value", &dup_same, false, "Wire §Header format (one line per header); I2"));

    let dup_diff = base_wire.replacen("Owner: alice@example.com\n", "Owner: mallory@example.com\nOwner: alice@example.com\n", 1);
    vectors.push(vec_entry("W-DUP-02", "a header repeated; the first occurrence is unsigned attacker text, the last is the signed value", &dup_diff, false, "I2: duplicate header"));

    let crlf = base_wire.replacen("Action: post\n", "Action: post\r\n", 1);
    vectors.push(vec_entry("W-CRLF-01", "CRLF line ending on one header", &crlf, false, "Wire §Encoding Rules: LF only"));

    let cl_plus = base_wire.replacen("Content-Length: 16\n", "Content-Length: +16\n", 1);
    assert_ne!(cl_plus, base_wire);
    vectors.push(vec_entry("W-CL-01", "Content-Length written as `+16`", &cl_plus, false, "Wire §Encoding Rules: canonical decimal (S22)"));
    let cl_zero = base_wire.replacen("Content-Length: 16\n", "Content-Length: 016\n", 1);
    vectors.push(vec_entry("W-CL-02", "Content-Length written as `016`", &cl_zero, false, "Wire §Encoding Rules: canonical decimal (S22)"));
    let cl_big = base_wire.replacen("Content-Length: 16\n", "Content-Length: 17\n", 1);
    vectors.push(vec_entry("W-CL-03", "Content-Length larger than the payload", &cl_big, false, "Wire §Validation 4"));
    let cl_small = base_wire.replacen("Content-Length: 16\n", "Content-Length: 15\n", 1);
    vectors.push(vec_entry("W-CL-04", "Content-Length smaller than the payload (one trailing byte unframed)", &cl_small, false, "Wire §Validation 4"));

    let sig_line = hdrs.iter().find(|(n, _)| n == "Signature").unwrap().1.clone();
    let sig_upper = base_wire.replacen(&sig_line, &sig_line.to_uppercase(), 1);
    assert_ne!(sig_upper, base_wire);
    vectors.push(vec_entry("W-HEX-01", "Signature hex in uppercase", &sig_upper, false, "Wire §Encoding Rules: hex lowercase (S22)"));
    let pk_line = hdrs.iter().find(|(n, _)| n == "Public-Key").unwrap().1.clone();
    let pk_hex = pk_line.replacen("ed25519:", "", 1);
    let pk_upper = base_wire.replacen(&pk_line, &format!("ed25519:{}", pk_hex.to_uppercase()), 1);
    assert!(pk_upper.contains("Public-Key: ed25519:"), "{pk_upper}");
    vectors.push(vec_entry("W-HEX-02", "Public-Key hex in uppercase", &pk_upper, false, "Wire §Encoding Rules: hex lowercase (S22)"));

    // Header injected AFTER signing: the signer never saw it.
    let injected = base_wire.replacen("Public-Key: ", "X-Injected: by-the-network\nPublic-Key: ", 1);
    vectors.push(vec_entry("W-INJ-01", "an unlisted header injected after signing", &injected, false, "Core §Signature Scope: the bytes verified are the bytes received (I2); an implementation that drops unlisted headers before verifying accepts bytes the signer never produced"));
    let injected_known = base_wire.replacen("Content-Schema: ", "Attestation: injected\nContent-Schema: ", 1);
    vectors.push(vec_entry("W-INJ-02", "the listed `Attestation` header injected after signing", &injected_known, false, "Core §Signature Scope (I2)"));

    // ---- identifiers in headers (I5, Q5) ----
    // The grammar now rejects these at `Id::new` (Q5 / Q24), so the hostile
    // headers are produced textually, re-signed over the edited header lines.
    let id_vec = |vid: &str, desc: &str, from: &str, to: &str, spec_ref: &str| {
        let edited = base_wire.replacen(from, to, 1);
        assert!(edited != base_wire, "{vid}: substitution did not apply");
        let lines = header_lines_of(&edited);
        let refs: Vec<(&str, &str)> = lines.iter().filter(|(n, _)| n != "Signature").map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let resigned = sign_raw(&key, &refs, base.payload.as_deref().unwrap_or(&[]));
        vec_entry(vid, desc, &resigned, false, spec_ref)
    };
    vectors.push(id_vec("W-ID-01", "ID is `..`", "ID: p1\n", "ID: ..\n", "I5 / D21"));
    vectors.push(id_vec("W-ID-02", "Path contains a `..` segment", "Path: /communities/cooks/spaces/general/\n", "Path: /communities/../\n", "I5 / D21"));
    vectors.push(id_vec("W-ID-03", "Owner carries two `@`", "Owner: alice@example.com\n", "Owner: alice@example.com@evil\n", "Q5 / D54"));
    vectors.push(id_vec("W-ID-04", "Owner domain in uppercase (non-canonical on-chain form)", "Owner: alice@example.com\n", "Owner: alice@EXAMPLE.com\n", "Q5: canonical lowercase domain"));

    // ---- enumerations (I5) ----
    vectors.push(vec_entry("W-ENUM-01", "Type: Object (case)", &base_wire.replacen("Type: object\n", "Type: Object\n", 1), false, "Wire §Validation 9"));
    vectors.push(vec_entry("W-ENUM-02", "Action: POST (case)", &base_wire.replacen("Action: post\n", "Action: POST\n", 1), false, "Wire §Validation 8"));
    vectors.push(vec_entry("W-ENUM-03", "Action: create (not a wire action)", &base_wire.replacen("Action: post\n", "Action: create\n", 1), false, "Wire §Validation 8"));
    vectors.push(vec_entry("W-ENUM-04", "SBO-Version: 0.6", &base_wire.replacen("SBO-Version: 0.5\n", "SBO-Version: 0.6\n", 1), false, "Wire §Validation 7"));
    vectors.push(vec_entry("W-ENUM-05", "Public-Key with secp256k1 prefix", &base_wire.replacen("Public-Key: ed25519:", "Public-Key: secp256k1:", 1), false, "Wire §Validation 11 (S21: ed25519 is the only REQUIRED algorithm)"));
    vectors.push(vec_entry("W-ENUM-06", "Content-Hash with keccak256 prefix", &base_wire.replacen("Content-Hash: sha256:", "Content-Hash: keccak256:", 1), false, "Wire §Validation 11 (S21)"));

    // ---- signature (I7) ----
    let mut sig_bytes = hex::decode(&sig_line).unwrap();
    sig_bytes[10] ^= 0x01;
    vectors.push(vec_entry("W-SIG-01", "one signature bit flipped", &base_wire.replacen(&sig_line, &hex::encode(&sig_bytes), 1), false, "Wire §Validation 6"));
    vectors.push(vec_entry("W-SIG-02", "signature truncated to 63 bytes", &base_wire.replacen(&sig_line, &sig_line[..126], 1), false, "Wire §Validation 10"));
    let mut m = base.clone();
    m.sign(&key_b);
    let wrong_key = text(&wire::serialize(&m)).replacen(&key_b.public_key().to_string(), &key.public_key().to_string(), 1);
    vectors.push(vec_entry("W-SIG-03", "signed by another key, Public-Key claims the first", &wrong_key, false, "Wire §Validation 6"));
    vectors.push(vec_entry("W-SIG-04", "Signature header missing", &base_wire.replacen(&format!("Signature: {sig_line}\n"), "", 1), false, "Wire §Validation 3"));

    // ---- structure ----
    vectors.push(vec_entry("W-STR-01", "no blank line between headers and payload", &base_wire.replacen("\n\n", "\n", 1), false, "Wire §Parsing"));
    vectors.push(vec_entry("W-STR-02", "header separator without the space (`Action:post`)", &base_wire.replacen("Action: post\n", "Action:post\n", 1), false, "Wire §Encoding Rules: `Name: value`"));
    vectors.push(vec_entry("W-STR-03", "Path header missing", &base_wire.replacen("Path: /communities/cooks/spaces/general/\n", "", 1), false, "Wire §Validation 3"));
    vectors.push(vec_entry("W-STR-04", "empty input", "", false, "Wire §Parsing"));

    let doc = json!({
        "suite": "sbo conformance 2026-11 / wire envelope",
        "description": "Each vector is one wire message as received. `spec.valid` is the Wire/Core spec verdict (threat-model I1, I2, I5, I7; decisions Q5, S21, S22). `object_hash_raw` is sha256 over the bytes exactly as given (State Commitment §Object Hash). Implementations under test: sbo-core `wire::parse` + `verify_message`, sbo-wasm (same source compiled separately), the daemon's object_hash rule (sha256 of `wire::serialize(parse(bytes))`, sync.rs:1122).",
        "key": { "seed_hex": hex::encode(SEED), "public_key": key.public_key().to_string() },
        "vectors": vectors,
    });
    write("wire.json", &doc);

    // ---------------- batch ----------------
    // Key-rooted writes (no Owner header): the signer is the controller, so the
    // daemon runner can apply them without browserid attribution.
    let mut base = base.clone();
    base.owner = None;
    base.sign(&key);
    let m1 = base.clone();
    let mut m2 = base.clone();
    m2.id = Id::new("p2").unwrap();
    m2.sign(&key);
    let mut m3 = base.clone();
    m3.id = Id::new("p3").unwrap();
    m3.sign(&key);
    let w1 = text(&wire::serialize(&m1));
    let w2 = text(&wire::serialize(&m2));
    let w3 = text(&wire::serialize(&m3));
    let w2_bad_sig = {
        let l = header_lines_of(&w2).into_iter().find(|(n, _)| n == "Signature").unwrap().1;
        let mut b = hex::decode(&l).unwrap();
        b[0] ^= 1;
        w2.replacen(&l, &hex::encode(b), 1)
    };
    let w2_unparseable = w2.replacen("Type: object\n", "Type: Object\n", 1);
    let mut m1_dup = base.clone();
    m1_dup.payload = Some(br#"{"body":"second"}"#.to_vec());
    m1_dup.content_hash = Some(ContentHash::sha256(m1_dup.payload.as_ref().unwrap()));
    m1_dup.signing_key = key_b.public_key();
    m1_dup.sign(&key_b);
    let w1_other_signer = text(&wire::serialize(&m1_dup));

    let batch_doc = json!({
        "suite": "sbo conformance 2026-11 / batch semantics",
        "description": "Decision Q4 (2026-11-04): per-message, ordered, state-threaded. Rules: (1) a submission that fails to parse anywhere is ignored whole; (2) messages validate and apply in submission order, N against state after 1..N-1; (3) a rejected message leaves state unchanged and is invisible to later messages; (4) an LWW loser is valid with no effect; (5) index within a submission breaks slot ties; (6) state root commits per block; (7) genesis is not an atomic exception. `parse` is the expected result of parsing the submission as a unit; `applied` lists the (0-based) indices of messages that end up in state after sequential validation from a root policy granting `*` create+update under the path.",
        "key": { "seed_hex": hex::encode(SEED), "public_key": key.public_key().to_string(), "second_seed_hex": hex::encode(SEED_B) },
        "vectors": [
            { "id": "B-01", "description": "three valid messages", "wire": format!("{w1}{w2}{w3}"), "parse": "accept", "count": 3, "applied": [0, 1, 2] },
            { "id": "B-02", "description": "middle message has a bad signature: it is rejected alone; the others apply (rule 2, 3)", "wire": format!("{w1}{w2_bad_sig}{w3}"), "parse": "accept", "count": 3, "applied": [0, 2] },
            { "id": "B-03", "description": "middle message does not parse: the whole submission is ignored (rule 1)", "wire": format!("{w1}{w2_unparseable}{w3}"), "parse": "reject", "count": 0, "applied": [] },
            { "id": "B-04", "description": "two creates into the same slot by different signers: the lower index wins, the second is an unauthorized update (rule 5)", "wire": format!("{w1}{w1_other_signer}"), "parse": "accept", "count": 2, "applied": [0] },
            { "id": "B-05", "description": "trailing garbage after the last message", "wire": format!("{w1}garbage"), "parse": "reject", "count": 0, "applied": [] },
            { "id": "B-06", "description": "empty submission", "wire": "", "parse": "accept", "count": 0, "applied": [] }
        ]
    });
    write("batch.json", &batch_doc);

    // ---------------- ed25519 ----------------
    let msg = b"sbo conformance 2026-11";
    let sig = key.sign(msg);
    let pk = key.public_key();
    let mut tampered = sig.0;
    tampered[3] ^= 0x80;
    // Non-canonical S: S + L (L = group order). Valid under the group equation,
    // rejected by any verifier that requires canonical S (RFC 8032 §5.1.7).
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    let mut s_plus_l = sig.0;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s_plus_l[32 + i] as u16 + L[i] as u16 + carry;
        s_plus_l[32 + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "S + L must not overflow 256 bits for this vector");
    // Small-order public key (the identity point, y = 1) with R = identity and
    // S = 0 verifies for EVERY message under the non-strict equation.
    let mut identity_pt = [0u8; 32];
    identity_pt[0] = 1;
    let mut small_order_sig = [0u8; 64];
    small_order_sig[..32].copy_from_slice(&identity_pt);

    let ed = json!({
        "suite": "sbo conformance 2026-11 / ed25519",
        "description": "Threat-model I7: both wrappers (`sbo-core::crypto::ed25519::verify`, `sbo-crypto::ed25519::verify`) accept exactly the same signatures, and the spec admits one canonical signature per (key, message): RFC 8032 §5.1.7 canonical S, no small-order keys (D30).",
        "vectors": [
            { "id": "ED-OK-01", "public_key": hex::encode(pk.bytes), "message_hex": hex::encode(msg), "signature": hex::encode(sig.0), "valid": true },
            { "id": "ED-REJ-01", "description": "tampered signature", "public_key": hex::encode(pk.bytes), "message_hex": hex::encode(msg), "signature": hex::encode(tampered), "valid": false },
            { "id": "ED-REJ-02", "description": "wrong message", "public_key": hex::encode(pk.bytes), "message_hex": hex::encode(b"other"), "signature": hex::encode(sig.0), "valid": false },
            { "id": "ED-REJ-03", "description": "non-canonical S (S + L)", "public_key": hex::encode(pk.bytes), "message_hex": hex::encode(msg), "signature": hex::encode(s_plus_l), "valid": false },
            { "id": "ED-REJ-04", "description": "small-order public key (identity point), R = identity, S = 0", "public_key": hex::encode(identity_pt), "message_hex": hex::encode(msg), "signature": hex::encode(small_order_sig), "valid": false },
            { "id": "ED-REJ-05", "description": "public key of 31 bytes", "public_key": hex::encode(&pk.bytes[..31]), "message_hex": hex::encode(msg), "signature": hex::encode(sig.0), "valid": false },
            { "id": "ED-REJ-06", "description": "signature of 65 bytes", "public_key": hex::encode(pk.bytes), "message_hex": hex::encode(msg), "signature": format!("{}00", hex::encode(sig.0)), "valid": false }
        ]
    });
    write("ed25519.json", &ed);

    // ---------------- trie ----------------
    use sbo_core::SparseTrie;
    let h = |b: &[u8]| sha256(b);
    let mut t1 = SparseTrie::new();
    t1.insert(vec!["a".into(), "b".into()], h(b"obj-ab"));
    let mut t2 = SparseTrie::new();
    t2.insert(vec!["a".into(), "b".into()], h(b"obj-ab"));
    t2.insert(vec!["a".into(), "c".into()], h(b"obj-ac"));
    t2.insert(vec!["z".into()], h(b"obj-z"));
    // Domain-separation probe (I30 / D4): an object at ["a"] whose object_hash
    // happens to equal the hash of the subtree node {"b": H} must NOT produce
    // the same root as the object at ["a","b"] with hash H.
    let mut sub = sbo_crypto::trie::TrieNode::new();
    sub.children.insert("b".into(), h(b"obj-ab"));
    let mut t3 = SparseTrie::new();
    t3.insert(vec!["a".into()], sub.hash());
    // Object-versus-container (W3-4): an object at ["a"] and one at ["a","b"]
    // coexist; the node for "a" carries both, whichever is written first.
    let mut t5 = SparseTrie::new();
    t5.insert(vec!["a".into(), "b".into()], h(b"obj-ab"));
    t5.insert(vec!["a".into()], h(b"obj-a"));

    let trie = json!({
        "suite": "sbo conformance 2026-11 / state trie",
        "description": "State Commitment v2 §Domain Separation / §Object Versus Container: leaf = sha256(0x00 || object_hash); node = sha256(0x01 || canonical JSON {\"children\":{seg:\"sha256:<hex>\",…}[,\"object\":\"sha256:<hex>\"]}) with sorted keys; an object and a container at the same segments coexist. Threat-model I30: a leaf and an internal node are distinguishable (D4). Implementations: sbo-crypto `SparseTrie` (builder), `PartialTrie` via `verify_state_transition` (verifier, also the zkVM guest's code), sbo-core `StateDb::compute_trie_state_root` (daemon, rocksdb). `root` is what the builder computes today and every other implementation must reproduce; `distinct_from` names a vector whose root the spec requires to differ.",
        "vectors": [
            { "id": "TRIE-01", "objects": [ {"segments": ["a","b"], "object_hash": hex::encode(h(b"obj-ab"))} ], "root": hex::encode(t1.root_hash()) },
            { "id": "TRIE-02", "objects": [ {"segments": ["a","b"], "object_hash": hex::encode(h(b"obj-ab"))}, {"segments": ["a","c"], "object_hash": hex::encode(h(b"obj-ac"))}, {"segments": ["z"], "object_hash": hex::encode(h(b"obj-z"))} ], "root": hex::encode(t2.root_hash()) },
            { "id": "TRIE-03", "description": "object at [a] whose object_hash equals the hash of the node {b: H}", "objects": [ {"segments": ["a"], "object_hash": hex::encode(sub.hash())} ], "root": hex::encode(t3.root_hash()), "distinct_from": "TRIE-01" },
            { "id": "TRIE-04", "description": "empty state: node_hash of the empty node, no zero sentinel (Q41)", "objects": [], "root": hex::encode(sbo_crypto::trie::empty_root()) },
            { "id": "TRIE-05", "description": "object at [a] and object at [a,b] coexist (object-versus-container); order-independent", "objects": [ {"segments": ["a","b"], "object_hash": hex::encode(h(b"obj-ab"))}, {"segments": ["a"], "object_hash": hex::encode(h(b"obj-a"))} ], "root": hex::encode(t5.root_hash()), "distinct_from": "TRIE-01" }
        ]
    });
    write("trie.json", &trie);

    // ---------------- checkpoint claims (S18) ----------------
    let root = hex::encode(h(b"some-root"));
    let cp = json!({
        "suite": "sbo conformance 2026-11 / checkpoint claims",
        "description": "State Commitment spec examples write `state_root` as `sha256:<hex>`; the daemon's `trust::claim_from_message` and `bootstrap` read bare hex (S18). One form must win; until Dan decides (Q22) the spec form is expected and the bare form is tolerated.",
        "vectors": [
            { "id": "CP-01", "schema": "checkpoint.v1", "payload": { "block": 100, "state_root": format!("sha256:{root}") }, "claim": { "block": 100, "state_root": root } },
            { "id": "CP-02", "schema": "checkpoint.v1", "payload": { "block": 100, "state_root": root }, "claim": { "block": 100, "state_root": root }, "note": "bare hex tolerated" },
            { "id": "CP-03", "schema": "checkpoint-attestation.v1", "payload": { "block": 7, "state_root": format!("sha256:{root}") }, "claim": { "block": 7, "state_root": root } },
            { "id": "CP-04", "schema": "checkpoint.v1", "payload": { "block": 100, "state_root": "sha256:abc" }, "claim": null, "note": "wrong length" },
            { "id": "CP-05", "schema": "checkpoint.v1", "payload": { "block": 100, "state_root": format!("keccak256:{root}") }, "claim": null, "note": "unsupported algorithm" }
        ]
    });
    write("checkpoint.json", &cp);
}
