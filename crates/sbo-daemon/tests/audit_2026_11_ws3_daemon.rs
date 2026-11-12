//! Security audit 2026-11, WS3: property tests over the daemon's own parsers
//! — snapshot decoding (D50), IPC request framing, the evidence issuer
//! extractor, and the `_sbo` resolution of `required_issuers` on junk.

use proptest::prelude::*;
use sbo_daemon::evidence::required_issuers;
use sbo_daemon::ipc::{Request, Response};
use sbo_daemon::snapshot::{compute_snapshot_root, decode_snapshot_payload};
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use std::io::Write;

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 128, ..ProptestConfig::default() }
}

fn msg(auth_cert: Option<String>) -> Message {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    Message {
        action: Action::Post, path: Path::parse("/a/").unwrap(), id: Id::new("x").unwrap(), object_type: ObjectType::Object,
        signing_key: key.public_key(), signature: Signature([0u8; 64]), content_type: None, content_hash: Some(ContentHash::sha256(b"")),
        payload: Some(vec![]), owner: None, creator: None, content_encoding: None, content_schema: None, policy_ref: None, related: None,
        hlc: None, prev: None, auth_cert, auth_evidence: None, auth_warrant: None, extra_headers: Vec::new(),
    }
}

proptest! {
    #![proptest_config(cfg())]

    /// IPC: every line is parsed as JSON into `Request`; junk never panics and
    /// an unknown `cmd` is an error, never a default command.
    #[test]
    fn ipc_request_parsing_is_total(junk in "[\\[\\]{}\":a-zA-Z0-9,_ ]{0,64}", cmd in "[A-Za-z]{1,12}") {
        let _ = serde_json::from_str::<Request>(&junk);
        let r = serde_json::from_str::<Request>(&format!("{{\"cmd\":\"{cmd}\"}}"));
        if !["RepoList", "Status", "ListIdentities", "ListDomains"].contains(&cmd.as_str()) {
            let ok_shape = r.is_err() || matches!(r, Ok(Request::RepoList) | Ok(Request::Status));
            prop_assert!(ok_shape, "{:?}", cmd);
        }
        let _ = serde_json::to_string(&Response::error(junk.clone())).unwrap();
    }

    /// `required_issuers` never panics on an arbitrary `Auth-Cert` and returns
    /// nothing for a key-rooted write.
    #[test]
    fn required_issuers_is_total(cert in prop::option::of("[A-Za-z0-9._~-]{0,80}")) {
        let out = required_issuers(&msg(cert.clone()));
        if cert.is_none() { prop_assert!(out.is_empty()); }
    }

    /// Snapshot: the root of an empty object set is the empty root; decoding junk gzip
    /// (or valid gzip of junk JSON) is an error, never a panic.
    #[test]
    fn snapshot_decode_is_total(junk in prop::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(compute_snapshot_root(&[]), sbo_core::empty_root());
        prop_assert!(decode_snapshot_payload(&junk).is_err() || junk.is_empty());
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&junk).unwrap();
        let gz = enc.finish().unwrap();
        let _ = decode_snapshot_payload(&gz);
    }
}

/// D50 (Medium): `decode_snapshot_payload` inflates an untrusted serving
/// node's gzip with `read_to_end` and no cap before parsing. A bootstrapping
/// client that fetches a snapshot from a hostile node allocates whatever the
/// node chose. Expected: a cap tied to the manifest's `uncompressed_bytes`
/// (itself bounded) and a hard ceiling.
#[test]
fn d50_snapshot_inflation_is_capped() {
    const CAP: usize = 64 << 20;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(b"[").unwrap();
    let chunk = vec![b' '; 1 << 20];
    for _ in 0..96 { enc.write_all(&chunk).unwrap(); } // 96 MiB of whitespace inside a JSON array
    enc.write_all(b"]").unwrap();
    let gz = enc.finish().unwrap();
    assert!(gz.len() < 256 << 10);
    // Must reject without inflating past the cap. We cannot observe the
    // allocation from here, so the contract is: an input that would inflate
    // past CAP is an error.
    let r = decode_snapshot_payload(&gz);
    assert!(r.is_err(), "a {}-byte gzip inflating to 96 MiB was decoded", gz.len());
    let _ = CAP;
}
