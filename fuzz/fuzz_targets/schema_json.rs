#![no_main]
//! WS3: every payload schema parser (`attestation.v1`, `collection.v1`,
//! `post.v1`, `comment.v1`, `reaction.v1`, identity/domain JWT schemas) and
//! `validate_schema` are total on arbitrary (schema-name, payload) pairs;
//! an attestation that validates has a well-formed type and a non-negative
//! expiry span; a collection that validates has non-negative lags.

use libfuzzer_sys::fuzz_target;
use sbo_core::schema::{parse_attestation, parse_collection, parse_comment, parse_post, parse_reaction, validate_schema};

fuzz_target!(|data: &[u8]| {
    let Some(nul) = data.iter().position(|&b| b == 0) else { return };
    let schema = String::from_utf8_lossy(&data[..nul]).into_owned();
    let payload = data[nul + 1..].to_vec();
    if schema.contains(['\n', '\r']) { return; }
    let _ = parse_attestation(&payload);
    let _ = parse_collection(&payload);
    let _ = parse_post(&payload);
    let _ = parse_comment(&payload);
    let _ = parse_reaction(&payload);
    let mut msg = sbo_fuzz::envelope("/u/alice/attestations/bob/", "role:moderator", payload.clone(), 1);
    msg.content_schema = Some(schema.clone());
    msg.owner = Some(sbo_core::message::Id::new("alice").unwrap());
    let r = validate_schema(&msg);
    if r.is_ok() {
        match schema.as_str() {
            "attestation.v1" => {
                let a = parse_attestation(&payload).expect("validated attestation parses");
                assert!(!a.subject.is_empty());
                assert!(a.type_.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':' || b == b'-'), "type {:?}", a.type_);
                if let Some(e) = a.expires { assert!(e >= a.issued_at); }
                if let Some(i) = &a.issuer { assert_eq!(i, "alice"); }
                // in-force is monotone: effective at issued_at, never after expires.
                assert!(a.is_in_force(a.issued_at) || a.expires == Some(a.issued_at));
                if let Some(e) = a.expires { assert!(!a.is_in_force(e)); }
            }
            "collection.v1" => {
                let c = parse_collection(&payload).unwrap();
                assert!(c.batch_interval_s.map_or(true, |v| v >= 0));
                assert!(c.max_authoring_lag_s.map_or(true, |v| v >= 0));
            }
            _ => {}
        }
    }
});
