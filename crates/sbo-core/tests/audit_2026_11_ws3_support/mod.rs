//! Shared strategies and builders for the WS3 property suites (security audit
//! 2026-11). Integration-test support module: `mod audit_2026_11_ws3_support;`.
#![allow(dead_code)]

use proptest::prelude::*;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};

/// The Core spec identifier grammar: `A-Z a-z 0-9 - _ . ~ @ + :`, 1–256 chars.
pub fn id_char() -> impl Strategy<Value = char> {
    prop::sample::select(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~@+:"
            .chars()
            .collect::<Vec<_>>(),
    )
}

/// A grammar-valid id (short, so paths stay readable in failure output).
pub fn id_str() -> impl Strategy<Value = String> {
    prop::collection::vec(id_char(), 1..12).prop_map(|v| v.into_iter().collect())
}

/// An id made only of the "safe" subset (no `.`-only forms, no `@`): what
/// ordinary object ids look like.
pub fn plain_id_str() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9_-]{0,10}".prop_map(|s| s)
}

/// A well-formed path `/a/b/` with 0..4 segments.
pub fn path_str() -> impl Strategy<Value = String> {
    prop::collection::vec(plain_id_str(), 0..4)
        .prop_map(|segs| if segs.is_empty() { "/".to_string() } else { format!("/{}/", segs.join("/")) })
}

/// Arbitrary payload bytes (bounded).
pub fn payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

/// A deterministic signing key from a seed byte, so shrinking is stable.
pub fn key_from_seed(seed: u8) -> SigningKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[31] = seed.wrapping_mul(7).wrapping_add(1);
    SigningKey::from_bytes(&b)
}

/// Build an unsigned message with the given shape (payload carried, hash set).
pub fn message(path: &str, id: &str, payload: Vec<u8>, key: &SigningKey) -> Message {
    Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
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
    }
}

/// Build and sign.
pub fn signed(path: &str, id: &str, payload: Vec<u8>, key: &SigningKey) -> Message {
    let mut m = message(path, id, payload, key);
    m.sign(key);
    m
}

/// Replace the value of header `name` in a wire image (first occurrence).
pub fn set_header(wire: &[u8], name: &str, value: &str) -> Vec<u8> {
    let (head, body) = split_wire(wire);
    let mut out = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        if line.is_empty() { continue; }
        if line.starts_with(format!("{name}: ").as_bytes()) {
            out.extend_from_slice(format!("{name}: {value}").as_bytes());
        } else {
            out.extend_from_slice(line);
        }
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}

/// Split a wire image at the blank line → (header block incl. trailing LF, payload).
pub fn split_wire(wire: &[u8]) -> (&[u8], &[u8]) {
    let pos = wire.windows(2).position(|w| w == b"\n\n").expect("blank line");
    (&wire[..pos + 1], &wire[pos + 2..])
}

/// The header lines of a wire image as (name, value) pairs, in wire order.
pub fn header_lines(wire: &[u8]) -> Vec<(String, String)> {
    let (head, _) = split_wire(wire);
    head.split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let s = std::str::from_utf8(l).unwrap();
            let (n, v) = s.split_once(": ").unwrap();
            (n.to_string(), v.to_string())
        })
        .collect()
}

/// Rebuild a wire image from header pairs (in the given order) and a payload.
pub fn join_wire(headers: &[(String, String)], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, v) in headers {
        out.extend_from_slice(format!("{n}: {v}\n").as_bytes());
    }
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}
