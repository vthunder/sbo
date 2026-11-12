//! Wire format serializer — the producer side only.
//!
//! Decision Q32 (c), "bytes in, bytes out": a consumer never reserializes a
//! received message to verify, hash, store or forward it; it uses the bytes it
//! received (see [`super::signing_content`] and [`super::parse_batch_raw`]).
//! `serialize` exists for the signer, which serializes once, when it signs.
//! Because the parser admits only canonical input, `serialize(parse(x)) == x`
//! for every accepted `x`, which the audit suite pins.

use crate::message::{Message, ObjectType};
use super::headers::header_rank;

/// Every header line of `msg` in canonical order, including `Signature` when
/// `with_signature` is set.
pub(crate) fn header_lines(msg: &Message, with_signature: bool) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();

    headers.push(("SBO-Version".to_string(), "0.5".to_string()));
    headers.push(("Action".to_string(), msg.action.name().to_string()));
    if let crate::message::Action::Transfer { new_owner, new_path, new_id } = &msg.action {
        if let Some(v) = new_id { headers.push(("New-ID".to_string(), v.as_str().to_string())); }
        if let Some(v) = new_owner { headers.push(("New-Owner".to_string(), v.as_str().to_string())); }
        if let Some(v) = new_path { headers.push(("New-Path".to_string(), v.to_string())); }
    }
    headers.push(("Path".to_string(), msg.path.to_string()));
    headers.push(("ID".to_string(), msg.id.as_str().to_string()));
    headers.push(("Type".to_string(), match msg.object_type {
        ObjectType::Object => "object",
        ObjectType::Collection => "collection",
    }.to_string()));

    if let Some(ref ct) = msg.content_type {
        headers.push(("Content-Type".to_string(), ct.clone()));
    }
    if let Some(ref ce) = msg.content_encoding {
        headers.push(("Content-Encoding".to_string(), ce.clone()));
    }
    if let Some(ref payload) = msg.payload {
        headers.push(("Content-Length".to_string(), payload.len().to_string()));
    }
    if let Some(ref ch) = msg.content_hash {
        headers.push(("Content-Hash".to_string(), ch.to_string()));
    }
    if let Some(ref cs) = msg.content_schema {
        headers.push(("Content-Schema".to_string(), cs.clone()));
    }
    if let Some(ref creator) = msg.creator {
        headers.push(("Creator".to_string(), creator.as_str().to_string()));
    }
    if let Some(ref owner) = msg.owner {
        headers.push(("Owner".to_string(), owner.as_str().to_string()));
    }
    if let Some(ref rel) = msg.related {
        if let Some(v) = crate::message::Related::header_value(rel) {
            headers.push(("Related".to_string(), v));
        }
    }
    if let Some(ref pr) = msg.policy_ref {
        headers.push(("Policy-Ref".to_string(), pr.clone()));
    }
    if let Some(ref v) = msg.hlc { headers.push(("HLC".to_string(), v.clone())); }
    if let Some(ref v) = msg.prev { headers.push(("Prev".to_string(), v.clone())); }
    if let Some(ref v) = msg.auth_cert { headers.push(("Auth-Cert".to_string(), v.clone())); }
    if let Some(ref v) = msg.auth_evidence { headers.push(("Auth-Evidence".to_string(), v.clone())); }
    if let Some(ref v) = msg.auth_warrant { headers.push(("Auth-Warrant".to_string(), v.clone())); }

    // Headers this implementation does not model (Q32 (c)): listed ones sort
    // to their listed slot, unknown ones to slot 27 in byte order of name.
    for (name, value) in &msg.extra_headers {
        headers.push((name.clone(), value.clone()));
    }

    headers.push(("Public-Key".to_string(), msg.signing_key.to_string()));
    if with_signature {
        headers.push(("Signature".to_string(), msg.signature.to_hex()));
    }

    headers.sort_by(|(a, _), (b, _)| header_rank(a).cmp(&header_rank(b)).then_with(|| a.cmp(b)));
    headers
}

fn write_header_block(headers: &[(String, String)]) -> Vec<u8> {
    let mut output = Vec::new();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    output.push(b'\n');
    output
}

/// The signing content of a message built by a producer: every header in
/// canonical order except `Signature`, then the blank line. For a parsed
/// message this equals [`super::signing_content`] of the received bytes.
pub(crate) fn signing_content_of(msg: &Message) -> Vec<u8> {
    write_header_block(&header_lines(msg, false))
}

/// Serialize a Message to wire format bytes
pub fn serialize(msg: &Message) -> Vec<u8> {
    let mut output = write_header_block(&header_lines(msg, true));
    if let Some(ref payload) = msg.payload {
        output.extend_from_slice(payload);
    }
    output
}
