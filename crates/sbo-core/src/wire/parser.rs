//! Wire format parser — the consumer side.
//!
//! The parser admits only canonical input (Wire Format spec §Validation):
//! headers in canonical order, each at most once, `Content-Length` a canonical
//! decimal, hex lowercase, `Content-Hash` equal to the hash of the payload.
//! Headers it does not model are kept, in place, in `Message::extra_headers`
//! (decision Q32 (c): sign what was sent; an unknown header is valid iff the
//! signer covered it). A `Critical` header lists names a consumer must
//! understand; one it does not rejects the message.
//!
//! Every accepted message therefore reserializes to the bytes received, and a
//! consumer verifies and hashes the received bytes themselves:
//! [`signing_content`] and [`parse_batch_raw`].

use crate::error::ParseError;
use crate::message::Message;
use super::headers::{
    extension_rank, header_rank, is_modelled, CRITICAL_HEADER, MAX_HEADER_BLOCK_BYTES,
    MAX_MESSAGE_BYTES, MAX_SUBMISSION_BYTES,
};

/// Parse a single header line "Name: value"
pub fn parse_header_line(line: &[u8]) -> Result<(&str, &str), ParseError> {
    // Reject CRLF
    if line.contains(&b'\r') {
        return Err(ParseError::CrlfNotAllowed);
    }

    let line_str = std::str::from_utf8(line)
        .map_err(|_| ParseError::InvalidHeader("Invalid UTF-8".to_string()))?;

    let colon_pos = line_str.find(": ")
        .ok_or_else(|| ParseError::InvalidHeader("Missing ': ' separator".to_string()))?;

    let name = &line_str[..colon_pos];
    let value = &line_str[colon_pos + 2..];

    if name.is_empty() {
        return Err(ParseError::InvalidHeader("Empty header name".to_string()));
    }

    Ok((name, value))
}

/// Split message into header lines and payload at blank line (returns all remaining bytes as payload)
pub fn split_message(bytes: &[u8]) -> Result<(Vec<(&str, &str)>, &[u8]), ParseError> {
    let s = scan_headers(bytes, 0)?;
    Ok((s.headers, &bytes[s.body_start..]))
}

/// The header block of one message, as scanned from `start`.
struct Scan<'a> {
    headers: Vec<(&'a str, &'a str)>,
    /// Offset of the first byte of the last header line (relative to the buffer).
    last_header_start: usize,
    /// Offset of the first payload byte (just past the blank line).
    body_start: usize,
}

/// Walk header lines from `start` up to and including the blank line.
fn scan_headers(bytes: &[u8], start: usize) -> Result<Scan<'_>, ParseError> {
    let mut pos = start;
    let mut headers: Vec<(&str, &str)> = Vec::new();
    let mut last_header_start = start;

    while pos < bytes.len() {
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];

        if line.is_empty() {
            return Ok(Scan { headers, last_header_start, body_start: line_end + 1 });
        }

        // §Size Bounds: the header block of one message is at most
        // MAX_HEADER_BLOCK_BYTES, checked before the line is interpreted.
        if line_end - start >= MAX_HEADER_BLOCK_BYTES {
            return Err(ParseError::InvalidHeader("header block too large".to_string()));
        }

        let (name, value) = parse_header_line(line)?;
        headers.push((name, value));
        last_header_start = pos;

        pos = line_end + 1;
    }

    Err(ParseError::MissingBlankLine)
}

/// A canonical decimal integer: digits only, no sign, no leading zero
/// (Wire Format spec §Encoding Rules; S22).
fn parse_canonical_usize(field: &str, s: &str) -> Result<usize, ParseError> {
    let bad = |why: &str| ParseError::InvalidHeader(format!("{field}: {why}"));
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("not a canonical decimal integer"));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(bad("leading zero"));
    }
    if s.len() > 19 {
        return Err(bad("out of range"));
    }
    let v: u64 = s.parse().map_err(|_| bad("out of range"))?;
    usize::try_from(v).map_err(|_| bad("out of range"))
}

/// Hex values are lowercase (Wire Format spec §Encoding Rules). Non-hex
/// characters and wrong lengths are rejected by the typed parsers.
fn require_lowercase_hex(field: &str, hex: &str) -> Result<(), ParseError> {
    if hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ParseError::InvalidHeader(format!("{field}: hex must be lowercase")));
    }
    Ok(())
}

/// The bytes a signature covers, taken from the received message: the header
/// block minus the `Signature` line, then the blank line (Core spec
/// §Signature Scope; decision Q32 (c)). `Signature` must be the last header.
/// Nothing is reserialized.
pub fn signing_content(bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    let s = scan_headers(bytes, 0)?;
    match s.headers.last() {
        Some(("Signature", _)) => {}
        Some((other, _)) => {
            return Err(ParseError::HeaderOrder(format!("{other} after Signature")));
        }
        None => return Err(ParseError::MissingHeader("Signature".to_string())),
    }
    let mut out = bytes[..s.last_header_start].to_vec();
    out.push(b'\n');
    Ok(out)
}

/// Parse raw bytes into a validated Message
pub fn parse(bytes: &[u8]) -> Result<Message, ParseError> {
    let (msg, _) = parse_at(bytes, 0)?;
    Ok(msg)
}

/// Parse multiple concatenated messages from a batch
pub fn parse_batch(bytes: &[u8]) -> Result<Vec<Message>, ParseError> {
    Ok(parse_batch_raw(bytes)?.into_iter().map(|(m, _)| m).collect())
}

/// Parse a batch and return, with each message, the exact bytes it was parsed
/// from. Consumers hash, store and forward those bytes (`object_hash =
/// sha256(received)`), never a reserialization. A submission over
/// `MAX_SUBMISSION_BYTES`, or any message that fails to parse, rejects the
/// whole submission (§Batch Parsing Algorithm).
pub fn parse_batch_raw(bytes: &[u8]) -> Result<Vec<(Message, &[u8])>, ParseError> {
    if bytes.len() > MAX_SUBMISSION_BYTES {
        return Err(ParseError::InvalidHeader("submission too large".to_string()));
    }
    let mut messages = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        let (msg, end_pos) = parse_at(bytes, pos)?;
        messages.push((msg, &bytes[pos..end_pos]));
        pos = end_pos;
    }

    Ok(messages)
}

/// Reject duplicate headers and non-canonical order (§Validation 2, 14, 15):
/// listed headers in list order, unknown headers in slot 27 in byte order of
/// their names.
fn check_canonical_form(headers: &[(&str, &str)]) -> Result<(), ParseError> {
    let mut seen: Vec<&str> = Vec::with_capacity(headers.len());
    let mut prev: Option<(usize, &str)> = None;
    let ext = extension_rank();
    for (name, _) in headers {
        if seen.contains(name) {
            return Err(ParseError::DuplicateHeader(name.to_string()));
        }
        seen.push(name);
        let rank = header_rank(name);
        if let Some((p_rank, p_name)) = prev {
            let ok = rank > p_rank || (rank == p_rank && rank == ext && *name > p_name);
            if !ok {
                return Err(ParseError::HeaderOrder(name.to_string()));
            }
        }
        prev = Some((rank, name));
    }
    Ok(())
}

/// Parse a single message starting at offset, returns (Message, end_position)
fn parse_at(bytes: &[u8], start: usize) -> Result<(Message, usize), ParseError> {
    use crate::message::{Action, ObjectType, Id, Path};
    use crate::crypto::{PublicKey, Signature, ContentHash};
    use std::collections::HashMap;

    let scan = scan_headers(bytes, start)?;
    check_canonical_form(&scan.headers)?;

    // Headers this implementation does not model are carried verbatim, in
    // received (= canonical) order. `Critical` is interpreted below but still
    // carried, so the message reserializes to the received bytes.
    let extra_headers: Vec<(String, String)> = scan.headers.iter()
        .filter(|(n, _)| !is_modelled(n) || *n == CRITICAL_HEADER)
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();

    let headers: HashMap<&str, &str> = scan.headers.iter().copied().collect();

    // Required headers
    let version = headers.get("SBO-Version")
        .ok_or_else(|| ParseError::MissingHeader("SBO-Version".to_string()))?;
    if *version != "0.5" {
        return Err(ParseError::UnsupportedVersion(version.to_string()));
    }

    // Q32 (c): a header this consumer must not skip, and does not know, rejects.
    if let Some(critical) = headers.get(CRITICAL_HEADER) {
        for name in critical.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            if !is_modelled(name) {
                return Err(ParseError::UnknownCriticalHeader(name.to_string()));
            }
        }
    }

    let action_str = headers.get("Action")
        .ok_or_else(|| ParseError::MissingHeader("Action".to_string()))?;
    let action = Action::parse(action_str)
        .map_err(|e| ParseError::InvalidHeader(format!("Action: {}", e)))?;

    let path = Path::parse(headers.get("Path")
        .ok_or_else(|| ParseError::MissingHeader("Path".to_string()))?)?;

    let id = Id::new(headers.get("ID")
        .ok_or_else(|| ParseError::MissingHeader("ID".to_string()))?)?;

    let object_type = match *headers.get("Type")
        .ok_or_else(|| ParseError::MissingHeader("Type".to_string()))? {
        "object" => ObjectType::Object,
        "collection" => ObjectType::Collection,
        other => return Err(ParseError::InvalidHeader(format!("Type: {}", other))),
    };

    // Payload length: the batch splitter needs it before anything else
    // (checked arithmetic — W3-10).
    let content_length = headers.get("Content-Length")
        .map(|v| parse_canonical_usize("Content-Length", v))
        .transpose()?;
    let payload_len = content_length.unwrap_or(0);
    // §Size Bounds: one message (header block + payload) is at most
    // MAX_MESSAGE_BYTES; the payload must also fit the bytes remaining.
    let header_block_len = scan.body_start - start;
    if payload_len > MAX_MESSAGE_BYTES || header_block_len + payload_len > MAX_MESSAGE_BYTES {
        return Err(ParseError::InvalidHeader("Content-Length: out of range".to_string()));
    }
    let end_pos = scan.body_start.checked_add(payload_len)
        .filter(|&e| e <= bytes.len())
        .ok_or(ParseError::ContentLengthMismatch {
            expected: payload_len,
            actual: bytes.len().saturating_sub(scan.body_start),
        })?;
    let payload = &bytes[scan.body_start..end_pos];

    // Content headers. A payload is declared by Content-Length; the hash is
    // REQUIRED with a payload and meaningless without one (D1).
    let content_type = headers.get("Content-Type").map(|s| s.to_string());
    let content_encoding = headers.get("Content-Encoding").map(|s| s.to_string());
    let content_hash = headers.get("Content-Hash")
        .map(|s| {
            let hex = s.split_once(':').map(|(_, h)| h).unwrap_or(s);
            require_lowercase_hex("Content-Hash", hex)?;
            ContentHash::parse(s)
                .map_err(|e| ParseError::InvalidHeader(format!("Content-Hash: {:?}", e)))
        })
        .transpose()?;

    match (content_length, &content_hash) {
        (Some(_), Some(ch)) => {
            if *ch != ContentHash::sha256(payload) {
                return Err(ParseError::ContentHashMismatch);
            }
        }
        (Some(_), None) => return Err(ParseError::MissingHeader("Content-Hash".to_string())),
        (None, Some(_)) => {
            return Err(ParseError::InvalidHeader("Content-Hash without Content-Length".to_string()));
        }
        (None, None) => {}
    }
    if content_length.is_none() && (content_type.is_some() || content_encoding.is_some()) {
        return Err(ParseError::InvalidHeader("content header without Content-Length".to_string()));
    }
    // A `post` of an object carries content (Wire Format spec §Required Headers).
    if matches!(action, Action::Post) && object_type == ObjectType::Object && content_length.is_none() {
        return Err(ParseError::MissingHeader("Content-Length".to_string()));
    }

    // Crypto headers
    let pk_str = headers.get("Public-Key")
        .ok_or_else(|| ParseError::MissingHeader("Public-Key".to_string()))?;
    require_lowercase_hex("Public-Key", pk_str.split_once(':').map(|(_, h)| h).unwrap_or(pk_str))?;
    let signing_key = PublicKey::parse(pk_str)
        .map_err(|e| ParseError::InvalidHeader(format!("Public-Key: {:?}", e)))?;

    let sig_str = headers.get("Signature")
        .ok_or_else(|| ParseError::MissingHeader("Signature".to_string()))?;
    require_lowercase_hex("Signature", sig_str)?;
    let signature = Signature::parse(sig_str)
        .map_err(|e| ParseError::InvalidHeader(format!("Signature: {:?}", e)))?;

    // Optional headers
    let owner = headers.get("Owner").map(|s| Id::new(*s)).transpose()?;
    let creator = headers.get("Creator").map(|s| Id::new(*s)).transpose()?;
    let content_schema = headers.get("Content-Schema").map(|s| s.to_string());
    let policy_ref = headers.get("Policy-Ref").map(|s| s.to_string());
    let related = headers.get("Related").and_then(|s| crate::message::Related::parse_header(s));
    let hlc = headers.get("HLC").map(|s| s.to_string());
    let prev = headers.get("Prev").map(|s| s.to_string());
    let auth_cert = headers.get("Auth-Cert").map(|s| s.to_string());
    let auth_evidence = headers.get("Auth-Evidence").map(|s| s.to_string());
    let auth_warrant = headers.get("Auth-Warrant").map(|s| s.to_string());

    // Transfer destination headers. `Action::parse` cannot see headers, so it
    // yields `Transfer { None, None, None }`; populate the fields here and
    // enforce the wire rule that at least one New-* is present (Wire Format
    // Spec §Conditionally Required Headers). `New-Owner: null:` is the delete
    // spelling and is carried through verbatim.
    let action = if matches!(action, Action::Transfer { .. }) {
        let new_owner = headers.get("New-Owner").map(|s| Id::new(*s)).transpose()?;
        let new_path = headers.get("New-Path").map(|s| Path::parse(s)).transpose()?;
        let new_id = headers.get("New-ID").map(|s| Id::new(*s)).transpose()?;
        if new_owner.is_none() && new_path.is_none() && new_id.is_none() {
            return Err(ParseError::InvalidHeader(
                "transfer requires at least one of New-Owner, New-Path, New-ID".to_string(),
            ));
        }
        Action::Transfer { new_owner, new_path, new_id }
    } else {
        action
    };

    Ok((Message {
        action,
        path,
        id,
        object_type,
        signing_key,
        signature,
        content_type,
        content_hash,
        // A message carries a payload iff it declared one (Content-Length present).
        // Payload-less actions (e.g. transfer/delete) have no Content-Length and
        // must round-trip to `payload: None`, not `Some(empty)`.
        payload: content_length.map(|_| payload.to_vec()),
        owner,
        creator,
        content_encoding,
        content_schema,
        policy_ref,
        related,
        hlc,
        prev,
        auth_cert,
        auth_evidence,
        auth_warrant,
        extra_headers,
    }, end_pos))
}
