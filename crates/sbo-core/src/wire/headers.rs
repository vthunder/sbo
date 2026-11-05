//! Header types, the canonical header order and the modelled-header set.

use std::collections::HashMap;

/// Canonical header order (Wire Format spec §Canonical Header Order). A
/// producer emits headers in this order; a consumer rejects a message whose
/// headers are not in it (§Validation 2). Every name here is "listed": a
/// listed header the implementation does not model (`Attestation`, `Origin`,
/// `Proof`, …) is still placed at its listed rank. Unknown and `X-` headers
/// take slot 27, between `Critical` and `Auth-Cert`.
///
/// `Auth-Warrant` is no longer a header in the spec (v0.5 audit: the warrant
/// lives in the `Auth-Cert` presentation); it stays here, after
/// `Auth-Evidence`, until the `Message` field is removed by the Q1 bean.
pub const HEADER_ORDER: &[&str] = &[
    "SBO-Version",
    "Action",
    "Path",
    "ID",
    "Type",
    "Content-Type",
    "Content-Encoding",
    "Content-Length",
    "Content-Hash",
    "Attestation",
    "Content-Schema",
    "Creator",
    "HLC",
    "New-ID",
    "New-Owner",
    "New-Path",
    "Object-Path",
    "Origin",
    "Owner",
    "Policy-Ref",
    "Prev",
    "Proof",
    "Proof-Type",
    "Registry-Path",
    "Related",
    "Critical",
    "Auth-Cert",
    "Auth-Evidence",
    "Auth-Warrant",
    "Public-Key",
    "Signature",
];

/// Size bounds (Wire Format spec §Size Bounds). Every length computation in
/// the parser is checked against these before any slice is taken.
pub const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SUBMISSION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;

/// Headers whose meaning this implementation understands. A `Critical` header
/// naming anything outside this set rejects the message (decision Q32 (c)).
pub const MODELLED_HEADERS: &[&str] = &[
    "SBO-Version",
    "Action",
    "Path",
    "ID",
    "Type",
    "Content-Type",
    "Content-Encoding",
    "Content-Length",
    "Content-Hash",
    "Content-Schema",
    "Creator",
    "HLC",
    "New-ID",
    "New-Owner",
    "New-Path",
    "Owner",
    "Policy-Ref",
    "Prev",
    "Related",
    "Auth-Cert",
    "Auth-Evidence",
    "Auth-Warrant",
    "Public-Key",
    "Signature",
    "Critical",
];

/// The header that lists names an old client must not skip (Q32 (c)).
pub const CRITICAL_HEADER: &str = "Critical";

/// Prefix reserved for experimental headers (Q32 (c)).
pub const EXPERIMENTAL_PREFIX: &str = "X-";

/// Rank of a header in the canonical order. Listed headers rank by position
/// (doubled, so a slot exists between any two). Headers not in the list —
/// `X-…` and any other unknown header — share slot 27, immediately after
/// `Critical` and before `Auth-Cert`: after every modelled header, inside the
/// signed block, and in byte order of their names among themselves.
pub fn header_rank(name: &str) -> usize {
    match HEADER_ORDER.iter().position(|&h| h == name) {
        Some(i) => i * 2,
        None => extension_rank(),
    }
}

/// The rank shared by every unknown header.
pub fn extension_rank() -> usize {
    let auth = HEADER_ORDER.iter().position(|&h| h == "Auth-Cert").expect("Auth-Cert is listed");
    auth * 2 - 1
}

pub fn is_modelled(name: &str) -> bool {
    MODELLED_HEADERS.contains(&name)
}

/// Map of header names to values
#[derive(Debug, Default)]
pub struct HeaderMap(HashMap<String, String>);

impl HeaderMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.insert(name.into(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }

    pub fn require(&self, name: &str) -> Result<&str, crate::error::ParseError> {
        self.get(name)
            .ok_or_else(|| crate::error::ParseError::MissingHeader(name.to_string()))
    }
}
