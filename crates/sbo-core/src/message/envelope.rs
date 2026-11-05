//! SBO message envelope

use crate::crypto::{ContentHash, PublicKey, Signature};
use super::actions::Action;

/// Object type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Object,
    Collection,
}

/// Related object reference (Wire Format Spec §Related Objects).
///
/// Serialized on the wire as one JSON array in the `Related` header:
/// `Related: [{"rel":"license","ref":"sbo+raw://avail:mainnet:13/licenses/cc-by"}]`
///
/// `rel` is an open vocabulary — the spec names `license`, `collection`,
/// `policy` and `origin` as common types and requires unknown ones to pass
/// through, so applications may define their own.
///
/// The Rust field is `reference` because `ref` is a keyword; serde maps it to
/// the spec's `ref` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Related {
    pub rel: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

impl Related {
    /// The `Related` header value: a JSON array, or `None` when there is
    /// nothing to say (an empty array is never emitted).
    pub fn header_value(items: &[Related]) -> Option<String> {
        if items.is_empty() { return None; }
        serde_json::to_string(items).ok()
    }

    /// Parse a `Related` header value. A malformed value is dropped rather than
    /// failing the message: the header is descriptive, never authorizing, and
    /// the Wire spec requires unknown relationship types to pass through.
    pub fn parse_header(v: &str) -> Option<Vec<Related>> {
        serde_json::from_str::<Vec<Related>>(v).ok().filter(|r| !r.is_empty())
    }
}

/// Validated identifier and path: THE identifier grammar lives in `sbo-types`
/// (Core spec §Identifier Syntax; audit 2026-11 Q36) and is re-exported here
/// so the wire parser, sbo-wasm (which `#[path]`-includes this module) and the
/// zkVM guest share one definition by construction.
pub use sbo_types::{Id, Path};

/// Full SBO message
#[derive(Debug, Clone)]
pub struct Message {
    // Required fields
    pub action: Action,
    pub path: Path,
    pub id: Id,
    pub object_type: ObjectType,
    pub signing_key: PublicKey,
    pub signature: Signature,

    // Content fields (required for objects, optional for collections)
    pub content_type: Option<String>,
    pub content_hash: Option<ContentHash>,
    pub payload: Option<Vec<u8>>,

    // Optional fields
    pub owner: Option<Id>,
    pub creator: Option<Id>,
    pub content_encoding: Option<String>,
    pub content_schema: Option<String>,
    pub policy_ref: Option<String>,
    pub related: Option<Vec<Related>>,
    pub hlc: Option<String>,
    pub prev: Option<String>,
    pub auth_cert: Option<String>,
    pub auth_evidence: Option<String>,
    /// Delegator-signed agent warrant (browserid-agent-warrant-v1), required
    /// when `auth_cert` is a typed agent certificate. See the SBO
    /// Authorization Specification (Agent Warrant).
    pub auth_warrant: Option<String>,
}

impl Message {
    /// Build canonical signing content (headers without Signature + blank line)
    pub fn canonical_signing_content(&self) -> Vec<u8> {
        // Header order must match serializer for consistency
        let order: &[&str] = &[
            "SBO-Version", "Action", "Path", "ID", "Type",
            "Content-Type", "Content-Encoding", "Content-Length", "Content-Hash",
            "Attestation", "Content-Schema", "Creator", "HLC", "New-ID", "New-Owner",
            "New-Path", "Object-Path", "Origin", "Owner", "Policy-Ref", "Prev",
            "Proof", "Proof-Type", "Registry-Path", "Related", "Auth-Cert",
            "Auth-Evidence", "Auth-Warrant", "Public-Key",
            // NOTE: Signature is NOT included in signing content
        ];

        let mut headers: Vec<(String, String)> = Vec::new();

        headers.push(("SBO-Version".to_string(), "0.5".to_string()));
        headers.push(("Action".to_string(), self.action.name().to_string()));
        if let crate::message::Action::Transfer { new_owner, new_path, new_id } = &self.action {
            if let Some(v) = new_id { headers.push(("New-ID".to_string(), v.as_str().to_string())); }
            if let Some(v) = new_owner { headers.push(("New-Owner".to_string(), v.as_str().to_string())); }
            if let Some(v) = new_path { headers.push(("New-Path".to_string(), v.to_string())); }
        }
        headers.push(("Path".to_string(), self.path.to_string()));
        headers.push(("ID".to_string(), self.id.as_str().to_string()));
        headers.push(("Type".to_string(), match self.object_type {
            ObjectType::Object => "object",
            ObjectType::Collection => "collection",
        }.to_string()));

        if let Some(ref ct) = self.content_type {
            headers.push(("Content-Type".to_string(), ct.clone()));
        }
        if let Some(ref ce) = self.content_encoding {
            headers.push(("Content-Encoding".to_string(), ce.clone()));
        }
        if let Some(ref payload) = self.payload {
            headers.push(("Content-Length".to_string(), payload.len().to_string()));
        }
        if let Some(ref ch) = self.content_hash {
            headers.push(("Content-Hash".to_string(), ch.to_string()));
        }
        if let Some(ref cs) = self.content_schema {
            headers.push(("Content-Schema".to_string(), cs.clone()));
        }
        if let Some(ref creator) = self.creator {
            headers.push(("Creator".to_string(), creator.as_str().to_string()));
        }
        if let Some(ref owner) = self.owner {
            headers.push(("Owner".to_string(), owner.as_str().to_string()));
        }
        if let Some(ref pr) = self.policy_ref {
            headers.push(("Policy-Ref".to_string(), pr.clone()));
        }
        if let Some(ref v) = self.related {
            if let Some(h) = Related::header_value(v) { headers.push(("Related".to_string(), h)); }
        }
        if let Some(ref v) = self.hlc { headers.push(("HLC".to_string(), v.clone())); }
        if let Some(ref v) = self.prev { headers.push(("Prev".to_string(), v.clone())); }
        if let Some(ref v) = self.auth_cert { headers.push(("Auth-Cert".to_string(), v.clone())); }
        if let Some(ref v) = self.auth_evidence { headers.push(("Auth-Evidence".to_string(), v.clone())); }
        if let Some(ref v) = self.auth_warrant { headers.push(("Auth-Warrant".to_string(), v.clone())); }
        headers.push(("Public-Key".to_string(), self.signing_key.to_string()));
        // NOTE: Signature is NOT included

        // Sort by canonical order
        headers.sort_by_key(|(name, _)| {
            order.iter().position(|&h| h == name).unwrap_or(999)
        });

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

    /// Sign this message
    pub fn sign(&mut self, signing_key: &crate::crypto::SigningKey) {
        let content = self.canonical_signing_content();
        self.signature = signing_key.sign(&content);
    }
}

