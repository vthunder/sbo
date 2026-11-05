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
    /// Headers this implementation does not model, verbatim and in received
    /// order (decision Q32 (c)): listed-but-unmodelled ones (`Attestation`,
    /// `Origin`, …), `Critical`, and `X-` experimental headers. They are inside
    /// the signed block and reserialize to their received position, so the
    /// message hashes and verifies as the signer produced it.
    pub extra_headers: Vec<(String, String)>,
}

impl Message {
    /// The signing content a producer signs: every header in canonical order
    /// except `Signature`, then the blank line. A consumer verifies the
    /// received bytes instead (`wire::signing_content`); for a parsed message
    /// the two are byte-equal because the parser admits only canonical input.
    pub fn canonical_signing_content(&self) -> Vec<u8> {
        crate::wire::signing_content_of(self)
    }

    /// Sign this message
    pub fn sign(&mut self, signing_key: &crate::crypto::SigningKey) {
        let content = self.canonical_signing_content();
        self.signature = signing_key.sign(&content);
    }
}

