//! Policy types

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::path::PathPattern;

/// Policy document (policy.v2 schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub roles: HashMap<String, Vec<Identity>>,

    #[serde(default)]
    pub deny: Vec<PathPattern>,

    #[serde(default)]
    pub grants: Vec<Grant>,

    #[serde(default)]
    pub restrictions: Vec<Restriction>,
}

/// Grant: who can do what on which paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub to: Identity,
    pub can: Vec<ActionType>,
    pub on: PathPattern,
}

/// Restriction: conditions on allowed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restriction {
    pub on: PathPattern,
    pub require: Requirements,
}

/// Identity reference in grants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Identity {
    /// Special values: "owner", "*", or a name
    Name(String),
    /// Public key reference
    Key { key: String },
    /// Role reference
    Role { role: String },
    /// Attestation-defined membership: matches a requester who is the in-force
    /// subject of an attestation of `type` (optionally by issuer `by`).
    Attested { attested: AttestedSource },
    /// Any of these identities
    Any { any: Vec<Identity> },
}

/// An attestation source: binds a role member or restriction condition to
/// on-chain attestations rather than a static identity. A requester matches
/// when an in-force `attestation.v1` exists whose `type` equals `type`, whose
/// issuer matches `by` (when given), and whose `subject` resolves to the
/// requester's controller (Policy Spec §Attestation-Defined Roles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedSource {
    #[serde(rename = "type")]
    pub type_: String,
    /// Issuer (attestation `Owner`) whose claims count. Omit to accept any
    /// issuer, including the subject's own self-attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// Action types for grants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    Create,
    Update,
    Post,
    Delete,
    Transfer,
    Import,
    /// Authority to install/replace/delete a `policy.v2` object at a path —
    /// i.e. to GOVERN a subtree. Deliberately NOT covered by `*`/`post`/`create`
    /// (governance is meta-authority, granted only by an explicit `govern`), and
    /// a policy write is authorized against the PARENT policy, never the object's
    /// own. This is what stops an ordinary `create` grant from doubling as a
    /// governance grant (a signer planting a shadowing policy to capture a
    /// subtree). See the SBO policy-delegation model.
    Govern,
    #[serde(rename = "*")]
    All,
}

/// Requirements for restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaRequirement>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Require the payload to be signed by an object at the specified path pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_payload_signed_by: Option<RequirePayloadSignedBy>,

    /// The acting user MUST be the in-force subject of this attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested: Option<AttestedSource>,

    /// The acting user MUST NOT be the in-force subject of this attestation
    /// (e.g. a ban). Absent claim ⇒ condition satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_attested: Option<AttestedSource>,

    /// The payload MUST be a valid RFC 9102 DNSSEC proof for the domain named by
    /// the write's target path (`/sys/dnssec/<domain>` ⇒ `<domain>`). This makes
    /// the object *self-authorizing*: the payload itself proves write-authority
    /// (verified offline against the pinned IANA root KSK on every replay), so an
    /// unprivileged (`to: "*"`) grant is safe. The proof must validate AND carry
    /// a `_browserid.<domain>` record, which binds it to the exact path — a proof
    /// for a different domain is rejected. See the SBO Policy Specification.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dnssec_proof: bool,
}

/// Requirement that an object's payload (JWT) must be signed by another object
///
/// The payload's JWT issuer (e.g., "domain:example.com") is mapped to an object path
/// (e.g., "/sys/domains/example.com"), and the signature is verified against that object's
/// public key. The issuer path must match the specified pattern.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequirePayloadSignedBy {
    /// Path pattern where the signing object must exist
    /// e.g., "/sys/domains/*" means the issuer must be a domain object
    pub path: String,
}

/// Schema requirement (single or multiple allowed)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaRequirement {
    Single(String),
    Any { any: Vec<String> },
}
