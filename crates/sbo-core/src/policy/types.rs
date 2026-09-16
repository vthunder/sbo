//! Policy types

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::path::{IdPattern, PathPattern};

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

    /// P2 — version pin. When present, this policy freezes its delegation terms
    /// to a specific historical version of its ancestor policy: the ancestor's
    /// governance (who may amend THIS policy) resolves against the pinned
    /// version, so later ancestor amendments cannot reach in (the sovereignty
    /// property). Absent ⇒ the policy TRACKS its latest ancestor (revocable /
    /// eminent-domain regime). Optional + skipped when absent, so an unpinned
    /// `policy.v2` document is byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<PolicyPin>,

    /// P3/P4 — descendant-policy constraint clause. A ceiling/template this
    /// policy imposes on its DIRECT child policies. Absent ⇒ no constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descendant_constraint: Option<DescendantConstraint>,
}

/// P2 — a version pin: the specific historical ancestor-policy version this
/// policy agreed to. The `hash` (the ancestor policy object's on-chain
/// content-hash, `"sha256:<hex>"`) is authoritative and reorg-safe; `block` is a
/// locator hint only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPin {
    /// Fully-qualified container path of the pinned ancestor policy
    /// (e.g. `"/sys/policies/"`).
    pub ancestor: String,
    /// The pinned ancestor policy object's content-hash (`"sha256:<hex>"`).
    pub hash: String,
    /// Block number of the pinned version — a locator HINT only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<u64>,
}

/// P3/P4 — descendant-policy constraint clause: what a parent policy allows and
/// mandates for its DIRECT child policies (each level re-delegates its own
/// template downward, keeping every check local).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DescendantConstraint {
    /// The grants a direct child policy MAY make. Every child grant must be
    /// covered by one of these (subset-of-template). An empty list forbids the
    /// child from granting anything.
    #[serde(default)]
    pub allowed_grants: Vec<Grant>,

    /// Restrictions every direct child policy MUST carry (present verbatim).
    #[serde(default)]
    pub mandated_restrictions: Vec<Restriction>,

    /// P4 — forbid direct children from pinning, forcing them to always track
    /// the latest ancestor version (strict top-down / unix-fs regime).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forbid_pinning: bool,
}

/// Grant: who can do what on which paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub to: Identity,
    pub can: Vec<ActionType>,
    pub on: PathPattern,

    /// Optional object-id pattern. `on` matches the container PATH; this matches
    /// the object's ID within it. Absent ⇒ any id, so every policy written before
    /// this field existed keeps its exact meaning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<IdPattern>,
}

/// Restriction: conditions on allowed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restriction {
    pub on: PathPattern,

    /// Optional object-id pattern, with the same meaning as on a [`Grant`]:
    /// absent ⇒ any id. The matching language is deliberately identical for
    /// grants and restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<IdPattern>,

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

    /// Conditions on values inside the payload, addressed by JSON pointer.
    /// Every condition must hold (they are AND-ed with each other and with the
    /// rest of the requirements). Empty ⇒ no payload-value conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldCondition>,

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

/// A condition on one value inside a JSON payload.
///
/// Deliberately **scalar**: the policy compares one addressed value against a
/// constant and never evaluates an expression. Anything formula-shaped is
/// carried by the STRUCTURE of the payload and pinned with several conditions
/// (e.g. `fn == "max"` plus a floor on each operand), which keeps the policy
/// language free of a parser.
///
/// Fails closed: a payload that is not JSON, a pointer that resolves to nothing,
/// or a value of the wrong type is a denial, never a pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCondition {
    /// RFC 6901 JSON pointer into the payload, e.g. `/contribution/percentage`.
    pub pointer: String,

    /// The value must equal this exactly (any JSON type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eq: Option<serde_json::Value>,

    /// The value, read as a number, must be >= this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,

    /// The value, read as a number, must be <= this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}
