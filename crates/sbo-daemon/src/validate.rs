//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::authorize::{
    agent_effective_email, authorize_message, authorize_owner, encode_auth_evidence_inline,
    message_attribution, parse_auth_evidence, AuthzOutcome,
};
use sbo_core::attribution::{self, TrustAnchors};
use sbo_core::uri::SboRawUri;
use sbo_core::message::{Message, Action, Id, Path as SboPath};
use sbo_core::policy::{evaluate, ActionType, AttestedSource, PolicyResult};
use sbo_core::resolve::{resolve_controller, Controller, NameRecord, DEFAULT_HOP_LIMIT};
use sbo_core::schema::{parse_attestation, validate_schema, SchemaError};
use sbo_core::state::StoredObject;

use crate::state_view::StateView;
use std::path::Path;

/// Validation stage that failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    Signature,
    Schema,
    /// HLC ordering-integrity: the write's `HLC` is malformed or falls outside
    /// the validity bound `T_b − W ≤ physical ≤ T_b + ε` (Content Spec).
    Ordering,
    /// L2 attribution: the signer does not speak for the object's owner.
    Attribution,
    State,
    Policy,
}

impl std::fmt::Display for ValidationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStage::Signature => write!(f, "sig"),
            ValidationStage::Schema => write!(f, "schema"),
            ValidationStage::Ordering => write!(f, "ordering"),
            ValidationStage::Attribution => write!(f, "attr"),
            ValidationStage::State => write!(f, "state"),
            ValidationStage::Policy => write!(f, "policy"),
        }
    }
}

/// Context for the L2 attribution layer: the write's DA inclusion time and the
/// pinned trust anchors. Threaded from the block being replayed.
pub struct L2Context {
    /// The DA block's inclusion time (UNIX seconds), if known. `None` means the
    /// block carried no usable timestamp — email-rooted owners then cannot be
    /// attributed and their writes are carried-but-filtered.
    pub inclusion_time: Option<i64>,
    /// Pinned trust anchors (authorized brokers + informational root KSK).
    pub anchors: TrustAnchors,
    /// This database's canonical identity, for checking an agent warrant's
    /// audience (Authorization Spec — the Agent Warrant). `None` when unknown
    /// (e.g. some tests); agent writes then fail closed (no audience to check).
    pub db: Option<DbIdentity>,
}

/// A database's canonical identity for warrant-audience matching.
#[derive(Debug, Clone)]
pub struct DbIdentity {
    /// The repo's `sbo+raw://chain:appId[@firstBlock]` address.
    pub uri: SboRawUri,
    /// The genesis hash (`sha256:…`), if known — pins the audience further.
    pub genesis: Option<String>,
}

impl L2Context {
    /// Build the L2 context for a block, sourcing trust anchors from state.
    pub fn for_block(inclusion_time: Option<i64>, state: &dyn StateView) -> Self {
        Self {
            inclusion_time,
            anchors: load_trust_anchors(state),
            db: None,
        }
    }

    /// Attach this database's identity so agent-warrant audiences can be checked.
    pub fn with_db(mut self, uri: SboRawUri, genesis: Option<String>) -> Self {
        self.db = Some(DbIdentity { uri, genesis });
        self
    }
}

/// Trust-anchor path: the pinned authorized-broker list.
const TRUST_BROKERS_PATH: &str = "/sys/trust/";
const TRUST_BROKERS_ID: &str = "brokers";

/// Load the pinned trust anchors from `/sys/trust/brokers`.
///
/// The object payload is expected to be a JSON array of authorized broker
/// provider domains. Absent or unparseable → an empty broker set (only
/// primary-IdP attribution will succeed). The DNS root KSK is hardcoded inside
/// `dnssec-prover`, so `/sys/trust/dns-root` is not consulted here.
fn load_trust_anchors(state: &dyn StateView) -> TrustAnchors {
    let brokers = (|| {
        let path = SboPath::parse(TRUST_BROKERS_PATH).ok()?;
        let id = Id::new(TRUST_BROKERS_ID).ok()?;
        let obj = state.get_object(&path, &id).ok()??;
        serde_json::from_slice::<Vec<String>>(&obj.payload).ok()
    })()
    .unwrap_or_default();
    // TODO: also surface /sys/trust/dns-root for out-of-band auditing.
    TrustAnchors::with_brokers(brokers)
}

/// Build a `/sys/names/<name>` resolver closure over the state DB, mapping each
/// name record to its [`NameRecord`] kind (key-rooted `identity.v1` vs
/// email-rooted `identity.email.v1`) for [`resolve_controller`] indirection.
fn name_lookup(state: &dyn StateView) -> impl Fn(&str) -> Option<NameRecord> + '_ {
    move |name: &str| {
        let path = SboPath::parse("/sys/names/").ok()?;
        let id = Id::new(name).ok()?;
        let obj = state.get_object(&path, &id).ok()??;
        match obj.content_schema.as_deref() {
            Some("identity.email.v1") => {
                // Email-rooted: recurse on the stored Owner reference.
                obj.owner_ref.map(NameRecord::EmailRooted)
            }
            Some("identity.v1") => {
                // Key-rooted: the durable public key lives in the identity JWT
                // payload (it carries ':' and cannot be an `Id`/`owner`).
                let token = std::str::from_utf8(&obj.payload).ok()?;
                let claims = sbo_core::jwt::decode_identity_claims(token).ok()?;
                Some(NameRecord::KeyRooted(claims.public_key))
            }
            // Unknown/legacy name records are not resolvable controllers.
            _ => None,
        }
    }
}

/// Run the L2 attribution check: does the message's signer speak for
/// `owner_ref` at the block's inclusion time? Returns `Ok(())` if authorized,
/// `Err(reason)` if the write must be carried-but-filtered.
/// The repo's primary domain: the single `/sys/domains/<D>` record if exactly one
/// exists. `None` if there is none, or several (multi-domain repos need
/// domain-qualified name records — deferred; see the sovereignty design). This is
/// what scopes the email→name resolution override.
pub fn primary_domain(state: &dyn StateView) -> Option<String> {
    let domains = state.list_objects_by_path_prefix("/sys/domains/").ok()?;
    let mut it = domains
        .into_iter()
        .filter(|o| o.path.to_string() == "/sys/domains/");
    let first = it.next()?;
    if it.next().is_some() {
        return None; // ambiguous — no override
    }
    Some(first.id.as_str().to_string())
}

/// The **effective author** of an agent write (Authorization Spec §On-behalf
/// writes): the **delegator** when the warrant carries `as:<delegator>`, else
/// the agent's own identity. `Err` if the warrant/scopes don't verify for THIS
/// write.
///
/// The spec requires owner-authorization, `Creator` integrity, name-claim
/// checks, AND "the same on-chain policy the delegator faces" to all evaluate
/// against this effective author. So `l2_authorize` (owner) and
/// `attributed_email` (policy actor / `$email` / attestation subject) both
/// resolve it here — they must never disagree on who the write acts as.
fn resolve_agent_effective(
    msg: &Message,
    state: &dyn StateView,
    l2: &L2Context,
) -> Result<String, String> {
    let signer = msg.signing_key.to_string();
    let cert = msg
        .auth_cert
        .as_deref()
        .ok_or_else(|| "agent write missing Auth-Cert".to_string())?;
    let warrant = msg
        .auth_warrant
        .as_deref()
        .ok_or(attribution::AttributionError::MissingWarrant.to_string())?;
    let ev = resolve_evidence(msg, state)
        .ok_or_else(|| "agent write missing Auth-Evidence".to_string())?;
    let ev_bytes = parse_auth_evidence(&ev)?;
    let db = l2
        .db
        .as_ref()
        .ok_or_else(|| "agent write cannot be validated without database identity".to_string())?;
    let inclusion_time = l2.inclusion_time.unwrap_or(0);
    // Cross-issuer warrant: resolve the delegator issuer's on-chain /sys/dnssec
    // proof (same-issuer warrants ignore it — the agent proof covers both).
    let deleg_ev_bytes = attribution::warrant_delegator_issuer(warrant)
        .and_then(|iss| fetch_evidence_object(state, &format!("/sys/dnssec/{iss}")));
    let wa = attribution::verify_attribution_with_warrant(
        &signer,
        cert,
        warrant,
        &ev_bytes,
        deleg_ev_bytes.as_deref(),
        inclusion_time,
        &l2.anchors,
    )
    .map_err(|e| e.to_string())?;
    // on_behalf_allowed defaults to true (spec: honored absent a repo opt-out).
    agent_effective_email(
        &wa,
        &db.uri,
        db.genesis.as_deref(),
        msg.action.name(),
        &msg.path.to_string(),
        msg.content_schema.as_deref(),
        true,
    )
}

fn l2_authorize(msg: &Message, state: &dyn StateView, l2: &L2Context, owner_ref: &str) -> Result<(), String> {
    let signer = msg.signing_key.to_string();
    let lookup = name_lookup(state);
    let pd = primary_domain(state);
    // Resolve referenced / conventional evidence to inline bytes the pure
    // verifier can consume (the pure path can't reach state).
    let evidence = resolve_evidence(msg, state);
    // An unknown block time cannot satisfy any cert/RRSig window, so email-rooted
    // owners fail closed; key-rooted owners are time-independent.
    let inclusion_time = l2.inclusion_time.unwrap_or(0);

    // Agent write (browserid-ng v0.4): a typed agent certificate, or any
    // presence of an Auth-Warrant. The agent certificate is inert without a
    // warrant, so verify the warrant, confine it to this database, enforce
    // scopes, and resolve the effective author (agent, or delegator under
    // `as:`). Fail closed on any missing piece.
    let cert_is_agent = msg
        .auth_cert
        .as_deref()
        .map(sbo_core::authorize::auth_cert_is_agent)
        .unwrap_or(false);
    if cert_is_agent || msg.auth_warrant.is_some() {
        // The write acts as its effective author (delegator under `as:`, else
        // the agent). Owner-authorization evaluates against that identity.
        let effective = resolve_agent_effective(msg, state, l2)?;
        return match authorize_owner(owner_ref, &signer, Some(&effective), &lookup, DEFAULT_HOP_LIMIT, pd.as_deref()) {
            AuthzOutcome::Authorized => Ok(()),
            AuthzOutcome::Unauthorized(reason) => Err(reason),
        };
    }

    match authorize_message(
        owner_ref,
        &signer,
        msg.auth_cert.as_deref(),
        evidence.as_deref(),
        inclusion_time,
        &l2.anchors,
        &lookup,
        DEFAULT_HOP_LIMIT,
        pd.as_deref(),
    ) {
        AuthzOutcome::Authorized => Ok(()),
        AuthzOutcome::Unauthorized(reason) => Err(reason),
    }
}

/// Resolve a message's `Auth-Evidence` to an `inline:<base64url>` value the pure
/// verifier accepts. Three carriage forms (Authorization Spec §DNSSEC Evidence):
/// - `inline:…` passes through unchanged;
/// - `ref:<sbo-path>` is fetched from the referenced on-chain `dnssec.v1`
///   object (its payload IS the RFC 9102 chain);
/// - absent evidence, but an `Auth-Cert` is present → the conventional
///   `/sys/dnssec/<issuer>` object is consulted (line 140, a MAY).
///
/// Returns `None` when nothing resolves; the signer is then simply unattributed
/// (carried-but-filtered for an email-rooted owner). Because a referenced
/// `dnssec.v1` object is self-authenticating (re-validated against the pinned
/// root KSK by the verifier), resolving it is not a trusted read.
pub fn resolve_evidence(msg: &Message, state: &dyn StateView) -> Option<String> {
    match msg.auth_evidence.as_deref() {
        Some(inline) if inline.starts_with("inline:") => Some(inline.to_string()),
        Some(reference) if reference.starts_with("ref:") => {
            let target = reference.trim_start_matches("ref:");
            let bytes = fetch_evidence_object(state, target)?;
            Some(encode_auth_evidence_inline(&bytes))
        }
        Some(_) => None, // unrecognized form
        None => {
            // Absent evidence: try the conventional /sys/dnssec/<issuer> object.
            let issuer = sbo_core::authorize::cert_issuer(msg.auth_cert.as_deref()?)?;
            let bytes = fetch_evidence_object(state, &format!("/sys/dnssec/{issuer}"))?;
            Some(encode_auth_evidence_inline(&bytes))
        }
    }
}

/// Fetch a referenced evidence object's payload (the RFC 9102 DNSSEC chain) by
/// an `sbo-path` ref like `/sys/dnssec/<issuer>`: the final segment is the
/// object id, the rest the path. Creator-independent (the object is
/// self-authenticating, so any creator's copy is equivalent).
pub fn fetch_evidence_object(state: &dyn StateView, ref_path: &str) -> Option<Vec<u8>> {
    let (path_str, id_str) = ref_path.trim_end_matches('/').rsplit_once('/')?;
    let path = SboPath::parse(&format!("{path_str}/")).ok()?;
    let id = Id::new(id_str).ok()?;
    let obj = state.get_object(&path, &id).ok()??;
    Some(obj.payload)
}

/// Validation result with stage information
#[derive(Debug)]
pub enum ValidationResult {
    /// Message is valid, proceed with write
    Valid {
        /// Resolved creator name (for logging)
        creator: String,
    },
    /// Message is invalid, skip with reason
    Invalid {
        stage: ValidationStage,
        reason: String,
    },
}

/// Root policy path constant
const ROOT_POLICY_PATH: &str = "/sys/policies/";
const ROOT_POLICY_ID: &str = "root";
/// Content-Schema of a governing policy object. A write carrying this schema is
/// what the apply path indexes via `put_policy`, so it is exactly the set of
/// writes that must pass the `govern` gate.
const POLICY_SCHEMA: &str = "policy.v2";

/// The email the message's signer is *proven* to speak for at the block's
/// inclusion time (valid `Auth-Cert` + DNSSEC evidence), or `None` if the
/// signer carries no valid attribution. Deterministic given the message and
/// chain state — the same inclusion-time-pinned check the L2 gate uses.
fn attributed_email(msg: &Message, state: Option<&dyn StateView>, l2: &L2Context) -> Option<String> {
    // On-behalf agent write (Authorization Spec §On-behalf writes): the write's
    // attributed identity is its **effective author** — the delegator when the
    // warrant carries `as:<delegator>`, else the agent. This is the identity the
    // policy actor, `$email`/`$user` vars, and attestation-role matching must
    // all evaluate against, so an on-behalf write faces "the same on-chain
    // policy the delegator faces". Resolving the effective author needs state
    // (evidence + database identity); the pure path (no state) can't attribute
    // an agent write and returns None (fails closed).
    let cert_is_agent = msg
        .auth_cert
        .as_deref()
        .map(sbo_core::authorize::auth_cert_is_agent)
        .unwrap_or(false);
    if cert_is_agent || msg.auth_warrant.is_some() {
        return state.and_then(|s| resolve_agent_effective(msg, s, l2).ok());
    }

    let signer = msg.signing_key.to_string();
    // Evidence resolution (ref:/dnssec) needs state; inline works without it.
    let evidence = state.and_then(|db| resolve_evidence(msg, db));
    let inclusion_time = l2.inclusion_time.unwrap_or(0);
    message_attribution(
        &signer,
        msg.auth_cert.as_deref(),
        evidence.as_deref(),
        inclusion_time,
        &l2.anchors,
    )
    .map(|a| a.email)
}

/// Resolve the creator ID for a message — the durable identity of its author.
///
/// Order (Identity/State-Commitment specs): explicit `Creator` header → the
/// **attributed email** (so an email author's writes share a stable creator
/// across browserid key rotation, instead of fragmenting under each ephemeral
/// key) → the signer's claimed name → truncated key hex.
/// Locate the object a transfer/delete targets — the single object occupying the
/// globally-unique `(msg.path, msg.id)` slot (a point lookup). Its `creator` is
/// an immutable attribute, invariant across the move, not the signer's. Both
/// `validate_transfer` and the sync apply path use this so they agree on the
/// exact `(path, id)` leaf.
pub fn resolve_transfer_target(
    msg: &Message,
    state: &dyn StateView,
    _l2: &L2Context,
) -> Result<Option<StoredObject>, sbo_core::error::DbError> {
    state.get_object(&msg.path, &msg.id)
}

pub fn resolve_creator(msg: &Message, state: Option<&dyn StateView>, l2: &L2Context) -> Id {
    // If message has explicit creator, use it
    if let Some(creator) = &msg.creator {
        return creator.clone();
    }

    // An attributed email is the author's stable, rotation-independent identity.
    if let Some(email) = attributed_email(msg, state, l2) {
        if let Ok(id) = Id::new(&email) {
            return id;
        }
    }

    let pubkey = msg.signing_key.to_string();

    // Try to look up the signer's claimed name. On a primary-domain repo a local
    // name `<local>` IS the identity `<local>@<domain>` (the sovereignty record),
    // so canonicalize to that email — keeping a user's creator segment stable
    // whether they signed via browserid (attributed email, above) or via their
    // pinned key (this branch). Outside a primary domain the bare name stands.
    if let Some(db) = state {
        match db.get_name_for_pubkey(&pubkey) {
            Ok(Some(name)) => {
                let canonical = match primary_domain(db) {
                    Some(domain) => format!("{}@{}", name, domain),
                    None => name,
                };
                if let Ok(id) = Id::new(&canonical) {
                    return id;
                }
            }
            Ok(None) => {} // No name claim, fall through
            Err(e) => {
                tracing::debug!("Error looking up name for pubkey: {}", e);
            }
        }
    }

    // Fall back to truncated key hex with type disambiguation
    // 16 hex chars of key material + 2 char prefix = 18 chars total
    let (prefix, key_hex) = if let Some(hex) = pubkey.strip_prefix("ed25519:") {
        ("e_", hex)
    } else if let Some(hex) = pubkey.strip_prefix("bls12-381:") {
        ("b_", hex)
    } else {
        ("", pubkey.as_str())
    };
    let key_part = &key_hex[..std::cmp::min(16, key_hex.len())];
    let creator_str = format!("{}{}", prefix, key_part);
    Id::new(&creator_str).unwrap_or_else(|_| Id::new("unknown").unwrap())
}

/// Enforce the HLC ordering-integrity rule (Content Spec §Validity bound) for a
/// write that carries an `HLC` header. A malformed `HLC` is always rejected. The
/// `T_b − W ≤ physical ≤ T_b + ε` bound is enforced only when the block's
/// inclusion time is known; absent a timestamp the bound cannot be evaluated and
/// we fail open on it (the write is still carried, matching the attribution
/// carry semantics). Returns `Err(reason)` if the write must be filtered.
///
/// `W` (max authoring lag) defaults to [`sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS`];
/// per-collection `W` from a `collection.v1` descriptor is wired in a later step.
fn check_hlc_bound(msg: &Message, state: &dyn StateView, l2: &L2Context) -> Result<(), String> {
    let hlc_str = match &msg.hlc {
        Some(h) => h,
        None => return Ok(()), // no HLC → base inclusion-order semantics
    };
    let hlc = sbo_core::hlc::Hlc::parse(hlc_str).map_err(|e| format!("malformed HLC: {e}"))?;

    if let Some(t_b_secs) = l2.inclusion_time {
        let t_b_ms = t_b_secs.saturating_mul(1000);
        let max_lag = collection_max_lag_ms(msg, state);
        let skew = sbo_core::hlc::DEFAULT_SKEW_TOLERANCE_MS;
        if !hlc.within_bound(t_b_ms, max_lag, skew) {
            return Err(format!(
                "HLC physical {} outside validity bound [{}, {}] (T_b={}ms, W={}ms, ε={}ms)",
                hlc.physical,
                t_b_ms - max_lag,
                t_b_ms + skew,
                t_b_ms,
                max_lag,
                skew
            ));
        }
    }
    Ok(())
}

/// Resolve the collection's `W` (max authoring lag) in **milliseconds** for a
/// write, from a `collection.v1` descriptor at the write's collection root
/// (`<path>/_config`). Absent a descriptor (or its `max_authoring_lag_s`), the
/// collection defaults to a small `W` ([`sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS`]).
/// The descriptor is looked up at the write's own path; deeper ancestor
/// resolution is a later refinement.
fn collection_max_lag_ms(msg: &Message, state: &dyn StateView) -> i64 {
    let descriptor = state
        .get_object(&msg.path, &Id::new(sbo_core::schema::COLLECTION_CONFIG_ID).unwrap())
        .ok()
        .flatten();
    if let Some(obj) = descriptor {
        if obj.content_schema.as_deref() == Some("collection.v1") {
            if let Ok(collection) = sbo_core::schema::parse_collection(&obj.payload) {
                if let Some(lag_s) = collection.max_authoring_lag_s {
                    return lag_s.saturating_mul(1000);
                }
            }
        }
    }
    sbo_core::hlc::DEFAULT_MAX_AUTHORING_LAG_MS
}

/// Validate the `Prev` causal-link header (Content Spec §Causal Links), if
/// present: it must be the hex encoding of a 32-byte `object_hash`. `Prev` points
/// at the version a mutable write was based on; the chain of links is a
/// verifiable per-object history. We validate only its *form* here — that the
/// referenced version actually exists is a read-side/indexer concern, not a
/// validity rule (a write may legitimately reference a version not yet seen).
fn check_prev(msg: &Message) -> Result<(), String> {
    let prev = match &msg.prev {
        Some(p) => p,
        None => return Ok(()), // a create sets no Prev
    };
    if prev.len() != 64 || !prev.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "malformed Prev '{prev}': expected 64 hex chars (a 32-byte object_hash)"
        ));
    }
    Ok(())
}

/// Last-writer-wins admission check (Content Spec §Conflict Resolution): whether
/// an incoming write should overwrite the current value at its key. When both the
/// incoming write and the existing object carry an `HLC`, the incoming one is
/// admitted only if it **wins** the total order (HLC, then signer public key,
/// then `object_hash`) — making LWW independent of inclusion order so a
/// back-dated write included later cannot clobber a higher-HLC value. If either
/// side lacks an `HLC` (or the `HLC` fails to parse), base inclusion-order
/// semantics apply and the write is admitted. `object_hash` is the incoming
/// write's hash (the full raw bytes).
pub fn lww_admits(msg: &Message, existing: Option<&StoredObject>, object_hash: &[u8; 32]) -> bool {
    let (Some(new_hlc_str), Some(old)) = (&msg.hlc, existing) else {
        return true;
    };
    let Some(old_hlc_str) = &old.hlc else {
        return true;
    };
    let (Ok(new_hlc), Ok(old_hlc)) = (
        sbo_core::hlc::Hlc::parse(new_hlc_str),
        sbo_core::hlc::Hlc::parse(old_hlc_str),
    ) else {
        return true;
    };
    let new_signer = msg.signing_key.to_string();
    let new_key = sbo_core::hlc::LwwKey { hlc: new_hlc, signer: &new_signer, object_hash };
    let old_key = sbo_core::hlc::LwwKey {
        hlc: old_hlc,
        signer: old.owner.as_str(),
        object_hash: &old.object_hash,
    };
    sbo_core::hlc::lww_wins(new_key, old_key)
}

/// The effective owner reference for a message, per the Authorization Spec
/// verification algorithm: the `Owner` header, else the `Creator` header, else
/// the signing key. The L2 gate authorizes the signer against this reference.
fn effective_owner_ref(msg: &Message) -> String {
    if let Some(owner) = &msg.owner {
        owner.as_str().to_string()
    } else if let Some(creator) = &msg.creator {
        creator.as_str().to_string()
    } else {
        msg.signing_key.to_string()
    }
}

/// Validate a message against the current state
pub fn validate_message(
    msg: &Message,
    state: &dyn StateView,
    _repo_path: &Path,
    l2: &L2Context,
) -> ValidationResult {
    // 1. Verify cryptographic signature
    if let Err(e) = sbo_core::message::verify_message(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Signature,
            reason: e.to_string(),
        };
    }

    // 2. Validate payload against Content-Schema (if specified). Transfer/delete
    // are exempt: they act on an *existing* object and carry no new payload, but
    // may still name the target's `Content-Schema` (e.g. so a delegated-signer
    // warrant's `schema:` scope matches). Schema-validating their empty payload
    // would spuriously fail (EOF parsing an empty body). Same "acts on an existing
    // object" exemption the L2 attribution gate below applies.
    let is_transfer_or_delete =
        matches!(msg.action, Action::Transfer { .. } | Action::Delete);
    if !is_transfer_or_delete {
        if let Err(e) = validate_schema(msg) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Schema,
                reason: format_schema_error(&e),
            };
        }
    }

    // 2.25. HLC ordering-integrity gate. A write that carries an `HLC` header
    // must parse and satisfy the validity bound against the block's inclusion
    // time (`T_b − W ≤ physical ≤ T_b + ε`). This bounds future-dating and
    // back-dated insertion; it is an ordering rule only and does not touch
    // attribution. Writes without an `HLC` use base inclusion-order semantics and
    // skip this gate. When the block carries no usable timestamp we cannot
    // evaluate the bound, so we only enforce the parse (fail-open on the bound,
    // matching the carry semantics elsewhere).
    if let Err(reason) = check_hlc_bound(msg, state, l2) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Ordering,
            reason,
        };
    }
    if let Err(reason) = check_prev(msg) {
        return ValidationResult::Invalid {
            stage: ValidationStage::Ordering,
            reason,
        };
    }

    // 2.5. L2 attribution gate. The signer must speak for the write's
    // *effective owner* — `Owner`, else `Creator`, else the signing key
    // (Authorization Spec §Verification Algorithm) — at the block's inclusion
    // time. For key-rooted effective owners (including the signer-fallback case)
    // this is a direct key match the L1 signature already guarantees; for
    // email-rooted owners it requires valid browserid+DNSSEC attribution.
    // L1-valid but L2-unauthorized writes are carried by the DA layer but
    // disregarded here — they never reach state mutation.
    //
    // Transfer/delete are exempt: they do not assert authorship of a new write,
    // they act on an *existing* object whose target creator they merely name
    // (via `Creator`). Their authorization — current owner OR a policy grant
    // (the admin-override) — is handled in full by `validate_transfer`, so the
    // owner-speaks-for-self gate would wrongly reject a legitimate admin move.
    // (`is_transfer_or_delete` computed above at the schema gate.)
    if !is_transfer_or_delete {
        let effective_owner = effective_owner_ref(msg);
        if let Err(reason) = l2_authorize(msg, state, l2, &effective_owner) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Attribution,
                reason,
            };
        }
    }

    // 2.6. Creator integrity. `Creator` is the object's immutable author
    // attribute (no longer part of the state-trie key — identity is `(path, id)`).
    // It gates provenance and ownership defaulting independently of `Owner`. If a
    // `Creator` is declared, the signer must control it, else a writer could file
    // objects under another identity's `Creator`. The owner gate above only covers
    // `Creator` when no `Owner`
    // is present (it is `Owner → else Creator → else signer`), so validate it
    // explicitly here whenever it is set. Applies to all actions.
    if let Some(creator) = &msg.creator {
        if let Err(reason) = l2_authorize(msg, state, l2, creator.as_str()) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Attribution,
                reason: format!(
                    "Signer does not control declared Creator {}: {}",
                    creator.as_str(),
                    reason
                ),
            };
        }
    }

    // 3. Check if root policy exists (genesis check)
    // SECURITY: Fail closed if we can't determine root policy state
    let root_policy_status = check_root_policy_exists(state);
    if let RootPolicyCheck::Error(e) = &root_policy_status {
        tracing::error!("Cannot verify root policy state: {}", e);
        return ValidationResult::Invalid {
            stage: ValidationStage::State,
            reason: format!("Cannot verify root policy state: {}", e),
        };
    }
    let root_policy_exists = matches!(root_policy_status, RootPolicyCheck::Exists);

    // 4. Handle based on action
    match &msg.action {
        Action::Post => validate_post(msg, state, root_policy_exists, l2),
        Action::Transfer { .. } => validate_transfer(msg, state, root_policy_exists, l2),
        Action::Delete => validate_delete(msg, state, root_policy_exists, l2),
        Action::Import { .. } => {
            ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: "Import action not yet implemented".to_string(),
            }
        }
    }
}

/// Whether the root policy (`/sys/policies/root`) is present in `state`.
///
/// When this is false, `validate_message` runs in "genesis mode" and accepts
/// EVERY write with no policy enforcement. That is only correct before genesis
/// has been applied; on any synced chain the root policy is posted at genesis
/// and must be present. Callers use this to assert enforcement is active after
/// genesis and catch a silent regression into genesis mode (see mingo-9vck /
/// the Mode-B hardcoded-creator bug). Returns false on DB error (fail-closed:
/// treat an unverifiable root policy as "assert the invariant loudly").
pub fn root_policy_present(state: &dyn StateView) -> bool {
    matches!(check_root_policy_exists(state), RootPolicyCheck::Exists)
}

/// Result of checking root policy existence
enum RootPolicyCheck {
    Exists,
    DoesNotExist,
    Error(String),
}

/// Check if the root policy (/sys/policies/root) exists
/// SECURITY: Returns explicit error on DB failure (fail closed)
fn check_root_policy_exists(state: &dyn StateView) -> RootPolicyCheck {
    let path = match SboPath::parse(ROOT_POLICY_PATH) {
        Ok(p) => p,
        Err(e) => return RootPolicyCheck::Error(format!("Invalid root policy path: {}", e)),
    };
    let id = match Id::new(ROOT_POLICY_ID) {
        Ok(id) => id,
        Err(e) => return RootPolicyCheck::Error(format!("Invalid root policy id: {}", e)),
    };

    // Look up by (path, id) regardless of creator. The root policy's creator is
    // whatever form the sys identity resolves to — a bare name ("sys") for a
    // key-rooted genesis, but an email ("sys@<domain>") for a domain-certified
    // (Mode B) genesis. Hardcoding creator "sys" here would miss the email-rooted
    // case and silently drop the daemon into genesis mode (no policy enforcement
    // at all). The object's existence is what gates genesis mode; its creator is
    // irrelevant to that question.
    match state.get_object(&path, &id) {
        Ok(Some(_)) => RootPolicyCheck::Exists,
        Ok(None) => RootPolicyCheck::DoesNotExist,
        Err(e) => RootPolicyCheck::Error(format!("DB error checking root policy: {}", e)),
    }
}

/// Validate a post action
fn validate_post(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Name-claim paths carry a dedicated authorization flow: the primary-domain
    // anti-hijack on creation and controller-only (no policy override) updates. The
    // *uniqueness* it used to enforce via a per-creator scan is now just the
    // general `(path, id)` point lookup below — but the name-specific
    // authorization is retained (Authorization Spec §Name-claim anti-hijack).
    if is_name_claim_path(&msg.path) {
        return validate_name_claim(msg, state, root_policy_exists, l2);
    }

    // Get the creator (use name resolution if available)
    let creator = resolve_creator(msg, Some(state), l2);

    // Look up the object occupying the globally-unique `(path, id)` slot. Global
    // uniqueness makes this a point lookup: an occupied slot means this write is
    // an update to the incumbent (whatever its creator — a `create` into a slot
    // held by a different creator lands on the update path and is rejected unless
    // authorized), an empty slot means a create.
    // SECURITY: Fail closed - if we can't verify state, we must deny.
    let existing = match state.get_object(&msg.path, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            tracing::error!("State DB error checking object existence: {}", e);
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("Cannot verify object state (DB error): {}", e),
            };
        }
    };

    // Installing/replacing a governing policy is a `govern` action authorized by
    // the PARENT policy, not by ordinary create/update grants and NOT by the
    // owner fast-path — otherwise any `create` grant (or owning the policy slot)
    // would let a signer plant a shadowing policy and capture the subtree. Genesis
    // (no root policy yet) still bootstraps freely.
    if is_policy_write(msg) {
        if !root_policy_exists {
            tracing::debug!("Allowing policy write without root policy (genesis mode)");
        } else if let Err(reason) = require_govern(state, msg, l2) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason: format!("Policy write requires `govern` on {} (from parent policy): {}", msg.path, reason),
            };
        }
        return ValidationResult::Valid { creator: creator.to_string() };
    }

    if let Some(existing_obj) = existing {
        // Slot occupied - this is an update. Authorize the signer against the
        // object's *resolved controller* (its stored `owner_ref`), not the legacy
        // signer-key `owner`: a direct key match for key-rooted owners, browserid
        // attribution for email-rooted owners. The controller can always update
        // their own object; anyone else must be granted `update` by policy (which
        // also covers the "create into a slot held by a different creator" case —
        // it is an unauthorized update and is rejected).
        let owner_ref = stored_owner_ref(&existing_obj);
        if l2_authorize(msg, state, l2, owner_ref).is_ok() {
            tracing::debug!("Controller updating object {}:{}", msg.path, msg.id);
        } else {
            // Signer is not the controller - must check policy for update.
            if let Err(reason) = check_policy(state, msg, ActionType::Update, Some(owner_ref), l2) {
                return ValidationResult::Invalid {
                    stage: ValidationStage::Policy,
                    reason,
                };
            }
        }
    } else if !root_policy_exists {
        // No root policy yet - this might be genesis
        // Allow any post since we're bootstrapping
        tracing::debug!("Allowing post without root policy (genesis mode)");
    } else {
        // New object creation into an empty slot - must check policy
        if let Err(reason) = check_policy(state, msg, ActionType::Create, None, l2) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason,
            };
        }
    }

    ValidationResult::Valid { creator: creator.to_string() }
}

/// Whether `path` is a name-claim path (`/sys/names/…`), which carries the
/// primary-domain anti-hijack authorization. Uniqueness itself is no longer
/// special-cased here — it is the general `(path, id)` rule.
fn is_name_claim_path(path: &SboPath) -> bool {
    path.to_string().starts_with("/sys/names/")
}

/// Validate a name claim. Uniqueness is now the general `(path, id)` rule (a
/// point lookup, no per-creator scan); what remains name-specific is the
/// authorization: a new claim on a primary-domain repo must control the mapped
/// email (anti-hijack), and an update is controller-only (no policy override).
fn validate_name_claim(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // The object occupying this `(path, id)` slot, if any (a point lookup —
    // globally unique). SECURITY: fail closed on a DB error.
    let existing = match state.get_object(&msg.path, &msg.id) {
        Ok(obj) => obj,
        Err(e) => {
            tracing::error!("State DB error checking name claim: {}", e);
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("Cannot verify name claim state (DB error): {}", e),
            };
        }
    };

    let claimed_name = msg.id.as_str().to_string();

    if let Some(existing_obj) = existing {
        // Name already claimed - the updater must be the current controller.
        // Authorize against the stored controller (`owner_ref`): a direct key
        // match for key-rooted name records, browserid attribution for
        // email-rooted ones (whose ephemeral signer key rotates, so a direct
        // key match would lock the owner out after a cert rotation).
        let owner_ref = stored_owner_ref(&existing_obj);
        if let Err(reason) = l2_authorize(msg, state, l2, owner_ref) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Attribution,
                reason: format!("Name '{}' already claimed by {}: {}", msg.id.as_str(), owner_ref, reason),
            };
        }
        tracing::debug!("Controller updating name claim: {}", msg.id.as_str());
    } else {
        // New name claim. On a primary-domain repo a local name `<local>` governs
        // the identity `<local>@<domain>` (the sovereignty record), so claiming it
        // requires controlling that identity — otherwise a stranger (or a
        // front-runner) could hijack it. This anti-hijack layers ON TOP of the
        // global first-valid-write-wins uniqueness rule: policy makes the slot
        // claimable only by the rightful email; uniqueness makes the first valid
        // claim final. Off a primary-domain repo, or during genesis (no root
        // policy yet), name claims remain first-come.
        if root_policy_exists {
            if let Some(domain) = primary_domain(state) {
                let email = format!("{}@{}", claimed_name, domain);
                if let Err(reason) = l2_authorize(msg, state, l2, &email) {
                    return ValidationResult::Invalid {
                        stage: ValidationStage::Attribution,
                        reason: format!(
                            "Name '{}' maps to {} on this repo; claiming it requires controlling that identity: {}",
                            claimed_name, email, reason
                        ),
                    };
                }
            }
        }
        tracing::debug!("New name claim: {}", msg.id.as_str());
    }

    ValidationResult::Valid { creator: claimed_name }
}

/// Validate a transfer action
fn validate_transfer(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    if !root_policy_exists {
        return ValidationResult::Invalid {
            stage: ValidationStage::State,
            reason: "Cannot transfer before genesis".to_string(),
        };
    }

    // Locate the TARGET object. The actor is the signer; the object is named by
    // (path, id). Prefer the signer's own object at that path+id (the common
    // owner case); otherwise fall back to the sole object there regardless of
    // creator (the admin-acting-on-a-user's-object case). `creator` is the
    // TARGET object's creator — invariant across the transfer — not the actor.
    let obj = match resolve_transfer_target(msg, state, l2) {
        Ok(Some(o)) => o,
        Ok(None) => {
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: "Cannot transfer non-existent object".to_string(),
            };
        }
        Err(e) => {
            return ValidationResult::Invalid {
                stage: ValidationStage::State,
                reason: format!("State DB error: {}", e),
            };
        }
    };
    let creator = obj.creator.clone();
    let owner_ref = stored_owner_ref(&obj).to_string();

    // Destructure the transfer destination fields. `validate_delete` routes here
    // with `Action::Delete` (no New-* fields); `New-Owner: null:` is the other
    // delete spelling.
    let (new_owner, new_path, new_id) = match &msg.action {
        sbo_core::message::Action::Transfer { new_owner, new_path, new_id } => (
            new_owner.as_ref().map(|o| o.as_str().to_string()),
            new_path.clone(),
            new_id.as_ref().map(|i| i.as_str().to_string()),
        ),
        _ => (None, None, None),
    };
    let is_delete = matches!(msg.action, sbo_core::message::Action::Delete)
        || new_owner.as_deref() == Some("null:");

    // (A) SOURCE AUTHORIZATION. Deleting or relocating a governing POLICY object
    // is a `govern` action: authorized by the PARENT policy, never the owner
    // fast-path — so an ancestor with `govern` can always reclaim a delegated
    // subtree (reversibility), and owning a policy cannot be used to transfer it
    // out of governance. Ordinary objects keep the owner-or-policy rule below.
    if is_policy_object(&obj) {
        if let Err(reason) = require_govern(state, msg, l2) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason: format!(
                    "{:?} of policy object {} requires `govern` (from parent policy): {}",
                    if is_delete { ActionType::Delete } else { ActionType::Transfer },
                    msg.path, reason
                ),
            };
        }
    } else if l2_authorize(msg, state, l2, &owner_ref).is_err() {
        // The current owner may always act on the object; otherwise the object's
        // (source-path) policy must grant the action to the signer. This is the
        // "unless allowed by the object's policy" clause in SBO
        // Specification.md §transfer, and is how a sys/admin role (granted
        // `transfer`/`delete` on `/**`) acts on objects it does not own.
        let action = if is_delete { ActionType::Delete } else { ActionType::Transfer };
        if let Err(reason) = check_policy(state, msg, action, Some(&owner_ref), l2) {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason: format!(
                    "Signer does not control owner {} and policy denies {:?}: {}",
                    owner_ref, action, reason
                ),
            };
        }
    }

    // (B) DESTINATION — only when relocating (New-Path and/or New-ID). Both the
    // collision rule and the destination-path policy apply (SBO Specification.md
    // §transfer). The collision check is now GLOBAL: the move is valid only if the
    // destination `(New-Path, New-ID)` slot is occupied by NO valid object,
    // regardless of creator (global `(path, id)` uniqueness). Creator is still
    // preserved by the move — it is an immutable attribute, not part of the key.
    if new_path.is_some() || new_id.is_some() {
        let dest_path = new_path.clone().unwrap_or_else(|| msg.path.clone());
        let dest_id_str = new_id.clone().unwrap_or_else(|| msg.id.as_str().to_string());
        let dest_id = match sbo_core::message::Id::new(&dest_id_str) {
            Ok(i) => i,
            Err(e) => {
                return ValidationResult::Invalid {
                    stage: ValidationStage::State,
                    reason: format!("Invalid New-ID: {}", e),
                };
            }
        };
        match state.get_object(&dest_path, &dest_id) {
            Ok(Some(occupant)) => {
                return ValidationResult::Invalid {
                    stage: ValidationStage::State,
                    reason: format!(
                        "Destination {}{} already occupied (creator {})",
                        dest_path, dest_id, occupant.creator
                    ),
                };
            }
            Ok(None) => {}
            Err(e) => {
                return ValidationResult::Invalid {
                    stage: ValidationStage::State,
                    reason: format!("State DB error checking destination: {}", e),
                };
            }
        }
        // The destination collection must admit the object. The post-transfer
        // owner (New-Owner if changing ownership, else the current owner) is the
        // namespace owner the destination's `create` grant authorizes against —
        // so a move into `/u/$owner/**` succeeds when the object lands in its
        // owner's namespace, for both self-moves and admin filing.
        let owner_after = new_owner.clone().unwrap_or_else(|| owner_ref.clone());
        if let Err(reason) =
            check_policy_at(state, msg, &dest_path, ActionType::Create, Some(&owner_after), l2)
        {
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason: format!("Destination {} does not admit object: {}", dest_path, reason),
            };
        }
    }

    ValidationResult::Valid { creator: creator.to_string() }
}

/// Validate a delete action
fn validate_delete(
    msg: &Message,
    state: &dyn StateView,
    root_policy_exists: bool,
    l2: &L2Context,
) -> ValidationResult {
    // Same rules as transfer
    validate_transfer(msg, state, root_policy_exists, l2)
}

/// The controller reference an existing object is owned by: its stored
/// `owner_ref` (the resolved effective owner recorded at write time), falling
/// back to the legacy signer-key `owner` for objects written before `owner_ref`
/// was recorded. This is what ownership checks authorize the signer against.
fn stored_owner_ref(obj: &StoredObject) -> &str {
    obj.owner_ref.as_deref().unwrap_or_else(|| obj.owner.as_str())
}

#[cfg(test)]
mod dnssec_repro_tests {
    use super::*;
    use sbo_core::crypto::{ContentHash, Signature, SigningKey};
    use sbo_core::message::ObjectType;
    use sbo_core::policy::Policy;
    use sbo_core::state::StateDb;

    #[test]
    fn dnssec_garbage_is_rejected_by_full_validate() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();

        // The self-authorizing /sys/dnssec policy (minimal), as resolve_policy
        // would return it (indexed at /sys/policies/).
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create", "update"], "on": "/sys/dnssec/**"}],
            "restrictions": [{
                "on": "/sys/dnssec/**",
                "require": {"schema": "dnssec.v1", "content_type": "application/octet-stream", "dnssec_proof": true}
            }]
        })).unwrap();
        db.put_policy(&SboPath::parse("/sys/policies/").unwrap(), &policy).unwrap();

        // The root policy OBJECT must also exist, else validate_post treats the
        // write as genesis-mode and skips policy entirely (root_policy_exists).
        let policy_payload = serde_json::to_vec(&policy).unwrap();
        db.put_object(&StoredObject {
            path: SboPath::parse("/sys/policies/").unwrap(),
            id: Id::new("root").unwrap(),
            // Email-rooted sys creator, as on the live (Mode B) chain — this is
            // what check_root_policy_exists's hardcoded "sys" fails to match.
            creator: Id::new("sys@mingo.place").unwrap(),
            owner: Id::new("sys@mingo.place").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&policy_payload),
            payload: policy_payload,
            policy_ref: None,
            content_schema: Some("policy.v2".to_string()),
            owner_ref: Some("sys".to_string()),
            block_number: 1,
            object_hash: [9u8; 32],
            hlc: Some("1.0".to_string()),
            prev: None,
        }).unwrap();

        // Sanity: resolve_policy for a /sys/dnssec/ target returns the restriction.
        let resolved = db.resolve_policy(&SboPath::parse("/sys/dnssec/").unwrap()).unwrap().unwrap();
        eprintln!("resolved restrictions={} grants={}", resolved.restrictions.len(), resolved.grants.len());
        assert_eq!(resolved.restrictions.len(), 1, "restriction must survive put/resolve");
        assert!(resolved.restrictions[0].require.dnssec_proof, "dnssec_proof must be true after round-trip");

        // A garbage, key-rooted /sys/dnssec/<domain> write.
        let key = SigningKey::generate();
        let payload = b"garbage-not-a-proof".to_vec();
        let mut msg = Message {
            action: Action::Post,
            path: SboPath::parse("/sys/dnssec/").unwrap(),
            id: Id::new("dbg.example").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("application/octet-stream".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("dnssec.v1".to_string()),
            policy_ref: None,
            related: None,
            hlc: Some("1700000000000.0".to_string()), // physical ms ~= inclusion time
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(&key);

        let l2 = L2Context::for_block(Some(1_700_000_000), &db);
        let res = validate_message(&msg, &db, std::path::Path::new("/tmp"), &l2);
        eprintln!("validate result: {:?}", res);
        match res {
            ValidationResult::Invalid { stage, reason } => {
                eprintln!("DENIED at {stage:?}: {reason}");
            }
            ValidationResult::Valid { .. } => {
                panic!("BUG REPRODUCED LOCALLY: garbage /sys/dnssec write validated as VALID");
            }
        }
    }

    #[test]
    fn root_policy_present_finds_email_rooted_creator() {
        // Locks the mingo-9vck / genesis-mode fix. The root policy object exists
        // under an EMAIL-ROOTED sys creator (Mode-B, domain-certified genesis).
        // root_policy_present must find it regardless of creator form. If a future
        // change reintroduces a hardcoded "sys" creator lookup, the email-rooted
        // object is missed, this returns false, and the daemon would silently drop
        // into genesis mode (all enforcement off) — so this test would fail.
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();

        // Before genesis: no root policy object => genesis mode is expected.
        assert!(!root_policy_present(&db), "no root policy object should read as genesis mode");

        // Insert the root policy object with an email-rooted creator.
        let payload = b"{}".to_vec();
        db.put_object(&StoredObject {
            path: SboPath::parse("/sys/policies/").unwrap(),
            id: Id::new("root").unwrap(),
            creator: Id::new("sys@mingo.place").unwrap(),
            owner: Id::new("sys@mingo.place").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&payload),
            payload,
            policy_ref: None,
            content_schema: Some("policy.v2".to_string()),
            owner_ref: Some("sys".to_string()),
            block_number: 1,
            object_hash: [9u8; 32],
            hlc: Some("1.0".to_string()),
            prev: None,
        }).unwrap();

        // After genesis: enforcement must be active regardless of creator form.
        assert!(
            root_policy_present(&db),
            "email-rooted root policy must be found (creator-agnostic) — else enforcement silently disabled"
        );
    }

    // A key-rooted owner deleting their own object, where the delete envelope
    // carries the target's Content-Schema (post.v1) so a delegated-signer
    // warrant's schema: scope matches, but has an EMPTY payload. Before the fix
    // the schema gate ran on all actions and rejected this at Schema stage with
    // "Invalid JSON payload: EOF while parsing" (observed live via mingo delete).
    // Transfer/delete must be exempt from payload schema validation.
    #[test]
    fn owner_delete_with_schema_and_empty_payload_passes_schema_stage() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();

        let owner_key = SigningKey::generate();
        let owner_ref = owner_key.public_key().to_string();

        // Owner-can-always-act root policy (owner has * on their own subtree).
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/**"}]
        })).unwrap();
        db.put_policy(&SboPath::parse("/sys/policies/").unwrap(), &policy).unwrap();
        let policy_payload = serde_json::to_vec(&policy).unwrap();
        db.put_object(&StoredObject {
            path: SboPath::parse("/sys/policies/").unwrap(),
            id: Id::new("root").unwrap(),
            creator: Id::new("sys@mingo.place").unwrap(),
            owner: Id::new("sys@mingo.place").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&policy_payload),
            payload: policy_payload,
            policy_ref: None,
            content_schema: Some("policy.v2".to_string()),
            owner_ref: Some("sys".to_string()),
            block_number: 1,
            object_hash: [9u8; 32],
            hlc: Some("1.0".to_string()),
            prev: None,
        }).unwrap();

        // The existing post the owner will delete.
        let body = br#"{"title":"hi"}"#.to_vec();
        db.put_object(&StoredObject {
            path: SboPath::parse("/communities/cooks/spaces/general/").unwrap(),
            id: Id::new("p1").unwrap(),
            creator: Id::new(&owner_ref).unwrap(),
            owner: Id::new(&owner_ref).unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&body),
            payload: body,
            policy_ref: None,
            content_schema: Some("post.v1".to_string()),
            owner_ref: Some(owner_ref.clone()),
            block_number: 2,
            object_hash: [7u8; 32],
            hlc: Some("2.0".to_string()),
            prev: None,
        }).unwrap();

        // Delete envelope: names post.v1 (for warrant schema scoping) but empty payload.
        let mut msg = Message {
            action: Action::Delete,
            path: SboPath::parse("/communities/cooks/spaces/general/").unwrap(),
            id: Id::new("p1").unwrap(),
            object_type: ObjectType::Object,
            signing_key: owner_key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: None,
            content_hash: None,
            payload: None,
            owner: Some(Id::new(&owner_ref).unwrap()),
            creator: None,
            content_encoding: None,
            content_schema: Some("post.v1".to_string()),
            policy_ref: None,
            related: None,
            hlc: Some("1700000000000.0".to_string()),
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(&owner_key);

        let l2 = L2Context::for_block(Some(1_700_000_000), &db);
        let res = validate_message(&msg, &db, std::path::Path::new("/tmp"), &l2);
        if let ValidationResult::Invalid { stage, reason } = &res {
            assert_ne!(
                *stage,
                ValidationStage::Schema,
                "delete with schema+empty payload must not be rejected at Schema stage (got: {reason})"
            );
        }
    }

    // Install a root policy (both the policies-CF index and the object, so
    // root_policy_present() is true) that grants the sys key `govern` on /**.
    fn install_root_with_admin_govern(db: &StateDb, sys_pubkey: &str) {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "roles": { "admin": [{ "key": sys_pubkey }] },
            "grants": [
                { "to": { "role": "admin" }, "can": ["govern", "delete"], "on": "/**" },
                { "to": "owner", "can": ["*"], "on": "/**" }
            ]
        })).unwrap();
        db.put_policy(&SboPath::parse("/sys/policies/").unwrap(), &policy).unwrap();
        let payload = serde_json::to_vec(&policy).unwrap();
        db.put_object(&StoredObject {
            path: SboPath::parse("/sys/policies/").unwrap(),
            id: Id::new("root").unwrap(),
            creator: Id::new("sys@mingo.place").unwrap(),
            owner: Id::new("sys@mingo.place").unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&payload),
            payload,
            policy_ref: None,
            content_schema: Some("policy.v2".to_string()),
            owner_ref: Some(sys_pubkey.to_string()),
            block_number: 1,
            object_hash: [9u8; 32],
            hlc: Some("1.0".to_string()),
            prev: None,
        }).unwrap();
    }

    fn policy_write_msg(key: &SigningKey, path: &str, policy_json: serde_json::Value) -> Message {
        let payload = serde_json::to_vec(&policy_json).unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: SboPath::parse(path).unwrap(),
            id: Id::new("root").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("policy.v2".to_string()),
            policy_ref: None,
            related: None,
            hlc: Some("1700000000000.0".to_string()),
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(key);
        msg
    }

    // THE sbo-vos1 CAPTURE ATTACK, blocked. A community policy grants `create`
    // under spaces/**; a member uses it to try to plant a shadowing `policy.v2`.
    // Under P1 a policy write needs `govern` (resolved from the PARENT policy),
    // which the community policy does not grant — so the plant is denied and the
    // subtree cannot be captured.
    #[test]
    fn member_create_grant_cannot_install_shadowing_policy() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let sys = SigningKey::generate();
        install_root_with_admin_govern(&db, &sys.public_key().to_string());

        // Community policy: anyone may CREATE under spaces/** (no govern).
        let comm: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{ "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" }]
        })).unwrap();
        db.put_policy(&SboPath::parse("/communities/cooks/").unwrap(), &comm).unwrap();

        // A member (random key) plants a self-serving policy under spaces/**.
        let member = SigningKey::generate();
        let evil = serde_json::json!({
            "grants": [{ "to": "*", "can": ["*"], "on": "/communities/cooks/spaces/**" }]
        });
        let msg = policy_write_msg(&member, "/communities/cooks/spaces/general/evil/", evil);

        let l2 = L2Context::for_block(Some(1_700_000_000), &db);
        match validate_message(&msg, &db, std::path::Path::new("/tmp"), &l2) {
            ValidationResult::Invalid { stage, reason } => {
                assert_eq!(stage, ValidationStage::Policy, "reason: {reason}");
                assert!(reason.contains("govern"), "expected a govern denial, got: {reason}");
            }
            ValidationResult::Valid { .. } => panic!("CAPTURE: member planted a shadowing policy"),
        }
    }

    // The govern grant works for the delegated authority (sys/admin) and denies a
    // non-authority. Also proves parent-resolution: the community policy at
    // /communities/cooks/ is governed by the ROOT policy (its parent), so sys's
    // admin-govern authorizes writing it, while a stranger is refused.
    #[test]
    fn admin_govern_authorizes_community_policy_write_stranger_denied() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let sys = SigningKey::generate();
        install_root_with_admin_govern(&db, &sys.public_key().to_string());

        let comm = serde_json::json!({
            "grants": [
                { "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" },
                { "to": "owner", "can": ["update"], "on": "/communities/cooks/spaces/**" }
            ]
        });

        // sys holds admin-govern (from root, the parent of /communities/cooks/).
        let sys_msg = policy_write_msg(&sys, "/communities/cooks/", comm.clone());
        let l2 = L2Context::for_block(Some(1_700_000_000), &db);
        assert!(
            matches!(validate_message(&sys_msg, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "admin with govern must be able to write a community policy"
        );

        // A stranger cannot.
        let stranger = SigningKey::generate();
        let bad = policy_write_msg(&stranger, "/communities/cooks/", comm);
        match validate_message(&bad, &db, std::path::Path::new("/tmp"), &l2) {
            ValidationResult::Invalid { stage, .. } => assert_eq!(stage, ValidationStage::Policy),
            ValidationResult::Valid { .. } => panic!("stranger wrote a community policy without govern"),
        }
    }
}

/// Check if an action is allowed by policy
/// Returns Ok(()) if allowed, Err(reason) if denied
fn check_policy(
    state: &dyn StateView,
    msg: &Message,
    action: ActionType,
    owner: Option<&str>,
    l2: &L2Context,
) -> Result<(), String> {
    check_policy_at(state, msg, &msg.path, action, owner, l2)
}

/// Like [`check_policy`] but evaluates against an explicit `target` path rather
/// than `msg.path`. Used by transfer validation to evaluate the **destination**
/// path's policy (the source path is checked via the `msg.path` default).
fn check_policy_at(
    state: &dyn StateView,
    msg: &Message,
    target: &sbo_core::message::Path,
    action: ActionType,
    owner: Option<&str>,
    l2: &L2Context,
) -> Result<(), String> {
    check_policy_resolving_at(state, msg, target, target, action, owner, l2)
}

/// The parent-container path of a policy object's own path — the path whose
/// policy GOVERNS writes to this policy. `/communities/cooks/` → `/communities/`,
/// `/sys/policies/` → `/sys/`. A policy is governed by its parent, never itself
/// (self-governance is the lock-in vector we close); resolving one level up
/// guarantees the walk cannot return the very policy being written. Root
/// (`/sys/policies/`) resolves up to `/sys/` → no policy → falls back to the root
/// policy itself, so the trust anchor is controlled by whoever it grants `govern`.
fn parent_container_path(path: &sbo_core::message::Path) -> sbo_core::message::Path {
    let s = path.to_string();
    let trimmed = s.trim_end_matches('/');
    let parent = match trimmed.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => format!("{}/", &trimmed[..i]),
    };
    sbo_core::message::Path::parse(&parent).unwrap_or_else(|_| path.clone())
}

/// Whether this write installs/replaces a policy object — the only writes that
/// become governing policies (the apply path indexes exactly `policy.v2` objects
/// via `put_policy`). Such writes require `govern` on the target, evaluated
/// against the PARENT policy (see [`require_govern`]).
fn is_policy_write(msg: &Message) -> bool {
    msg.content_schema.as_deref() == Some(POLICY_SCHEMA)
}

/// Whether an existing object is a governing policy (for delete/transfer gating).
fn is_policy_object(obj: &StoredObject) -> bool {
    obj.content_schema.as_deref() == Some(POLICY_SCHEMA)
}

/// Authorize a `govern` action on `msg.path`: resolve the policy at the parent
/// container and require it to grant `govern` matching `msg.path`. The owner
/// fast-path is deliberately NOT consulted here — owning a policy object must not
/// let you rewrite/relocate it without `govern`, else first-writer-owns would
/// re-introduce self-governing capture.
fn require_govern(state: &dyn StateView, msg: &Message, l2: &L2Context) -> Result<(), String> {
    let parent = parent_container_path(&msg.path);
    check_policy_resolving_at(state, msg, &parent, &msg.path, ActionType::Govern, None, l2)
}

/// Core policy check: resolve the applicable policy at `resolve_at` (walking up
/// its ancestors) but evaluate grants/restrictions against `match_target`. These
/// coincide for ordinary writes; they differ for a `govern` check, which resolves
/// one level up (the parent policy) yet matches `on:` patterns against the policy
/// object's own path.
#[allow(clippy::too_many_arguments)]
fn check_policy_resolving_at(
    state: &dyn StateView,
    msg: &Message,
    resolve_at: &sbo_core::message::Path,
    match_target: &sbo_core::message::Path,
    action: ActionType,
    owner: Option<&str>,
    l2: &L2Context,
) -> Result<(), String> {
    let target = match_target;
    // Resolve the applicable policy by walking up the path hierarchy
    let policy = match state.resolve_policy(resolve_at) {
        Ok(Some(p)) => p,
        Ok(None) => {
            // No policy found - deny by default
            // This shouldn't happen if root policy exists, but fail closed
            return Err("No applicable policy found".to_string());
        }
        Err(e) => {
            tracing::error!("Error resolving policy: {}", e);
            return Err(format!("Error resolving policy: {}", e));
        }
    };

    // Resolve the actor's identity (name if available, otherwise key-based)
    let actor = resolve_creator(msg, Some(state), l2);
    let target_path = target.to_string();

    // The `$owner` reference (literal, never path-derived): the existing object's
    // resolved controller for updates (passed in), else the declared `Owner`
    // header for creates. De-circularized — no longer extracted from the path.
    let owner_ref: Option<String> = owner.map(|s| s.to_string()).or_else(|| {
        if action == ActionType::Create {
            msg.owner.as_ref().map(|o| o.as_str().to_string())
        } else {
            None
        }
    });
    // Whether the signer speaks for that owner's resolved controller (a direct
    // key match for key-rooted owners, browserid attribution for email-rooted
    // owners). This is what satisfies a `to: owner` grant.
    let signer_is_owner = owner_ref
        .as_deref()
        .map(|o| l2_authorize(msg, state, l2, o).is_ok())
        .unwrap_or(false);

    // The acting user's attributed email (if any) and local name (if any), for
    // the `$email` / `$name` policy variables; `$user` is the actor's canonical
    // id. All literal references; undefined forms fail closed in matching.
    let user_email = attributed_email(msg, Some(state), l2);
    let user_name = state.get_name_for_pubkey(&msg.signing_key.to_string()).ok().flatten();
    let policy_vars = sbo_core::policy::PolicyVars {
        owner: owner_ref.as_deref(),
        user: Some(actor.as_str()),
        email: user_email.as_deref(),
        name: user_name.as_deref(),
    };

    // The acting user's controller, for attestation-defined roles/conditions:
    // the attributed email if the signer carries valid attribution, else the
    // signing key. Matches an `attested` source whose subject resolves to it.
    let requester = match user_email.clone() {
        Some(email) => Controller::Email(email),
        None => Controller::Key(msg.signing_key.to_string()),
    };
    let is_attested = |source: &AttestedSource| attested_subject_matches(state, l2, &requester, source);

    // The repo's primary domain scopes resolution-based name matching in the
    // evaluator: a bare grant name `<local>` resolves to `<local>@<primary_domain>`,
    // the same email form `resolve_creator` canonicalizes the actor to. `None`
    // (no/ambiguous domain) keeps bare-name matching literal.
    let pd = primary_domain(state);

    // Evaluate the policy
    match evaluate(&policy, &actor, action, &target_path, &policy_vars, signer_is_owner, &is_attested, msg, pd.as_deref()) {
        PolicyResult::Allowed => {
            tracing::debug!(
                "Policy allowed {:?} on {} by {}",
                action,
                target_path,
                actor
            );
            Ok(())
        }
        PolicyResult::Denied(reason) => {
            tracing::info!(
                "Policy denied {:?} on {} by {}: {}",
                action,
                target_path,
                actor,
                reason
            );
            Err(reason)
        }
    }
}

/// Whether an in-force `attestation.v1` exists matching `source` whose subject
/// resolves to `requester` (the acting user's controller), per the Policy Spec
/// §Attestation-Defined Roles: `type` equals `source.type_`, the issuer matches
/// `source.by` (when given), and the attestation is in force at the block's
/// inclusion time.
///
/// When `by` is given we prefix-scan that issuer's namespace
/// (`/<by>/attestations/`); otherwise we scan all `attestation.v1` objects (any
/// issuer, including a self-attestation). All inputs are on-chain and
/// inclusion-time-pinned, so the decision is deterministic on replay.
fn attested_subject_matches(
    state: &dyn StateView,
    l2: &L2Context,
    requester: &Controller,
    source: &AttestedSource,
) -> bool {
    let lookup = name_lookup(state);
    let pd = primary_domain(state);
    let t = l2.inclusion_time.unwrap_or(0);
    let candidates = match &source.by {
        Some(by) => state
            .list_objects_by_path_prefix(&format!("/{by}/attestations/"))
            .unwrap_or_default(),
        None => state
            .list_objects_by_schema("attestation.v1")
            .unwrap_or_default(),
    };
    candidates.into_iter().any(|obj| {
        if obj.content_schema.as_deref() != Some("attestation.v1") {
            return false;
        }
        let att = match parse_attestation(&obj.payload) {
            Ok(a) => a,
            Err(_) => return false,
        };
        if att.type_ != source.type_ || !att.is_in_force(t) {
            return false;
        }
        // When `by` is given, confirm the issuer (the attestation's controller)
        // resolves to the same party — the prefix is just the writer's literal
        // issuer string.
        if let Some(by) = &source.by {
            let issuer_ctrl = resolve_controller(stored_owner_ref(&obj), &lookup, DEFAULT_HOP_LIMIT, pd.as_deref());
            // Must resolve to the same, *grounded* controller — two unresolvable
            // references must not match each other.
            if matches!(issuer_ctrl, Controller::Unresolved | Controller::None)
                || issuer_ctrl != resolve_controller(by, &lookup, DEFAULT_HOP_LIMIT, pd.as_deref())
            {
                return false;
            }
        }
        resolve_controller(&att.subject, &lookup, DEFAULT_HOP_LIMIT, pd.as_deref()) == *requester
    })
}

/// Create a StoredObject from a Message
/// If state is provided, uses name resolution for the creator field
/// object_hash should be sha256(raw_sbo_bytes) - the hash of the complete serialized message
pub fn message_to_stored_object(
    msg: &Message,
    block_number: u64,
    state: Option<&dyn StateView>,
    object_hash: [u8; 32],
    l2: &L2Context,
) -> Option<StoredObject> {
    // Only objects with content can be stored
    let payload = msg.payload.as_ref()?;
    let content_hash = msg.content_hash.as_ref()?;
    let content_type = msg.content_type.as_ref()?;

    // Resolve the author's durable identity (attributed email for email-rooted
    // writes, so it is stable across browserid key rotation).
    //
    // `creator` is IMMUTABLE. On an UPDATE to an already-occupied `(path, id)`
    // slot, preserve the incumbent object's creator: a *different* authorized
    // signer (e.g. a self-authorizing `/sys/dnssec` refresh, whose policy grants
    // update to all) changes the content/owner but never the creator. Only a
    // fresh CREATE (empty slot) derives a new creator from the message. Beyond
    // matching the spec's immutable-creator rule, this is what lets the pending
    // overlay distinguish a *losing create* (different creator → dropped) from a
    // *valid update* (creator preserved → same creator → LWW) — see
    // `state_view::merge`. Recomputing creator per-write would flip the stored
    // creator on a self-auth refresh and cause the overlay to drop it.
    let creator = match state.and_then(|s| s.get_object(&msg.path, &msg.id).ok().flatten()) {
        Some(existing) => existing.creator,
        None => resolve_creator(msg, state, l2),
    };

    // Legacy signer-key owner record (retained for objects/proofs that still
    // read it). Ownership checks key off `owner_ref` (the resolved controller).
    let owner = Id::new(&msg.signing_key.to_string())
        .unwrap_or_else(|_| Id::new("unknown").unwrap());

    Some(StoredObject {
        path: msg.path.clone(),
        id: msg.id.clone(),
        creator,
        owner,
        content_type: content_type.clone(),
        content_hash: content_hash.clone(),
        payload: payload.clone(),
        policy_ref: msg.policy_ref.clone(),
        content_schema: msg.content_schema.clone(),
        // Record the resolved effective owner (Owner → else Creator → else
        // signer) so later ownership checks authorize against the controller,
        // not the ephemeral signer key. Always set (never None for new writes).
        owner_ref: Some(effective_owner_ref(msg)),
        block_number,
        object_hash,
        hlc: msg.hlc.clone(),
        prev: msg.prev.clone(),
    })
}

/// Format a schema error for display
fn format_schema_error(e: &SchemaError) -> String {
    match e {
        SchemaError::UnknownSchema(schema) => {
            format!("Unknown Content-Schema: {}", schema)
        }
        SchemaError::InvalidJson(err) => {
            format!("Invalid JSON payload: {}", err)
        }
        SchemaError::MissingField(field) => {
            format!("Missing required field: {}", field)
        }
        SchemaError::InvalidField { field, reason } => {
            format!("Invalid field '{}': {}", field, reason)
        }
        SchemaError::KeyMismatch { payload_key, header_key } => {
            format!(
                "Key mismatch: public_key in payload ({}) does not match Public-Key header ({})",
                payload_key, header_key
            )
        }
        SchemaError::EmptyPayload => {
            "Payload is empty but Content-Schema requires validation".to_string()
        }
    }
}
