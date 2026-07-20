//! Message validation against state
//!
//! Validates SBO messages before they are applied to the repo.

use sbo_core::authorize::{
    audience_identifies_db, authorize_owner, authorized_write_email, encode_auth_evidence_inline,
    message_attribution, presentation_audience, presentation_issuer, AuthzOutcome,
};
use sbo_core::attribution::TrustAnchors;
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

/// The device-model attribution's **effective author** for a message that
/// carries a presentation (`Auth-Cert`) that authorizes THIS write: the warrant
/// identifier (a user or an agent, per the presentation's subject). Returns
/// `None` when the signer is unattributed — no presentation, verification fails,
/// the presentation's audience does not identify this database, the block time
/// is unknown, or the warrant's scopes do not permit this action/path/schema.
///
/// This is the single attribution path (device-cert model): it feeds both owner
/// authorization (`l2_authorize`) and the policy actor / `$email` var /
/// attestation subject (`attributed_email`), so they never disagree on who the
/// write acts as.
fn device_effective_email(msg: &Message, state: &dyn StateView, l2: &L2Context) -> Option<String> {
    let presentation = msg.auth_cert.as_deref()?;
    let evidence = resolve_evidence(msg, state)?;
    let db = l2.db.as_ref()?;
    // The presentation's warrant audience must identify THIS database; the exact
    // audience string is what the verifier enforces the assertion + warrant bind
    // to (bare authority survives a regenesis; a pinned one confines it).
    let aud = presentation_audience(presentation)?;
    if !audience_identifies_db(&aud, &db.uri, db.genesis.as_deref()) {
        return None;
    }
    // An unknown block time cannot satisfy any DNSSEC/cert window → fail closed.
    let inclusion_time = l2.inclusion_time?;
    let attr = message_attribution(
        &msg.signing_key.to_string(),
        Some(presentation),
        Some(&evidence),
        &aud,
        inclusion_time,
        &l2.anchors,
    )?;
    authorized_write_email(
        &attr,
        msg.action.name(),
        &msg.path.to_string(),
        msg.content_schema.as_deref(),
    )
    .ok()
}

fn l2_authorize(msg: &Message, state: &dyn StateView, l2: &L2Context, owner_ref: &str) -> Result<(), String> {
    let signer = msg.signing_key.to_string();
    let lookup = name_lookup(state);
    let pd = primary_domain(state);
    // The attributed email is the device-model effective author (or None for a
    // key-rooted owner authorized by direct signature, which needs no
    // attribution).
    let email = device_effective_email(msg, state, l2);
    match authorize_owner(owner_ref, &signer, email.as_deref(), &lookup, DEFAULT_HOP_LIMIT, pd.as_deref()) {
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
            // Absent evidence: try the conventional /sys/dnssec/<issuer> object,
            // where <issuer> is the presentation's access-cert issuer.
            let issuer = presentation_issuer(msg.auth_cert.as_deref()?)?;
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
    // The write's attributed identity is its device-model effective author — the
    // warrant identifier the presentation certifies. This is the identity the
    // policy actor, `$email`/`$user` vars, and attestation-role matching must all
    // evaluate against. Resolving it needs state (evidence + database identity);
    // the pure path (no state) can't attribute and returns None (fails closed).
    state.and_then(|s| device_effective_email(msg, s, l2))
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
        } else if let Err(reason) = check_policy_delegation(state, msg) {
            // P2/P3/P4 delegation terms: version pin rules, descendant-constraint
            // template, and the no-pin restriction.
            return ValidationResult::Invalid {
                stage: ValidationStage::Policy,
                reason: format!("Policy write violates delegation constraints on {}: {}", msg.path, reason),
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

    // A `by`-qualified attested role must resolve even when the issuer's
    // attestations live under a `/u/<issuer>/attestations/` namespace (mingo's
    // layout) rather than the bare `/<issuer>/attestations/`. Before the fix,
    // attested_subject_matches prefix-scanned `/<by>/attestations/` and silently
    // missed these — breaking every moderator role and every `not_attested{by}`
    // ban. Now it schema-scans and filters by resolved issuer, so layout is
    // irrelevant. (Regression for the mingo-n268 moderator-delete live failure.)
    #[test]
    fn by_qualified_attested_resolves_under_u_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();

        let issuer = SigningKey::generate().public_key().to_string();
        let subject = SigningKey::generate().public_key().to_string();

        // The moderator attestation, stored under /u/<issuer>/attestations/ (NOT
        // the bare /<issuer>/ the old prefix scan assumed).
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": subject,
            "type": "role:moderator:cooks",
            "value": "moderator",
            "issued_at": 1,
            "expires": serde_json::Value::Null,
            "issuer": issuer,
        })).unwrap();
        db.put_object(&StoredObject {
            path: SboPath::parse(&format!("/u/{issuer}/attestations/{subject}/")).unwrap(),
            id: Id::new("role:moderator:cooks").unwrap(),
            creator: Id::new(&issuer).unwrap(),
            owner: Id::new(&issuer).unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ContentHash::sha256(&payload),
            payload,
            policy_ref: None,
            content_schema: Some("attestation.v1".to_string()),
            owner_ref: Some(issuer.clone()),
            block_number: 2,
            object_hash: [4u8; 32],
            hlc: Some("2.0".to_string()),
            prev: None,
        }).unwrap();

        let l2 = L2Context::for_block(Some(1_000), &db);
        let requester = resolve_controller(&subject, &name_lookup(&db), DEFAULT_HOP_LIMIT, None);
        let source = AttestedSource { type_: "role:moderator:cooks".to_string(), by: Some(issuer.clone()) };
        assert!(
            attested_subject_matches(&db, &l2, &requester, &source),
            "by-qualified moderator attestation under /u/ must resolve"
        );

        // A different issuer must NOT match (the per-candidate issuer filter still bites).
        let other = SigningKey::generate().public_key().to_string();
        let wrong = AttestedSource { type_: "role:moderator:cooks".to_string(), by: Some(other) };
        assert!(
            !attested_subject_matches(&db, &l2, &requester, &wrong),
            "an attestation by a different issuer must not satisfy the role"
        );
    }

    // ===== P2/P3/P4 policy-delegation primitives =====

    use sbo_core::policy::PolicyPin;

    /// Index a `policy.v2` into state the way the sync apply path does: write the
    /// object, index the versioned policy entry (with the on-chain content-hash),
    /// and run the pin refcount/version bookkeeping. Returns the content-hash.
    fn index_policy(
        db: &StateDb,
        path: &str,
        id: &str,
        creator: &str,
        policy: &Policy,
        block: u64,
    ) -> String {
        let sbo_path = SboPath::parse(path).unwrap();
        let sid = Id::new(id).unwrap();
        let payload = serde_json::to_vec(policy).unwrap();
        let ch = ContentHash::sha256(&payload);
        let ch_str = ch.to_string();
        let old_pin = db
            .get_object(&sbo_path, &sid)
            .ok()
            .flatten()
            .and_then(|o| serde_json::from_slice::<Policy>(&o.payload).ok())
            .and_then(|p| p.pin);
        db.put_object(&StoredObject {
            path: sbo_path.clone(),
            id: sid,
            creator: Id::new(creator).unwrap(),
            owner: Id::new(creator).unwrap(),
            content_type: "application/json".to_string(),
            content_hash: ch.clone(),
            payload,
            policy_ref: None,
            content_schema: Some("policy.v2".to_string()),
            owner_ref: Some(creator.to_string()),
            block_number: block,
            object_hash: [block as u8; 32],
            hlc: Some(format!("{block}.0")),
            prev: None,
        })
        .unwrap();
        db.put_policy_at(&sbo_path, policy, &ch_str, block).unwrap();
        let new_pin = policy.pin.clone();
        if new_pin != old_pin {
            if let Some(pin) = &new_pin {
                if let Ok(Some(entry)) =
                    db.resolve_policy_entry(&SboPath::parse(&pin.ancestor).unwrap())
                {
                    db.pin_incref(&pin.hash, &entry.policy).unwrap();
                }
            }
            if let Some(pin) = &old_pin {
                db.pin_decref(&pin.hash).unwrap();
            }
        }
        ch_str
    }

    /// A root policy granting `board_key` govern on `/communities/cooks/**`, sys
    /// admin govern on `/**`, and owner-all. `extra` optionally splices in a
    /// descendant_constraint or drops the board grant (via a prebuilt json).
    fn root_policy(board_key: &str, board_can_govern: bool) -> Policy {
        let mut grants = serde_json::json!([
            { "to": "owner", "can": ["*"], "on": "/**" }
        ]);
        if board_can_govern {
            grants.as_array_mut().unwrap().push(serde_json::json!(
                { "to": { "key": board_key }, "can": ["govern"], "on": "/communities/cooks/**" }
            ));
        }
        serde_json::from_value(serde_json::json!({ "grants": grants })).unwrap()
    }

    fn community_policy(pin: Option<PolicyPin>) -> Policy {
        let mut p: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{ "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" }]
        }))
        .unwrap();
        p.pin = pin;
        p
    }

    // Install the root policy OBJECT + index so root_policy_present() is true.
    fn install_root(db: &StateDb, policy: &Policy, block: u64) -> String {
        index_policy(db, "/sys/policies/", "root", "sys@mingo.place", policy, block)
    }

    // P2 — creation pin MUST equal the current latest ancestor version.
    #[test]
    fn p2_creation_pin_must_be_latest() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let board = SigningKey::generate();
        let root_hash = install_root(&db, &root_policy(&board.public_key().to_string(), true), 1);
        let l2 = L2Context::for_block(Some(1_700_000_000), &db);

        // Correct pin (== latest root) → accepted.
        let good = community_policy(Some(PolicyPin {
            ancestor: "/sys/policies/".into(),
            hash: root_hash.clone(),
            block: Some(1),
        }));
        let msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&good).unwrap());
        assert!(
            matches!(validate_message(&msg, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "pin equal to latest ancestor must be accepted"
        );

        // Wrong/stale pin hash → rejected at Policy stage.
        let bad = community_policy(Some(PolicyPin {
            ancestor: "/sys/policies/".into(),
            hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            block: Some(1),
        }));
        let bad_msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&bad).unwrap());
        match validate_message(&bad_msg, &db, std::path::Path::new("/tmp"), &l2) {
            ValidationResult::Invalid { stage, reason } => {
                assert_eq!(stage, ValidationStage::Policy, "{reason}");
                assert!(reason.contains("latest ancestor") || reason.contains("forward-only"), "{reason}");
            }
            ValidationResult::Valid { .. } => panic!("a pin not equal to latest ancestor must be rejected"),
        }
    }

    // P2 — a PINNED child is immune to a later ancestor amendment that revokes the
    // board's govern; an UNPINNED (tracking) child is not.
    #[test]
    fn p2_pinned_child_immune_to_ancestor_change() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let board = SigningKey::generate();
        let bk = board.public_key().to_string();

        // Root V1 grants board govern; community pins root@V1.
        let root_v1 = root_policy(&bk, true);
        let root_v1_hash = install_root(&db, &root_v1, 1);
        let pin = PolicyPin { ancestor: "/sys/policies/".into(), hash: root_v1_hash.clone(), block: Some(1) };
        let comm = community_policy(Some(pin.clone()));
        // Board creates the pinned community policy (validate then persist).
        let l2 = L2Context::for_block(Some(1_700_000_000), &db);
        let create = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&comm).unwrap());
        assert!(matches!(validate_message(&create, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }));
        index_policy(&db, "/communities/cooks/", "root", "board", &comm, 2);

        // Root amended to V2, REVOKING the board's govern grant.
        let root_v2 = root_policy(&bk, false);
        install_root(&db, &root_v2, 3);

        // The board updates the community policy again, KEEPING pin@V1. Immune:
        // governance resolves against the pinned V1 (which still grants board govern).
        let comm2 = community_policy(Some(pin.clone()));
        let update = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&comm2).unwrap());
        assert!(
            matches!(validate_message(&update, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "a pinned child must stay governable under its pinned ancestor version"
        );

        // Control: an UNPINNED community tracks latest V2 → board govern is gone → denied.
        let dir2 = tempfile::tempdir().unwrap();
        let db2 = StateDb::open(dir2.path()).unwrap();
        install_root(&db2, &root_policy(&bk, true), 1);
        let unpinned = community_policy(None);
        index_policy(&db2, "/communities/cooks/", "root", "board", &unpinned, 2);
        install_root(&db2, &root_policy(&bk, false), 3); // revoke board govern
        let l2b = L2Context::for_block(Some(1_700_000_000), &db2);
        let track_update = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&unpinned).unwrap());
        match validate_message(&track_update, &db2, std::path::Path::new("/tmp"), &l2b) {
            ValidationResult::Invalid { stage, .. } => assert_eq!(stage, ValidationStage::Policy),
            ValidationResult::Valid { .. } => panic!("an unpinned child must lose govern when the ancestor revokes it"),
        }
    }

    // P2 — a snapshot round-trip carries the pinned historical version, so a
    // fast-synced node authorizes a write under the pinned child.
    #[test]
    fn p2_snapshot_roundtrip_authorizes_pinned_child() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let board = SigningKey::generate();
        let bk = board.public_key().to_string();

        let root_v1_hash = install_root(&db, &root_policy(&bk, true), 1);
        let pin = PolicyPin { ancestor: "/sys/policies/".into(), hash: root_v1_hash, block: Some(1) };
        let comm = community_policy(Some(pin));
        index_policy(&db, "/communities/cooks/", "root", "board", &comm, 2);
        install_root(&db, &root_policy(&bk, false), 3); // root moves on; V1 retained by pin

        // Build a snapshot payload from the source DB and load it into a fresh DB.
        let objects = db.list_objects_by_path_prefix("/").unwrap();
        let policy_versions = db.list_policy_versions().unwrap();
        assert!(!policy_versions.is_empty(), "the pinned V1 must be retained for the snapshot");
        let payload = crate::snapshot::SnapshotPayload { objects: objects.clone(), policy_versions };
        let root = crate::snapshot::compute_snapshot_root(&objects);

        let dir2 = tempfile::tempdir().unwrap();
        let db2 = StateDb::open(dir2.path()).unwrap();
        crate::bootstrap::verify_and_load_payload(&db2, &payload, root).unwrap();

        // On the fast-synced node the board updates the pinned community policy → authorized.
        let comm2 = community_policy(comm.pin.clone());
        let l2 = L2Context::for_block(Some(1_700_000_000), &db2);
        let update = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&comm2).unwrap());
        assert!(
            matches!(validate_message(&update, &db2, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "fast-synced node must authorize a write under a pinned child using the snapshotted version"
        );
    }

    // P3 — a child grant exceeding the parent's descendant-constraint template is
    // rejected; direct-children-only (a grandchild is not bound by the grandparent).
    #[test]
    fn p3_descendant_constraint_direct_only() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let board = SigningKey::generate();
        let bk = board.public_key().to_string();

        // Root grants board govern broadly + a descendant-constraint template that
        // only allows child `create` grants under spaces/**.
        let mut root: Policy = serde_json::from_value(serde_json::json!({
            "grants": [
                { "to": "owner", "can": ["*"], "on": "/**" },
                { "to": { "key": bk }, "can": ["govern"], "on": "/communities/**" }
            ],
            "descendant_constraint": {
                "allowed_grants": [{ "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" }]
            }
        }))
        .unwrap();
        root.pin = None;
        install_root(&db, &root, 1);
        let l2 = L2Context::for_block(Some(1_700_000_000), &db);

        // A community that grants `*` (over-broad) → rejected.
        let over: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{ "to": "*", "can": ["*"], "on": "/communities/cooks/spaces/**" }]
        }))
        .unwrap();
        let over_msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&over).unwrap());
        match validate_message(&over_msg, &db, std::path::Path::new("/tmp"), &l2) {
            ValidationResult::Invalid { stage, reason } => {
                assert_eq!(stage, ValidationStage::Policy, "{reason}");
                assert!(reason.contains("template") || reason.contains("descendant"), "{reason}");
            }
            ValidationResult::Valid { .. } => panic!("an over-broad child grant must be rejected"),
        }

        // A conforming community (create only) → accepted, then persisted.
        let ok = community_policy(None);
        let ok_msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&ok).unwrap());
        assert!(matches!(validate_message(&ok_msg, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }));
        index_policy(&db, "/communities/cooks/", "root", "board", &ok, 2);

        // Direct-only: a GRANDCHILD policy (under the community, whose own policy has
        // NO descendant_constraint) is NOT bound by the ROOT's clause. The community
        // grants create there and delegates govern to the board (add a govern grant).
        let mut comm_deleg: Policy = serde_json::from_value(serde_json::json!({
            "grants": [
                { "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" },
                { "to": { "key": bk }, "can": ["govern"], "on": "/communities/cooks/spaces/**" }
            ]
        }))
        .unwrap();
        comm_deleg.pin = None;
        index_policy(&db, "/communities/cooks/", "root", "board", &comm_deleg, 3);
        // The grandchild grants `*` — root's clause does NOT reach it (its parent,
        // the community policy, has no constraint), so it is admitted.
        let grand: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{ "to": "*", "can": ["*"], "on": "/communities/cooks/spaces/general/**" }]
        }))
        .unwrap();
        let grand_msg = policy_write_msg(&board, "/communities/cooks/spaces/general/", serde_json::to_value(&grand).unwrap());
        assert!(
            matches!(validate_message(&grand_msg, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "a grandchild must be constrained only by its DIRECT parent, not the grandparent"
        );
    }

    // P4 — a parent that forbids pinning rejects a pinned child; a tracking child passes.
    #[test]
    fn p4_no_pin_restriction() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path()).unwrap();
        let board = SigningKey::generate();
        let bk = board.public_key().to_string();

        let root: Policy = serde_json::from_value(serde_json::json!({
            "grants": [
                { "to": "owner", "can": ["*"], "on": "/**" },
                { "to": { "key": bk }, "can": ["govern"], "on": "/communities/**" }
            ],
            "descendant_constraint": {
                "allowed_grants": [{ "to": "*", "can": ["create"], "on": "/communities/cooks/spaces/**" }],
                "forbid_pinning": true
            }
        }))
        .unwrap();
        let root_hash = install_root(&db, &root, 1);
        let l2 = L2Context::for_block(Some(1_700_000_000), &db);

        // A pinned child under a forbid_pinning parent → rejected.
        let pinned = community_policy(Some(PolicyPin {
            ancestor: "/sys/policies/".into(),
            hash: root_hash,
            block: Some(1),
        }));
        let pinned_msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&pinned).unwrap());
        match validate_message(&pinned_msg, &db, std::path::Path::new("/tmp"), &l2) {
            ValidationResult::Invalid { stage, reason } => {
                assert_eq!(stage, ValidationStage::Policy, "{reason}");
                assert!(reason.contains("forbids pinning"), "{reason}");
            }
            ValidationResult::Valid { .. } => panic!("a pinned child under forbid_pinning must be rejected"),
        }

        // A tracking (unpinned) child → accepted.
        let tracking = community_policy(None);
        let track_msg = policy_write_msg(&board, "/communities/cooks/", serde_json::to_value(&tracking).unwrap());
        assert!(
            matches!(validate_message(&track_msg, &db, std::path::Path::new("/tmp"), &l2), ValidationResult::Valid { .. }),
            "a tracking child under forbid_pinning must be accepted"
        );
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
    // Pin-aware (P2): a pinned policy's governance resolves against the version
    // its EXISTING object pinned, so a later ancestor amendment cannot reach in
    // (the sovereignty property). Unpinned/create → the current latest parent.
    let (governing, _latest_hash) = governing_parent_policy(state, msg)?;
    evaluate_policy_for(state, msg, &governing, &msg.path, ActionType::Govern, None, l2)
}

/// The parent policy the govern/constraint checks evaluate against for a write to
/// the policy object at `msg.path`, plus the current-latest ancestor
/// content-hash (for P2 pin validation).
///
/// Governance is frozen by the EXISTING object's pin: if the policy currently at
/// `msg.path` pins a historical ancestor version, that version governs (who may
/// amend/delete it) — immune to later ancestor amendment. Absent a pin (or on a
/// create into an empty slot), the current latest parent governs (tracking /
/// eminent-domain regime).
fn governing_parent_policy(
    state: &dyn StateView,
    msg: &Message,
) -> Result<(sbo_core::policy::Policy, String), String> {
    let parent = parent_container_path(&msg.path);
    let parent_entry = match state.resolve_policy_entry(&parent) {
        Ok(Some(e)) => e,
        Ok(None) => return Err("No applicable parent policy found".to_string()),
        Err(e) => return Err(format!("Error resolving parent policy: {e}")),
    };
    let latest_hash = parent_entry.content_hash.clone();

    let old_pin = state
        .get_object(&msg.path, &msg.id)
        .ok()
        .flatten()
        .and_then(|o| policy_pin_of_object(&o));

    let governing = match old_pin {
        Some(pin) => state
            .get_policy_version(&pin.hash)
            .ok()
            .flatten()
            .unwrap_or(parent_entry.policy),
        None => parent_entry.policy,
    };
    Ok((governing, latest_hash))
}

/// Parse the [`PolicyPin`] a stored policy object carries, if any.
fn policy_pin_of_object(obj: &StoredObject) -> Option<sbo_core::policy::PolicyPin> {
    if !is_policy_object(obj) {
        return None;
    }
    serde_json::from_slice::<sbo_core::policy::Policy>(&obj.payload)
        .ok()
        .and_then(|p| p.pin)
}

/// Validate the delegation terms of a policy write (P2 pin rules, P3 descendant
/// constraint, P4 no-pin restriction). Called after [`require_govern`] for a
/// `policy.v2` create/update. `Err(reason)` rejects the write.
fn check_policy_delegation(
    state: &dyn StateView,
    msg: &Message,
) -> Result<(), String> {
    let payload = msg.payload.as_deref().ok_or("policy write has no payload")?;
    let new_policy: sbo_core::policy::Policy =
        serde_json::from_slice(payload).map_err(|e| format!("invalid policy payload: {e}"))?;

    let old_pin = state
        .get_object(&msg.path, &msg.id)
        .ok()
        .flatten()
        .and_then(|o| policy_pin_of_object(&o));

    // The current latest DIRECT parent policy + its content-hash.
    let parent = parent_container_path(&msg.path);
    let parent_entry = match state.resolve_policy_entry(&parent) {
        Ok(Some(e)) => e,
        Ok(None) => return Err("No applicable parent policy found".to_string()),
        Err(e) => return Err(format!("Error resolving parent policy: {e}")),
    };

    let new_pin = new_policy.pin.clone();
    let keeping = new_pin.is_some() && new_pin == old_pin;

    // P4 — a parent that forbids pinning rejects any pinned child (evaluated
    // against the CURRENT parent: it is the ancestor's live retightening lever).
    if new_pin.is_some() {
        if let Some(c) = &parent_entry.policy.descendant_constraint {
            if c.forbid_pinning {
                return Err("parent policy forbids pinning (P4): child must track the latest ancestor".to_string());
            }
        }
    }

    // P2 — pin must equal the current latest ancestor version, UNLESS the child
    // is keeping its existing pin verbatim (frozen). This makes creation-pin ==
    // latest and update either keep-or-advance-forward-to-current (never
    // backward, since the only non-keep value accepted is the current latest).
    if let Some(pin) = &new_pin {
        if !keeping && pin.hash != parent_entry.content_hash {
            return Err(format!(
                "policy pin {} must equal the current latest ancestor version {} (or keep the existing pin) — forward-only",
                pin.hash, parent_entry.content_hash
            ));
        }
    }

    // The parent version whose descendant-constraint template applies: the pinned
    // version when the child is keeping a frozen pin, else the current latest.
    let governing_parent = if keeping {
        new_pin
            .as_ref()
            .and_then(|p| state.get_policy_version(&p.hash).ok().flatten())
            .unwrap_or(parent_entry.policy)
    } else {
        parent_entry.policy
    };

    // P3 — the child must satisfy the parent's descendant-constraint template.
    if let Some(c) = &governing_parent.descendant_constraint {
        sbo_core::policy::check_descendant_constraint(&new_policy, c)?;
    }

    Ok(())
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
    evaluate_policy_for(state, msg, &policy, match_target, action, owner, l2)
}

/// Evaluate an already-resolved `policy` for `action` on `match_target`. Split
/// out of [`check_policy_resolving_at`] so a caller that has determined the
/// governing policy directly (e.g. the pin-aware govern check, which substitutes
/// a pinned historical ancestor version) can evaluate against it.
#[allow(clippy::too_many_arguments)]
fn evaluate_policy_for(
    state: &dyn StateView,
    msg: &Message,
    policy: &sbo_core::policy::Policy,
    match_target: &sbo_core::message::Path,
    action: ActionType,
    owner: Option<&str>,
    l2: &L2Context,
) -> Result<(), String> {
    let target = match_target;
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
    match evaluate(policy, &actor, action, &target_path, &policy_vars, signer_is_owner, &is_attested, msg, pd.as_deref()) {
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
/// We enumerate `attestation.v1` objects by SCHEMA (layout-independent) and, when
/// `by` is given, confirm each candidate's issuer resolves to `by` per-object
/// below. Correctness never depended on WHERE the attestation is stored — the
/// issuer is the object's authenticated controller (`owner_ref`), not its path —
/// so we must not narrow by a hardcoded path prefix: a `/<by>/attestations/`
/// prefix scan silently misses issuers whose namespace is laid out differently
/// (e.g. mingo stores them under `/u/<issuer>/attestations/`, which broke every
/// `by`-qualified role — moderators — and every `not_attested{by}` ban). All
/// inputs are on-chain and inclusion-time-pinned, so the decision is
/// deterministic on replay.
fn attested_subject_matches(
    state: &dyn StateView,
    l2: &L2Context,
    requester: &Controller,
    source: &AttestedSource,
) -> bool {
    let lookup = name_lookup(state);
    let pd = primary_domain(state);
    let t = l2.inclusion_time.unwrap_or(0);
    let candidates = state
        .list_objects_by_schema("attestation.v1")
        .unwrap_or_default();
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
