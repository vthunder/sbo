//! Genesis validation (SBO Genesis Specification §Genesis Validation).
//!
//! The bootstrap window is exactly the **mode-object prefix** of one DA
//! submission at the anchor block (Q7 (a), Q33 (b); audit 2026-11 D5/D23/S19):
//!
//! * Mode A: `/sys/names/sys`, `/sys/policies/root`;
//! * Mode B: `/sys/dnssec/<domain>`, `/sys/domains/<domain>`, `/sys/names/sys`,
//!   `/sys/policies/root`.
//!
//! The prefix is validated **structurally** here (mode detection, object set,
//! relative order, JWT chain of certification, signatures, DNSSEC
//! self-certification in Mode B). Everything after the root policy — in the
//! genesis submission and in every later one — is an ordinary write validated
//! by the normal rules against the state the prefix left; that is the caller's
//! job (`sbo-daemon`'s sync path), not this module's. There is no genesis
//! mode: before the root policy nothing but this prefix is ever valid.

use crate::attribution::TrustAnchors;
use crate::crypto::{ContentHash, PublicKey};
use crate::message::{verify_message, Action, Message, ObjectType};
use crate::policy::Policy;
use crate::wire;

/// Which trust model a genesis establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisMode {
    /// Mode A: `sys` is self-signed and is the root of trust.
    SelfSigned,
    /// Mode B: a DNSSEC-proven domain certifies `sys`.
    DomainCertified { domain: String },
}

/// What a valid genesis prefix established.
#[derive(Debug, Clone)]
pub struct GenesisInfo {
    pub mode: GenesisMode,
    /// The `sys` signing key (from the `/sys/names/sys` JWT).
    pub sys_key: PublicKey,
    /// The creator identity of the mode objects: `sys` (Mode A) or the
    /// domain-certified `sys@<domain>` (Mode B), as the identity JWT names it.
    pub sys_identity: String,
    /// Number of messages in the mode-object prefix (2 or 4). Messages at
    /// index `prefix_len..` are ordinary writes under the root policy.
    pub prefix_len: usize,
    /// The parsed root policy.
    pub root_policy: Policy,
}

/// Why a submission is not a valid genesis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenesisError {
    #[error("empty submission")]
    Empty,
    #[error("not a genesis submission: first message is {0}")]
    NotAGenesis(String),
    #[error("genesis message {index}: expected {expected}, got {got}")]
    UnexpectedObject { index: usize, expected: String, got: String },
    #[error("genesis message {index} ({what}): {reason}")]
    Invalid { index: usize, what: String, reason: String },
}

/// Genesis validator.
pub struct Genesis;

impl Genesis {
    /// Validate the mode-object prefix of a genesis submission, with no
    /// inclusion time and the library's built-in DNS root anchors. In Mode B
    /// the DNSSEC proof is validated but its RRSIG window is not pinned to a
    /// block; use [`Genesis::validate_at`] on the sync path.
    pub fn validate(messages: &[Message]) -> Result<GenesisInfo, GenesisError> {
        Self::validate_at(messages, None, &TrustAnchors::with_brokers(Vec::new()))
    }

    /// Whether `messages` *looks like* a genesis submission (Genesis Spec
    /// §Genesis Detection, step 2): its first message is a Mode A or Mode B
    /// opener. Structure is not checked; see [`Genesis::validate_at`].
    pub fn is_candidate(messages: &[Message]) -> bool {
        messages.first().map(|m| detect_mode(m).is_some()).unwrap_or(false)
    }

    /// Validate the mode-object prefix of a genesis submission at the anchor
    /// block's inclusion time `at` (when known) against `anchors`.
    ///
    /// Returns the prefix length and what it established; the caller applies
    /// the prefix objects structurally and validates every later message by
    /// the ordinary rules (Genesis Spec §Bootstrap Window rules 3–5).
    pub fn validate_at(
        messages: &[Message],
        at: Option<i64>,
        anchors: &TrustAnchors,
    ) -> Result<GenesisInfo, GenesisError> {
        let first = messages.first().ok_or(GenesisError::Empty)?;
        match detect_mode(first) {
            Some(GenesisMode::SelfSigned) => validate_mode_a(messages),
            Some(GenesisMode::DomainCertified { domain }) => validate_mode_b(messages, &domain, at, anchors),
            None => Err(GenesisError::NotAGenesis(describe(first))),
        }
    }
}

fn detect_mode(first: &Message) -> Option<GenesisMode> {
    if !matches!(first.action, Action::Post) {
        return None;
    }
    let path = first.path.to_string();
    if path == "/sys/dnssec/" {
        return Some(GenesisMode::DomainCertified { domain: first.id.as_str().to_string() });
    }
    if path == "/sys/names/" && first.id.as_str() == "sys" {
        return Some(GenesisMode::SelfSigned);
    }
    None
}

fn describe(m: &Message) -> String {
    format!("{:?} {}{}", m.action, m.path, m.id)
}

fn invalid(index: usize, what: &str, reason: impl std::fmt::Display) -> GenesisError {
    GenesisError::Invalid { index, what: what.to_string(), reason: reason.to_string() }
}

/// The message at `index` must be a signed `post` of an object at
/// `(path, id)` carrying `schema`.
fn expect_object<'a>(
    messages: &'a [Message],
    index: usize,
    path: &str,
    id: &str,
    schema: &str,
) -> Result<&'a Message, GenesisError> {
    let expected = format!("post {path}{id} ({schema})");
    let m = messages.get(index).ok_or_else(|| GenesisError::UnexpectedObject {
        index,
        expected: expected.clone(),
        got: "end of submission".to_string(),
    })?;
    let matches = matches!(m.action, Action::Post)
        && m.path.to_string() == path
        && m.id.as_str() == id
        && m.content_schema.as_deref() == Some(schema);
    if !matches {
        return Err(GenesisError::UnexpectedObject { index, expected, got: describe(m) });
    }
    if m.object_type != ObjectType::Object {
        return Err(invalid(index, &expected, "not an object"));
    }
    verify_message(m).map_err(|e| invalid(index, &expected, format!("signature: {e}")))?;
    Ok(m)
}

fn payload_str<'a>(m: &'a Message, index: usize, what: &str) -> Result<&'a str, GenesisError> {
    let bytes = m.payload.as_deref().ok_or_else(|| invalid(index, what, "no payload"))?;
    std::str::from_utf8(bytes).map_err(|_| invalid(index, what, "payload is not UTF-8"))
}

/// An owner header on a mode object, if present, must name `sys` itself (the
/// one self-certifying name; Identity Spec §Owner References).
fn check_self_owned(m: &Message, index: usize, what: &str, sys_identity: &str) -> Result<(), GenesisError> {
    for (header, value) in [("Owner", &m.owner), ("Creator", &m.creator)] {
        if let Some(v) = value {
            let v = v.as_str();
            if v != "sys" && v != sys_identity {
                return Err(invalid(index, what, format!("{header} '{v}' is not sys (a mode object is owned by sys)")));
            }
        }
    }
    Ok(())
}

fn check_root_policy(messages: &[Message], index: usize, sys_key: &PublicKey) -> Result<Policy, GenesisError> {
    let what = "/sys/policies/root";
    let root = expect_object(messages, index, "/sys/policies/", "root", "policy.v2")?;
    if &root.signing_key != sys_key {
        return Err(invalid(index, what, "root policy is not signed by the sys key"));
    }
    let bytes = root.payload.as_deref().ok_or_else(|| invalid(index, what, "no payload"))?;
    serde_json::from_slice::<Policy>(bytes).map_err(|e| invalid(index, what, format!("not a valid policy.v2 document: {e}")))
}

fn validate_mode_a(messages: &[Message]) -> Result<GenesisInfo, GenesisError> {
    // 1. /sys/names/sys: self-signed identity.v1, Public-Key header == payload key.
    let what = "/sys/names/sys";
    let sys = expect_object(messages, 0, "/sys/names/", "sys", "identity.v1")?;
    let token = payload_str(sys, 0, what)?;
    let claims = crate::jwt::verify_self_signed_identity(token)
        .map_err(|e| invalid(0, what, format!("identity JWT: {e}")))?;
    if claims.sub != "sys" {
        return Err(invalid(0, what, format!("JWT subject '{}' is not 'sys'", claims.sub)));
    }
    let sys_key = PublicKey::parse(&claims.public_key).map_err(|e| invalid(0, what, format!("JWT public_key: {e}")))?;
    if sys.signing_key != sys_key {
        return Err(invalid(0, what, "Public-Key header does not match the JWT public_key"));
    }
    check_self_owned(sys, 0, what, "sys")?;

    // 2. /sys/policies/root signed by sys.
    let root_policy = check_root_policy(messages, 1, &sys_key)?;
    check_self_owned(&messages[1], 1, "/sys/policies/root", "sys")?;

    Ok(GenesisInfo {
        mode: GenesisMode::SelfSigned,
        sys_key,
        sys_identity: "sys".to_string(),
        prefix_len: 2,
        root_policy,
    })
}

fn validate_mode_b(
    messages: &[Message],
    domain: &str,
    at: Option<i64>,
    anchors: &TrustAnchors,
) -> Result<GenesisInfo, GenesisError> {
    // 1. /sys/dnssec/<domain>: a dnssec.v1 evidence object. Its proof is judged
    //    together with the domain key it must prove (step 2).
    let dnssec_what = format!("/sys/dnssec/{domain}");
    let dnssec = expect_object(messages, 0, "/sys/dnssec/", domain, "dnssec.v1")?;
    let evidence = dnssec.payload.as_deref().ok_or_else(|| invalid(0, &dnssec_what, "no payload"))?;

    // 2. /sys/domains/<domain>: self-signed domain.v1, header key == payload key,
    //    and that key is the `_browserid.<domain>` provider key the proof
    //    establishes (self-certification, REQUIRED).
    let domain_what = format!("/sys/domains/{domain}");
    let dom = expect_object(messages, 1, "/sys/domains/", domain, "domain.v1")?;
    let token = payload_str(dom, 1, &domain_what)?;
    let dclaims = crate::jwt::verify_domain(token).map_err(|e| invalid(1, &domain_what, format!("domain JWT: {e}")))?;
    if dclaims.sub != domain {
        return Err(invalid(1, &domain_what, format!("JWT subject '{}' is not the domain", dclaims.sub)));
    }
    let domain_key = PublicKey::parse(&dclaims.public_key)
        .map_err(|e| invalid(1, &domain_what, format!("JWT public_key: {e}")))?;
    if dom.signing_key != domain_key {
        return Err(invalid(1, &domain_what, "Public-Key header does not match the JWT public_key"));
    }
    let (provider_key, inception, expiration) =
        crate::attribution::extract_provider_key_with_anchors(evidence, domain, anchors, at)
            .map_err(|e| invalid(0, &dnssec_what, format!("DNSSEC evidence: {e}")))?;
    let window_at = at.unwrap_or(inception);
    crate::attribution::check_domain_binding(&dclaims.public_key, &provider_key, inception, expiration, window_at)
        .map_err(|e| invalid(1, &domain_what, format!("self-certification: {e}")))?;

    // 3. /sys/names/sys: identity.v1 with iss "domain:<domain>", signed by the
    //    domain key, Public-Key header == payload key.
    let sys_what = "/sys/names/sys";
    let sys = expect_object(messages, 2, "/sys/names/", "sys", "identity.v1")?;
    let token = payload_str(sys, 2, sys_what)?;
    let claims = crate::jwt::verify_domain_certified_identity(token, &domain_key)
        .map_err(|e| invalid(2, sys_what, format!("identity JWT: {e}")))?;
    if claims.iss != format!("domain:{domain}") {
        return Err(invalid(2, sys_what, format!("JWT issuer '{}' is not domain:{domain}", claims.iss)));
    }
    let sys_key = PublicKey::parse(&claims.public_key).map_err(|e| invalid(2, sys_what, format!("JWT public_key: {e}")))?;
    if sys.signing_key != sys_key {
        return Err(invalid(2, sys_what, "Public-Key header does not match the JWT public_key"));
    }
    let sys_identity = claims.sub.clone();
    check_self_owned(dnssec, 0, &dnssec_what, &sys_identity)?;
    check_self_owned(dom, 1, &domain_what, &sys_identity)?;
    check_self_owned(sys, 2, sys_what, &sys_identity)?;

    // 4. /sys/policies/root signed by sys.
    let root_policy = check_root_policy(messages, 3, &sys_key)?;
    check_self_owned(&messages[3], 3, "/sys/policies/root", &sys_identity)?;

    Ok(GenesisInfo {
        mode: GenesisMode::DomainCertified { domain: domain.to_string() },
        sys_key,
        sys_identity,
        prefix_len: 4,
        root_policy,
    })
}

/// Compute the canonical genesis hash — the content-derived **verifying** half of a
/// database's identity (`{chain}:{appId}:{firstBlock}:{genesisHash}`).
///
/// `genesisHash = sha256(all_genesis_objects_bytes)`, where `all_genesis_objects_bytes`
/// is the canonical wire serialization of the ordered genesis messages concatenated with
/// no separators (each message is self-delimiting via its `Content-Length`). This is
/// exactly the byte sequence a genesis builder emits, and is reproducible offline from a
/// chain-read reconstruction because the wire serializer is deterministic. Returns a
/// [`ContentHash`] whose `to_string()` is `sha256:<hex>` — the form used in `?genesis=`
/// and the `_sbo` record's `genesis=` field.
pub fn genesis_hash(messages: &[Message]) -> ContentHash {
    let mut bytes = Vec::new();
    for m in messages {
        bytes.extend_from_slice(&wire::serialize(m));
    }
    ContentHash::sha256(&bytes)
}

/// Compute the genesis hash from the genesis-batch bytes as included on chain
/// (decision Q35 (a)): the batch must parse, and the hash is taken over the
/// received bytes themselves. Because the parser admits only canonical
/// messages this equals [`genesis_hash`] of the parsed messages.
pub fn genesis_hash_from_wire(wire_bytes: &[u8]) -> Result<ContentHash, crate::error::ParseError> {
    wire::parse_batch(wire_bytes)?;
    Ok(ContentHash::sha256(wire_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    #[test]
    fn genesis_hash_matches_wire_roundtrip() {
        // A hash computed over messages equals the hash computed from their wire batch.
        use crate::message::{Id, Path};
        use crate::crypto::Signature;

        let key = SigningKey::generate();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/test/").unwrap(),
            id: Id::new("a").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("text/plain".to_string()),
            content_hash: Some(ContentHash::sha256(b"hi")),
            payload: Some(b"hi".to_vec()),
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
            auth_warrant: None, extra_headers: Vec::new(),
        };
        msg.sign(&key);

        let batch = wire::serialize(&msg);
        let from_msgs = genesis_hash(std::slice::from_ref(&msg));
        let from_wire = genesis_hash_from_wire(&batch).unwrap();
        assert_eq!(from_msgs.to_string(), from_wire.to_string());
        assert!(from_msgs.to_string().starts_with("sha256:"));
    }

    #[test]
    fn mode_a_preset_genesis_validates() {
        let key = SigningKey::generate();
        let msgs = wire::parse_batch(&crate::presets::genesis(&key)).unwrap();
        let info = Genesis::validate(&msgs).unwrap();
        assert_eq!(info.mode, GenesisMode::SelfSigned);
        assert_eq!(info.prefix_len, 2);
        assert_eq!(info.sys_identity, "sys");
        assert_eq!(info.sys_key, key.public_key());
        assert!(Genesis::is_candidate(&msgs));
    }

    #[test]
    fn mode_a_rejects_wrong_order_and_strangers() {
        let key = SigningKey::generate();
        let mut msgs = wire::parse_batch(&crate::presets::genesis(&key)).unwrap();
        // Root policy first: not a genesis opener.
        msgs.swap(0, 1);
        assert!(matches!(Genesis::validate(&msgs), Err(GenesisError::NotAGenesis(_))));
        msgs.swap(0, 1);
        // A stranger's write between sys and root is invalid.
        let stranger = SigningKey::generate();
        let post = wire::parse(&crate::presets::post(&stranger, "/x/", "y", b"{}")).unwrap();
        msgs.insert(1, post);
        assert!(matches!(Genesis::validate(&msgs), Err(GenesisError::UnexpectedObject { index: 1, .. })));
        // Root policy signed by someone else.
        let mut msgs = wire::parse_batch(&crate::presets::genesis(&key)).unwrap();
        msgs[1].signing_key = stranger.public_key();
        msgs[1].sign(&stranger);
        assert!(Genesis::validate(&msgs).is_err());
        // No root policy at all.
        msgs.truncate(1);
        assert!(matches!(Genesis::validate(&msgs), Err(GenesisError::UnexpectedObject { index: 1, .. })));
        assert!(matches!(Genesis::validate(&[]), Err(GenesisError::Empty)));
    }

    #[test]
    fn mode_b_with_a_synthetic_dnssec_root_validates_and_binds_the_domain_key() {
        use crate::dnssec_fixture::{browserid_txt_for_sbo_key, SyntheticRoot};
        let root = SyntheticRoot::generate();
        let domain_key = SigningKey::generate();
        let sys_key = SigningKey::generate();
        let domain = "example.test";
        let (t0, t1, t2) = (1_700_000_000i64, 1_700_100_000i64, 1_700_200_000i64);
        let chain = root.browserid_chain(domain, &browserid_txt_for_sbo_key(&domain_key.public_key()), t0, t2);
        let anchors = TrustAnchors::with_brokers(Vec::new()).with_dns_root(vec![root.root_ksk(0, None)]);

        let mut msgs = wire::parse_batch(&crate::presets::set_dnssec(&sys_key, domain, &chain)).unwrap();
        msgs.extend(wire::parse_batch(&crate::presets::genesis_with_domain(&domain_key, &sys_key, domain)).unwrap());
        assert_eq!(msgs.len(), 4);

        let info = Genesis::validate_at(&msgs, Some(t1), &anchors).unwrap();
        assert_eq!(info.mode, GenesisMode::DomainCertified { domain: domain.to_string() });
        assert_eq!(info.prefix_len, 4);
        assert_eq!(info.sys_key, sys_key.public_key());
        assert_eq!(info.sys_identity, format!("sys@{domain}"));

        // Outside the RRSIG window the self-certification does not hold.
        assert!(matches!(
            Genesis::validate_at(&msgs, Some(t2 + 1), &anchors),
            Err(GenesisError::Invalid { .. })
        ));
        // A domain whose key is not the one the chain proves is not self-certified.
        let other = SigningKey::generate();
        let mut forged = wire::parse_batch(&crate::presets::set_dnssec(&sys_key, domain, &chain)).unwrap();
        forged.extend(wire::parse_batch(&crate::presets::genesis_with_domain(&other, &sys_key, domain)).unwrap());
        assert!(matches!(
            Genesis::validate_at(&forged, Some(t1), &anchors),
            Err(GenesisError::Invalid { index: 1, .. })
        ));
        // Without the synthetic root pinned, the chain does not verify.
        assert!(Genesis::validate_at(&msgs, Some(t1), &TrustAnchors::with_brokers(Vec::new())).is_err());
    }

    #[test]
    fn mode_b_requires_dnssec_evidence_first() {
        // The legacy Mode B preset (domain, sys, root; no dnssec object) is not
        // a genesis under Q33 (b): its first message is not an opener.
        let d = SigningKey::generate();
        let s = SigningKey::generate();
        let msgs = wire::parse_batch(&crate::presets::genesis_with_domain(&d, &s, "example.com")).unwrap();
        assert!(matches!(Genesis::validate(&msgs), Err(GenesisError::NotAGenesis(_))));
        // With a garbage dnssec object in front, the structure is right but the
        // self-certification cannot verify.
        let mut with_dnssec = wire::parse_batch(&crate::presets::set_dnssec(&s, "example.com", b"not-a-proof")).unwrap();
        with_dnssec.extend(msgs);
        assert!(Genesis::is_candidate(&with_dnssec));
        assert!(matches!(Genesis::validate(&with_dnssec), Err(GenesisError::Invalid { index: 0, .. })));
    }
}
