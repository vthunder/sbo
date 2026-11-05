//! SBO attribution verifier (the deterministic L2 check).
//!
//! Given a BrowserID certificate, a DNSSEC proof (RFC 9102), an inclusion
//! timestamp, and pinned trust anchors, this module deterministically decides
//! "this signing key speaks for this email at that time."
//!
//! This is self-contained: it does not touch owner/ownership resolution, the
//! state trie, or the wire `Message.owner` field.
//!
//! # Algorithm
//!
//! 1. Parse `auth_cert` (a BrowserID [`Certificate`]) and require the cert's
//!    certified public key to equal the SBO `public_key` argument.
//! 2. Validate `auth_evidence` as an RFC 9102 DNSSEC proof, anchored to the
//!    IANA root KSK, fully offline. Extract the validated
//!    `_browserid.<iss>` TXT record (→ the provider's Ed25519 key) and the
//!    proof's RRSig validity window.
//! 3. Check `inclusion_time` lies within BOTH the proof's RRSig window AND the
//!    cert `[iat, exp]`.
//! 4. Verify the cert signature against the provider key from step 2.
//! 5. Authority: the email's domain == `iss` (primary IdP path), OR `iss` is in
//!    `anchors.brokers` (broker path). Otherwise reject.
//!
//! On success the returned [`Attribution`] window is the intersection of the
//! cert and proof windows: `[max(iat, inception), min(exp, expiration)]`.
//!
//! ## Trust anchor note
//!
//! The DNS root KSK the chain is validated against is the on-chain
//! `/sys/trust/dns-root` (`dns-root.v1`) history, selected at the write's
//! inclusion time (Authorization Spec §On-Chain Trust Anchors; audit 2026-11
//! D6, Q3 (a)). It is injected into the (vendored) `dnssec-prover` through
//! `verify_rr_stream_with_anchors`. A repository that has not pinned a root
//! falls back to the library's compiled-in IANA anchors ([`TrustAnchors`]
//! documents this). Offline coverage uses the synthetic chain builder in
//! `crate::dnssec_fixture` (feature `dnssec-fixtures`).

use browserid_core::{DnsRecord, PublicKey};
use dnssec_prover::rr::{DnsKey, Name, DS, RR};

/// DNSKEY RR type (IANA).
const DNSKEY_TYPE: u16 = 48;
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::{root_hints, verify_rr_stream_with_anchors, VerifiedRRStream};
use thiserror::Error;

/// One entry of the `/sys/trust/dns-root` (`dns-root.v1`) key history
/// (Authorization Spec §DNS root KSK).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootKsk {
    /// DNSKEY key tag (IANA).
    pub key_tag: u16,
    /// DNSSEC algorithm number (IANA).
    pub algorithm: u8,
    /// The root KSK public key: the DNSKEY public-key field, base64 (the
    /// presentation-format key, e.g. `AwEAAa…`).
    pub public_key: String,
    /// Activation window start (UNIX seconds).
    pub valid_from: i64,
    /// Activation window end; `None` = current.
    #[serde(default)]
    pub valid_until: Option<i64>,
}

impl RootKsk {
    /// Whether this key is active at `t`.
    pub fn active_at(&self, t: i64) -> bool {
        t >= self.valid_from && self.valid_until.is_none_or(|u| t <= u)
    }

    /// The DS record (SHA-256, KSK flags 257, protocol 3) this key anchors, or
    /// `None` if the key does not decode or its computed tag disagrees with the
    /// declared one (a malformed history entry never anchors anything).
    pub fn to_ds(&self) -> Option<DS> {
        use base64::Engine as _;
        let pubkey = base64::engine::general_purpose::STANDARD.decode(self.public_key.trim()).ok()?;
        let name: Name = ".".try_into().ok()?;
        let dnskey = DnsKey { name: name.clone(), flags: 257, protocol: 3, alg: self.algorithm, pubkey };
        if dnskey.key_tag() != self.key_tag {
            return None;
        }
        // DS digest (RFC 4034 §5.1.4): SHA-256 over owner name (wire) || DNSKEY RDATA.
        use sha2::Digest as _;
        let mut ctx = sha2::Sha256::new();
        ctx.update([0u8]); // the root name "." in wire form
        ctx.update(dnskey.flags.to_be_bytes());
        ctx.update([dnskey.protocol, dnskey.alg]);
        ctx.update(&dnskey.pubkey);
        Some(DS { name, key_tag: self.key_tag, alg: self.algorithm, digest_type: 2, digest: ctx.finalize().to_vec() })
    }
}

/// Pinned trust anchors corresponding to `/sys/trust/dns-root` and
/// `/sys/trust/brokers`.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// The pinned DNS root KSK history (`/sys/trust/dns-root`), or `None` when
    /// the repository has not pinned one. **Fallback:** with no pinned root the
    /// verifier uses `dnssec-prover`'s compiled-in IANA anchors, so an
    /// un-pinned repository keeps working but its replay is only as durable as
    /// the library's anchor set; a pinned history is the spec's a-priori trust
    /// and is used exclusively.
    pub root_keys: Option<Vec<RootKsk>>,
    /// The set of authorized broker provider domains (`/sys/trust/brokers`).
    pub brokers: Vec<String>,
}

impl TrustAnchors {
    /// Construct trust anchors from a broker list with no pinned root (library
    /// IANA anchors).
    pub fn with_brokers(brokers: Vec<String>) -> Self {
        Self { root_keys: None, brokers }
    }

    /// Pin a root KSK history (the parsed `dns-root.v1` payload).
    pub fn with_dns_root(mut self, keys: Vec<RootKsk>) -> Self {
        self.root_keys = Some(keys);
        self
    }

    /// Parse a `dns-root.v1` payload: `{"keys":[{key_tag, algorithm, public_key,
    /// valid_from, valid_until}, …]}`.
    pub fn parse_dns_root(payload: &[u8]) -> Result<Vec<RootKsk>, String> {
        #[derive(serde::Deserialize)]
        struct DnsRootV1 {
            keys: Vec<RootKsk>,
        }
        serde_json::from_slice::<DnsRootV1>(payload).map(|d| d.keys).map_err(|e| e.to_string())
    }

    /// Whether a root history is pinned.
    pub fn has_pinned_root(&self) -> bool {
        self.root_keys.is_some()
    }

    /// The root DS anchors to validate a chain against at inclusion time `at`:
    /// the pinned keys active at `at` (all keys without a `valid_until` when the
    /// time is unknown), or the library's IANA set when nothing is pinned. A
    /// pinned history with no active key at `at` yields an empty set, which
    /// validates nothing (fail closed).
    pub fn root_anchors_at(&self, at: Option<i64>) -> Vec<DS> {
        match &self.root_keys {
            None => root_hints(),
            Some(keys) => keys
                .iter()
                .filter(|k| match at {
                    Some(t) => k.active_at(t),
                    None => k.valid_until.is_none(),
                })
                .filter_map(RootKsk::to_ds)
                .collect(),
        }
    }

    pub(crate) fn is_broker(&self, iss: &str) -> bool {
        self.brokers.iter().any(|b| b == iss)
    }
}

/// Failure modes of the attribution verifiers.
#[derive(Debug, Error)]
pub enum AttributionError {
    /// The certificate could not be parsed.
    #[error("certificate parse failed: {0}")]
    BadCertificate(String),
    /// The certificate certifies a different public key than the SBO key arg.
    #[error("certified key does not match the SBO public key")]
    KeyMismatch,
    /// The certificate has no email principal.
    #[error("certificate has no email principal")]
    MissingEmail,
    /// The DNSSEC proof bytes could not be deserialized.
    #[error("DNSSEC evidence could not be parsed")]
    EvidenceParse,
    /// The DNSSEC proof failed cryptographic validation against the root.
    #[error("DNSSEC evidence failed validation: {0}")]
    EvidenceInvalid(String),
    /// No validated `_browserid.<iss>` TXT record was found in the proof.
    #[error("no validated _browserid.{0} TXT record in evidence")]
    MissingProviderRecord(String),
    /// The provider TXT record could not be parsed into a key.
    #[error("provider DNS record parse failed: {0}")]
    BadProviderRecord(String),
    /// `inclusion_time` falls outside the proof's RRSig validity window.
    #[error("inclusion time {time} outside DNSSEC window [{from}, {until}]")]
    EvidenceWindowMismatch {
        /// The supplied inclusion time.
        time: i64,
        /// Window start (RRSig inception).
        from: i64,
        /// Window end (RRSig expiration).
        until: i64,
    },
    /// `inclusion_time` falls outside the certificate `[iat, exp]` window.
    #[error("inclusion time {time} outside cert window [{iat}, {exp}]")]
    CertWindowMismatch {
        /// The supplied inclusion time.
        time: i64,
        /// Certificate issued-at.
        iat: i64,
        /// Certificate expiry.
        exp: i64,
    },
    /// The certificate signature did not verify against the provider key.
    #[error("certificate signature verification failed")]
    SignatureInvalid,
    /// The device-model `access_cert~assertion~warrant~config_cert` presentation
    /// failed browserid-core's crypto/structural join (signature, expiry,
    /// audience, or the `(identity, subject, audience)` join).
    #[error("device presentation verification failed: {0}")]
    DevicePresentation(String),
    /// The warrant's `as:` scope is malformed: names someone other than the
    /// grantor, appears more than once, or lacks the required `path:` scope.
    #[error("invalid as: scope: {0}")]
    InvalidAsScope(String),
    /// An agent certificate was presented without the required warrant.
    #[error("agent certificate requires an Auth-Warrant")]
    MissingWarrant,
    /// The warrant could not be parsed or is structurally invalid.
    #[error("warrant invalid: {0}")]
    BadWarrant(String),
    /// A warrant binding (agent/delegator/parent-email) did not match.
    #[error("warrant binding mismatch: {0}")]
    WarrantBindingMismatch(String),
    /// The warrant (or its embedded parent certificate) signature did not verify.
    #[error("warrant signature verification failed")]
    WarrantSignatureInvalid,
    /// `inclusion_time` falls outside the warrant window, or the warrant was
    /// signed outside its parent certificate's window (signing-time rule).
    #[error("warrant window mismatch")]
    WarrantWindowMismatch,
    /// The warrant's delegator (parent) certificate is from a different issuer
    /// than the agent certificate, and no DNSSEC evidence for the delegator's
    /// issuer was supplied (needed to verify the parent certificate).
    #[error("cross-issuer warrant is missing DNSSEC evidence for the delegator's issuer")]
    MissingDelegatorEvidence,
    /// No DNSSEC evidence could be resolved for this issuer (grantee or grantor).
    #[error("missing DNSSEC evidence for issuer '{0}'")]
    MissingIssuerEvidence(String),
    /// The issuer is neither the email's domain nor a pinned broker.
    #[error("issuer '{iss}' is not authorized for email domain '{domain}'")]
    IssuerNotAuthorized {
        /// The certificate issuer.
        iss: String,
        /// The email's domain.
        domain: String,
    },
    /// The resulting validity window is empty (windows do not intersect).
    #[error("attribution window is empty after intersecting cert and proof windows")]
    EmptyWindow,
    /// The pinned `/sys/trust/dns-root` history has no key active at the
    /// inclusion time, so no chain can validate (fail closed).
    #[error("no pinned DNS root key is active at inclusion time {0}")]
    NoActiveRootAnchor(i64),
    /// A `/sys/dnssec/<domain>` refresh would roll the incumbent proof back
    /// (older RRSIG expiration or an older DNSKEY set), Q16 (a).
    #[error("DNSSEC refresh rollback: {0}")]
    RefreshRollback(String),
}

/// Parse and validate an RFC 9102 chain against `anchors` as of `at`.
fn verify_evidence<'a>(
    rrs: &'a [RR],
    anchors: &TrustAnchors,
    at: Option<i64>,
) -> Result<VerifiedRRStream<'a>, AttributionError> {
    let ds = anchors.root_anchors_at(at);
    if ds.is_empty() {
        return Err(AttributionError::NoActiveRootAnchor(at.unwrap_or(0)));
    }
    verify_rr_stream_with_anchors(rrs, &ds).map_err(|e| AttributionError::EvidenceInvalid(format!("{:?}", e)))
}

/// Validate the RFC 9102 proof offline and extract the provider Ed25519 key
/// (from `_browserid.<iss>`) together with the proof's RRSig validity window
/// `(inception, expiration)` in UNIX seconds.
pub fn extract_provider_key(
    auth_evidence: &[u8],
    iss: &str,
) -> Result<(PublicKey, i64, i64), AttributionError> {
    extract_provider_key_with_anchors(auth_evidence, iss, &TrustAnchors::default(), None)
}

/// [`extract_provider_key`] against the pinned root anchors in `anchors`,
/// selected as of inclusion time `at` (audit 2026-11 D6).
pub fn extract_provider_key_with_anchors(
    auth_evidence: &[u8],
    iss: &str,
    anchors: &TrustAnchors,
    at: Option<i64>,
) -> Result<(PublicKey, i64, i64), AttributionError> {
    let rrs: Vec<RR> =
        parse_rr_stream(auth_evidence).map_err(|_| AttributionError::EvidenceParse)?;

    let verified = verify_evidence(&rrs, anchors, at)?;

    // Names in dnssec-prover are FQDNs with a trailing dot.
    let target = format!("_browserid.{}.", iss);
    let name: Name = target
        .clone()
        .try_into()
        .map_err(|_| AttributionError::MissingProviderRecord(iss.to_string()))?;

    let records = verified.resolve_name(&name);
    let txt = records
        .iter()
        .find_map(|rr| match rr {
            RR::Txt(txt) => Some(txt),
            _ => None,
        })
        .ok_or_else(|| AttributionError::MissingProviderRecord(iss.to_string()))?;

    let txt_str = String::from_utf8(txt.data.as_vec())
        .map_err(|e| AttributionError::BadProviderRecord(e.to_string()))?;
    let record = DnsRecord::parse(&txt_str)
        .map_err(|e| AttributionError::BadProviderRecord(e.to_string()))?;

    Ok((record.public_key, verified.valid_from as i64, verified.expires as i64))
}

/// Validate an RFC 9102 DNSSEC proof offline against the pinned IANA root and
/// confirm it carries a `_browserid.<domain>` provider record, returning the
/// proof's RRSig validity window `(inception, expiration)` in UNIX seconds.
///
/// This is the building block for the *self-authorizing* `/sys/dnssec/<domain>`
/// write: the payload IS the proof, and a proof that does not validate, or that
/// is for a different domain (no `_browserid.<domain>` record), is rejected.
/// Domain-binding is therefore intrinsic — the caller passes the domain taken
/// from the write's target path, and a proof for any other domain fails with
/// [`AttributionError::MissingProviderRecord`].
pub fn verify_dnssec_proof_for_domain(
    proof: &[u8],
    domain: &str,
) -> Result<(i64, i64), AttributionError> {
    verify_dnssec_proof_for_domain_with_anchors(proof, domain, &TrustAnchors::default(), None)
}

/// [`verify_dnssec_proof_for_domain`] against pinned anchors as of `at`.
pub fn verify_dnssec_proof_for_domain_with_anchors(
    proof: &[u8],
    domain: &str,
    anchors: &TrustAnchors,
    at: Option<i64>,
) -> Result<(i64, i64), AttributionError> {
    let (_provider_key, inception, expiration) = extract_provider_key_with_anchors(proof, domain, anchors, at)?;
    Ok((inception, expiration))
}

/// What a `/sys/dnssec/<domain>` refresh is compared on (Q16 (a), audit D33):
/// the proof's validity window and the freshness of the `<domain>` zone's
/// DNSKEY set (the inception of the RRSIG that signs it, and its key tags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofFreshness {
    /// Proof-wide RRSIG window start (latest inception across the chain).
    pub inception: i64,
    /// Proof-wide RRSIG window end (earliest expiration across the chain).
    pub expiration: i64,
    /// Inception of the RRSIG covering the `<domain>.` DNSKEY RRset: a
    /// re-signed (rotated) key set has a later one, so a pre-rotation proof
    /// is detectably older even while its RRSIGs are still inside their window.
    pub dnskey_inception: i64,
    /// Key tags of the `<domain>.` DNSKEY RRset carried by the proof, sorted.
    pub key_tags: Vec<u16>,
}

/// Validate `proof` for `domain` against `anchors` as of `at` and report its
/// [`ProofFreshness`].
pub fn dnssec_proof_freshness(
    proof: &[u8],
    domain: &str,
    anchors: &TrustAnchors,
    at: Option<i64>,
) -> Result<ProofFreshness, AttributionError> {
    let rrs: Vec<RR> = parse_rr_stream(proof).map_err(|_| AttributionError::EvidenceParse)?;
    let verified = verify_evidence(&rrs, anchors, at)?;
    // The provider record must be present (same binding as the proof check).
    let target = format!("_browserid.{}.", domain);
    let name: Name = target.try_into().map_err(|_| AttributionError::MissingProviderRecord(domain.to_string()))?;
    if !verified.resolve_name(&name).iter().any(|rr| matches!(rr, RR::Txt(_))) {
        return Err(AttributionError::MissingProviderRecord(domain.to_string()));
    }
    let zone = format!("{}.", domain.trim_end_matches('.'));
    let dnskey_inception = rrs
        .iter()
        .filter_map(|rr| match rr {
            RR::RRSig(sig) if sig.ty == DNSKEY_TYPE && sig.name.as_str() == zone => Some(sig.inception as i64),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let mut key_tags: Vec<u16> = rrs
        .iter()
        .filter_map(|rr| match rr {
            RR::DnsKey(k) if k.name.as_str() == zone => Some(k.key_tag()),
            _ => None,
        })
        .collect();
    key_tags.sort_unstable();
    key_tags.dedup();
    Ok(ProofFreshness {
        inception: verified.valid_from as i64,
        expiration: verified.expires as i64,
        dnskey_inception,
        key_tags,
    })
}

/// Monotonic refresh rule for `/sys/dnssec/<domain>` (Q16 (a)): a replacement
/// proof must not lower the incumbent's RRSIG expiration, and must carry the
/// same or a newer DNSKEY set (DNSKEY-RRSIG inception not older than the
/// incumbent's). Equal values are allowed (an idempotent re-post is harmless).
pub fn check_dnssec_refresh_monotonic(new: &ProofFreshness, incumbent: &ProofFreshness) -> Result<(), AttributionError> {
    if new.expiration < incumbent.expiration {
        return Err(AttributionError::RefreshRollback(format!(
            "RRSIG expiration {} is older than the incumbent's {}",
            new.expiration, incumbent.expiration
        )));
    }
    if new.dnskey_inception < incumbent.dnskey_inception {
        return Err(AttributionError::RefreshRollback(format!(
            "DNSKEY set signed at {} is older than the incumbent's {} (keys {:?} vs {:?})",
            new.dnskey_inception, incumbent.dnskey_inception, new.key_tags, incumbent.key_tags
        )));
    }
    Ok(())
}

/// Verify a **self-certifying `domain.v1`** (Identity Spec §Domain Objects,
/// Validation Rule 4): the domain object's key is proven to control the DNS zone
/// `<domain>` by a `dnssec.v1` evidence chain, at the object's inclusion time.
///
/// Checks, in order:
/// 1. the DNSSEC chain validates to the pinned root and yields the `_browserid.<domain>`
///    provider key (via [`extract_provider_key`]);
/// 2. `inclusion_time` lies within the proof's RRSig window (the inclusion-time
///    clock — not wall-clock "now" — so a genesis-pinned root stays verifiable
///    forever against the fixed genesis instant, and RRSig wall-clock expiry is
///    irrelevant);
/// 3. the provider key **equals** `domain_public_key` (the key in the `domain.v1`
///    JWT), accepting either the `ed25519:<hex>` or base64url form.
///
/// This is point-in-time certification: it attests control at `inclusion_time`.
/// Post-genesis lapse/transfer/rotation is out of scope (Identity Spec).
pub fn verify_domain_self_cert(
    domain_public_key: &str,
    evidence: &[u8],
    domain: &str,
    inclusion_time: i64,
) -> Result<(), AttributionError> {
    verify_domain_self_cert_with_anchors(domain_public_key, evidence, domain, inclusion_time, &TrustAnchors::default())
}

/// [`verify_domain_self_cert`] against the pinned root anchors (audit D6).
pub fn verify_domain_self_cert_with_anchors(
    domain_public_key: &str,
    evidence: &[u8],
    domain: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<(), AttributionError> {
    let (provider_key, inception, expiration) =
        extract_provider_key_with_anchors(evidence, domain, anchors, Some(inclusion_time))?;
    check_domain_binding(domain_public_key, &provider_key, inception, expiration, inclusion_time)
}

/// The window + key-equality half of [`verify_domain_self_cert`], separated so it
/// can be unit-tested offline with a directly-supplied provider key (bypassing
/// DNSSEC — mirrors [`verify_attribution_with_provider_key`]).
pub fn check_domain_binding(
    domain_public_key: &str,
    provider_key: &PublicKey,
    inception: i64,
    expiration: i64,
    inclusion_time: i64,
) -> Result<(), AttributionError> {
    if inclusion_time < inception || inclusion_time > expiration {
        return Err(AttributionError::EvidenceWindowMismatch {
            time: inclusion_time,
            from: inception,
            until: expiration,
        });
    }

    // The domain object refers to keys as `ed25519:<hex>`; the DNSSEC record
    // yields a browserid `PublicKey`. Compare by value, accepting either encoding.
    let provider_key_sbo = format!("ed25519:{}", hex::encode(provider_key.as_bytes()));
    if domain_public_key != provider_key_sbo && domain_public_key != provider_key.to_base64() {
        return Err(AttributionError::KeyMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::KeyPair;
    use chrono::Utc;

    // A fixed proof window around "now" for deterministic tests.
    fn window() -> (i64, i64) {
        let now = Utc::now().timestamp();
        (now - 3600, now + 3600)
    }

    // --- Domain self-certification (check_domain_binding) --------------------
    // The DNSSEC extraction is exercised by the attribution tests above; these
    // cover the window + key-equality half, offline with a generated key.

    #[test]
    fn domain_self_cert_matching_key_in_window_ok() {
        let provider = KeyPair::generate();
        let pk = provider.public_key();
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        // Domain object key in `ed25519:<hex>` form.
        let dom_key = format!("ed25519:{}", hex::encode(pk.as_bytes()));
        check_domain_binding(&dom_key, &pk, inception, expiration, now).unwrap();
        // …and the base64url form is accepted too.
        check_domain_binding(&pk.to_base64(), &pk, inception, expiration, now).unwrap();
    }

    #[test]
    fn domain_self_cert_key_mismatch_rejected() {
        let provider = KeyPair::generate();
        let other = KeyPair::generate();
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        let wrong = format!("ed25519:{}", hex::encode(other.public_key().as_bytes()));
        assert!(matches!(
            check_domain_binding(&wrong, &provider.public_key(), inception, expiration, now),
            Err(AttributionError::KeyMismatch)
        ));
    }

    #[test]
    fn domain_self_cert_inclusion_outside_window_rejected() {
        let provider = KeyPair::generate();
        let pk = provider.public_key();
        let (inception, expiration) = window();
        let dom_key = format!("ed25519:{}", hex::encode(pk.as_bytes()));
        // Before inception and after expiration both fail.
        assert!(matches!(
            check_domain_binding(&dom_key, &pk, inception, expiration, inception - 1),
            Err(AttributionError::EvidenceWindowMismatch { .. })
        ));
        assert!(matches!(
            check_domain_binding(&dom_key, &pk, inception, expiration, expiration + 1),
            Err(AttributionError::EvidenceWindowMismatch { .. })
        ));
    }
}
