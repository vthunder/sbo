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
//! `dnssec-prover` hardcodes the IANA DNSSEC root trust anchors in
//! `dnssec_prover::validation::root_hints()` and offers no way to inject a
//! custom root into [`verify_rr_stream`]. Consequently the [`TrustAnchors`]
//! `root_ksk` field is informational/configurable for callers that wish to pin
//! a root out-of-band; the actual proof validation always uses the library's
//! hardcoded IANA root. This means a fully-synthetic offline DNSSEC proof
//! cannot be validated against the real root, so the DNSSEC-dependent path is
//! covered by an `#[ignore]`d live test, while the cert/window/authority logic
//! is unit-tested offline via [`verify_attribution_with_provider_key`].

use browserid_core::{DnsRecord, PublicKey};
use dnssec_prover::rr::{Name, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;
use thiserror::Error;

/// Pinned trust anchors corresponding to `/sys/trust/dns-root` and
/// `/sys/trust/brokers`.
///
/// Note: `dnssec-prover` hardcodes the IANA root KSK internally, so `root_ksk`
/// is informational only — it lets a caller record/pin the root they expect,
/// but it is not (and cannot be) injected into the proof validator.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// The pinned DNS root KSK, recorded for out-of-band auditing. The actual
    /// proof validation uses `dnssec-prover`'s hardcoded IANA root anchors.
    pub root_ksk: Option<String>,
    /// The set of authorized broker provider domains (`/sys/trust/brokers`).
    pub brokers: Vec<String>,
}

impl TrustAnchors {
    /// Construct trust anchors from a broker list, relying on the library's
    /// hardcoded IANA root KSK.
    pub fn with_brokers(brokers: Vec<String>) -> Self {
        Self { root_ksk: None, brokers }
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
}

/// Validate the RFC 9102 proof offline and extract the provider Ed25519 key
/// (from `_browserid.<iss>`) together with the proof's RRSig validity window
/// `(inception, expiration)` in UNIX seconds.
pub(crate) fn extract_provider_key(
    auth_evidence: &[u8],
    iss: &str,
) -> Result<(PublicKey, i64, i64), AttributionError> {
    let rrs: Vec<RR> =
        parse_rr_stream(auth_evidence).map_err(|_| AttributionError::EvidenceParse)?;

    let verified = verify_rr_stream(&rrs)
        .map_err(|e| AttributionError::EvidenceInvalid(format!("{:?}", e)))?;

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
    let (_provider_key, inception, expiration) = extract_provider_key(proof, domain)?;
    Ok((inception, expiration))
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
    let (provider_key, inception, expiration) = extract_provider_key(evidence, domain)?;
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
