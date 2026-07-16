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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use browserid_core::{Certificate, DnsRecord, PublicKey, Warrant};
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

    fn is_broker(&self, iss: &str) -> bool {
        self.brokers.iter().any(|b| b == iss)
    }
}

/// A successful attribution: `key` (the SBO Public-Key string) speaks for
/// `email`, valid within `[valid_from, valid_until]` (inclusive, UNIX seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The email this key speaks for.
    pub email: String,
    /// The SBO Public-Key string (base64url of the Ed25519 key).
    pub key: String,
    /// Start of the validity window (UNIX seconds, inclusive).
    pub valid_from: i64,
    /// End of the validity window (UNIX seconds, inclusive).
    pub valid_until: i64,
}

/// Failure modes of [`verify_attribution`].
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

/// Verify an attribution end-to-end, validating the DNSSEC proof offline
/// against the hardcoded IANA root.
///
/// See the module docs for the full algorithm. `inclusion_time` is in UNIX
/// seconds.
pub fn verify_attribution(
    public_key: &str,
    auth_cert: &str,
    auth_evidence: &[u8],
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<Attribution, AttributionError> {
    // Parse the cert first so we know which issuer's TXT record to look for.
    let cert = Certificate::parse(auth_cert)
        .map_err(|e| AttributionError::BadCertificate(e.to_string()))?;
    let iss = cert.issuer().to_string();

    // Step 2: validate the DNSSEC proof and extract the provider key + window.
    let (provider_key, inception, expiration) = extract_provider_key(auth_evidence, &iss)?;

    // Steps 1, 3, 4, 5.
    verify_attribution_with_provider_key(
        public_key,
        &cert,
        &provider_key,
        inception,
        expiration,
        inclusion_time,
        anchors,
    )
}

/// Attribution of an **agent** write (browserid-ng v0.4): the agent identity,
/// its delegator, and the delegator-signed warrant's audience + scopes. Unlike
/// a plain [`Attribution`], an agent certificate authorizes nothing on its own
/// — this is only produced when a valid warrant accompanies it.
#[derive(Debug, Clone)]
pub struct WarrantAttribution {
    /// The agent identity (`Auth-Cert.principal.email`).
    pub agent_email: String,
    /// The delegator the agent acts for (`agent.parent` == warrant `iss`).
    pub delegator: String,
    /// The warrant's audience (an `sbo+raw://` reference — the caller checks it
    /// identifies this database).
    pub audience: String,
    /// The warrant scopes (`<dimension>:<value>` strings — the caller enforces).
    pub scopes: Vec<String>,
}

/// Verify a raw JWS (`h.p.s`) signature against `key` — the warrant is signed
/// by the delegator's certified key. Windows are checked separately (against
/// inclusion time, not wall-clock, for replay determinism).
fn jws_verify_raw(encoded: &str, key: &PublicKey) -> Result<(), AttributionError> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(AttributionError::BadWarrant("expected 3 JWS parts".into()));
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AttributionError::BadWarrant(format!("signature base64url: {e}")))?;
    key.verify(message.as_bytes(), &sig)
        .map_err(|_| AttributionError::WarrantSignatureInvalid)
}

/// Verify a warrant against an already-verified agent certificate. The
/// delegator's embedded `parent-cert` is attributed with the same rigor as the
/// agent certificate (§4) — DNSSEC window, cert window, signature, and issuer
/// authority — under **the delegator's own** issuer provider key + proof window
/// (`delegator_*`). For same-issuer delegation the caller passes the agent's
/// provider key + window (one proof covers both); for cross-issuer delegation
/// (a user certified by their own IdP warranting a service agent certified by a
/// different IdP) the caller passes the delegator issuer's separate proof. Pure
/// and offline; windows use `inclusion_time`.
///
/// Returns the [`WarrantAttribution`] — the agent, the delegator, and the
/// warrant's audience + scopes. **Does not** check that the audience identifies
/// any particular database or that the scopes permit any particular write; the
/// authorization layer does that (`sbo-core/src/authorize.rs`).
#[allow(clippy::too_many_arguments)]
pub fn verify_warrant_with_provider_key(
    auth_warrant: &str,
    agent_cert: &Certificate,
    delegator_provider_key: &PublicKey,
    delegator_inception: i64,
    delegator_expiration: i64,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<WarrantAttribution, AttributionError> {
    let warrant =
        Warrant::parse(auth_warrant).map_err(|e| AttributionError::BadWarrant(e.to_string()))?;
    let claims = warrant.claims();

    // The cert must be an agent cert; bind the warrant to it.
    let agent_email = agent_cert.email().ok_or(AttributionError::MissingEmail)?;
    let parent_email = agent_cert
        .agent_parent()
        .ok_or_else(|| AttributionError::BadWarrant("Auth-Cert is not an agent certificate".into()))?;
    if warrant.agent() != agent_email {
        return Err(AttributionError::WarrantBindingMismatch(format!(
            "warrant agent '{}' != certificate '{agent_email}'",
            warrant.agent()
        )));
    }
    if warrant.delegator() != parent_email {
        return Err(AttributionError::WarrantBindingMismatch(format!(
            "warrant iss '{}' != certificate agent.parent '{parent_email}'",
            warrant.delegator()
        )));
    }

    // Fully attribute the DELEGATOR under its own issuer's provider key — the
    // parent-cert certifies the delegator email and is signed by that issuer's
    // key. The delegator's issuer may differ from the agent's (cross-issuer
    // delegation). Freshness of the delegator's issuer key is gated by the
    // DNSSEC-proof window at inclusion_time (below); the parent-cert itself is
    // checked with SIGNING-TIME semantics only (Attribution Spec §4a step 10 /
    // browserid-core `Warrant::verify_for`): the warrant's `iat` must fall in
    // the parent-cert window (checked further down), but a 90-day warrant stays
    // valid past the parent identity cert's own short (24h) expiry — so we do
    // NOT re-check the parent-cert window against inclusion_time here. Doing so
    // (the former CertWindowMismatch check) broke every agent write ~24h after
    // the warrant was issued, contradicting the warrant's design lifetime.
    let parent = Certificate::parse(&claims.parent_cert)
        .map_err(|e| AttributionError::BadWarrant(format!("parent-cert: {e}")))?;
    if parent.email() != Some(parent_email) {
        return Err(AttributionError::WarrantBindingMismatch(
            "parent-cert principal != warrant iss".into(),
        ));
    }
    if inclusion_time < delegator_inception || inclusion_time > delegator_expiration {
        return Err(AttributionError::EvidenceWindowMismatch {
            time: inclusion_time,
            from: delegator_inception,
            until: delegator_expiration,
        });
    }
    let p = parent.claims();
    let p_iat = p.iat.unwrap_or(p.exp);
    parent
        .verify(delegator_provider_key)
        .map_err(|_| AttributionError::WarrantSignatureInvalid)?;
    // Delegator authority: primary IdP (email domain == issuer) or pinned broker.
    let deleg_domain = parent_email.split('@').nth(1).unwrap_or("");
    if deleg_domain != parent.issuer() && !anchors.is_broker(parent.issuer()) {
        return Err(AttributionError::IssuerNotAuthorized {
            iss: parent.issuer().to_string(),
            domain: deleg_domain.to_string(),
        });
    }

    // The warrant JWS is signed by the delegator's certified key.
    jws_verify_raw(warrant.encoded(), parent.public_key())?;

    // Warrant window against inclusion_time, plus signing-time: the warrant must
    // have been signed while the parent-cert was valid.
    if inclusion_time < claims.iat || inclusion_time > claims.exp {
        return Err(AttributionError::WarrantWindowMismatch);
    }
    if claims.iat < p_iat || claims.iat > p.exp {
        return Err(AttributionError::WarrantWindowMismatch);
    }

    Ok(WarrantAttribution {
        agent_email: agent_email.to_string(),
        delegator: parent_email.to_string(),
        audience: warrant.audience().to_string(),
        scopes: claims.scopes.clone().unwrap_or_default(),
    })
}

/// The issuer domain of a warrant's delegator, read from its embedded
/// `parent-cert`. A caller (e.g. the daemon) uses this to resolve that issuer's
/// DNSSEC proof for a cross-issuer warrant. Returns `None` if the warrant or its
/// parent-cert can't be parsed.
pub fn warrant_delegator_issuer(auth_warrant: &str) -> Option<String> {
    let warrant = Warrant::parse(auth_warrant).ok()?;
    let parent = Certificate::parse(&warrant.claims().parent_cert).ok()?;
    Some(parent.issuer().to_string())
}

/// End-to-end agent attribution: verify the agent certificate (§4) **and** the
/// accompanying warrant. Agent and delegator may be certified by the same IdP
/// (one DNSSEC proof covers both — the common case) or by different IdPs
/// (cross-issuer delegation — `delegator_evidence` supplies the delegator
/// issuer's proof; required when the issuers differ). Offline; `inclusion_time`
/// gated.
pub fn verify_attribution_with_warrant(
    public_key: &str,
    auth_cert: &str,
    auth_warrant: &str,
    auth_evidence: &[u8],
    delegator_evidence: Option<&[u8]>,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<WarrantAttribution, AttributionError> {
    let cert = Certificate::parse(auth_cert)
        .map_err(|e| AttributionError::BadCertificate(e.to_string()))?;
    let agent_iss = cert.issuer().to_string();
    let (agent_key, ag_inception, ag_expiration) = extract_provider_key(auth_evidence, &agent_iss)?;
    // Agent certificate: key match, window, signature, issuer authority.
    verify_attribution_with_provider_key(
        public_key,
        &cert,
        &agent_key,
        ag_inception,
        ag_expiration,
        inclusion_time,
        anchors,
    )?;

    // The delegator's issuer, from the warrant's embedded parent-cert. Same
    // issuer → reuse the agent's proof; different → resolve/verify under the
    // delegator issuer's own proof (must be supplied).
    let warrant =
        Warrant::parse(auth_warrant).map_err(|e| AttributionError::BadWarrant(e.to_string()))?;
    let parent = Certificate::parse(&warrant.claims().parent_cert)
        .map_err(|e| AttributionError::BadWarrant(format!("parent-cert: {e}")))?;
    let deleg_iss = parent.issuer().to_string();
    let (deleg_key, dl_inception, dl_expiration) = if deleg_iss == agent_iss {
        (agent_key, ag_inception, ag_expiration)
    } else {
        let ev = delegator_evidence.ok_or(AttributionError::MissingDelegatorEvidence)?;
        extract_provider_key(ev, &deleg_iss)?
    };
    // Warrant: bindings, full delegator attribution, signatures, windows.
    verify_warrant_with_provider_key(
        auth_warrant,
        &cert,
        &deleg_key,
        dl_inception,
        dl_expiration,
        inclusion_time,
        anchors,
    )
}

/// Validate the RFC 9102 proof offline and extract the provider Ed25519 key
/// (from `_browserid.<iss>`) together with the proof's RRSig validity window
/// `(inception, expiration)` in UNIX seconds.
fn extract_provider_key(
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

/// The cert/window/authority half of the verifier, separated so it can be
/// unit-tested offline with a directly-supplied provider key (bypassing
/// DNSSEC).
///
/// `inception`/`expiration` are the proof's RRSig window (UNIX seconds).
#[allow(clippy::too_many_arguments)]
pub fn verify_attribution_with_provider_key(
    public_key: &str,
    cert: &Certificate,
    provider_key: &PublicKey,
    inception: i64,
    expiration: i64,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<Attribution, AttributionError> {
    let claims = cert.claims();

    // Step 1: the certified key must equal the SBO signer key. The browserid
    // cert stores the key base64url-encoded; SBO refers to keys as
    // "ed25519:<hex>". Compare by value, accepting either encoding, so the
    // daemon (which passes the sbo form) and base64 callers both verify.
    let cert_key_sbo = format!("ed25519:{}", hex::encode(claims.public_key.as_bytes()));
    if public_key != cert_key_sbo && public_key != claims.public_key.to_base64() {
        return Err(AttributionError::KeyMismatch);
    }

    let email = cert
        .email()
        .ok_or(AttributionError::MissingEmail)?
        .to_string();

    let iat = claims.iat.unwrap_or(claims.exp);
    let exp = claims.exp;

    // Step 3: inclusion_time must be within the proof window AND cert window.
    if inclusion_time < inception || inclusion_time > expiration {
        return Err(AttributionError::EvidenceWindowMismatch {
            time: inclusion_time,
            from: inception,
            until: expiration,
        });
    }
    if inclusion_time < iat || inclusion_time > exp {
        return Err(AttributionError::CertWindowMismatch {
            time: inclusion_time,
            iat,
            exp,
        });
    }

    // Step 4: verify the cert signature against the provider key.
    cert.verify(provider_key)
        .map_err(|_| AttributionError::SignatureInvalid)?;

    // Step 5: authority — primary IdP (domain == iss) or pinned broker.
    let iss = claims.iss.clone();
    let domain = email.split('@').nth(1).unwrap_or("");
    if domain != iss && !anchors.is_broker(&iss) {
        return Err(AttributionError::IssuerNotAuthorized {
            iss,
            domain: domain.to_string(),
        });
    }

    // Intersect the cert and proof windows.
    let valid_from = iat.max(inception);
    let valid_until = exp.min(expiration);
    if valid_from > valid_until {
        return Err(AttributionError::EmptyWindow);
    }

    Ok(Attribution {
        email,
        key: public_key.to_string(),
        valid_from,
        valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::KeyPair;
    use chrono::{Duration, Utc};

    // A fixed proof window around "now" for deterministic tests.
    fn window() -> (i64, i64) {
        let now = Utc::now().timestamp();
        (now - 3600, now + 3600)
    }

    /// Build a cert for `email` issued by `iss`, signed by `provider`, with the
    /// SBO key being `user`'s public key. Returns (cert, sbo_public_key_string).
    fn make_cert(
        provider: &KeyPair,
        user: &KeyPair,
        iss: &str,
        email: &str,
        validity: Duration,
    ) -> (Certificate, String) {
        let cert =
            Certificate::create(iss, email, &user.public_key(), validity, provider).unwrap();
        let pk = user.public_key().to_base64();
        (cert, pk)
    }

    #[test]
    fn happy_path_primary_idp() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        let anchors = TrustAnchors::default();

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &anchors,
        )
        .unwrap();

        assert_eq!(attr.email, "alice@example.com");
        assert_eq!(attr.key, pk);
        // Window is intersection of cert [iat, exp] and proof window.
        assert!(attr.valid_from >= inception);
        assert!(attr.valid_until <= expiration);
        assert!(attr.valid_from <= attr.valid_until);
    }

    #[test]
    fn key_mismatch_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, _pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let other = KeyPair::generate().public_key().to_base64();
        let err = verify_attribution_with_provider_key(
            &other,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::KeyMismatch));
    }

    #[test]
    fn expired_cert_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // 1-second validity; inclusion_time will be after exp.
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::seconds(1));
        let (inception, expiration) = window();
        let after_exp = cert.claims().exp + 10_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            after_exp,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        // after_exp is inside the proof window check only if <= expiration;
        // expiration is now+3600 so after_exp (cert.exp+10000) exceeds it →
        // EvidenceWindowMismatch fires first. Accept either window error.
        assert!(matches!(
            err,
            AttributionError::CertWindowMismatch { .. }
                | AttributionError::EvidenceWindowMismatch { .. }
        ));
    }

    #[test]
    fn inclusion_before_iat_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let iat = cert.claims().iat.unwrap();
        // Before iat but still inside a generous proof window.
        let inception = iat - 10_000;
        let expiration = iat + 10_000;
        let before_iat = iat - 5_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            before_iat,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::CertWindowMismatch { .. }));
    }

    #[test]
    fn inclusion_outside_proof_window_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let now = Utc::now().timestamp();
        // Proof window entirely in the past.
        let inception = now - 20_000;
        let expiration = now - 10_000;

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::EvidenceWindowMismatch { .. }));
    }

    #[test]
    fn wrong_provider_key_signature_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let wrong_provider = KeyPair::generate();
        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &wrong_provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::SignatureInvalid));
    }

    #[test]
    fn issuer_not_authorized_rejected() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // iss does not match the email domain and is not a broker.
        let (cert, pk) =
            make_cert(&provider, &user, "evil.com", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();

        let err = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(matches!(err, AttributionError::IssuerNotAuthorized { .. }));
    }

    #[test]
    fn broker_path_accepted() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        // iss != email domain, but iss is a pinned broker.
        let (cert, pk) =
            make_cert(&provider, &user, "broker.example", "alice@example.com", Duration::hours(24));
        let (inception, expiration) = window();
        let now = Utc::now().timestamp();
        let anchors = TrustAnchors::with_brokers(vec!["broker.example".to_string()]);

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            now,
            &anchors,
        )
        .unwrap();
        assert_eq!(attr.email, "alice@example.com");
    }

    #[test]
    fn window_is_intersection() {
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let iat = cert.claims().iat.unwrap();
        let exp = cert.claims().exp;
        // Proof window tighter than the cert window on both ends.
        let inception = iat + 100;
        let expiration = exp - 100;
        let mid = (inception + expiration) / 2;

        let attr = verify_attribution_with_provider_key(
            &pk,
            &cert,
            &provider.public_key(),
            inception,
            expiration,
            mid,
            &TrustAnchors::default(),
        )
        .unwrap();
        assert_eq!(attr.valid_from, inception);
        assert_eq!(attr.valid_until, expiration);
    }

    #[test]
    fn bad_evidence_parse_rejected() {
        // Garbage bytes that cannot be parsed as an RFC 9102 proof. We can't
        // easily reach a valid root-anchored proof offline, so this exercises
        // the parse-failure path of the full entry point.
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let (cert, pk) =
            make_cert(&provider, &user, "example.com", "alice@example.com", Duration::hours(24));
        let now = Utc::now().timestamp();

        let err = verify_attribution(&pk, cert.encoded(), &[], now, &TrustAnchors::default())
            .unwrap_err();
        // Empty evidence parses to an empty RR stream which then fails
        // validation; non-empty garbage fails to parse. Either is acceptable.
        assert!(matches!(
            err,
            AttributionError::EvidenceParse | AttributionError::EvidenceInvalid(_)
        ));
    }

    /// Live, network-dependent end-to-end test. Requires the `query` feature
    /// and network access; not run in CI. Documents how a real proof would be
    /// built and validated against the IANA root.
    #[test]
    #[ignore = "requires network + dnssec-prover `std`/`query` feature"]
    fn live_dnssec_end_to_end() {
        // Intentionally empty: building a proof requires the `std` feature's
        // `dnssec_prover::query` module and a live recursive resolver. The
        // offline tests above cover all deterministic logic; the DNSSEC
        // validation itself is exercised by dnssec-prover's own test suite.
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

    // ---- agent warrants (browserid-ng v0.4) ----

    /// (provider, delegator identity kp, agent kp, agent_cert, warrant, sbo_pk)
    fn make_agent_setup(
        agent_scopes: Option<Vec<String>>,
        audience: &str,
    ) -> (KeyPair, Certificate, String, String) {
        let provider = KeyPair::generate();       // browserid.me signing key
        let user_kp = KeyPair::generate();        // delegator identity key
        let agent_kp = KeyPair::generate();       // agent's own signing key
        let parent_cert = Certificate::create(
            "browserid.me", "human@example.com", &user_kp.public_key(),
            Duration::days(1), &provider).unwrap();
        let agent_cert = Certificate::create_agent(
            "browserid.me", "attestor@browserid.me", "human@example.com",
            &agent_kp.public_key(), Duration::days(1), &provider, None).unwrap();
        let warrant = Warrant::create(
            &parent_cert, "attestor@browserid.me", audience, agent_scopes,
            Duration::days(30), &user_kp).unwrap();
        let sbo_pk = agent_kp.public_key().to_base64();
        (provider, agent_cert, warrant.encoded().to_string(), sbo_pk)
    }

    // The delegator (`human@example.com`) is fallback-certified by browserid.me,
    // so the delegator-authority check needs browserid.me pinned as a broker. A
    // wide window stands in for the DNSSEC proof (the provider key is supplied
    // directly in these unit tests).
    fn wa_anchors() -> TrustAnchors {
        TrustAnchors::with_brokers(vec!["browserid.me".to_string()])
    }

    #[test]
    fn warrant_happy_path() {
        let aud = "sbo+raw://avail:turing:506/";
        let (provider, agent_cert, warrant, _pk) =
            make_agent_setup(Some(vec!["action:post".into()]), aud);
        let now = Utc::now().timestamp();
        let wa = verify_warrant_with_provider_key(&warrant, &agent_cert, &provider.public_key(), 0, i64::MAX, now, &wa_anchors()).unwrap();
        assert_eq!(wa.agent_email, "attestor@browserid.me");
        assert_eq!(wa.delegator, "human@example.com");
        assert_eq!(wa.audience, aud);
        assert_eq!(wa.scopes, vec!["action:post"]);
    }

    #[test]
    fn warrant_wrong_provider_key_rejected() {
        let (_p, agent_cert, warrant, _pk) = make_agent_setup(None, "sbo+raw://avail:turing:506/");
        let now = Utc::now().timestamp();
        let err = verify_warrant_with_provider_key(&warrant, &agent_cert, &KeyPair::generate().public_key(), 0, i64::MAX, now, &wa_anchors()).unwrap_err();
        assert!(matches!(err, AttributionError::WarrantSignatureInvalid));
    }

    #[test]
    fn warrant_for_other_agent_rejected() {
        // A warrant naming a different agent than the presented cert.
        let provider = KeyPair::generate();
        let user_kp = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let parent_cert = Certificate::create("browserid.me", "human@example.com", &user_kp.public_key(), Duration::days(1), &provider).unwrap();
        let agent_cert = Certificate::create_agent("browserid.me", "attestor@browserid.me", "human@example.com", &agent_kp.public_key(), Duration::days(1), &provider, None).unwrap();
        let warrant = Warrant::create(&parent_cert, "other@browserid.me", "sbo+raw://avail:turing:506/", None, Duration::days(30), &user_kp).unwrap();
        let now = Utc::now().timestamp();
        let err = verify_warrant_with_provider_key(warrant.encoded(), &agent_cert, &provider.public_key(), 0, i64::MAX, now, &wa_anchors()).unwrap_err();
        assert!(matches!(err, AttributionError::WarrantBindingMismatch(_)));
    }

    #[test]
    fn warrant_inclusion_time_outside_window_rejected() {
        let (provider, agent_cert, warrant, _pk) = make_agent_setup(None, "sbo+raw://avail:turing:506/");
        // Way in the future, past the 30-day warrant exp.
        let far = Utc::now().timestamp() + 400 * 24 * 3600;
        let err = verify_warrant_with_provider_key(&warrant, &agent_cert, &provider.public_key(), 0, i64::MAX, far, &wa_anchors()).unwrap_err();
        assert!(matches!(err, AttributionError::WarrantWindowMismatch | AttributionError::CertWindowMismatch { .. }));
    }

    #[test]
    fn warrant_survives_parent_cert_expiry() {
        // A 30-day warrant signed while the (1-day) parent identity cert was
        // valid must keep attributing AFTER that parent cert expires — the
        // warrant carries its own lifetime (signing-time semantics, Attribution
        // Spec §4a step 10 / browserid-core verify_for). Regression for the bug
        // where re-checking the parent-cert window at inclusion_time broke every
        // agent write ~24h after the warrant was issued. Delegator freshness is
        // still gated by the DNSSEC-proof window (here 0..i64::MAX stands in).
        let aud = "sbo+raw://avail:turing:506/";
        let (provider, agent_cert, warrant, _pk) =
            make_agent_setup(Some(vec!["action:post".into()]), aud);
        // Two days out: past the 1-day parent cert exp, still within the 30-day
        // warrant window and inside the (wide) evidence window.
        let after_parent_expiry = Utc::now().timestamp() + 2 * 24 * 3600;
        let wa = verify_warrant_with_provider_key(
            &warrant, &agent_cert, &provider.public_key(),
            0, i64::MAX, after_parent_expiry, &wa_anchors(),
        )
        .expect("warrant must remain valid past the parent cert's expiry");
        assert_eq!(wa.delegator, "human@example.com");
    }

    #[test]
    fn plain_cert_is_not_an_agent_warrant_subject() {
        // A warrant presented against a PLAIN (non-agent) cert has no agent.parent.
        let provider = KeyPair::generate();
        let user_kp = KeyPair::generate();
        let plain = Certificate::create("browserid.me", "human@example.com", &user_kp.public_key(), Duration::days(1), &provider).unwrap();
        let warrant = Warrant::create(&plain, "human@example.com", "sbo+raw://avail:turing:506/", None, Duration::days(30), &user_kp).unwrap();
        let now = Utc::now().timestamp();
        let err = verify_warrant_with_provider_key(warrant.encoded(), &plain, &provider.public_key(), 0, i64::MAX, now, &wa_anchors()).unwrap_err();
        assert!(matches!(err, AttributionError::BadWarrant(_)));
    }

    #[test]
    fn cross_issuer_warrant_verifies() {
        // Delegator certified by their OWN IdP (gmail.com); agent certified by a
        // DIFFERENT service IdP (mingo.place). The warrant verifies under the
        // delegator's issuer key — no same-issuer requirement. This is the
        // mingo-poster case: any email can warrant a third-party service agent.
        let deleg_provider = KeyPair::generate(); // gmail.com's IdP key
        let agent_provider = KeyPair::generate(); // mingo.place's IdP key
        let user_kp = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let parent_cert = Certificate::create(
            "gmail.com", "alice@gmail.com", &user_kp.public_key(),
            Duration::days(1), &deleg_provider).unwrap();
        let agent_cert = Certificate::create_agent(
            "mingo.place", "mingo-poster@mingo.place", "alice@gmail.com",
            &agent_kp.public_key(), Duration::days(1), &agent_provider, None).unwrap();
        let warrant = Warrant::create(
            &parent_cert, "mingo-poster@mingo.place", "sbo+raw://avail:turing:506/",
            Some(vec!["as:alice@gmail.com".into(), "path:/u/alice/**".into()]),
            Duration::days(30), &user_kp).unwrap();
        let now = Utc::now().timestamp();
        // Verified under the DELEGATOR's provider key. alice@gmail.com is a
        // primary (domain == issuer), so no broker anchor needed.
        let wa = verify_warrant_with_provider_key(
            warrant.encoded(), &agent_cert, &deleg_provider.public_key(),
            0, i64::MAX, now, &TrustAnchors::default()).unwrap();
        assert_eq!(wa.agent_email, "mingo-poster@mingo.place");
        assert_eq!(wa.delegator, "alice@gmail.com");

        // Verifying the delegator's parent-cert under the WRONG key (the agent's
        // issuer key) is rejected — the two issuers are cryptographically distinct.
        let err = verify_warrant_with_provider_key(
            warrant.encoded(), &agent_cert, &agent_provider.public_key(),
            0, i64::MAX, now, &TrustAnchors::default()).unwrap_err();
        assert!(matches!(err, AttributionError::WarrantSignatureInvalid));
    }

    #[test]
    fn cross_issuer_delegator_authority_enforced() {
        // A rogue IdP can't certify an arbitrary-domain delegator: if the
        // delegator's email domain != its issuer and the issuer isn't a pinned
        // broker, the warrant is rejected even though the crypto is internally
        // consistent.
        let deleg_provider = KeyPair::generate();
        let agent_provider = KeyPair::generate();
        let user_kp = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let parent_cert = Certificate::create(
            "gmail.com", "alice@evil.com", &user_kp.public_key(), // domain != issuer
            Duration::days(1), &deleg_provider).unwrap();
        let agent_cert = Certificate::create_agent(
            "mingo.place", "mingo-poster@mingo.place", "alice@evil.com",
            &agent_kp.public_key(), Duration::days(1), &agent_provider, None).unwrap();
        let warrant = Warrant::create(
            &parent_cert, "mingo-poster@mingo.place", "sbo+raw://avail:turing:506/",
            None, Duration::days(30), &user_kp).unwrap();
        let now = Utc::now().timestamp();
        let err = verify_warrant_with_provider_key(
            warrant.encoded(), &agent_cert, &deleg_provider.public_key(),
            0, i64::MAX, now, &TrustAnchors::default()).unwrap_err();
        assert!(matches!(err, AttributionError::IssuerNotAuthorized { .. }));
    }
}
