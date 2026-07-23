//! SBO attribution verifier for the **device-cert model** (browserid-ng v0.5).
//!
//! This is the additive counterpart to [`crate::attribution`]'s legacy
//! `Auth-Cert` / `Auth-Evidence` path. Instead of a single BrowserID
//! certificate binding the SBO signing key to an email, the device model
//! presents a 4-object bundle
//! (`access_cert ~ assertion ~ warrant ~ config_cert`, see
//! `browserid_core::device::AccessPresentation`) whose issuer key is still
//! rooted in the same DNSSEC `_browserid.<iss>` evidence this crate already
//! validates offline.
//!
//! # Algorithm
//!
//! 1. Parse the bundle into an [`AccessPresentation`].
//! 2. Validate `auth_evidence` (RFC 9102 DNSSEC proof) offline against the
//!    pinned IANA root and extract the `_browserid.<iss>` provider Ed25519 key
//!    plus the proof's RRSig window — exactly as the legacy path does, reusing
//!    [`crate::attribution::extract_provider_key`]. `iss` is the access cert's
//!    issuer.
//! 3. Check `inclusion_time` lies within the DNSSEC window (replay-deterministic
//!    clock, matching the legacy verifier).
//! 4. Authority: the identity's email domain == `iss` (primary IdP path), OR
//!    `iss` is a pinned broker (fallback path) — same rule as the legacy path.
//! 5. Delegate the cryptographic + structural join to
//!    [`AccessPresentation::verify`], resolving the (single) IdP key from the
//!    DNSSEC-proven provider key. `verify` enforces
//!    `config_cert.iss == access_cert.iss` (privilege-escalation fix), all four
//!    signatures, expiries, and the `(identity, holder∈matcher, audience)` join. Since
//!    the resolver only ever returns the DNSSEC-proven key, the config cert
//!    issuer binding is transitively bound to the DNSSEC-proven provider.
//! 6. Bind the SBO signing key: the access cert's certified `access-key` MUST
//!    equal the SBO `public_key` argument (the key that signs the SBO envelope),
//!    mirroring the legacy `KeyMismatch` check.
//!
//! ## Window / clock note
//!
//! `AccessPresentation::verify` checks cert/assertion/warrant expiries against
//! wall-clock `now` (browserid-core semantics), whereas SBO replay uses
//! `inclusion_time`. This path additionally pins the DNSSEC window and the
//! access-cert window to `inclusion_time` (steps 3 + the returned window), so
//! the *provider-key freshness* is inclusion-time-deterministic. The short-lived
//! object expiries remain wall-clock inside `verify`; that is acceptable for the
//! capture/verify roundtrip and flagged here for the later coordinated cleanup.

use browserid_core::device::{AccessPresentation, Holder, VerifiedAccess};

use crate::attribution::{extract_provider_key, AttributionError, TrustAnchors};

/// A successful device-model attribution: the SBO `key` speaks for `email`
/// (via the opaque `holder`), the warrant grants `scopes` for the write's audience, valid
/// within `[valid_from, valid_until]` (inclusive, UNIX seconds — the
/// intersection of the DNSSEC proof window and the access cert window).
#[derive(Debug, Clone)]
pub struct DeviceAttribution {
    /// The EFFECTIVE author: the warrant grantor — whom the write is attributed
    /// to and whose ownership it can satisfy. Equals the actor (`grantee`) for an
    /// as-you grant; the delegating user for a delegated on-behalf grant.
    pub email: String,
    /// The ACTOR of record: the warrant grantee == the access cert identity (the
    /// identity that minted the access cert and signs the SBO envelope). Equals
    /// `email` for as-you grants; a distinct service for delegated grants
    /// (provenance).
    pub grantee: String,
    /// Which of the grantee's holders is acting (opaque, broker-assigned).
    /// Advisory — authorization keys off `email`/owner, not this.
    pub holder: Holder,
    /// The SBO Public-Key string (base64url) — equals the access cert's key.
    pub key: String,
    /// The warrant's granted scopes (`<dimension>:<value>`; caller enforces).
    pub scopes: Vec<String>,
    /// The IdP/broker domain that vouches for the ATTRIBUTED identity (`email`) —
    /// the grantor's issuer (the config cert's `iss`).
    pub issuer: String,
    /// The grantee/actor's issuer (the access cert's `iss`). Equals `issuer` for
    /// an as-you grant; may differ for a cross-issuer delegated grant.
    pub grantee_issuer: String,
    /// Start of the validity window (UNIX seconds, inclusive).
    pub valid_from: i64,
    /// End of the validity window (UNIX seconds, inclusive).
    pub valid_until: i64,
    /// The full verified result from browserid-core, carrying the three
    /// revocation status refs the caller MUST check fail-closed
    /// (access → IdP, config → IdP, warrant → broker).
    pub verified: VerifiedAccess,
}

/// Verify a device-model attribution end-to-end, validating the DNSSEC proof
/// offline against the hardcoded IANA root. See the module docs for the
/// algorithm. `inclusion_time` is in UNIX seconds.
///
/// - `public_key`: the SBO signing key (base64url) that signs the envelope; must
///   equal the access cert's certified `access-key`.
/// - `presentation`: the `access_cert~assertion~warrant~config_cert` bundle.
/// - `auth_evidence`: the RFC 9102 DNSSEC proof of `_browserid.<iss>`.
/// - `expected_audience`: the write's audience (an `sbo+raw://` reference — the
///   authorization layer checks it identifies this database).
pub fn verify_device_attribution(
    public_key: &str,
    presentation: &str,
    get_evidence: impl Fn(&str) -> Option<Vec<u8>>,
    expected_audience: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<DeviceAttribution, AttributionError> {
    // Parse the 4-object bundle so we know which issuers' TXT records to look for.
    let pres = AccessPresentation::parse(presentation)
        .map_err(|e| AttributionError::BadCertificate(e.to_string()))?;
    let ac_iss = pres.access_cert.claims().iss.clone();
    let cc_iss = pres.config_cert.claims().iss.clone();

    // Prove each DISTINCT issuer's provider key + RRSig window from its DNSSEC
    // evidence: the grantee's issuer (the access cert) and — when a delegated
    // grant crosses issuers — the grantor's issuer (the config cert). Both proofs
    // are self-authenticating; anyone may post them on-chain ahead of the write.
    let mut proven: Vec<(String, browserid_core::PublicKey, i64, i64)> = Vec::new();
    for iss in [ac_iss.as_str(), cc_iss.as_str()] {
        if proven.iter().any(|(i, ..)| i == iss) {
            continue;
        }
        let evidence = get_evidence(iss)
            .ok_or_else(|| AttributionError::MissingIssuerEvidence(iss.to_string()))?;
        let (key, inception, expiration) = extract_provider_key(&evidence, iss)?;
        proven.push((iss.to_string(), key, inception, expiration));
    }

    verify_device_attribution_with_provider_keys(
        public_key,
        pres,
        &proven,
        expected_audience,
        inclusion_time,
        anchors,
    )
}

/// The offline core of [`verify_device_attribution`]: everything after the
/// DNSSEC proof has yielded the provider key + window. Split out (mirroring the
/// legacy `verify_attribution_with_provider_key`) so the join logic is
/// unit-testable without a real, unforgeable DNSSEC proof — the DNSSEC-dependent
/// extraction is covered by an `#[ignore]`d live test.
/// Same-issuer convenience wrapper (one DNSSEC-proven provider key covering both
/// the access and config certs). Used by tests and as-you callers; delegates to
/// the general multi-issuer core.
#[allow(clippy::too_many_arguments)]
pub fn verify_device_attribution_with_provider_key(
    public_key: &str,
    pres: AccessPresentation,
    provider_key: &browserid_core::PublicKey,
    inception: i64,
    expiration: i64,
    expected_audience: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<DeviceAttribution, AttributionError> {
    let iss = pres.access_cert.claims().iss.clone();
    let proven = vec![(iss, provider_key.clone(), inception, expiration)];
    verify_device_attribution_with_provider_keys(
        public_key,
        pres,
        &proven,
        expected_audience,
        inclusion_time,
        anchors,
    )
}

/// The offline core: everything after DNSSEC proofs have yielded a provider key +
/// window for each distinct issuer in the presentation (`proven`, keyed by issuer
/// domain). Resolves the grantee (access) and grantor (config) issuer keys
/// independently — a delegated grant may cross issuers — and enforces the
/// grantor/grantee authority and window bindings.
pub fn verify_device_attribution_with_provider_keys(
    public_key: &str,
    pres: AccessPresentation,
    proven: &[(String, browserid_core::PublicKey, i64, i64)],
    expected_audience: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<DeviceAttribution, AttributionError> {
    let ac = pres.access_cert.claims();
    let grantee = ac.identity.clone();
    let grantee_iss = ac.iss.clone();
    let grantor = pres.warrant.claims().grantor.clone();
    let grantor_iss = pres.config_cert.claims().iss.clone();

    // inclusion_time must lie within EVERY proof's DNSSEC (RRSig) window.
    for (_iss, _key, inception, expiration) in proven {
        if inclusion_time < *inception || inclusion_time > *expiration {
            return Err(AttributionError::EvidenceWindowMismatch {
                time: inclusion_time,
                from: *inception,
                until: *expiration,
            });
        }
    }

    // Authority (domain-binding) for BOTH identities: the attributed identity
    // (grantor) must be served by the config cert's issuer, and the actor
    // (grantee) by the access cert's issuer — or that issuer is a pinned broker.
    // The grantor check is what makes the cross-issuer split safe: issuer X can
    // only attribute to an identity in a domain it is authoritative for.
    let check_authority = |identity: &str, iss: &str| -> Result<(), AttributionError> {
        let domain = identity.split('@').nth(1).unwrap_or("");
        if domain != iss && !anchors.is_broker(iss) {
            return Err(AttributionError::IssuerNotAuthorized {
                iss: iss.to_string(),
                domain: domain.to_string(),
            });
        }
        Ok(())
    };
    check_authority(&grantor, &grantor_iss)?;
    check_authority(&grantee, &grantee_iss)?;

    // Crypto + structural join, resolving each cert's issuer key from the
    // DNSSEC-proven set (access under its iss, config under ITS iss). Only proven
    // issuers resolve, so a rogue-IdP cert cannot be verified.
    let verified = pres
        .verify(expected_audience, |q_iss| {
            proven
                .iter()
                .find(|(i, ..)| i == q_iss)
                .map(|(_, key, ..)| key.clone())
                .ok_or_else(|| {
                    browserid_core::Error::InvalidCertificate(format!(
                        "no DNSSEC-proven key for issuer '{q_iss}'"
                    ))
                })
        })
        .map_err(|e| AttributionError::DevicePresentation(e.to_string()))?;

    // SBO signing-key binding: the envelope signer key == the access cert key.
    // SBO refers to keys as `ed25519:<hex>`; the access cert stores the key
    // base64url. Accept either encoding so the daemon (which passes the sbo form)
    // and base64 callers both verify. The canonical `key` we return is base64url.
    let cert_key = ac.access_key.to_base64();
    let cert_key_sbo = format!("ed25519:{}", hex::encode(ac.access_key.as_bytes()));
    if public_key != cert_key && public_key != cert_key_sbo {
        return Err(AttributionError::KeyMismatch);
    }

    // Window = intersection of every proof window and the access cert window.
    let mut valid_from = ac.iat;
    let mut valid_until = ac.exp;
    for (_iss, _key, inception, expiration) in proven {
        valid_from = valid_from.max(*inception);
        valid_until = valid_until.min(*expiration);
    }
    if valid_from > valid_until {
        return Err(AttributionError::EmptyWindow);
    }

    Ok(DeviceAttribution {
        email: verified.email.clone(),
        grantee,
        holder: ac.holder.clone(),
        key: cert_key,
        scopes: verified.scopes.clone(),
        issuer: verified.issuer.clone(),
        grantee_issuer: grantee_iss,
        valid_from,
        valid_until,
        verified,
    })
}

#[cfg(test)]
mod tests;
