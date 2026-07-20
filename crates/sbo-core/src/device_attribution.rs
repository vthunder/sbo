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
//!    signatures, expiries, and the `(identity, subject, audience)` join. Since
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

use browserid_core::device::{AccessPresentation, Subject, VerifiedAccess};

use crate::attribution::{extract_provider_key, AttributionError, TrustAnchors};

/// A successful device-model attribution: the SBO `key` speaks for `email`
/// (as `subject`), the warrant grants `scopes` for the write's audience, valid
/// within `[valid_from, valid_until]` (inclusive, UNIX seconds — the
/// intersection of the DNSSEC proof window and the access cert window).
#[derive(Debug, Clone)]
pub struct DeviceAttribution {
    /// The email the access cert certifies (the warrant identifier).
    pub email: String,
    /// Whether this acts for a user or an agent.
    pub subject: Subject,
    /// The SBO Public-Key string (base64url) — equals the access cert's key.
    pub key: String,
    /// The warrant's granted scopes (`<dimension>:<value>`; caller enforces).
    pub scopes: Vec<String>,
    /// The issuing IdP/broker domain (`access_cert.iss == config_cert.iss`).
    pub issuer: String,
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
    auth_evidence: &[u8],
    expected_audience: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Result<DeviceAttribution, AttributionError> {
    // Parse the 4-object bundle so we know which issuer's TXT record to look for.
    let pres = AccessPresentation::parse(presentation)
        .map_err(|e| AttributionError::BadCertificate(e.to_string()))?;
    let iss = pres.access_cert.claims().iss.clone();

    // DNSSEC: provider key + proof window for _browserid.<iss>.
    let (provider_key, inception, expiration) = extract_provider_key(auth_evidence, &iss)?;

    verify_device_attribution_with_provider_key(
        public_key,
        pres,
        &provider_key,
        inception,
        expiration,
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
    let ac = pres.access_cert.claims();
    let iss = ac.iss.clone();
    let email = ac.identity.clone();

    // inclusion_time must lie within the DNSSEC (RRSig) window.
    if inclusion_time < inception || inclusion_time > expiration {
        return Err(AttributionError::EvidenceWindowMismatch {
            time: inclusion_time,
            from: inception,
            until: expiration,
        });
    }

    // 4. Authority: primary IdP (email domain == iss) or a pinned broker.
    let domain = email.split('@').nth(1).unwrap_or("");
    if domain != iss && !anchors.is_broker(&iss) {
        return Err(AttributionError::IssuerNotAuthorized {
            iss: iss.clone(),
            domain: domain.to_string(),
        });
    }

    // 5. Crypto + structural join, resolving the single IdP key from the
    //    DNSSEC-proven provider key. `verify` enforces config_cert.iss ==
    //    access_cert.iss, so the config cert issuer binds transitively to the
    //    DNSSEC-proven provider — a rogue-IdP config cert cannot be resolved.
    let verified = pres
        .verify(expected_audience, |q_iss| {
            if q_iss == iss {
                Ok(provider_key.clone())
            } else {
                Err(browserid_core::Error::InvalidCertificate(format!(
                    "no DNSSEC-proven key for issuer '{q_iss}'"
                )))
            }
        })
        .map_err(|e| AttributionError::DevicePresentation(e.to_string()))?;

    // 6. SBO signing-key binding: the envelope signer key == the access cert key.
    // SBO refers to keys as `ed25519:<hex>`; the access cert stores the key
    // base64url. Accept either encoding so the daemon (which passes the sbo form)
    // and base64 callers both verify. The canonical `key` we return is base64url.
    let cert_key = ac.access_key.to_base64();
    let cert_key_sbo = format!("ed25519:{}", hex::encode(ac.access_key.as_bytes()));
    if public_key != cert_key && public_key != cert_key_sbo {
        return Err(AttributionError::KeyMismatch);
    }

    // Window = intersection of the DNSSEC proof window and the access cert window.
    let valid_from = inception.max(ac.iat);
    let valid_until = expiration.min(ac.exp);
    if valid_from > valid_until {
        return Err(AttributionError::EmptyWindow);
    }

    Ok(DeviceAttribution {
        email,
        subject: ac.subject,
        key: cert_key,
        scopes: verified.scopes.clone(),
        issuer: iss,
        valid_from,
        valid_until,
        verified,
    })
}

#[cfg(test)]
mod tests;
