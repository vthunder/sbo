//! Offline roundtrip: build a device-model `access~assertion~warrant~config`
//! bundle with `browserid_core::device`, then verify it attributes correctly
//! through [`verify_device_attribution_with_provider_key`] (the DNSSEC proof
//! extraction is the one live-only step — see the module docs).

use super::*;
use browserid_core::device::{
    AccessCert, AccessPresentation, DeviceCert, Purpose, Subject, Warrant,
};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;

const IDP_DOMAIN: &str = "sandmill.org";
const EMAIL: &str = "danmills@sandmill.org";
const AUDIENCE: &str = "sbo+raw://avail:turing:506/";

/// A fully valid bundle: `idp` signs the access + config certs; `access_key` is
/// the fresh SBO signing key (signs the assertion); `config_key` signs the
/// warrant. Returns the bundle plus the idp public key (the "DNSSEC-proven
/// provider key") and the SBO signing key.
fn fixture() -> (AccessPresentation, KeyPair, KeyPair) {
    let idp = KeyPair::generate();
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();

    let access_cert = AccessCert::create(
        IDP_DOMAIN,
        EMAIL,
        Subject::User,
        &access_key.public_key(),
        Duration::hours(24),
        &idp,
        None,
    )
    .unwrap();
    let config_cert = DeviceCert::create(
        IDP_DOMAIN,
        &config_key.public_key(),
        Purpose::Authorization,
        Subject::User,
        vec![EMAIL.to_string()],
        Duration::days(90),
        &idp,
        None,
    )
    .unwrap();
    let warrant = Warrant::create(
        EMAIL,
        Subject::User,
        AUDIENCE,
        vec!["dim:val".to_string()],
        Duration::days(90),
        &config_key,
        None,
    )
    .unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::days(1), &access_key).unwrap();

    let pres = AccessPresentation {
        access_cert,
        assertion,
        warrant,
        config_cert,
    };
    (pres, idp, access_key)
}

fn anchors() -> TrustAnchors {
    // Primary IdP path: the email domain equals the issuer, so no broker anchor
    // is needed for authority.
    TrustAnchors::default()
}

#[test]
fn device_attribution_roundtrip_ok() {
    let (pres, idp, access_key) = fixture();
    let now = chrono::Utc::now().timestamp();
    // A generous DNSSEC window around now.
    let (inception, expiration) = (now - 3600, now + 3600);

    let attr = verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &idp.public_key(),
        inception,
        expiration,
        AUDIENCE,
        now,
        &anchors(),
    )
    .expect("valid bundle should attribute");

    assert_eq!(attr.email, EMAIL);
    assert_eq!(attr.key, access_key.public_key().to_base64());
    assert_eq!(attr.subject, Subject::User);
    assert_eq!(attr.scopes, vec!["dim:val".to_string()]);
    assert_eq!(attr.issuer, IDP_DOMAIN);
}

#[test]
fn wrong_sbo_key_is_rejected() {
    let (pres, idp, _access_key) = fixture();
    let now = chrono::Utc::now().timestamp();
    let other = KeyPair::generate();

    let err = verify_device_attribution_with_provider_key(
        &other.public_key().to_base64(), // not the access cert's key
        pres,
        &idp.public_key(),
        now - 3600,
        now + 3600,
        AUDIENCE,
        now,
        &anchors(),
    )
    .unwrap_err();
    assert!(matches!(err, AttributionError::KeyMismatch));
}

#[test]
fn rogue_provider_key_fails_signature() {
    let (pres, _idp, access_key) = fixture();
    let now = chrono::Utc::now().timestamp();
    let rogue = KeyPair::generate();

    // A provider key that did not sign the certs → presentation verify fails.
    let err = verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &rogue.public_key(),
        now - 3600,
        now + 3600,
        AUDIENCE,
        now,
        &anchors(),
    )
    .unwrap_err();
    assert!(matches!(err, AttributionError::DevicePresentation(_)));
}

#[test]
fn audience_mismatch_is_rejected() {
    let (pres, idp, access_key) = fixture();
    let now = chrono::Utc::now().timestamp();

    let err = verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &idp.public_key(),
        now - 3600,
        now + 3600,
        "sbo+raw://avail:turing:999/", // wrong audience
        now,
        &anchors(),
    )
    .unwrap_err();
    assert!(matches!(err, AttributionError::DevicePresentation(_)));
}

#[test]
fn inclusion_time_outside_dnssec_window_is_rejected() {
    let (pres, idp, access_key) = fixture();
    let now = chrono::Utc::now().timestamp();

    let err = verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &idp.public_key(),
        now + 3600, // window starts in the future
        now + 7200,
        AUDIENCE,
        now,
        &anchors(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        AttributionError::EvidenceWindowMismatch { .. }
    ));
}
