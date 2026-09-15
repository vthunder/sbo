//! Offline roundtrip: build a device-model `access~assertion~warrant~config`
//! bundle with `browserid_core::device`, then verify it attributes correctly
//! through [`verify_device_attribution_with_provider_key`] (the DNSSEC proof
//! extraction is the one live-only step — see the module docs).

use super::*;
use browserid_core::device::{
    AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
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
        Holder::new("svc.sbo").unwrap(),
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
        Holder::new("svc.sbo").unwrap(),
        vec![EMAIL.to_string()],
        Duration::days(90),
        &idp,
        None,
    )
    .unwrap();
    let warrant = Warrant::create(
        EMAIL,
        EMAIL,
        HolderMatcher::new("svc.sbo").unwrap(),
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
        None,
        &anchors(),
    )
    .expect("valid bundle should attribute");

    assert_eq!(attr.email, EMAIL);
    assert_eq!(attr.key, access_key.public_key().to_base64());
    assert_eq!(attr.holder.as_str(), "svc.sbo");
    assert_eq!(attr.scopes, vec!["dim:val".to_string()]);
    assert_eq!(attr.issuer, IDP_DOMAIN);
}

/// A DELEGATED (model-A) bundle: a distinct grantee service acts under a
/// grantor user's warrant, same issuer. The access cert certifies the grantee
/// (the actor that signs); the config cert authorizes the GRANTOR (who
/// delegated); the warrant delegates grantor → grantee with `scopes`.
fn delegated_fixture() -> (AccessPresentation, KeyPair, KeyPair) {
    delegated_fixture_with(vec!["action:post".to_string()])
}

fn delegated_fixture_with(scopes: Vec<String>) -> (AccessPresentation, KeyPair, KeyPair) {
    const GRANTOR: &str = "dan@mingo.place";
    const GRANTEE: &str = "mingo-poster@mingo.place";
    const ISS: &str = "mingo.place";
    let idp = KeyPair::generate();
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();

    // Access cert certifies the GRANTEE (the actor + SBO signing key).
    let access_cert = AccessCert::create(
        ISS, GRANTEE, Holder::new("svc.poster").unwrap(), &access_key.public_key(),
        Duration::hours(24), &idp, None,
    )
    .unwrap();
    // Config cert authorizes the GRANTOR (whom the write attributes to).
    let config_cert = DeviceCert::create(
        ISS, &config_key.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![GRANTOR.to_string()], Duration::days(90), &idp, None,
    )
    .unwrap();
    // Warrant delegates grantor → grantee, bound to the grantee's holder.
    let warrant = Warrant::create(
        GRANTOR, GRANTEE, HolderMatcher::new("svc.poster").unwrap(), AUDIENCE,
        scopes, Duration::days(90), &config_key, None,
    )
    .unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::days(1), &access_key).unwrap();
    let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
    (pres, idp, access_key)
}

#[test]
fn delegated_attribution_lands_on_grantee_by_default() {
    let (pres, idp, access_key) = delegated_fixture();
    let now = chrono::Utc::now().timestamp();
    let attr = verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &idp.public_key(),
        now - 3600,
        now + 3600,
        AUDIENCE,
        now,
        None,
        &anchors(),
    )
    .expect("delegated bundle should attribute to the grantee");

    // No `as:` ⇒ the agent authors as ITSELF (Authorization Spec, "On-behalf
    // writes"); the grantor is provenance. The holder is the grantee's.
    assert_eq!(attr.email, "mingo-poster@mingo.place");
    assert_eq!(attr.grantee, "mingo-poster@mingo.place");
    assert_eq!(attr.grantor, "dan@mingo.place");
    assert_eq!(attr.holder.as_str(), "svc.poster");
    assert_eq!(attr.issuer, "mingo.place");
    assert_eq!(attr.grantee_issuer, "mingo.place");
    assert_eq!(attr.scopes, vec!["action:post".to_string()]);
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
        None,
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
        None,
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
        None,
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
        None,
        &anchors(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        AttributionError::EvidenceWindowMismatch { .. }
    ));
}

#[test]
fn replay_judges_expiries_at_the_authoring_instant() {
    // Deterministic replay (module Window/clock note): a write whose 5-minute
    // assertion was valid when AUTHORED must still attribute when a node
    // replays the block later — and must not attribute at an instant past the
    // assertion's life. Build a bundle whose assertion expired 1h ago.
    let idp = KeyPair::generate();
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();
    let access_cert = AccessCert::create(
        IDP_DOMAIN, EMAIL, Holder::new("svc.sbo").unwrap(),
        &access_key.public_key(), Duration::hours(24), &idp, None,
    ).unwrap();
    let config_cert = DeviceCert::create(
        IDP_DOMAIN, &config_key.public_key(), Purpose::Authorization,
        Holder::new("svc.sbo").unwrap(), vec![EMAIL.to_string()],
        Duration::days(90), &idp, None,
    ).unwrap();
    let warrant = Warrant::create(
        EMAIL, EMAIL, HolderMatcher::new("svc.sbo").unwrap(), AUDIENCE,
        vec![], Duration::days(90), &config_key, None,
    ).unwrap();
    let stale_assertion = Assertion::create(AUDIENCE, Duration::hours(-1), &access_key).unwrap();
    let authored = stale_assertion.claims().exp - 60; // inside its life
    let pres = AccessPresentation { access_cert, assertion: stale_assertion, warrant, config_cert };

    let now = chrono::Utc::now().timestamp();
    let call = |authored_at: Option<i64>| {
        verify_device_attribution_with_provider_key(
            &access_key.public_key().to_base64(),
            AccessPresentation::parse(&pres.encode()).unwrap(),
            &idp.public_key(),
            now - 7200,
            now + 7200,
            AUDIENCE,
            now, // inclusion: the block landed after the assertion expired
            authored_at,
            &anchors(),
        )
    };
    // At the HLC-bounded authoring instant: attributes.
    assert!(call(Some(authored)).is_ok());
    // Without an authoring instant, expiries are judged at inclusion — the
    // assertion is dead there, so attribution fails (deterministically, not
    // because of anyone's wall clock).
    assert!(call(None).is_err());
}

fn attr_for(scopes: Vec<String>) -> Result<DeviceAttribution, AttributionError> {
    let (pres, idp, access_key) = delegated_fixture_with(scopes);
    let now = chrono::Utc::now().timestamp();
    verify_device_attribution_with_provider_key(
        &access_key.public_key().to_base64(),
        pres,
        &idp.public_key(),
        now - 3600,
        now + 3600,
        AUDIENCE,
        now,
        None,
        &anchors(),
    )
}

#[test]
fn as_grantor_makes_the_grantor_the_author() {
    let attr = attr_for(vec![
        "action:post".into(),
        "path:/u/dan/**".into(),
        "as:dan@mingo.place".into(),
    ])
    .expect("as:<grantor> with a path: scope is a valid on-behalf grant");
    assert_eq!(attr.email, "dan@mingo.place");
    assert_eq!(attr.grantee, "mingo-poster@mingo.place");
    assert_eq!(attr.grantor, "dan@mingo.place");
}

#[test]
fn as_someone_else_is_rejected() {
    let err = attr_for(vec!["path:/u/**".into(), "as:mallory@mingo.place".into()]).unwrap_err();
    assert!(matches!(err, AttributionError::InvalidAsScope(_)), "{err}");
    // Even naming the grantee is wrong: `as:` selects the grantor only.
    let err = attr_for(vec!["path:/u/**".into(), "as:mingo-poster@mingo.place".into()]).unwrap_err();
    assert!(matches!(err, AttributionError::InvalidAsScope(_)), "{err}");
}

#[test]
fn as_without_path_scope_is_rejected() {
    let err = attr_for(vec!["action:post".into(), "as:dan@mingo.place".into()]).unwrap_err();
    assert!(matches!(err, AttributionError::InvalidAsScope(_)), "{err}");
}

#[test]
fn two_as_scopes_are_rejected() {
    let err = attr_for(vec![
        "path:/u/**".into(),
        "as:dan@mingo.place".into(),
        "as:dan@mingo.place".into(),
    ])
    .unwrap_err();
    assert!(matches!(err, AttributionError::InvalidAsScope(_)), "{err}");
}
