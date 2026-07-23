//! Smoke test: a warrant-backed device-model write, assembled the way an agent
//! would, round-tripped through the wire, and run through the full verification
//! the daemon performs — all offline. (The DNSSEC-extraction half is covered by
//! attribution.rs's live `#[ignore]`d test; here the provider key is supplied
//! directly, exercising everything else: wire framing of the presentation,
//! the presentation crypto + bindings, the sbo+raw:// audience rule, the scope
//! grammar, and the attributed identity.)

use browserid_core::device::{
    AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
};
use browserid_core::{Assertion, KeyPair};
use chrono::{Duration, Utc};
use sbo_core::attribution::TrustAnchors;
use sbo_core::authorize::{audience_identifies_db, authorized_write_email, presentation_audience};
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::device_attribution::verify_device_attribution_with_provider_key;
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::uri::SboRawUri;
use sbo_core::wire;

/// mingo's live canonical identity (deploy/sbo-daemon/entrypoint.sh).
const MINGO_AUD_BARE: &str = "sbo+raw://avail:turing:506/";
const IDP: &str = "example.com";
const IDENTITY: &str = "attestor@example.com";
fn mingo_db() -> SboRawUri {
    SboRawUri::parse("sbo+raw://avail:turing:506@3567386/").unwrap()
}
const MINGO_GENESIS: &str =
    "sha256:7c429116819b67b7be4cb5c698a8ede1886e93a63f614abbf9fbb16e5375c291";

struct Artifacts {
    idp: KeyPair,
    presentation: String,
    access_seed: [u8; 32],
}

/// The device-cert ceremony, in code: the IdP certifies the identity's access
/// key and its config (authorization) cert; the config key signs a warrant for
/// `aud` with `scopes`; the access key signs the assertion. `holder` is the
/// opaque broker-assigned id the certs carry; the warrant grants that exact
/// holder (`<id>` isolation). Authorization keys off `email` + scopes, not the
/// holder — passing it just makes a well-formed presentation.
fn artifacts(scopes: Vec<String>, aud: &str, holder: &str) -> Artifacts {
    let idp = KeyPair::generate(); // stands in for the IdP's signing key
    let access = KeyPair::generate();
    let config = KeyPair::generate();

    let access_cert = AccessCert::create(
        IDP, IDENTITY, Holder::new(holder).unwrap(), &access.public_key(), Duration::hours(24), &idp, None,
    )
    .unwrap();
    let config_cert = DeviceCert::create(
        IDP, &config.public_key(), Purpose::Authorization, Holder::new(holder).unwrap(),
        vec![IDENTITY.to_string()], Duration::days(90), &idp, None,
    )
    .unwrap();
    let warrant = Warrant::create(
        IDENTITY, IDENTITY, HolderMatcher::new(holder).unwrap(), aud, scopes, Duration::days(90), &config, None,
    )
    .unwrap();
    let assertion = Assertion::create(aud, Duration::days(1), &access).unwrap();
    let presentation = AccessPresentation { access_cert, assertion, warrant, config_cert }.encode();

    Artifacts { idp, presentation, access_seed: *access.secret_bytes() }
}

/// The identity's email domain equals the issuer (primary IdP path), so no
/// broker anchor is needed for authority.
fn anchors() -> TrustAnchors {
    TrustAnchors::default()
}

/// Assemble the SBO write an agent would post: signed by the access key (the key
/// the access cert certifies), carrying the presentation as `Auth-Cert`.
fn device_write(a: &Artifacts, action: Action, path: &str, schema: Option<&str>) -> Message {
    let key = SigningKey::from_bytes(&a.access_seed);
    let payload = b"{}".to_vec();
    let mut msg = Message {
        action,
        path: Path::parse(path).unwrap(),
        id: Id::new("note-1").unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature::parse(&"0".repeat(128)).unwrap(),
        content_type: Some("application/json".into()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: Some(Id::new(IDENTITY).unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: schema.map(String::from),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: Some(a.presentation.clone()),
        // Real writes carry `inline:<dnssec>`; the smoke test verifies the
        // presentation against the provider key directly (DNSSEC is the live test).
        auth_evidence: Some("inline:placeholder".into()),
        auth_warrant: None,
    };
    msg.sign(&key);
    msg
}

/// The daemon's offline attribution + authorization sequence for a device write.
fn verify(a: &Artifacts, msg: &Message) -> Result<String, String> {
    let now = Utc::now().timestamp();
    let presentation = msg.auth_cert.as_deref().unwrap();
    let aud = presentation_audience(presentation).ok_or("no audience")?;
    // Audience must identify this database (bare authority survives the pin).
    if !audience_identifies_db(&aud, &mingo_db(), Some(MINGO_GENESIS)) {
        return Err("audience does not identify db".into());
    }
    let pres = AccessPresentation::parse(presentation).unwrap();
    let attr = verify_device_attribution_with_provider_key(
        &msg.signing_key.to_string(),
        pres,
        &a.idp.public_key(),
        0,
        i64::MAX,
        &aud,
        now,
        &anchors(),
    )
    .map_err(|e| e.to_string())?;
    authorized_write_email(
        &attr,
        msg.action.name(),
        &msg.path.to_string(),
        msg.content_schema.as_deref(),
    )
}

#[test]
fn warrant_backed_write_verifies_end_to_end_offline() {
    let a = artifacts(
        vec!["action:post".into(), "path:/attestor/**".into()],
        MINGO_AUD_BARE,
        "svc.agent",
    );
    let msg = device_write(&a, Action::Post, "/attestor/", None);

    // 1. Wire framing: the presentation survives a serialize → parse round-trip.
    let wire_bytes = wire::serialize(&msg);
    let parsed = wire::parse(&wire_bytes).unwrap();
    assert_eq!(parsed.auth_cert.as_deref(), Some(a.presentation.as_str()));

    // 2..4. Attribution + audience + scope authorization; the write is attributed
    // to the warrant identifier.
    let email = verify(&a, &parsed).expect("write should be authorized");
    assert_eq!(email, IDENTITY);
}

#[test]
fn warrant_for_a_different_chain_is_rejected() {
    let a = artifacts(vec!["action:post".into()], "sbo+raw://avail:turing:999/", "svc.agent");
    let msg = device_write(&a, Action::Post, "/attestor/", None);
    // Presentation is cryptographically fine, but its audience is a different app.
    assert!(verify(&a, &msg).is_err());
}

#[test]
fn out_of_scope_write_is_rejected() {
    let a = artifacts(vec!["path:/attestor/**".into()], MINGO_AUD_BARE, "svc.agent");
    let msg = device_write(&a, Action::Post, "/somewhere/", None);
    assert!(verify(&a, &msg).is_err());
}

#[test]
fn plain_user_write_with_empty_scopes_is_unconstrained() {
    // A warrant with no scopes attributes to the identity for any write.
    let a = artifacts(vec![], MINGO_AUD_BARE, "br.main");
    let msg = device_write(&a, Action::Post, "/u/attestor/", None);
    let email = verify(&a, &msg).expect("empty scopes are unconstrained");
    assert_eq!(email, IDENTITY);
}
