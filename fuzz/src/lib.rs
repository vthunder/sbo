//! Shared fixtures for the WS3 fuzz targets (security audit 2026-11):
//! deterministic keys, a valid signed envelope and a valid device
//! presentation every target can mutate from, so a crash reproduces.

use std::sync::OnceLock;

use sbo_core::browserid_core::device::{
    AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
};
use sbo_core::browserid_core::{Assertion, KeyPair};
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};

pub const IDP: &str = "example.com";
pub const EMAIL: &str = "user@example.com";
pub const AUD: &str = "sbo+raw://avail:turing:506/";
/// A fixed "now" for the presentation fixture (2027-01-15), so expiries are
/// stable across runs.
pub const NOW: i64 = 1_800_000_000;

/// Lossy text from fuzz bytes (what every text parser in the tree sees after
/// a `from_utf8_lossy`).
pub fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

pub fn key(seed: u8) -> SigningKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[31] = 0x5a;
    SigningKey::from_bytes(&b)
}

/// A valid signed envelope.
pub fn envelope(path: &str, id: &str, payload: Vec<u8>, seed: u8) -> Message {
    let k = key(seed);
    let mut m = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: k.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".into()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
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
        auth_warrant: None,
        extra_headers: Vec::new(),
    };
    m.sign(&k);
    m
}

pub struct Fixture {
    pub idp: KeyPair,
    pub access: KeyPair,
    pub config: KeyPair,
    /// `ed25519:<hex>` form of the access key (the SBO `Public-Key`).
    pub access_key_sbo: String,
    pub presentation: String,
}

/// A valid presentation for `EMAIL` at `AUD`, certs valid for a year around
/// `NOW`, signed by deterministic keys.
pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let idp = KeyPair::from_seed(&[1u8; 32]).unwrap();
        let access = KeyPair::from_seed(&[3u8; 32]).unwrap();
        let config = KeyPair::from_seed(&[4u8; 32]).unwrap();
        let year = chrono::Duration::days(365);
        let access_cert = AccessCert::create(IDP, EMAIL, Holder::new("h").unwrap(), &access.public_key(), year, &idp, None).unwrap();
        let config_cert = DeviceCert::create(IDP, &config.public_key(), Purpose::Authorization, Holder::new("h").unwrap(), vec![EMAIL.into()], year, &idp, None).unwrap();
        let warrant = Warrant::create(EMAIL, EMAIL, HolderMatcher::new("h").unwrap(), AUD, vec!["action:post".into(), "path:/u/**".into()], year, &config, None).unwrap();
        let assertion = Assertion::create(AUD, year, &access).unwrap();
        let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
        Fixture {
            access_key_sbo: format!("ed25519:{}", hex::encode(access.public_key().as_bytes())),
            presentation: pres.encode(),
            idp,
            access,
            config,
        }
    })
}
