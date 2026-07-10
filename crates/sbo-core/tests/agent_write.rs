//! Smoke test: a warrant-backed agent write, assembled the way an agent would,
//! round-tripped through the wire, and run through the full verification the
//! daemon performs — all offline. (The DNSSEC-extraction half is covered by
//! attribution.rs's live `#[ignore]`d test; here the provider key is supplied
//! directly, exercising everything else: wire framing of `Auth-Warrant`,
//! warrant crypto + bindings, the sbo+raw:// audience rule, the scope grammar,
//! and agent-vs-delegator effective authorship.)

use browserid_core::{Certificate, KeyPair, Warrant};
use chrono::{Duration, Utc};
use sbo_core::attribution::verify_warrant_with_provider_key;
use sbo_core::authorize::{agent_effective_email, audience_identifies_db};
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::uri::SboRawUri;
use sbo_core::wire;

/// mingo's live canonical identity (deploy/sbo-daemon/entrypoint.sh).
const MINGO_AUD_BARE: &str = "sbo+raw://avail:turing:506/";
fn mingo_db() -> SboRawUri {
    SboRawUri::parse("sbo+raw://avail:turing:506@3567386/").unwrap()
}
const MINGO_GENESIS: &str =
    "sha256:7c429116819b67b7be4cb5c698a8ede1886e93a63f614abbf9fbb16e5375c291";

struct Artifacts {
    provider: KeyPair,
    agent_cert: Certificate,
    warrant: String,
    agent_seed: [u8; 32],
}

/// The one-time browser ceremony, in code: browserid.me certifies the human and
/// the agent; the human signs a warrant for `aud` with `scopes`.
fn artifacts(scopes: Option<Vec<String>>, aud: &str) -> Artifacts {
    let provider = KeyPair::generate(); // stands in for browserid.me's signing key
    let human = KeyPair::generate();
    let agent = KeyPair::generate();
    let parent = Certificate::create(
        "browserid.me", "human@example.com", &human.public_key(), Duration::days(1), &provider,
    ).unwrap();
    let agent_cert = Certificate::create_agent(
        "browserid.me", "attestor@browserid.me", "human@example.com",
        &agent.public_key(), Duration::days(1), &provider,
    ).unwrap();
    let warrant = Warrant::create(
        &parent, "attestor@browserid.me", aud, scopes, Duration::days(30), &human,
    ).unwrap();
    Artifacts { provider, agent_cert, warrant: warrant.encoded().to_string(), agent_seed: *agent.secret_bytes() }
}

/// Assemble the SBO write an agent would post: signed by the agent's own key
/// (the key its cert certifies), carrying Auth-Cert + Auth-Warrant.
fn agent_write(a: &Artifacts, action: Action, path: &str, schema: Option<&str>) -> Message {
    let key = SigningKey::from_bytes(&a.agent_seed);
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
        owner: Some(Id::new("attestor@browserid.me").unwrap()),
        creator: None,
        content_encoding: None,
        content_schema: schema.map(String::from),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: Some(a.agent_cert.encoded().to_string()),
        // Real writes carry `inline:<dnssec>`; the smoke test verifies the
        // warrant against the provider key directly (DNSSEC is the live test).
        auth_evidence: Some("inline:placeholder".into()),
        auth_warrant: Some(a.warrant.clone()),
    };
    msg.sign(&key);
    msg
}

#[test]
fn warrant_backed_write_verifies_end_to_end_offline() {
    let a = artifacts(
        Some(vec!["action:post".into(), "path:/attestor/**".into()]),
        MINGO_AUD_BARE,
    );
    let msg = agent_write(&a, Action::Post, "/attestor/", None);

    // 1. Wire framing: Auth-Warrant survives a serialize → parse round-trip.
    let wire_bytes = wire::serialize(&msg);
    let parsed = wire::parse(&wire_bytes).unwrap();
    assert_eq!(parsed.auth_warrant.as_deref(), Some(a.warrant.as_str()));

    // 2. Warrant crypto + bindings (offline, inclusion-time gated).
    let now = Utc::now().timestamp();
    let wa = verify_warrant_with_provider_key(
        parsed.auth_warrant.as_deref().unwrap(),
        &a.agent_cert,
        &a.provider.public_key(),
        now,
    )
    .expect("warrant should verify");
    assert_eq!(wa.agent_email, "attestor@browserid.me");
    assert_eq!(wa.delegator, "human@example.com");

    // 3. Audience identifies mingo (bare authority survives the regenesis pin).
    assert!(audience_identifies_db(&wa.audience, &mingo_db(), Some(MINGO_GENESIS)));

    // 4. Scopes authorize this write; effective author is the agent.
    let email = agent_effective_email(
        &wa, &mingo_db(), Some(MINGO_GENESIS),
        parsed.action.name(), &parsed.path.to_string(), parsed.content_schema.as_deref(), true,
    )
    .expect("write should be authorized");
    assert_eq!(email, "attestor@browserid.me");
}

#[test]
fn warrant_for_a_different_chain_is_rejected() {
    let a = artifacts(Some(vec!["action:post".into()]), "sbo+raw://avail:turing:999/");
    let msg = agent_write(&a, Action::Post, "/attestor/", None);
    let now = Utc::now().timestamp();
    let wa = verify_warrant_with_provider_key(msg.auth_warrant.as_deref().unwrap(), &a.agent_cert, &a.provider.public_key(), now).unwrap();
    // Warrant is cryptographically fine, but its audience is a different app.
    assert!(agent_effective_email(&wa, &mingo_db(), None, "post", "/attestor/", None, true).is_err());
}

#[test]
fn out_of_scope_write_is_rejected() {
    let a = artifacts(Some(vec!["path:/attestor/**".into()]), MINGO_AUD_BARE);
    let msg = agent_write(&a, Action::Post, "/somewhere/", None);
    let now = Utc::now().timestamp();
    let wa = verify_warrant_with_provider_key(msg.auth_warrant.as_deref().unwrap(), &a.agent_cert, &a.provider.public_key(), now).unwrap();
    assert!(agent_effective_email(&wa, &mingo_db(), None, "post", "/somewhere/", None, true).is_err());
}

#[test]
fn on_behalf_write_attributes_to_the_delegator() {
    // "act as me" under /u/human/**.
    let a = artifacts(
        Some(vec!["as:human@example.com".into(), "path:/u/human/**".into()]),
        MINGO_AUD_BARE,
    );
    let msg = agent_write(&a, Action::Post, "/u/human/", None);
    let now = Utc::now().timestamp();
    let wa = verify_warrant_with_provider_key(msg.auth_warrant.as_deref().unwrap(), &a.agent_cert, &a.provider.public_key(), now).unwrap();
    let email = agent_effective_email(&wa, &mingo_db(), None, "post", "/u/human/", None, true).unwrap();
    assert_eq!(email, "human@example.com", "on-behalf: the write authorizes as the delegator");
    // And a repo that opts out of on-behalf rejects it.
    assert!(agent_effective_email(&wa, &mingo_db(), None, "post", "/u/human/", None, false).is_err());
}
