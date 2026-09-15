//! Write-time DNSSEC evidence: a submitting node keeps `/sys/dnssec/<issuer>`
//! fresh for every issuer a write's attribution will need, and posts the
//! refresh AHEAD of the write so it precedes it in chain order.
//!
//! Replay validation (`validate.rs`) only ever reads evidence already on
//! chain — deterministic, no live DNS. That is correct for replay and useless
//! for a writer: an email-rooted write whose issuer's on-chain RRSIG window
//! has lapsed is simply disregarded. Every client used to carry its own
//! "ensure evidence, then submit" (mingo's `ensure_dnssec_fresh`,
//! browserid-pay's `dsp-genesis dnssec-refresh`, …). This module is that
//! logic, once, inside `/v1/submit`.
//!
//! The refresh object is what those clients posted: a `dnssec.v1` object at
//! `/sys/dnssec/<domain>` signed by a throwaway key — self-authorizing (the
//! proof validates against the pinned root KSK; the `/sys/dnssec/**` policy
//! grants create/update to any signer), so no identity is involved.

use sbo_core::crypto::SigningKey;
use sbo_core::message::Message;
use sbo_core::presets::signed_object;

use crate::state_view::StateView;
use crate::validate::fetch_evidence_object;

/// Headroom (seconds) beyond "now" the on-chain window must cover, absorbing
/// inclusion latency. Same default the `/v1/dnssec` clients used.
pub const DEFAULT_MARGIN_SECS: i64 = 3600;

/// The issuer domains whose on-chain evidence this write's attribution will
/// demand. A key-rooted write (no `Auth-Cert`) needs none.
///
/// - device model: the 4-object presentation in `Auth-Cert` — the access
///   cert's issuer (grantee) AND the config cert's issuer (grantor; different
///   on a cross-issuer grant);
/// - legacy: a single identity JWT in `Auth-Cert` — its `iss`
///   (`domain:<d>`; `self` needs nothing).
pub fn required_issuers(msg: &Message) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |d: String| {
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    };
    if let Some(cert) = msg.auth_cert.as_deref() {
        if cert.contains('~') {
            if let Ok(pres) = sbo_core::browserid_core::device::AccessPresentation::parse(cert) {
                push(pres.access_cert.claims().iss.clone());
                push(pres.config_cert.claims().iss.clone());
            }
        } else if let Ok(claims) = sbo_core::jwt::decode_identity_claims(cert) {
            if let Some(d) = claims.iss.strip_prefix("domain:") {
                push(d.to_string());
            }
        }
    }
    out
}

/// The on-chain proof's RRSIG window for `domain`, if a valid proof is there.
pub fn on_chain_window(state: &dyn StateView, domain: &str) -> Option<(i64, i64)> {
    let bytes = fetch_evidence_object(state, &format!("/sys/dnssec/{domain}"))?;
    sbo_core::attribution::verify_dnssec_proof_for_domain(&bytes, domain).ok()
}

/// Does `domain`'s on-chain evidence cover `deadline`?
pub fn is_fresh(state: &dyn StateView, domain: &str, deadline: i64) -> bool {
    on_chain_window(state, domain).is_some_and(|(_, exp)| exp >= deadline)
}

/// The refresh write: `/sys/dnssec/<domain>` = `proof`, throwaway-signed.
pub fn refresh_wire(domain: &str, proof: Vec<u8>) -> Vec<u8> {
    let throwaway = SigningKey::generate();
    signed_object(
        &throwaway,
        "/sys/dnssec/",
        domain,
        "dnssec.v1",
        "application/octet-stream",
        proof,
        None,
        None,
        None,
    )
}

/// Capture a fresh RFC 9102 proof for `domain` from live DNS.
pub async fn capture(domain: &str) -> Result<Vec<u8>, String> {
    let resolver: std::net::SocketAddr = sbo_capture::DEFAULT_RESOLVER
        .parse()
        .map_err(|e| format!("bad default resolver: {e}"))?;
    sbo_capture::capture_evidence(resolver, domain)
        .await
        .map_err(|e| format!("DNSSEC capture failed for '{domain}': {e}"))
}

/// The issuers in `issuers` whose on-chain evidence does not cover
/// `deadline` (synchronous — takes no state borrow across an await).
pub fn stale_issuers(state: &dyn StateView, issuers: &[String], deadline: i64) -> Vec<String> {
    issuers
        .iter()
        .filter(|d| !is_fresh(state, d, deadline))
        .cloned()
        .collect()
}

/// Capture a proof and build the refresh write for each stale issuer, in
/// order. A capture failure is an error: the write would be unattributed
/// anyway, and a silent gap is exactly what this exists to end.
pub async fn build_refreshes(stale: &[String]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for d in stale {
        let proof = capture(d).await?;
        out.push((d.clone(), refresh_wire(d, proof)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::browserid_core::device::{AccessCert, DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
    use sbo_core::browserid_core::{Assertion, KeyPair};
    use chrono::Duration;
    use sbo_core::message::{Action, Id, ObjectType, Path};

    fn message_with_auth_cert(cert: Option<&str>) -> Message {
        let key = SigningKey::generate();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/x/").unwrap(),
            id: Id::new("y").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: sbo_core::crypto::Signature([0u8; 64]),
            content_type: None,
            content_hash: None,
            payload: None,
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: cert.map(str::to_string),
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(&key);
        msg
    }

    /// A device-model presentation whose access cert is issued by `grantee_iss`
    /// and whose config cert (the grantor's) by `grantor_iss`.
    fn presentation(grantee_iss: &str, grantor_iss: &str) -> String {
        let idp_a = KeyPair::generate();
        let idp_b = KeyPair::generate();
        let access_kp = KeyPair::generate();
        let config_kp = KeyPair::generate();
        let holder = Holder::new("ag.k1").unwrap();
        let access = AccessCert::create(
            grantee_iss, "agent@a.test", holder.clone(), &access_kp.public_key(),
            Duration::hours(1), &idp_a, None,
        )
        .unwrap();
        let config = DeviceCert::create(
            grantor_iss, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.1").unwrap(),
            vec!["user@b.test".to_string()], Duration::days(90), &idp_b, None,
        )
        .unwrap();
        let warrant = Warrant::create(
            "user@b.test", "agent@a.test", HolderMatcher::new("ag.k1").unwrap(),
            "sbo+raw://avail:turing:530/", vec!["action:post".into()], Duration::days(30), &config_kp, None,
        )
        .unwrap();
        let assertion = Assertion::create("sbo+raw://avail:turing:530/", Duration::minutes(5), &access_kp).unwrap();
        format!("{}~{}~{}~{}", access.encoded(), assertion.encoded(), warrant.encoded(), config.encoded())
    }

    #[test]
    fn key_rooted_write_needs_no_issuers() {
        assert!(required_issuers(&message_with_auth_cert(None)).is_empty());
    }

    #[test]
    fn device_presentation_yields_both_issuers_once() {
        let same = presentation("a.test", "a.test");
        assert_eq!(required_issuers(&message_with_auth_cert(Some(&same))), vec!["a.test"]);
        let cross = presentation("a.test", "browserid.me");
        assert_eq!(
            required_issuers(&message_with_auth_cert(Some(&cross))),
            vec!["a.test", "browserid.me"]
        );
    }

    #[test]
    fn legacy_identity_jwt_yields_its_domain() {
        let domain_key = SigningKey::generate();
        let user = SigningKey::generate();
        let token = sbo_core::jwt::create_domain_certified_identity(
            &domain_key, "sandmill.org", "alice@sandmill.org", &user.public_key(), None,
        )
        .unwrap();
        assert_eq!(required_issuers(&message_with_auth_cert(Some(&token))), vec!["sandmill.org"]);
        let selfsigned = sbo_core::jwt::create_self_signed_identity(&user, "alice", None).unwrap();
        assert!(required_issuers(&message_with_auth_cert(Some(&selfsigned))).is_empty());
    }

    #[test]
    fn refresh_wire_is_a_self_authorizing_dnssec_object() {
        let wire = refresh_wire("example.org", b"proof-bytes".to_vec());
        let msgs = sbo_core::wire::parse_batch(&wire).unwrap();
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m.path.to_string(), "/sys/dnssec/");
        assert_eq!(m.id.as_str(), "example.org");
        assert_eq!(m.content_schema.as_deref(), Some("dnssec.v1"));
        assert!(m.auth_cert.is_none() && m.owner.is_none());
        assert_eq!(m.payload.as_deref(), Some(&b"proof-bytes"[..]));
    }
}
