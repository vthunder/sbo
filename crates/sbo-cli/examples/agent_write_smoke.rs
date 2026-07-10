//! Live smoke test: take a browserid agent's identity + a warrant it holds,
//! capture a real DNSSEC proof for its issuer, and run the exact
//! attribution+authorization the sbo daemon performs on chain — proving a
//! warrant-backed agent write is accepted (or, for the negative cases,
//! correctly rejected). Nothing mocked: real cert, real warrant, real DNSSEC.
//!
//! Usage:
//!   cargo run -p sbo-cli --example agent_write_smoke -- <identity.json>
//!
//! The identity.json is browserid-agent's StoredIdentity
//! ({secret_key, email, cert, warrants:[...]}).

use browserid_core::{Certificate, Warrant};
use sbo_core::attribution::{verify_attribution_with_warrant, TrustAnchors};
use sbo_core::authorize::{agent_effective_email, authorize_owner, encode_auth_evidence_inline, parse_auth_evidence, AuthzOutcome};
use sbo_core::resolve::{NameRecord, DEFAULT_HOP_LIMIT};
use sbo_core::uri::SboRawUri;

// mingo's live canonical identity (deploy/sbo-daemon/entrypoint.sh).
const MINGO_DB: &str = "sbo+raw://avail:turing:506@3567386/";
const MINGO_GENESIS: &str = "sha256:7c429116819b67b7be4cb5c698a8ede1886e93a63f614abbf9fbb16e5375c291";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: agent_write_smoke <identity.json>");
    let ident: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;

    let cert_str = ident["cert"].as_str().expect("cert").to_string();
    let cert = Certificate::parse(&cert_str)?;
    let agent_email = cert.email().expect("agent email").to_string();
    let signer_pub = cert.public_key().to_base64(); // the SBO signer key == cert's key
    let warrants: Vec<String> = ident["warrants"].as_array().unwrap_or(&vec![])
        .iter().filter_map(|w| w.as_str().map(String::from)).collect();

    println!("agent identity : {agent_email}");
    println!("issuer         : {}", cert.issuer());
    println!("cert is_agent  : {}", cert.is_agent());
    println!("warrants held  : {}", warrants.len());
    for w in &warrants {
        if let Ok(p) = Warrant::parse(w) {
            println!("   • aud={}  scopes={:?}", p.audience(), p.claims().scopes);
        }
    }

    // Capture a real RFC 9102 DNSSEC proof for the cert's issuer.
    let issuer = cert.issuer().to_string();
    let resolver = "8.8.8.8:53".parse().unwrap();
    println!("\ncapturing DNSSEC proof for _browserid.{issuer} …");
    let proof = sbo_capture::capture_evidence(resolver, &issuer).await?;
    let evidence = encode_auth_evidence_inline(&proof);
    println!("  proof: {} bytes", proof.len());

    let db = SboRawUri::parse(MINGO_DB)?;
    let anchors = TrustAnchors::default(); // primary path (issuer == email domain); no broker needed
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let empty_lookup = |_: &str| -> Option<NameRecord> { None };

    // One "would the daemon accept this write?" check — the exact l2 sequence.
    let check = |label: &str, warrant: &str, action: &str, path: &str, owner: &str| {
        print!("\n[{label}]\n  action={action} path={path} owner={owner}\n  → ");
        let ev = match parse_auth_evidence(&evidence) { Ok(e) => e, Err(e) => { println!("REJECT (evidence: {e})"); return; } };
        let wa = match verify_attribution_with_warrant(&signer_pub, &cert_str, warrant, &ev, now, &anchors) {
            Ok(wa) => wa,
            Err(e) => { println!("REJECT (attribution: {e})"); return; }
        };
        let eff = match agent_effective_email(&wa, &db, Some(MINGO_GENESIS), action, path, None, true) {
            Ok(e) => e,
            Err(e) => { println!("REJECT ({e})"); return; }
        };
        match authorize_owner(owner, &signer_pub, Some(&eff), &empty_lookup, DEFAULT_HOP_LIMIT, None) {
            AuthzOutcome::Authorized => println!("ACCEPT (authored by {eff})"),
            AuthzOutcome::Unauthorized(r) => println!("REJECT (owner: {r})"),
        }
    };

    // Pick the canonical (sbo+raw://) warrant and the sbo:// one, if present.
    let raw_warrant = warrants.iter().find(|w| Warrant::parse(w).map(|p| p.audience().starts_with("sbo+raw://avail:turing:506")).unwrap_or(false)).cloned();
    let dns_warrant = warrants.iter().find(|w| Warrant::parse(w).map(|p| p.audience() == "sbo://mingo.place").unwrap_or(false)).cloned();

    println!("\n=== smoke matrix ===");
    if let Some(w) = &raw_warrant {
        check("canonical warrant, in-scope write", w, "post", "/attestor/", &agent_email);
        check("canonical warrant, OUT-of-scope path", w, "post", "/somewhere/", &agent_email);
        check("canonical warrant, OUT-of-scope action", w, "delete", "/attestor/", &agent_email);
    } else {
        println!("\n(no sbo+raw://avail:turing:506 warrant held — run: agent_cli grant 'sbo+raw://avail:turing:506/' action:post 'path:/attestor/**')");
    }
    if let Some(w) = &dns_warrant {
        check("DNS-form (sbo://) warrant — should be rejected on chain", w, "post", "/attestor/", &agent_email);
    }
    Ok(())
}
