//! One-off: capture the live DNSSEC proof for a domain and build a
//! `/sys/dnssec/<domain>` write stamped with a current-ms HLC, so it supersedes
//! an existing on-chain proof (the `sbo domain evidence` preset uses hlc=None,
//! which loses conflict resolution to any object that already carries an HLC).
//! Self-authorizing (key-rooted), so a fresh throwaway key signs it.
//!
//! Run: cargo run -p sbo-cli --example dnssec_hlc -- <domain> <out-file>

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use sbo_core::crypto::{ContentHash, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::wire;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let domain = args.next().expect("usage: dnssec_hlc <domain> <out>");
    let out = args.next().expect("usage: dnssec_hlc <domain> <out>");

    let resolver: SocketAddr = sbo_capture::DEFAULT_RESOLVER.parse()?;
    println!("Capturing DNSSEC proof for _browserid.{domain} via {resolver} ...");
    let proof = sbo_capture::capture_evidence(resolver, &domain)
        .await
        .map_err(|e| anyhow::anyhow!("capture failed: {e}"))?;
    println!("  ✓ proof: {} bytes", proof.len());

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let hlc = format!("{now_ms}.0");

    // A fresh throwaway key signs this self-authorizing (key-rooted) write.
    // (Historical note: this used to grind a low-sorting pubkey to win the
    // lexicographic-first-creator tiebreak on `/sys/dnssec/<domain>`. Under global
    // `(path, id)` uniqueness there is no creator tiebreak and no fork to work
    // around — the first valid writer owns the slot — so the grind is retired.)
    let key = SigningKey::generate();
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/dnssec/").unwrap(),
        id: Id::new(&domain).expect("valid id"),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: Some("application/octet-stream".to_string()),
        content_hash: Some(ContentHash::sha256(&proof)),
        payload: Some(proof.clone()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("dnssec.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: Some(hlc),
        prev: None,
        auth_cert: None,
        auth_evidence: None,
        auth_warrant: None,
    };
    msg.sign(&key);

    let wire = wire::serialize(&msg);
    std::fs::write(&out, &wire)?;
    println!("  ✓ wrote {} bytes to {out} (hlc {now_ms}.0)", wire.len());
    Ok(())
}
