//! Live (network) capture of a real `_browserid.<domain>` DNSSEC chain into a
//! fixture file, for the offline DNSSEC tests in `sbo-core` (audit 2026-11
//! W6-5, `sbo-ospt`). Read-only DNS queries against the default resolver.
//!
//! Regenerate the mingo.place fixture (the RRSIG windows are ~2 weeks; the
//! offline test pins an inclusion time inside the captured window, so the file
//! stays valid forever — regenerate only to pick up a key rollover):
//!
//! ```text
//! SBO_CAPTURE_DOMAIN=mingo.place \
//! SBO_CAPTURE_OUT=crates/sbo-core/tests/fixtures/mingo-place-browserid.rfc9102 \
//!   cargo test -p sbo-capture --test capture_fixture -- --ignored
//! ```

#[tokio::test]
#[ignore] // live DNS; run by hand to (re)generate a fixture
async fn capture_browserid_chain_to_file() {
    let domain = std::env::var("SBO_CAPTURE_DOMAIN").expect("SBO_CAPTURE_DOMAIN");
    let out = std::env::var("SBO_CAPTURE_OUT").expect("SBO_CAPTURE_OUT");
    let resolver: std::net::SocketAddr = std::env::var("SBO_CAPTURE_RESOLVER")
        .unwrap_or_else(|_| sbo_capture::DEFAULT_RESOLVER.to_string())
        .parse()
        .unwrap();
    let proof = sbo_capture::capture_evidence(resolver, &domain).await.expect("capture");
    // Sanity: it validates against the IANA root right now.
    let (inception, expiration) = sbo_core::attribution::verify_dnssec_proof_for_domain(&proof, &domain).expect("validates");
    std::fs::write(&out, &proof).expect("write fixture");
    eprintln!("wrote {} bytes to {out}; RRSIG window [{inception}, {expiration}]", proof.len());
}
