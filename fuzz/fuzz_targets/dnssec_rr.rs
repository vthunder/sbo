#![no_main]
//! WS3 (D51): untrusted RFC 9102 bytes reach `dnssec_prover::parse_rr_stream`
//! and `verify_rr_stream` from the chain (`/sys/dnssec/<domain>` payloads,
//! `Auth-Evidence`), from `/v1/dnssec`, and from the submit gate. The
//! extractor must be total; an `Ok` cannot come from arbitrary bytes (it
//! needs a chain to the IANA root), so any `Ok` here is a finding.

use libfuzzer_sys::fuzz_target;
use sbo_core::attribution::{extract_provider_key, verify_dnssec_proof_for_domain, verify_domain_self_cert};

fuzz_target!(|data: &[u8]| {
    let r = extract_provider_key(data, "example.com");
    assert!(r.is_err(), "arbitrary bytes validated as a DNSSEC chain to the root");
    let _ = verify_dnssec_proof_for_domain(data, "example.com");
    let _ = verify_domain_self_cert("ed25519:00", data, "example.com", 1_800_000_000);
});
