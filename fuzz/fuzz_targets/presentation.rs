#![no_main]
//! WS3: device-presentation attribution on mutated encodings of a valid
//! bundle. Oracle: whatever VERIFIES must be the fixture's identity on the
//! fixture's key for the fixture's audience, inside the DNSSEC window; the
//! parsers (`AccessPresentation::parse`, `presentation_status_refs`,
//! `effective_author`, `scopes_authorize`) are total.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sbo_core::attribution::TrustAnchors;
use sbo_core::authorize::{presentation_audience, presentation_issuer, scopes_authorize};
use sbo_core::browserid_core::device::AccessPresentation;
use sbo_core::device_attribution::{effective_author, presentation_status_refs, verify_device_attribution_with_provider_keys};
use sbo_fuzz::{fixture, AUD, EMAIL, IDP, NOW};

#[derive(Arbitrary, Debug)]
struct Input {
    /// Byte edits applied to the valid encoding: (position, new byte).
    edits: Vec<(u16, u8)>,
    /// Or an entirely arbitrary string.
    raw: Option<String>,
    at_off: i32,
    scopes: Vec<String>,
}

fuzz_target!(|input: Input| {
    let f = fixture();
    let text = match &input.raw {
        Some(r) => r.clone(),
        None => {
            let mut b = f.presentation.clone().into_bytes();
            for (pos, byte) in input.edits.iter().take(8) {
                let i = (*pos as usize) % b.len();
                b[i] = *byte;
            }
            String::from_utf8_lossy(&b).into_owned()
        }
    };
    let _ = (presentation_issuer(&text), presentation_audience(&text), presentation_status_refs(&text));
    let _ = effective_author(EMAIL, EMAIL, &input.scopes);
    let _ = scopes_authorize(&input.scopes, "post", "/u/x/", None);
    let Ok(pres) = AccessPresentation::parse(&text) else { return };
    let at = NOW + (input.at_off as i64);
    let proven = vec![(IDP.to_string(), f.idp.public_key(), NOW - 86_400, NOW + 86_400)];
    if let Ok(attr) = verify_device_attribution_with_provider_keys(&f.access_key_sbo, pres, &proven, AUD, at, None, &TrustAnchors::default()) {
        assert_eq!(attr.email, EMAIL);
        assert_eq!(attr.grantee, EMAIL);
        assert_eq!(attr.issuer, IDP);
        assert!(at >= NOW - 86_400 && at <= NOW + 86_400, "verified outside the DNSSEC window");
        assert!(attr.valid_from <= attr.valid_until);
        assert_eq!(attr.key, f.access.public_key().to_base64());
        // Any edit that still verifies must leave the canonical encoding intact
        // (base64url padding/alphabet aside, the signed bytes are unchanged).
        if input.raw.is_none() {
            let re = AccessPresentation::parse(&text).unwrap();
            assert_eq!(re.access_cert.claims().identity, EMAIL);
            assert_eq!(re.warrant.claims().audience, AUD);
        }
    }
});
