#![no_main]
//! WS3: the identity / domain JWT verifiers are total on arbitrary text and
//! on mutated valid tokens; a token that verifies as self-signed carries the
//! key that signed it, and a domain-certified token verifies only under the
//! domain key.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sbo_core::crypto::PublicKey;
use sbo_core::jwt;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Option<String>,
    edits: Vec<(u16, u8)>,
    which: bool,
}

fuzz_target!(|input: Input| {
    let k1 = sbo_fuzz::key(1);
    let k2 = sbo_fuzz::key(2);
    let valid = if input.which {
        jwt::create_self_signed_identity(&k1, "alice", Some("/alice/profile")).unwrap()
    } else {
        jwt::create_domain(&k2, "example.com").unwrap()
    };
    let text = match &input.raw {
        Some(r) => r.clone(),
        None => {
            let mut b = valid.clone().into_bytes();
            for (pos, byte) in input.edits.iter().take(6) {
                let i = (*pos as usize) % b.len();
                b[i] = *byte;
            }
            String::from_utf8_lossy(&b).into_owned()
        }
    };
    let _ = jwt::decode_identity_claims(&text);
    let _ = jwt::decode_domain_claims(&text);
    let _ = jwt::Issuer::parse(&text);
    if let Ok(c) = jwt::verify_self_signed_identity(&text) {
        assert_eq!(c.iss, "self");
        let pk = PublicKey::parse(&c.public_key).expect("verified token has a parseable key");
        // A domain JWT (iss "self", signed by k2) also decodes as IdentityClaims.
        let signer = if input.which { k1.public_key() } else { k2.public_key() };
        assert_eq!(pk, signer, "self-signed token verified under a key other than the signer");
    }
    if let Ok(d) = jwt::verify_domain(&text) {
        assert_eq!(d.iss, "self");
        // IdentityClaims and DomainClaims are mutually decodable (no kind
        // claim), so a self-signed identity token also verifies as a domain.
        let signer = if input.which { k1.public_key() } else { k2.public_key() };
        assert_eq!(PublicKey::parse(&d.public_key).unwrap(), signer);
    }
    if let Ok(c) = jwt::verify_domain_certified_identity(&text, &k2.public_key()) {
        assert!(c.iss.starts_with("domain:"));
    }
    // Neither fixture is a domain-certified identity signed by k1.
    assert!(jwt::verify_domain_certified_identity(&text, &k1.public_key()).is_err());
});
