//! Offline DNSSEC fixtures: a synthetic RFC 9102 chain builder for tests
//! (audit 2026-11 W6-5, bean `sbo-ospt`). Feature `dnssec-fixtures`.
//!
//! `dnssec-prover` validates RSA (8/10) and ECDSA P-256/P-384 (13/14) but has
//! no Ed25519 (alg 15, W6-2), so every synthetic zone here is signed with
//! **ECDSA P-256 / SHA-256 (alg 13)** via `ring`. The builder produces exactly
//! the record stream the verifier walks: for the root and every zone cut down
//! to `<domain>.`, a DNSKEY RRset + its RRSIG, a DS in the parent + its RRSIG,
//! and finally the `_browserid.<domain>.` TXT + its RRSIG. The root zone's
//! DNSKEY is what a test pins as the `/sys/trust/dns-root` anchor
//! ([`SyntheticRoot::root_ksk`] / [`SyntheticRoot::dns_root_v1`]).
//!
//! Byte-exact signing input mirrors `dnssec_prover::validation::verify_rrsig`:
//! the RRSIG RDATA prefix (through the signer name) followed by each covered
//! record in canonical wire form at `orig_ttl`, which is precisely what
//! `dnssec_prover::ser::write_rr` emits.
//!
//! This is **test-only** material: keys are random per process and the chain
//! is only ever meaningful against the matching synthetic root anchor.

use base64::Engine as _;
use dnssec_prover::rr::{DnsKey, Name, RRSig, Record, Txt, TxtBytes, DS, RR};
use dnssec_prover::ser::write_rr;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use sha2::Digest as _;

use crate::attribution::RootKsk;

/// DNSSEC algorithm number for ECDSA P-256 / SHA-256.
pub const ALG_ECDSA_P256: u8 = 13;
const KSK_FLAGS: u16 = 257;
const PROTOCOL: u8 = 3;
const TTL: u32 = 3600;

/// One synthetic zone signing key (KSK+ZSK in one, flags 257).
pub struct ZoneKey {
    name: Name,
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    /// Raw X||Y (64 bytes): the DNSKEY public-key field for alg 13.
    pubkey: Vec<u8>,
}

impl ZoneKey {
    /// A fresh random P-256 key for zone `name` (FQDN with trailing dot, `.` for root).
    pub fn generate(name: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("keygen");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).expect("pkcs8");
        // ring hands back the uncompressed SEC1 point 0x04 || X || Y.
        let pubkey = pair.public_key().as_ref()[1..].to_vec();
        Self { name: name.try_into().expect("zone name"), pair, rng, pubkey }
    }

    /// The zone's DNSKEY record.
    pub fn dnskey(&self) -> DnsKey {
        DnsKey { name: self.name.clone(), flags: KSK_FLAGS, protocol: PROTOCOL, alg: ALG_ECDSA_P256, pubkey: self.pubkey.clone() }
    }

    /// The DS (SHA-256) a parent zone publishes for this key.
    pub fn ds(&self) -> DS {
        let k = self.dnskey();
        let mut ctx = sha2::Sha256::new();
        ctx.update(name_wire(&self.name));
        ctx.update(k.flags.to_be_bytes());
        ctx.update([k.protocol, k.alg]);
        ctx.update(&k.pubkey);
        DS { name: self.name.clone(), key_tag: k.key_tag(), alg: ALG_ECDSA_P256, digest_type: 2, digest: ctx.finalize().to_vec() }
    }

    /// Sign `records` (all of one `(name, type)` RRset) with this key.
    fn sign(&self, records: &[RR], inception: u32, expiration: u32) -> RRSig {
        let first = &records[0];
        let name = RR::name(first).clone();
        let ty = Record::ty(first);
        let key_tag = self.dnskey().key_tag();
        let mut data = Vec::new();
        data.extend_from_slice(&ty.to_be_bytes());
        data.push(ALG_ECDSA_P256);
        data.push(name.labels());
        data.extend_from_slice(&TTL.to_be_bytes());
        data.extend_from_slice(&expiration.to_be_bytes());
        data.extend_from_slice(&inception.to_be_bytes());
        data.extend_from_slice(&key_tag.to_be_bytes());
        data.extend_from_slice(&name_wire(&self.name));
        let mut sorted: Vec<&RR> = records.iter().collect();
        sorted.sort_unstable();
        for rr in sorted {
            write_rr(rr, TTL, &mut data);
        }
        let signature = self.pair.sign(&self.rng, &data).expect("sign").as_ref().to_vec();
        RRSig {
            name,
            ty,
            alg: ALG_ECDSA_P256,
            labels: RR::name(first).labels(),
            orig_ttl: TTL,
            expiration,
            inception,
            key_tag,
            key_name: self.name.clone(),
            signature,
        }
    }
}

/// The root of a synthetic hierarchy: the key a test pins as its DNS root KSK.
pub struct SyntheticRoot {
    pub key: ZoneKey,
}

impl SyntheticRoot {
    pub fn generate() -> Self {
        Self { key: ZoneKey::generate(".") }
    }

    /// The root DS anchor (what `dnssec-prover` matches the root DNSKEY against).
    pub fn ds(&self) -> DS {
        self.key.ds()
    }

    /// This root as a `/sys/trust/dns-root` history entry with the given window.
    pub fn root_ksk(&self, valid_from: i64, valid_until: Option<i64>) -> RootKsk {
        let k = self.key.dnskey();
        RootKsk {
            key_tag: k.key_tag(),
            algorithm: ALG_ECDSA_P256,
            public_key: base64::engine::general_purpose::STANDARD.encode(&k.pubkey),
            valid_from,
            valid_until,
        }
    }

    /// A complete `dns-root.v1` payload pinning only this root.
    pub fn dns_root_v1(&self, valid_from: i64, valid_until: Option<i64>) -> Vec<u8> {
        dns_root_v1(&[self.root_ksk(valid_from, valid_until)])
    }

    /// Build the full chain proving `_browserid.<domain>` = `txt` under this
    /// root, every RRSIG valid over `[inception, expiration]`. Intermediate
    /// zones (one per label suffix of `domain`) get fresh random keys.
    pub fn browserid_chain(&self, domain: &str, txt: &str, inception: i64, expiration: i64) -> Vec<u8> {
        ChainSpec::new(domain, txt).window(inception, expiration).build(self)
    }
}

/// Serialize a `dns-root.v1` payload for a key history.
pub fn dns_root_v1(keys: &[RootKsk]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "keys": keys })).expect("json")
}

/// Fine-grained chain construction: lets a test re-sign the leaf zone with a
/// different key set or window (rotation / rollback scenarios, audit D33).
pub struct ChainSpec {
    domain: String,
    txt: String,
    inception: u32,
    expiration: u32,
    /// Explicit leaf-zone key (defaults to a fresh one).
    leaf_key: Option<ZoneKey>,
    /// Window for the leaf DNSKEY RRSIG only (defaults to the chain window).
    leaf_dnskey_window: Option<(u32, u32)>,
}

impl ChainSpec {
    pub fn new(domain: &str, txt: &str) -> Self {
        Self {
            domain: domain.trim_end_matches('.').to_string(),
            txt: txt.to_string(),
            inception: 0,
            expiration: u32::MAX,
            leaf_key: None,
            leaf_dnskey_window: None,
        }
    }

    pub fn window(mut self, inception: i64, expiration: i64) -> Self {
        self.inception = inception as u32;
        self.expiration = expiration as u32;
        self
    }

    pub fn leaf_key(mut self, key: ZoneKey) -> Self {
        self.leaf_key = Some(key);
        self
    }

    /// Sign the leaf zone's DNSKEY RRset over its own window (e.g. an older
    /// inception to model a pre-rotation key set).
    pub fn leaf_dnskey_window(mut self, inception: i64, expiration: i64) -> Self {
        self.leaf_dnskey_window = Some((inception as u32, expiration as u32));
        self
    }

    /// Build the RFC 9102 `AuthenticationChain` bytes rooted at `root`.
    pub fn build(self, root: &SyntheticRoot) -> Vec<u8> {
        let labels: Vec<&str> = self.domain.split('.').collect();
        // Zones from the TLD down to the leaf: "place.", "mingo.place.", …
        let mut zone_names: Vec<String> = Vec::new();
        for i in (0..labels.len()).rev() {
            zone_names.push(format!("{}.", labels[i..].join(".")));
        }
        let leaf_name = zone_names.last().cloned().expect("domain has a label");

        let mut keys: Vec<ZoneKey> = Vec::new();
        for z in &zone_names {
            if *z == leaf_name {
                keys.push(self.leaf_key.unwrap_or_else(|| ZoneKey::generate(z)));
                break;
            }
            keys.push(ZoneKey::generate(z));
        }

        let (inc, exp) = (self.inception, self.expiration);
        let mut out: Vec<RR> = Vec::new();

        // Root apex: DNSKEY + self-signature.
        let root_set = vec![RR::DnsKey(root.key.dnskey())];
        let root_sig = root.key.sign(&root_set, inc, exp);
        out.extend(root_set);
        out.push(RR::RRSig(root_sig));

        let mut parent: &ZoneKey = &root.key;
        for (i, key) in keys.iter().enumerate() {
            // Delegation in the parent: DS + RRSIG by the parent key.
            let ds_set = vec![RR::DS(key.ds())];
            let ds_sig = parent.sign(&ds_set, inc, exp);
            out.extend(ds_set);
            out.push(RR::RRSig(ds_sig));
            // Apex: DNSKEY + self-signature (the leaf may use its own window).
            let set = vec![RR::DnsKey(key.dnskey())];
            let (ki, ke) = match (i + 1 == keys.len(), self.leaf_dnskey_window) {
                (true, Some(w)) => w,
                _ => (inc, exp),
            };
            let sig = key.sign(&set, ki, ke);
            out.extend(set);
            out.push(RR::RRSig(sig));
            parent = key;
        }

        // Leaf: the provider TXT record, signed by the leaf zone key.
        let txt_name: Name = format!("_browserid.{leaf_name}").try_into().expect("txt name");
        let txt_set = vec![RR::Txt(Txt { name: txt_name, data: TxtBytes::new(self.txt.as_bytes()).expect("txt") })];
        let txt_sig = parent.sign(&txt_set, inc, exp);
        out.extend(txt_set);
        out.push(RR::RRSig(txt_sig));

        let mut bytes = Vec::new();
        for rr in &out {
            write_rr(rr, TTL, &mut bytes);
        }
        bytes
    }
}

/// Canonical (lowercase) wire form of a name, `.` → `[0]`.
fn name_wire(name: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    let s = name.as_str().to_ascii_lowercase();
    if s == "." {
        out.push(0);
    } else {
        for label in s.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out
}

/// The `_browserid` TXT record content for a browserid provider key, as
/// `browserid_core::DnsRecord::parse` reads it.
pub fn browserid_txt(provider: &browserid_core::PublicKey) -> String {
    format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}", provider.to_base64())
}

/// [`browserid_txt`] for a provider key held as an SBO Ed25519 public key (so a
/// test can make the domain key and the DNS-published provider key the same).
pub fn browserid_txt_for_sbo_key(provider: &crate::crypto::PublicKey) -> String {
    let pk = browserid_core::PublicKey::from_bytes(&provider.bytes).expect("ed25519 public key");
    browserid_txt(&pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{dnssec_proof_freshness, extract_provider_key_with_anchors, TrustAnchors};

    #[test]
    fn synthetic_chain_validates_against_its_own_root_only() {
        let root = SyntheticRoot::generate();
        let provider = browserid_core::KeyPair::generate();
        let txt = browserid_txt(&provider.public_key());
        let chain = root.browserid_chain("example.test", &txt, 1_700_000_000, 1_700_100_000);

        let pinned = TrustAnchors::default().with_dns_root(vec![root.root_ksk(0, None)]);
        let (key, inc, exp) = extract_provider_key_with_anchors(&chain, "example.test", &pinned, Some(1_700_050_000)).unwrap();
        assert_eq!(key.as_bytes(), provider.public_key().as_bytes());
        assert_eq!((inc, exp), (1_700_000_000, 1_700_100_000));

        // The library's IANA root does not know this chain.
        assert!(extract_provider_key_with_anchors(&chain, "example.test", &TrustAnchors::default(), Some(1_700_050_000)).is_err());
        // A different synthetic root does not either.
        let other = SyntheticRoot::generate().root_ksk(0, None);
        let wrong = TrustAnchors::default().with_dns_root(vec![other]);
        assert!(extract_provider_key_with_anchors(&chain, "example.test", &wrong, Some(1_700_050_000)).is_err());
        // And the binding is to this domain only.
        assert!(extract_provider_key_with_anchors(&chain, "other.test", &pinned, Some(1_700_050_000)).is_err());

        let f = dnssec_proof_freshness(&chain, "example.test", &pinned, Some(1_700_050_000)).unwrap();
        assert_eq!(f.expiration, 1_700_100_000);
        assert_eq!(f.dnskey_inception, 1_700_000_000);
        assert_eq!(f.key_tags.len(), 1);
    }

    #[test]
    fn dns_root_v1_round_trips_and_anchors() {
        let root = SyntheticRoot::generate();
        let payload = root.dns_root_v1(10, Some(20));
        let keys = TrustAnchors::parse_dns_root(&payload).unwrap();
        assert_eq!(keys, vec![root.root_ksk(10, Some(20))]);
        assert_eq!(keys[0].to_ds().unwrap(), root.ds());
        let anchors = TrustAnchors::default().with_dns_root(keys);
        assert_eq!(anchors.root_anchors_at(Some(15)).len(), 1);
        assert!(anchors.root_anchors_at(Some(25)).is_empty(), "outside the window: no anchor");
        assert!(anchors.root_anchors_at(None).is_empty(), "not current (valid_until set) and time unknown");
    }
}
