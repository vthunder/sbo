//! Security audit 2026-11 — GENERATOR for the post-regenesis genesis fixture
//! `tests/fixtures/mingo-genesis-v6.wire` (sbo-3q6x, decision Q33 (b)).
//!
//! The v5 fixture (`mingo-genesis-v5.wire`) is the pre-regenesis live genesis:
//! Mode B without a `dnssec.v1` opener, root policy last, no `Owner` headers.
//! Under the strict bootstrap window it is not a genesis, and it is kept only
//! for the tests that pin its historical hash. This generator rebuilds the
//! same object set with **test keys** in the new order:
//!
//! 1. `/sys/names/sys` (self-signed; the fixture is Mode A because a Mode B
//!    opener needs a DNSSEC chain for a real domain, which test keys cannot
//!    produce — see the core `genesis` unit tests for a synthetic Mode B);
//! 2. `/sys/policies/root` (the live root with an explicit `to: owner`
//!    update/transfer/delete grant, Q13 (a));
//! 3. everything else, each naming `Owner: sys` (Q6), validated by the root
//!    policy: `sys-checkpointer`, `/sys/trust/brokers`, and per community the
//!    descriptor, the `_config` and then the community policy (the `_config`
//!    must precede the policy: once the community policy governs the subtree
//!    it does not grant `govern` to sys, so a `_config` after it is refused).
//!
//! Run with
//!     cargo test -p sbo-core --test audit_2026_11_genesis_v6_generate -- --ignored

use sbo_core::crypto::{ContentHash, SigningKey};
use sbo_core::message::{Id, Message};
use sbo_core::wire;
use std::path::PathBuf;

const SYS_SEED: [u8; 32] = [0x51; 32];
const CHECKPOINTER_SEED: [u8; 32] = [0x52; 32];
const V5_SYS_HEX: &str = "564aafe4694de311c85f8faed52b2943336678018f9e1ddd2594c107c5ccf4bd";
const V5_CHECKPOINTER_HEX: &str = "937fc1e8073a1d3939bb59fa744e4fd2d7ff365c2cd573ca8a931b47e7949c00";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn hex_of(key: &SigningKey) -> String {
    key.public_key().to_string().trim_start_matches("ed25519:").to_string()
}

/// Re-sign `m` with `key`, naming `owner`, with `payload` (key literals rewritten).
fn resign(m: &Message, key: &SigningKey, owner: Option<&str>, payload: Vec<u8>) -> Message {
    let mut n = m.clone();
    n.signing_key = key.public_key();
    n.owner = owner.map(|o| Id::new(o).unwrap());
    n.content_hash = Some(ContentHash::sha256(&payload));
    n.payload = Some(payload);
    n.sign(key);
    n
}

#[test]
#[ignore]
fn write_mingo_genesis_v6_fixture() {
    let sys = SigningKey::from_bytes(&SYS_SEED);
    let checkpointer = SigningKey::from_bytes(&CHECKPOINTER_SEED);
    let rewrite = |bytes: &[u8]| -> Vec<u8> {
        String::from_utf8(bytes.to_vec())
            .unwrap()
            .replace(V5_SYS_HEX, &hex_of(&sys))
            .replace(V5_CHECKPOINTER_HEX, &hex_of(&checkpointer))
            .into_bytes()
    };

    let v5 = wire::parse_batch(&std::fs::read(fixtures().join("mingo-genesis-v5.wire")).unwrap()).unwrap();
    let find = |path: &str, id: &str| -> &Message {
        v5.iter().find(|m| m.path.to_string() == path && m.id.as_str() == id).unwrap_or_else(|| panic!("{path}{id}"))
    };

    let mut out: Vec<Message> = Vec::new();

    // 1. sys (Mode A, self-signed).
    let sys_jwt = sbo_core::jwt::create_self_signed_identity(&sys, "sys", None).unwrap();
    out.push(resign(find("/sys/names/", "sys"), &sys, None, sys_jwt.into_bytes()));

    // 2. root policy: the live one, keys rewritten, plus the explicit owner grant.
    let mut root: serde_json::Value = serde_json::from_slice(&rewrite(find("/sys/policies/", "root").payload.as_ref().unwrap())).unwrap();
    // The live `/sys/names/*` pattern requires three segments and so never
    // matches the `/sys/names/` container a name claim targets (the policy
    // evaluator matches the write's container path); the Genesis spec's
    // default root policy grants on `/sys/names/`. Rewrite it, or no name
    // claim after genesis is ever admitted (D56 evaluates policy for claims).
    for g in root["grants"].as_array_mut().unwrap() {
        if g["on"] == "/sys/names/*" {
            g["on"] = serde_json::Value::String("/sys/names/".into());
        }
    }
    root["grants"].as_array_mut().unwrap().push(serde_json::json!({
        "can": ["update", "transfer", "delete"], "on": "/**", "to": "owner"
    }));
    out.push(resign(find("/sys/policies/", "root"), &sys, None, serde_json::to_vec(&root).unwrap()));

    // 3. sys-checkpointer: a self-certifying key-rooted name claim.
    let cp_jwt = sbo_core::jwt::create_self_signed_identity(&checkpointer, "sys-checkpointer", None).unwrap();
    out.push(resign(find("/sys/names/", "sys-checkpointer"), &checkpointer, None, cp_jwt.into_bytes()));

    // 4. trust anchors, in the object form the Genesis spec requires.
    out.push(resign(find("/sys/trust/", "brokers"), &sys, Some("sys"), br#"{"brokers":["browserid.me"]}"#.to_vec()));

    // 5. communities: descriptor, _config, then the community policy.
    for c in ["cooks", "woodworking", "homelab"] {
        let base = format!("/communities/{c}/");
        for (path, id) in [(base.clone(), "community"), (format!("{base}spaces/general/"), "_config"), (base.clone(), "root")] {
            let m = find(&path, id);
            out.push(resign(m, &sys, Some("sys"), rewrite(m.payload.as_ref().unwrap())));
        }
    }

    assert_eq!(out.len(), 13); // v5 had 14: Mode A has no domain object
    let mut bytes = Vec::new();
    for m in &out {
        bytes.extend_from_slice(&wire::serialize(m));
    }
    let path = fixtures().join("mingo-genesis-v6.wire");
    std::fs::write(&path, &bytes).unwrap();
    eprintln!("wrote {} ({} bytes, {})", path.display(), bytes.len(), ContentHash::sha256(&bytes).to_string());
}
