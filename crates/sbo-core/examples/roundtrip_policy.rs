// Diagnose: does a Policy round-trip (parse → serialize → parse) preserve the
// dnssec restriction + dnssec_proof? Mirrors daemon put_policy/resolve_policy.
use sbo_core::policy::Policy;

fn main() {
    let json = std::fs::read(std::env::var("POLICY_FILE").unwrap()).unwrap();
    let p: Policy = serde_json::from_slice(&json).expect("parse json");
    eprintln!("parsed: grants={} restrictions={}", p.grants.len(), p.restrictions.len());
    for (i, r) in p.restrictions.iter().enumerate() {
        eprintln!("  restriction[{i}] on={:?} dnssec_proof={} schema={:?} ct={:?}",
            r.on, r.require.dnssec_proof, r.require.schema, r.require.content_type);
    }
    // Round-trip exactly like the daemon: to_vec (put_policy) → from_slice (resolve_policy)
    let stored = serde_json::to_vec(&p).expect("serialize");
    eprintln!("--- after to_vec/from_slice round-trip ---");
    eprintln!("stored json: {}", String::from_utf8_lossy(&stored));
    let p2: Policy = serde_json::from_slice(&stored).expect("reparse");
    for (i, r) in p2.restrictions.iter().enumerate() {
        eprintln!("  restriction[{i}] on={:?} dnssec_proof={}", r.on, r.require.dnssec_proof);
    }
}
