//! Fail-closed revocation checks at the submission gate (browserid spec §6.3).
//!
//! Replay/consensus validation (`validate::validate_message`) is deterministic
//! against the block's inclusion time and MUST NOT consult live revocation
//! state — nodes replaying the same block at different wall-clock times must
//! agree on it. Revocation is therefore enforced where wall-clock enforcement
//! is sound: the submit gate refuses NEW writes whose presentation carries a
//! revoked — or uncheckable, fail-closed — status ref. A revoked grant stops
//! producing accepted writes at every checking gateway within one cache
//! window; writes already included keep their inclusion-time validity
//! (deterministic replay).
//!
//! List authenticity: each status list is a signed `browserid-status-list-v1`
//! JWS, verified against the authority's **DNSSEC-published key** — resolved
//! by the caller from the on-chain `/sys/dnssec/<authority>` evidence, the
//! same root the attribution verifier uses. Support documents deliberately
//! carry NO key (a TLS-served key is a downgrade vector; the `_browserid`
//! record is the sole root of trust), so there is nothing to fetch besides
//! the list itself. The token's `iss` must equal the chain object's own
//! authority (an access cert's list is signed by its issuing IdP), and the
//! signature + `sub == uri` bind the list to the URI the credential named.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sbo_core::browserid_core::{PublicKey, StatusListToken, StatusRef};

/// A DNSSEC-proven authority key with its RRSig validity window (UNIX
/// seconds), as [`sbo_core::attribution::extract_provider_key`] returns it.
pub type AuthorityKey = (PublicKey, i64, i64);

/// How long a fetched list or support-document key is served from cache.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// How long a FAILED fetch is remembered (mirrors the broker verifier's
/// negative cache, audit M4 follow-up): a blackholed status URI otherwise
/// stalls every submit for the client timeout. Short, so a recovering
/// authority is retried quickly; still fail-closed either way.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// Bound on cached entries — status URIs arrive inside attacker-authored
/// presentations at the submit gate.
const MAX_ENTRIES: usize = 1024;

/// Cap on a fetched status-list body (W5-4): a list is a small JWS.
const MAX_LIST_BYTES: usize = 64 * 1024;

/// The host of an `https://…` URI (port stripped).
fn uri_host(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("https://")?;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

/// Resolve the URI's host and require every address to be globally routable.
/// Refuses literal and resolved loopback / private / link-local / ULA /
/// unspecified / multicast / CGNAT addresses before any connection is made.
/// Residual: this lookup and the client's own are distinct (a rebinding
/// window); the no-redirect client and the host == authority binding bound it.
pub async fn validate_status_host(uri: &str) -> Result<(), String> {
    let host = uri_host(uri).ok_or_else(|| format!("status uri '{uri}' has no host"))?;
    let rest = uri.strip_prefix("https://").unwrap_or(uri);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let port: u16 = hostport
        .rsplit_once(':')
        .filter(|(h, _)| !h.contains(':') || h.ends_with(']'))
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve status host '{host}': {e}"))?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if !is_global_ip(addr.ip()) {
            return Err(format!(
                "status host '{host}' resolves to non-global address {}",
                addr.ip()
            ));
        }
    }
    if !any {
        return Err(format!("status host '{host}' did not resolve"));
    }
    Ok(())
}

/// Whether an IP is safe to fetch from: not loopback, private, link-local,
/// unique-local, unspecified, multicast, broadcast, documentation or CGNAT.
/// `std`'s `is_global` is unstable, so the non-global ranges are enumerated.
pub fn is_global_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40))
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_global_ip(std::net::IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local
                || (seg0 & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (seg0 & 0xffc0) == 0xfe80)
        }
    }
}

/// Read a response body, refusing one that exceeds `cap` bytes (chunked
/// bodies included — the cap is enforced on the stream, not Content-Length).
pub async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > cap {
            return Err(format!("body of {len} bytes exceeds the {cap}-byte cap"));
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > cap {
            return Err(format!("body exceeds the {cap}-byte cap"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

struct CachedList {
    token: StatusListToken,
    fetched_at: Instant,
}

pub struct StatusChecker {
    client: reqwest::Client,
    lists: RwLock<HashMap<String, CachedList>>,
    /// uri → (failed_at, reason): the negative cache.
    failures: RwLock<HashMap<String, (Instant, String)>>,
    /// authority → live-captured key (+ RRSig window), cached briefly. The
    /// submit gate is a WALL-CLOCK check, not consensus: when the chain's
    /// /sys/dnssec copy is absent or its window has lapsed, the daemon
    /// captures a fresh RFC 9102 proof itself rather than failing closed on
    /// client refresh hygiene. Verification is unchanged — offline against
    /// the pinned IANA root — only the proof's transport differs.
    live_keys: RwLock<HashMap<String, (AuthorityKey, Instant)>>,
}

impl Default for StatusChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusChecker {
    pub fn new() -> Self {
        Self {
            // No redirects (W5-4): a status URI must answer where it points;
            // a bounce would defeat the host == authority and address checks.
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
            lists: RwLock::new(HashMap::new()),
            failures: RwLock::new(HashMap::new()),
            live_keys: RwLock::new(HashMap::new()),
        }
    }

    /// The usable key for `authority`: the on-chain evidence's when its
    /// window covers now, else a freshly captured live proof (cached). `None`
    /// ⇒ the caller's check fails closed.
    pub async fn authority_key(
        &self,
        authority: &str,
        on_chain: Option<AuthorityKey>,
    ) -> Option<AuthorityKey> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Some((_, inception, expiration)) = &on_chain {
            if now >= *inception && now <= *expiration {
                return on_chain;
            }
        }
        {
            let cached = self.live_keys.read().unwrap();
            if let Some((key, at)) = cached.get(authority) {
                if at.elapsed() < CACHE_TTL {
                    return Some(key.clone());
                }
            }
        }
        let resolver: std::net::SocketAddr = sbo_capture::DEFAULT_RESOLVER.parse().ok()?;
        let proof = sbo_capture::capture_evidence(resolver, authority).await.ok()?;
        let key = sbo_core::attribution::extract_provider_key(&proof, authority).ok()?;
        if now < key.1 || now > key.2 {
            return None;
        }
        let mut cached = self.live_keys.write().unwrap();
        if cached.len() >= MAX_ENTRIES && !cached.contains_key(authority) {
            cached.retain(|_, (_, at)| at.elapsed() < CACHE_TTL);
        }
        if cached.len() < MAX_ENTRIES || cached.contains_key(authority) {
            cached.insert(authority.to_string(), (key.clone(), Instant::now()));
        }
        Some(key)
    }

    /// Check every ref fail-closed: `Err(reason)` if any is revoked OR cannot
    /// be checked (unreachable list, unresolvable authority, bad signature,
    /// stale token). `Ok(())` only when every ref is affirmatively unrevoked.
    /// `keys` maps authority domains to their DNSSEC-proven keys (+ RRSig
    /// windows) — resolved by the caller from on-chain evidence; a ref whose
    /// authority is absent fails closed.
    pub async fn check_all(
        &self,
        refs: &[(&'static str, StatusRef, String)],
        keys: &HashMap<String, AuthorityKey>,
    ) -> Result<(), String> {
        for (label, r, authority) in refs {
            let token = self
                .list_for(label, &r.uri, authority, keys)
                .await
                .map_err(|e| format!("{label} status unavailable (fail-closed): {e}"))?;
            if token.is_revoked(r.idx) {
                return Err(format!("{label} revoked"));
            }
        }
        Ok(())
    }

    async fn list_for(
        &self,
        label: &str,
        uri: &str,
        authority: &str,
        keys: &HashMap<String, AuthorityKey>,
    ) -> Result<StatusListToken, String> {
        if let Some(c) = self.lists.read().unwrap().get(uri) {
            if c.fetched_at.elapsed() < CACHE_TTL {
                return Ok(c.token.clone());
            }
        }
        // Recently failed → refuse instantly instead of re-stalling on the
        // network (still fail-closed).
        if let Some((at, reason)) = self.failures.read().unwrap().get(uri) {
            if at.elapsed() < NEGATIVE_TTL {
                return Err(format!("{reason} (cached failure)"));
            }
        }
        match self.fetch_and_verify(label, uri, authority, keys).await {
            Ok(token) => {
                self.failures.write().unwrap().remove(uri);
                let mut lists = self.lists.write().unwrap();
                if lists.len() >= MAX_ENTRIES && !lists.contains_key(uri) {
                    lists.retain(|_, c| c.fetched_at.elapsed() < CACHE_TTL);
                }
                if lists.len() < MAX_ENTRIES || lists.contains_key(uri) {
                    lists.insert(
                        uri.to_string(),
                        CachedList { token: token.clone(), fetched_at: Instant::now() },
                    );
                }
                Ok(token)
            }
            Err(e) => {
                let mut neg = self.failures.write().unwrap();
                if neg.len() >= MAX_ENTRIES && !neg.contains_key(uri) {
                    neg.retain(|_, (at, _)| at.elapsed() < NEGATIVE_TTL);
                }
                if neg.len() < MAX_ENTRIES || neg.contains_key(uri) {
                    neg.insert(uri.to_string(), (Instant::now(), e.clone()));
                }
                Err(e)
            }
        }
    }

    async fn fetch_and_verify(
        &self,
        label: &str,
        uri: &str,
        authority: &str,
        keys: &HashMap<String, AuthorityKey>,
    ) -> Result<StatusListToken, String> {
        if !uri.starts_with("https://") {
            return Err(format!("status uri '{uri}' is not https"));
        }
        let (key, inception, expiration) = keys
            .get(authority)
            .ok_or_else(|| format!("no on-chain DNSSEC evidence for status authority '{authority}'"))?;
        // The DNSSEC proof must be live NOW — this is a wall-clock gate, not
        // replay validation. Stale evidence is refreshed by clients posting a
        // fresh /sys/dnssec/<authority> proof (mingo does before each write).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if now < *inception || now > *expiration {
            return Err(format!("DNSSEC evidence for '{authority}' is outside its validity window"));
        }
        // W5-4 / D52: the status URI is attacker-authored (it rides in the
        // presentation). Before any connection: the host must BE the
        // credential's authority for the IdP-issued certs (a warrant's list
        // host is signer-chosen and already IS the authority by construction,
        // see `presentation_status_refs`), and it must resolve only to
        // globally routable addresses — never loopback, private, link-local
        // or metadata ranges (browserid-ng H1 class).
        let host = uri_host(uri).ok_or_else(|| format!("status uri '{uri}' has no host"))?;
        if label != "warrant" && !host.eq_ignore_ascii_case(authority) {
            return Err(format!(
                "{label} status uri host '{host}' is not the credential's authority '{authority}'"
            ));
        }
        validate_status_host(uri).await?;
        let resp = self
            .client
            .get(uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("fetch {uri}: {e}"))?;
        let body = read_capped(resp, MAX_LIST_BYTES)
            .await
            .map_err(|e| format!("read {uri}: {e}"))?;
        let body = String::from_utf8_lossy(&body);
        let token =
            StatusListToken::parse(body.trim()).map_err(|e| format!("parse list at {uri}: {e}"))?;
        // The list's declared issuer must BE the chain object's own authority
        // (an access cert's list is signed by its issuing IdP) — then the
        // signature under the DNSSEC-proven key + `sub == uri` bind the list
        // to the URI the credential named.
        if token.claims().iss != authority {
            return Err(format!(
                "list at {uri} is signed by '{}', not the credential's authority '{authority}'",
                token.claims().iss
            ));
        }
        token
            .verify(key, uri)
            .map_err(|e| format!("verify list at {uri}: {e}"))?;
        // Freshness, with a consumer-imposed ttl ceiling (audit M3): a served
        // token older than its advertised (capped) lifetime fails closed.
        if !token.is_fresh_capped(60, 600) {
            return Err(format!("list at {uri} is stale"));
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(authority: &str) -> HashMap<String, AuthorityKey> {
        let kp = sbo_core::browserid_core::KeyPair::generate();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        HashMap::from([(authority.to_string(), (kp.public_key(), now - 3600, now + 3600))])
    }

    #[tokio::test]
    async fn unresolvable_authority_fails_closed_before_any_fetch() {
        let checker = StatusChecker::new();
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status-noauth".into(), idx: 1 },
            "browserid.me".to_string(),
        )];
        let err = checker.check_all(&refs, &HashMap::new()).await.unwrap_err();
        assert!(err.contains("no on-chain DNSSEC evidence"), "{err}");
    }

    #[tokio::test]
    async fn expired_evidence_fails_closed() {
        let checker = StatusChecker::new();
        let kp = sbo_core::browserid_core::KeyPair::generate();
        let keys = HashMap::from([(
            "browserid.me".to_string(),
            (kp.public_key(), 0i64, 1i64), // window long past
        )]);
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status-expired".into(), idx: 1 },
            "browserid.me".to_string(),
        )];
        let err = checker.check_all(&refs, &keys).await.unwrap_err();
        assert!(err.contains("outside its validity window"), "{err}");
    }

    #[tokio::test]
    async fn unreachable_list_fails_closed() {
        let checker = StatusChecker::new();
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status".into(), idx: 1 },
            "browserid.me".to_string(),
        )];
        let err = checker.check_all(&refs, &key_for("browserid.me")).await.unwrap_err();
        assert!(err.contains("fail-closed"), "{err}");
    }

    #[tokio::test]
    async fn repeat_failure_is_served_from_the_negative_cache() {
        let checker = StatusChecker::new();
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status-neg".into(), idx: 1 },
            "browserid.me".to_string(),
        )];
        let keys = key_for("browserid.me");
        let first = checker.check_all(&refs, &keys).await.unwrap_err();
        assert!(!first.contains("cached failure"), "{first}");
        let second = checker.check_all(&refs, &keys).await.unwrap_err();
        assert!(second.contains("cached failure"), "{second}");
    }

    #[tokio::test]
    async fn no_refs_is_ok() {
        let checker = StatusChecker::new();
        assert!(checker.check_all(&[], &HashMap::new()).await.is_ok());
    }

    #[test]
    fn uri_host_strips_port_and_path() {
        assert_eq!(uri_host("https://idp.test/list"), Some("idp.test"));
        assert_eq!(uri_host("https://idp.test:8443/list?x=1"), Some("idp.test"));
        assert_eq!(uri_host("https://[::1]:8443/list"), Some("::1"));
        assert_eq!(uri_host("http://idp.test/list"), None);
    }

    #[test]
    fn non_global_addresses_are_rejected() {
        use std::net::IpAddr;
        for bad in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(!is_global_ip(bad.parse::<IpAddr>().unwrap()), "{bad}");
        }
        for good in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(is_global_ip(good.parse::<IpAddr>().unwrap()), "{good}");
        }
    }

    #[tokio::test]
    async fn literal_loopback_status_host_is_refused_before_dialling() {
        let err = validate_status_host("https://127.0.0.1:1/list").await.unwrap_err();
        assert!(err.contains("non-global"), "{err}");
        let err = validate_status_host("https://[::1]:1/list").await.unwrap_err();
        assert!(err.contains("non-global"), "{err}");
    }
}
