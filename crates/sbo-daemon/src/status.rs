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
//! JWS. The signer key is fetched from the list origin's
//! `/.well-known/browserid` support document over TLS — the same key that
//! origin publishes for its certificates. This roots the check in WebPKI
//! rather than DNSSEC (the on-chain evidence covers issuers, not the broker
//! registry origin); the fetch of the list itself is TLS to the URI named
//! inside a signed credential, so the signature guards the cache/CDN path.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sbo_core::browserid_core::{PublicKey, StatusListToken, StatusRef};

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

struct CachedList {
    token: StatusListToken,
    fetched_at: Instant,
}

struct CachedKey {
    key: PublicKey,
    fetched_at: Instant,
}

pub struct StatusChecker {
    client: reqwest::Client,
    lists: RwLock<HashMap<String, CachedList>>,
    keys: RwLock<HashMap<String, CachedKey>>,
    /// uri → (failed_at, reason): the negative cache.
    failures: RwLock<HashMap<String, (Instant, String)>>,
}

impl Default for StatusChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            lists: RwLock::new(HashMap::new()),
            keys: RwLock::new(HashMap::new()),
            failures: RwLock::new(HashMap::new()),
        }
    }

    /// Check every ref fail-closed: `Err(reason)` if any is revoked OR cannot
    /// be checked (unreachable list, bad signature, stale token). `Ok(())`
    /// only when every ref is affirmatively unrevoked.
    pub async fn check_all(&self, refs: &[(&'static str, StatusRef)]) -> Result<(), String> {
        for (label, r) in refs {
            let token = self
                .list_for(&r.uri)
                .await
                .map_err(|e| format!("{label} status unavailable (fail-closed): {e}"))?;
            if token.is_revoked(r.idx) {
                return Err(format!("{label} revoked"));
            }
        }
        Ok(())
    }

    async fn list_for(&self, uri: &str) -> Result<StatusListToken, String> {
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
        match self.fetch_and_verify(uri).await {
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

    async fn fetch_and_verify(&self, uri: &str) -> Result<StatusListToken, String> {
        if !uri.starts_with("https://") {
            return Err(format!("status uri '{uri}' is not https"));
        }
        let body = self
            .client
            .get(uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("fetch {uri}: {e}"))?
            .text()
            .await
            .map_err(|e| format!("read {uri}: {e}"))?;
        let token =
            StatusListToken::parse(body.trim()).map_err(|e| format!("parse list at {uri}: {e}"))?;
        let key = self.origin_key(uri).await?;
        token
            .verify(&key, uri)
            .map_err(|e| format!("verify list at {uri}: {e}"))?;
        // Freshness, with a consumer-imposed ttl ceiling (audit M3): a served
        // token older than its advertised (capped) lifetime fails closed.
        if !token.is_fresh_capped(60, 600) {
            return Err(format!("list at {uri} is stale"));
        }
        Ok(token)
    }

    /// The list origin's published signing key, from its `/.well-known/browserid`
    /// support document (TLS-rooted).
    async fn origin_key(&self, list_uri: &str) -> Result<PublicKey, String> {
        let origin = origin_of(list_uri).ok_or_else(|| format!("bad status uri '{list_uri}'"))?;
        if let Some(c) = self.keys.read().unwrap().get(&origin) {
            if c.fetched_at.elapsed() < CACHE_TTL {
                return Ok(c.key.clone());
            }
        }
        #[derive(serde::Deserialize)]
        struct Doc {
            #[serde(rename = "public-key")]
            public_key: Option<PublicKey>,
        }
        let url = format!("{origin}/.well-known/browserid");
        let doc: Doc = self
            .client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("fetch {url}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("parse {url}: {e}"))?;
        let key = doc
            .public_key
            .ok_or_else(|| format!("{url} carries no public-key"))?;
        self.keys.write().unwrap().insert(
            origin,
            CachedKey { key: key.clone(), fetched_at: Instant::now() },
        );
        Ok(key)
    }
}

fn origin_of(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("https://")?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("https://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://browserid.me/.well-known/browserid-status").as_deref(),
            Some("https://browserid.me")
        );
        assert_eq!(origin_of("http://x/y"), None);
        assert_eq!(origin_of("https:///y"), None);
    }

    #[tokio::test]
    async fn unreachable_list_fails_closed() {
        let checker = StatusChecker::new();
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status".into(), idx: 1 },
        )];
        let err = checker.check_all(&refs).await.unwrap_err();
        assert!(err.contains("fail-closed"), "{err}");
    }

    #[tokio::test]
    async fn repeat_failure_is_served_from_the_negative_cache() {
        let checker = StatusChecker::new();
        let refs = vec![(
            "warrant",
            StatusRef { uri: "https://localhost:1/.well-known/browserid-status-neg".into(), idx: 1 },
        )];
        let first = checker.check_all(&refs).await.unwrap_err();
        assert!(!first.contains("cached failure"), "{first}");
        let second = checker.check_all(&refs).await.unwrap_err();
        assert!(second.contains("cached failure"), "{second}");
    }

    #[tokio::test]
    async fn no_refs_is_ok() {
        let checker = StatusChecker::new();
        assert!(checker.check_all(&[]).await.is_ok());
    }
}
