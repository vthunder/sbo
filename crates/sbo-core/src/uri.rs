//! Canonical SBO URI types — the single source of truth for parsing and emitting
//! `sbo+raw://` references.
//!
//! Grammar (see `specs/SBO URI Specification.md`):
//!
//! ```text
//! sbo+raw://chain:appId[@firstBlock]/[path/][creator:][id][?query]
//! ```
//!
//! - The authority is **exactly** `chain:appId` (CAIP-2 `namespace:reference` + appId).
//!   It never grows, so an opaque `appId` stays unambiguous.
//! - `@firstBlock` is the genesis **anchor** — a database-level locator inherited by
//!   every composed path. It is *not* a snapshot selector (for that, use `?as_of=`).
//! - Query selectors: `genesis` (identity hash), `as_of` (historical snapshot block),
//!   plus `content_hash`/`content_type`/`content_schema`/`encoding`/`size`.

use std::collections::BTreeMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Known chain aliases mapping friendly names to CAIP-2 identifiers.
/// Format: (alias_namespace, alias_reference, caip2_namespace, caip2_reference)
const CHAIN_ALIASES: &[(&str, &str, &str, &str)] = &[
    ("avail", "turing", "polkadot", "d3d2f3a3495dc597434a99d7d449ebad"),
    ("avail", "mainnet", "polkadot", "b91746b45e0346cc2f815a520b9c6cb4"),
];

/// Errors from parsing or validating an SBO URI.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum UriError {
    #[error("not an sbo+raw:// URI: {0}")]
    NotRawUri(String),
    #[error("sbo:// URI requires DNS resolution first: {0}")]
    NeedsDnsResolution(String),
    #[error("invalid authority (expected 'namespace:reference:appId'): {0}")]
    MalformedAuthority(String),
    #[error("invalid appId: {0}")]
    InvalidAppId(String),
    #[error("invalid @firstBlock anchor: {0}")]
    InvalidAnchor(String),
    #[error("malformed query component: {0}")]
    MalformedQuery(String),
    #[error("expected a bare repository URI (no path/creator/id/query): {0}")]
    NotBare(String),
}

type Result<T> = std::result::Result<T, UriError>;

/// A CAIP-2 chain identifier (`namespace:reference`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChainId {
    /// Namespace (e.g., "polkadot", "eip155", "avail").
    pub namespace: String,
    /// Reference (e.g., genesis-hash prefix, chain id, "turing").
    pub reference: String,
}

impl ChainId {
    /// Parse a CAIP-2 chain identifier like `polkadot:abc123` or `avail:turing`.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(UriError::MalformedAuthority(format!(
                "invalid CAIP-2 chain identifier '{s}': expected 'namespace:reference'"
            )));
        }
        Ok(Self {
            namespace: parts[0].to_lowercase(),
            reference: parts[1].to_lowercase(),
        })
    }

    /// Resolve a friendly alias to its canonical CAIP-2 identifier.
    pub fn resolve(&self) -> Self {
        for (a_ns, a_ref, c_ns, c_ref) in CHAIN_ALIASES {
            if self.namespace == *a_ns && self.reference == *a_ref {
                return Self { namespace: c_ns.to_string(), reference: c_ref.to_string() };
            }
        }
        self.clone()
    }

    /// True if this is an Avail chain (mainnet or turing), after alias resolution.
    pub fn is_avail(&self) -> bool {
        let r = self.resolve();
        r.namespace == "polkadot"
            && (r.reference == "d3d2f3a3495dc597434a99d7d449ebad"
                || r.reference == "b91746b45e0346cc2f815a520b9c6cb4")
    }

    /// The friendly display name (reverse-aliasing canonical → friendly when possible).
    pub fn display_name(&self) -> String {
        for (a_ns, a_ref, c_ns, c_ref) in CHAIN_ALIASES {
            if self.namespace == *c_ns && self.reference == *c_ref {
                return format!("{a_ns}:{a_ref}");
            }
        }
        format!("{}:{}", self.namespace, self.reference)
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

/// An application ID on a chain.
///
/// Numeric today (Avail app-id). Kept as a newtype so the inner representation can be
/// relaxed to an opaque token for other DA layers (Celestia namespace, EVM address)
/// without churning every call site — see the appId-opaqueness follow-up.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct AppId(pub u32);

impl AppId {
    pub fn parse(s: &str) -> Result<Self> {
        s.parse::<u32>().map(AppId).map_err(|_| UriError::InvalidAppId(s.to_string()))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parsed query selectors. Named fields for the spec'd selectors; `extra` keeps
/// unknown keys for forward-compatibility.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UriQuery {
    /// Genesis **hash** for identity verification/disambiguation (e.g. `sha256:abc`).
    pub genesis: Option<String>,
    /// Historical-snapshot block — resolve object state as of this block.
    pub as_of: Option<u64>,
    pub content_hash: Option<String>,
    pub content_type: Option<String>,
    pub content_schema: Option<String>,
    pub encoding: Option<String>,
    pub size: Option<String>,
    /// Unknown selectors, preserved for forward-compatibility.
    pub extra: BTreeMap<String, String>,
}

impl UriQuery {
    pub fn is_empty(&self) -> bool {
        self.genesis.is_none()
            && self.as_of.is_none()
            && self.content_hash.is_none()
            && self.content_type.is_none()
            && self.content_schema.is_none()
            && self.encoding.is_none()
            && self.size.is_none()
            && self.extra.is_empty()
    }

    fn parse(s: &str) -> Result<Self> {
        let mut q = UriQuery::default();
        if s.is_empty() {
            return Ok(q);
        }
        for pair in s.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').ok_or_else(|| {
                UriError::MalformedQuery(format!("expected key=value, got '{pair}'"))
            })?;
            match k {
                "genesis" => q.genesis = Some(v.to_string()),
                "as_of" => {
                    q.as_of = Some(v.parse::<u64>().map_err(|_| {
                        UriError::MalformedQuery(format!("as_of must be a block number, got '{v}'"))
                    })?)
                }
                "content_hash" => q.content_hash = Some(v.to_string()),
                "content_type" => q.content_type = Some(v.to_string()),
                "content_schema" => q.content_schema = Some(v.to_string()),
                "encoding" => q.encoding = Some(v.to_string()),
                "size" => q.size = Some(v.to_string()),
                _ => {
                    q.extra.insert(k.to_string(), v.to_string());
                }
            }
        }
        Ok(q)
    }

    /// Serialize back to a query string (without the leading `?`). Stable ordering.
    fn to_query_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(g) = &self.genesis {
            parts.push(format!("genesis={g}"));
        }
        if let Some(a) = self.as_of {
            parts.push(format!("as_of={a}"));
        }
        if let Some(c) = &self.content_hash {
            parts.push(format!("content_hash={c}"));
        }
        if let Some(c) = &self.content_type {
            parts.push(format!("content_type={c}"));
        }
        if let Some(c) = &self.content_schema {
            parts.push(format!("content_schema={c}"));
        }
        if let Some(e) = &self.encoding {
            parts.push(format!("encoding={e}"));
        }
        if let Some(s) = &self.size {
            parts.push(format!("size={s}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        parts.join("&")
    }
}

/// A fully-parsed `sbo+raw://` URI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SboRawUri {
    /// CAIP-2 chain identifier.
    pub chain: ChainId,
    /// Application ID — the authority is exactly `chain:appId`.
    pub app_id: AppId,
    /// Optional genesis **anchor** (`@firstBlock`): database-level, inherited by paths.
    pub first_block: Option<u64>,
    /// Path within the database (includes the leading `/`); `None` for a bare repo.
    pub path: Option<String>,
    /// Query selectors.
    pub query: UriQuery,
}

impl SboRawUri {
    /// Parse an `sbo+raw://` URI. Rejects `sbo://` (those require DNS resolution first).
    pub fn parse(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        let rest = if let Some(r) = uri.strip_prefix("sbo+raw://") {
            r
        } else if uri.starts_with("sbo://") {
            return Err(UriError::NeedsDnsResolution(uri.to_string()));
        } else {
            return Err(UriError::NotRawUri(uri.to_string()));
        };

        // Split off the query at the first '?'.
        let (before_q, query_str) = match rest.split_once('?') {
            Some((b, q)) => (b, q),
            None => (rest, ""),
        };
        let query = UriQuery::parse(query_str)?;

        // Split authority from path at the first '/'.
        let (authority, path) = match before_q.find('/') {
            Some(idx) => (&before_q[..idx], Some(&before_q[idx..])),
            None => (before_q, None),
        };
        let path = path
            .map(|p| p.to_string())
            .filter(|p| p != "/" && !p.is_empty());

        // Split the @firstBlock anchor off the authority.
        let (auth_main, first_block) = match authority.split_once('@') {
            Some((a, b)) => {
                let block = b.parse::<u64>().map_err(|_| {
                    UriError::InvalidAnchor(format!("@firstBlock must be a block number, got '{b}'"))
                })?;
                (a, Some(block))
            }
            None => (authority, None),
        };

        // Authority is exactly namespace:reference:appId (3 colon parts).
        let parts: Vec<&str> = auth_main.split(':').collect();
        if parts.len() != 3 {
            return Err(UriError::MalformedAuthority(format!(
                "expected 'namespace:reference:appId', got '{auth_main}'"
            )));
        }
        let chain = ChainId {
            namespace: parts[0].to_lowercase(),
            reference: parts[1].to_lowercase(),
        };
        let app_id = AppId::parse(parts[2])?;

        Ok(Self { chain, app_id, first_block, path, query })
    }

    /// True if this is a **bare repository** address: no path, no query (an anchor is
    /// allowed — it is part of the repository address). This is the DNS `repo=` rule.
    pub fn is_bare(&self) -> bool {
        self.path.is_none() && self.query.is_empty()
    }

    /// Compose a path onto this (bare) repository address, inheriting the anchor.
    /// Query selectors from `self` are dropped (a repo address carries none).
    pub fn compose(&self, path: &str) -> Self {
        let path = if path.is_empty() || path == "/" {
            None
        } else if let Some(stripped) = path.strip_prefix('/') {
            Some(format!("/{stripped}"))
        } else {
            Some(format!("/{path}"))
        };
        Self {
            chain: self.chain.clone(),
            app_id: self.app_id,
            first_block: self.first_block,
            path,
            query: UriQuery::default(),
        }
    }

    /// The bare authority string `chain:appId` (no anchor) — opaqueness-safe.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.chain.display_name(), self.app_id)
    }

    /// The `creator` component (the part before `:` in the last path segment), if any.
    pub fn creator(&self) -> Option<&str> {
        let last = self.path.as_ref()?.rsplit('/').next()?;
        last.split_once(':').map(|(c, _)| c)
    }

    /// The object `id` (the last path segment, after any `creator:` prefix), if any.
    pub fn id(&self) -> Option<&str> {
        let last = self.path.as_ref()?.rsplit('/').next()?;
        if last.is_empty() {
            return None;
        }
        Some(last.split_once(':').map(|(_, i)| i).unwrap_or(last))
    }

    /// The canonical database identity tuple `{chain}:{appId}:{firstBlock}:{genesisHash}`.
    /// Requires both the anchor and a genesis hash (the full identity).
    pub fn database_identity(&self, genesis_hash: &str) -> Option<String> {
        let block = self.first_block?;
        Some(format!("{}:{}:{}:{}", self.chain.resolve(), self.app_id, block, genesis_hash))
    }

    fn render(&self, chain_str: &str) -> String {
        let mut s = format!("sbo+raw://{}:{}", chain_str, self.app_id);
        if let Some(b) = self.first_block {
            s.push('@');
            s.push_str(&b.to_string());
        }
        match &self.path {
            Some(p) => s.push_str(p),
            None => s.push('/'),
        }
        if !self.query.is_empty() {
            s.push('?');
            s.push_str(&self.query.to_query_string());
        }
        s
    }

    /// Render using the friendly chain alias where possible.
    pub fn to_uri_string(&self) -> String {
        self.render(&self.chain.display_name())
    }

    /// Render the stable *identity* form: like `to_uri_string` but WITHOUT the
    /// optional `@firstBlock` anchor and without any query. Two URIs that denote
    /// the same logical chain+path but differ only in the mutable anchor — e.g. a
    /// DNS relink whose `_sbo` record omits it — produce the same identity string.
    ///
    /// Used to derive filesystem paths, repo dedup keys, and repo ids so synced
    /// state persists across restarts/relinks instead of being stranded when the
    /// anchor comes and goes (see mingo-stho: the `@firstBlock` anchor was leaking
    /// into the state-dir name, so `avail_turing_506@3545910` and the anchorless
    /// form mapped to different RocksDB dirs and re-backfilled from genesis).
    pub fn to_identity_string(&self) -> String {
        let mut s = format!("sbo+raw://{}:{}", self.chain.display_name(), self.app_id);
        match &self.path {
            Some(p) => s.push_str(p),
            None => s.push('/'),
        }
        s
    }

    /// Render using the canonical CAIP-2 chain identifier.
    pub fn to_canonical_string(&self) -> String {
        self.render(&self.chain.resolve().to_string())
    }
}

impl fmt::Display for SboRawUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_repo() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506/").unwrap();
        assert_eq!(u.chain, ChainId { namespace: "avail".into(), reference: "turing".into() });
        assert_eq!(u.app_id, AppId(506));
        assert_eq!(u.first_block, None);
        assert_eq!(u.path, None);
        assert!(u.is_bare());
    }

    #[test]
    fn parse_anchor_is_bare() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506@12345/").unwrap();
        assert_eq!(u.first_block, Some(12345));
        assert!(u.is_bare(), "an anchor is part of the bare repo address");
        assert_eq!(u.to_uri_string(), "sbo+raw://avail:turing:506@12345/");
    }

    #[test]
    fn identity_string_ignores_anchor_and_query() {
        // Anchored vs anchorless forms of the same chain must share one identity
        // (mingo-stho: prevents the state-dir name from flipping between them).
        let anchored = SboRawUri::parse("sbo+raw://avail:turing:506@3545910/").unwrap();
        let anchorless = SboRawUri::parse("sbo+raw://avail:turing:506/").unwrap();
        assert_eq!(anchored.to_identity_string(), anchorless.to_identity_string());
        assert_eq!(anchored.to_identity_string(), "sbo+raw://avail:turing:506/");

        // Path is part of identity; the query is not.
        let with_path = SboRawUri::parse("sbo+raw://avail:turing:506@3545910/nft").unwrap();
        assert_eq!(with_path.to_identity_string(), "sbo+raw://avail:turing:506/nft");
        assert_ne!(with_path.to_identity_string(), anchored.to_identity_string());
        let with_query = SboRawUri::parse("sbo+raw://avail:turing:506@3545910/?genesis=abc").unwrap();
        assert_eq!(with_query.to_identity_string(), anchored.to_identity_string());
    }

    #[test]
    fn parse_path_and_anchor() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506@12345/alice/nft-123").unwrap();
        assert_eq!(u.first_block, Some(12345));
        assert_eq!(u.path.as_deref(), Some("/alice/nft-123"));
        assert_eq!(u.id(), Some("nft-123"));
        assert_eq!(u.creator(), None);
        assert!(!u.is_bare());
    }

    #[test]
    fn parse_creator_id() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506@12345/bob/alice:art-7").unwrap();
        assert_eq!(u.creator(), Some("alice"));
        assert_eq!(u.id(), Some("art-7"));
    }

    #[test]
    fn parse_query_selectors() {
        let u = SboRawUri::parse(
            "sbo+raw://avail:mainnet:13@1000/alice/foo?genesis=sha256:abc&as_of=8765&content_hash=sha256:def",
        )
        .unwrap();
        assert_eq!(u.query.genesis.as_deref(), Some("sha256:abc"));
        assert_eq!(u.query.as_of, Some(8765));
        assert_eq!(u.query.content_hash.as_deref(), Some("sha256:def"));
        assert!(!u.is_bare());
    }

    #[test]
    fn unknown_query_keys_preserved() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506@1/x/y?future=whatever").unwrap();
        assert_eq!(u.query.extra.get("future").map(String::as_str), Some("whatever"));
    }

    #[test]
    fn roundtrip_full() {
        let s = "sbo+raw://avail:mainnet:13@1000/bob/alice:art-7?genesis=sha256:abc&as_of=8765";
        let u = SboRawUri::parse(s).unwrap();
        assert_eq!(u.to_uri_string(), s);
    }

    #[test]
    fn canonical_resolves_alias() {
        let u = SboRawUri::parse("sbo+raw://avail:turing:506@12345/").unwrap();
        assert_eq!(
            u.to_canonical_string(),
            "sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:506@12345/"
        );
    }

    #[test]
    fn compose_inherits_anchor() {
        let repo = SboRawUri::parse("sbo+raw://avail:turing:506@12345/").unwrap();
        let obj = repo.compose("/alice/nft");
        assert_eq!(obj.first_block, Some(12345));
        assert_eq!(obj.to_uri_string(), "sbo+raw://avail:turing:506@12345/alice/nft");
    }

    #[test]
    fn database_identity_tuple() {
        let u = SboRawUri::parse("sbo+raw://avail:mainnet:13@1000/").unwrap();
        assert_eq!(
            u.database_identity("sha256:abc").as_deref(),
            Some("polkadot:b91746b45e0346cc2f815a520b9c6cb4:13:1000:sha256:abc")
        );
        // No anchor → no full identity tuple.
        let bare = SboRawUri::parse("sbo+raw://avail:mainnet:13/").unwrap();
        assert_eq!(bare.database_identity("sha256:abc"), None);
    }

    #[test]
    fn rejects_sbo_dns_uri() {
        assert!(matches!(
            SboRawUri::parse("sbo://myapp.com/alice/nft"),
            Err(UriError::NeedsDnsResolution(_))
        ));
    }

    #[test]
    fn rejects_bad_authority() {
        assert!(matches!(
            SboRawUri::parse("sbo+raw://avail:turing/foo"),
            Err(UriError::MalformedAuthority(_))
        ));
    }

    #[test]
    fn rejects_bad_anchor() {
        assert!(matches!(
            SboRawUri::parse("sbo+raw://avail:turing:506@notablock/"),
            Err(UriError::InvalidAnchor(_))
        ));
    }

    #[test]
    fn bare_rule_rejects_path_and_query() {
        assert!(!SboRawUri::parse("sbo+raw://avail:turing:506/foo").unwrap().is_bare());
        assert!(!SboRawUri::parse("sbo+raw://avail:turing:506/?genesis=sha256:abc")
            .unwrap()
            .is_bare());
    }
}
