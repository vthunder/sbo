//! DNS resolution for sbo:// URIs.
//!
//! Resolves `sbo://domain.com/` URIs via DNS TXT records at `_sbo.domain.com`.
//! `_sbo` is **data-discovery only** — identity is on-chain, not in DNS.

use std::fmt;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

use crate::uri::SboRawUri;

/// Parsed SBO DNS record
#[derive(Debug, Clone, PartialEq)]
pub struct SboRecord {
    /// Bare repository URI (e.g., "sbo+raw://avail:turing:506@12345/")
    pub repo: String,
    /// Genesis identity hash (e.g., "sha256:abc...")
    pub genesis: Option<String>,
    /// Node endpoint URL
    pub node: Option<String>,
    /// Checkpoint endpoint URL
    pub checkpoint: Option<String>,
}

/// DNS resolution error
#[derive(Debug, Clone)]
pub enum DnsError {
    /// No _sbo. TXT record found
    NoRecord,
    /// Record exists but is malformed
    MalformedRecord(String),
    /// Unsupported version (e.g., sbo=v2)
    UnsupportedVersion(String),
    /// DNS lookup failed
    LookupFailed(String),
    /// URI is not an sbo:// URI
    NotSboUri,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NoRecord => write!(f, "No SBO DNS record found"),
            DnsError::MalformedRecord(msg) => write!(f, "Malformed SBO record: {}", msg),
            DnsError::UnsupportedVersion(v) => write!(f, "Unsupported SBO record version: {}", v),
            DnsError::LookupFailed(msg) => write!(f, "DNS lookup failed: {}", msg),
            DnsError::NotSboUri => write!(f, "Not an sbo:// URI"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Parse a DNS TXT record into an SboRecord
///
/// Format: "v=sbo1 repo=sbo+raw://avail:turing:506@12345/ genesis=sha256:abc node=<url> checkpoint=<url>"
/// Fields are space-separated key=value pairs; unknown keys are ignored.
/// The `repo=` URI must be a **bare** repository address (no path/creator/id/query;
/// an `@firstBlock` anchor is allowed).
pub fn parse_record(txt: &str) -> Result<SboRecord, DnsError> {
    let mut version: Option<&str> = None;
    let mut repo: Option<String> = None;
    let mut genesis: Option<String> = None;
    let mut node: Option<String> = None;
    let mut checkpoint: Option<String> = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "v" => version = Some(value),
                "repo" => repo = Some(value.to_string()),
                "genesis" => genesis = Some(value.to_string()),
                "node" => node = Some(value.to_string()),
                "checkpoint" => checkpoint = Some(value.to_string()),
                _ => {} // Ignore unknown fields for forward compatibility
            }
        }
    }

    // Validate version
    match version {
        Some("sbo1") => {}
        Some(v) => return Err(DnsError::UnsupportedVersion(v.to_string())),
        None => return Err(DnsError::MalformedRecord("missing v= version".to_string())),
    }

    // Validate required fields
    let repo = repo
        .ok_or_else(|| DnsError::MalformedRecord("missing repo= repository URI".to_string()))?;

    // Enforce the bare-repo rule.
    let parsed = SboRawUri::parse(&repo)
        .map_err(|e| DnsError::MalformedRecord(format!("invalid repo= URI: {}", e)))?;
    if !parsed.is_bare() {
        return Err(DnsError::MalformedRecord(format!(
            "repo= must be a bare repository URI (no path/query): {}",
            repo
        )));
    }

    Ok(SboRecord {
        repo,
        genesis,
        node,
        checkpoint,
    })
}

/// Resolve a domain to an SBO record via DNS TXT lookup
///
/// Queries _sbo.{domain} for TXT records
pub async fn resolve(domain: &str) -> Result<SboRecord, DnsError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let lookup_name = format!("_sbo.{}", domain);

    let response = resolver
        .txt_lookup(&lookup_name)
        .await
        .map_err(|e| {
            use hickory_resolver::error::ResolveErrorKind;
            match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => DnsError::NoRecord,
                _ => DnsError::LookupFailed(e.to_string()),
            }
        })?;

    // Try each TXT record until we find a valid one
    let mut last_error = DnsError::NoRecord;
    for record in response.iter() {
        let txt: String = record.iter()
            .map(|data| String::from_utf8_lossy(data))
            .collect();

        match parse_record(&txt) {
            Ok(sbo_record) => return Ok(sbo_record),
            Err(e) => last_error = e,
        }
    }

    Err(last_error)
}

/// Convert an sbo:// URI to sbo+raw:// using DNS resolution
///
/// Example: sbo://myapp.com/alice/nft -> sbo+raw://avail:turing:506/alice/nft
pub async fn resolve_uri(uri: &str) -> Result<String, DnsError> {
    let uri = uri.trim();

    if !uri.starts_with("sbo://") {
        return Err(DnsError::NotSboUri);
    }

    // Parse: sbo://domain.com/path/to/thing
    let rest = &uri[6..]; // Remove "sbo://"

    let (domain, path) = if let Some(idx) = rest.find('/') {
        (&rest[..idx], &rest[idx..])
    } else {
        (rest, "/")
    };

    let record = resolve(domain).await?;

    // Compose the path onto the bare repo URI, preserving the @firstBlock anchor.
    let repo = SboRawUri::parse(&record.repo)
        .map_err(|e| DnsError::MalformedRecord(format!("invalid repo= URI: {}", e)))?;
    Ok(repo.compose(path).to_uri_string())
}

/// Extract domain from an sbo:// URI
///
/// Returns None if not an sbo:// URI
pub fn extract_domain(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if !uri.starts_with("sbo://") {
        return None;
    }

    let rest = &uri[6..];
    let domain = if let Some(idx) = rest.find('/') {
        &rest[..idx]
    } else {
        rest
    };

    Some(domain.to_string())
}

/// Check if a URI is a DNS-based sbo:// URI
pub fn is_dns_uri(uri: &str) -> bool {
    uri.trim().starts_with("sbo://")
}

/// Parse an email address into (user, domain)
pub fn parse_email(email: &str) -> Option<(&str, &str)> {
    let (user, domain) = email.split_once('@')?;
    if user.is_empty() || domain.is_empty() {
        return None;
    }
    Some((user, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let txt = "v=sbo1 repo=sbo+raw://avail:turing:506/";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repo, "sbo+raw://avail:turing:506/");
        assert_eq!(record.genesis, None);
        assert_eq!(record.node, None);
        assert_eq!(record.checkpoint, None);
    }

    #[test]
    fn test_parse_full_record() {
        let txt = "v=sbo1 repo=sbo+raw://avail:mainnet:13@1000/ genesis=sha256:abc node=https://node.example.com checkpoint=https://cp.example.com";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repo, "sbo+raw://avail:mainnet:13@1000/");
        assert_eq!(record.genesis, Some("sha256:abc".to_string()));
        assert_eq!(record.node, Some("https://node.example.com".to_string()));
        assert_eq!(record.checkpoint, Some("https://cp.example.com".to_string()));
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "repo=sbo+raw://avail:turing:506/";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_unsupported_version() {
        let txt = "v=sbo2 repo=sbo+raw://avail:turing:506/";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_parse_missing_repo() {
        let txt = "v=sbo1 node=https://node.example.com";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let txt = "v=sbo1 repo=sbo+raw://avail:turing:506/ futureField=whatever";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.repo, "sbo+raw://avail:turing:506/");
    }

    #[test]
    fn test_parse_rejects_non_bare_repo_path() {
        let txt = "v=sbo1 repo=sbo+raw://avail:turing:506/alice/nft";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_rejects_non_bare_repo_query() {
        let txt = "v=sbo1 repo=sbo+raw://avail:turing:506/?genesis=sha256:abc";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_resolve_uri_preserves_anchor() {
        // Component-aware compose: the @firstBlock anchor survives path composition.
        let repo = SboRawUri::parse("sbo+raw://avail:turing:506@12345/").unwrap();
        let composed = repo.compose("/alice/nft").to_uri_string();
        assert_eq!(composed, "sbo+raw://avail:turing:506@12345/alice/nft");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("sbo://myapp.com/path"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo://myapp.com/"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo://myapp.com"), Some("myapp.com".to_string()));
        assert_eq!(extract_domain("sbo+raw://avail:mainnet:13/"), None);
    }

    #[test]
    fn test_is_dns_uri() {
        assert!(is_dns_uri("sbo://myapp.com/"));
        assert!(is_dns_uri("sbo://myapp.com/path/to/thing"));
        assert!(!is_dns_uri("sbo+raw://avail:mainnet:13/"));
        assert!(!is_dns_uri("https://example.com"));
    }

    #[test]
    fn test_parse_email() {
        assert_eq!(parse_email("alice@example.com"), Some(("alice", "example.com")));
        assert_eq!(parse_email("user@sub.domain.org"), Some(("user", "sub.domain.org")));
        assert_eq!(parse_email("invalid"), None);
        assert_eq!(parse_email("@domain.com"), None);
        assert_eq!(parse_email("user@"), None);
        assert_eq!(parse_email(""), None);
    }
}
