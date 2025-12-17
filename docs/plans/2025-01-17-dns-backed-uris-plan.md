# DNS-Backed SBO URIs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable `sbo://domain.com/` URIs that resolve via DNS TXT records to `sbo+raw://` chain references.

**Architecture:** DNS resolution in `sbo-core` library, CLI resolves before daemon calls, repos store both display and resolved URIs, DNS re-checked on startup/list/status with warnings on mismatch.

**Tech Stack:** Rust, hickory-resolver (DNS), tokio (async), serde (serialization)

---

## Task 1: Add hickory-resolver dependency

**Files:**
- Modify: `reference_impl/sbo-core/Cargo.toml`

**Step 1: Add dependency**

Add to `[dependencies]` section in `reference_impl/sbo-core/Cargo.toml`:

```toml
hickory-resolver = "0.24"
```

**Step 2: Verify it compiles**

Run: `cd reference_impl && cargo check -p sbo-core`
Expected: Compiles successfully (may download dependency)

**Step 3: Commit**

```bash
git add reference_impl/sbo-core/Cargo.toml
git commit -m "deps(sbo-core): add hickory-resolver for DNS lookups"
```

---

## Task 2: Create DNS module with record parsing

**Files:**
- Create: `reference_impl/sbo-core/src/dns.rs`
- Modify: `reference_impl/sbo-core/src/lib.rs`

**Step 1: Write failing test for parse_record**

Create `reference_impl/sbo-core/src/dns.rs`:

```rust
//! DNS resolution for sbo:// URIs
//!
//! Resolves sbo://domain.com/ URIs via DNS TXT records at _sbo.domain.com

use std::fmt;

/// Parsed SBO DNS record
#[derive(Debug, Clone, PartialEq)]
pub struct SboRecord {
    /// CAIP-2 chain identifier (e.g., "avail:mainnet")
    pub chain: String,
    /// Application ID on the chain
    pub app_id: u32,
    /// Genesis hash for verification (e.g., "sha256:abc123...")
    pub genesis: Option<String>,
    /// Block number containing genesis
    pub first_block: Option<u64>,
    /// URL for bootstrap checkpoint
    pub checkpoint: Option<String>,
    /// URL of full node for data fetching
    pub node: Option<String>,
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
/// Format: "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc..."
pub fn parse_record(txt: &str) -> Result<SboRecord, DnsError> {
    let mut version: Option<&str> = None;
    let mut chain: Option<&str> = None;
    let mut app_id: Option<u32> = None;
    let mut genesis: Option<String> = None;
    let mut first_block: Option<u64> = None;
    let mut checkpoint: Option<String> = None;
    let mut node: Option<String> = None;

    for part in txt.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "sbo" => version = Some(value),
                "chain" => chain = Some(value),
                "appId" => {
                    app_id = Some(value.parse().map_err(|_| {
                        DnsError::MalformedRecord(format!("invalid appId: {}", value))
                    })?);
                }
                "genesis" => genesis = Some(value.to_string()),
                "firstBlock" => {
                    first_block = Some(value.parse().map_err(|_| {
                        DnsError::MalformedRecord(format!("invalid firstBlock: {}", value))
                    })?);
                }
                "checkpoint" => checkpoint = Some(value.to_string()),
                "node" => node = Some(value.to_string()),
                _ => {} // Ignore unknown fields for forward compatibility
            }
        }
    }

    // Validate version
    match version {
        Some("v1") => {}
        Some(v) => return Err(DnsError::UnsupportedVersion(v.to_string())),
        None => return Err(DnsError::MalformedRecord("missing sbo version".to_string())),
    }

    // Validate required fields
    let chain = chain
        .ok_or_else(|| DnsError::MalformedRecord("missing chain".to_string()))?
        .to_string();

    let app_id = app_id.ok_or_else(|| DnsError::MalformedRecord("missing appId".to_string()))?;

    Ok(SboRecord {
        chain,
        app_id,
        genesis,
        first_block,
        checkpoint,
        node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.chain, "avail:mainnet");
        assert_eq!(record.app_id, 13);
        assert_eq!(record.genesis, None);
        assert_eq!(record.first_block, None);
        assert_eq!(record.checkpoint, None);
        assert_eq!(record.node, None);
    }

    #[test]
    fn test_parse_full_record() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123 firstBlock=1000 checkpoint=https://example.com/cp.json node=https://sbo.example.com";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.chain, "avail:mainnet");
        assert_eq!(record.app_id, 13);
        assert_eq!(record.genesis, Some("sha256:abc123".to_string()));
        assert_eq!(record.first_block, Some(1000));
        assert_eq!(record.checkpoint, Some("https://example.com/cp.json".to_string()));
        assert_eq!(record.node, Some("https://sbo.example.com".to_string()));
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "chain=avail:mainnet appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_unsupported_version() {
        let txt = "sbo=v2 chain=avail:mainnet appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_parse_missing_chain() {
        let txt = "sbo=v1 appId=13";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_missing_app_id() {
        let txt = "sbo=v1 chain=avail:mainnet";
        let err = parse_record(txt).unwrap_err();
        assert!(matches!(err, DnsError::MalformedRecord(_)));
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let txt = "sbo=v1 chain=avail:mainnet appId=13 futureField=whatever";
        let record = parse_record(txt).unwrap();
        assert_eq!(record.app_id, 13);
    }
}
```

**Step 2: Export module from lib.rs**

Add to `reference_impl/sbo-core/src/lib.rs`:

```rust
pub mod dns;
```

**Step 3: Run tests to verify they pass**

Run: `cd reference_impl && cargo test -p sbo-core dns`
Expected: All 7 tests pass

**Step 4: Commit**

```bash
git add reference_impl/sbo-core/src/dns.rs reference_impl/sbo-core/src/lib.rs
git commit -m "feat(sbo-core): add DNS record parsing for sbo:// URIs"
```

---

## Task 3: Add async DNS resolution

**Files:**
- Modify: `reference_impl/sbo-core/src/dns.rs`

**Step 1: Add resolve function**

Add to `reference_impl/sbo-core/src/dns.rs` after `parse_record`:

```rust
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

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
            if e.is_no_records_found() {
                DnsError::NoRecord
            } else {
                DnsError::LookupFailed(e.to_string())
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
/// Example: sbo://myapp.com/alice/nft -> sbo+raw://avail:mainnet:13/alice/nft
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

    Ok(format!("sbo+raw://{}:{}{}", record.chain, record.app_id, path))
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
```

**Step 2: Add tests for helper functions**

Add to the `tests` module in `dns.rs`:

```rust
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
```

**Step 3: Run tests**

Run: `cd reference_impl && cargo test -p sbo-core dns`
Expected: All tests pass (async resolve/resolve_uri not unit tested - needs real DNS)

**Step 4: Commit**

```bash
git add reference_impl/sbo-core/src/dns.rs
git commit -m "feat(sbo-core): add async DNS resolution for sbo:// URIs"
```

---

## Task 4: Update Repo struct with display_uri and dns_checked_at

**Files:**
- Modify: `reference_impl/sbo-daemon/src/repo.rs`

**Step 1: Update Repo struct**

In `reference_impl/sbo-daemon/src/repo.rs`, update the `Repo` struct (around line 175):

```rust
pub struct Repo {
    /// Unique identifier (hash of URI)
    pub id: String,
    /// What user provided (could be sbo:// or sbo+raw://)
    pub display_uri: String,
    /// The resolved SBO URI (always sbo+raw://)
    pub uri: SboUri,
    /// When DNS was last checked (None for sbo+raw:// URIs)
    pub dns_checked_at: Option<u64>,
    /// Local filesystem path
    pub path: PathBuf,
    /// Last synced block number
    pub head: u64,
    /// Creation timestamp
    pub created_at: u64,
}
```

**Step 2: Update Repo::new**

Update the `Repo::new` function (around line 190):

```rust
impl Repo {
    /// Create a new repo with optional starting block
    pub fn new(display_uri: String, uri: SboUri, path: PathBuf, from_block: Option<u64>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let id = Self::compute_id(&uri);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let dns_checked_at = if sbo_core::dns::is_dns_uri(&display_uri) {
            Some(created_at)
        } else {
            None
        };

        Self {
            id,
            display_uri,
            uri,
            dns_checked_at,
            path,
            head: from_block.unwrap_or(0),
            created_at,
        }
    }
```

**Step 3: Add sbo-core dependency to sbo-daemon if needed**

Check `reference_impl/sbo-daemon/Cargo.toml` - sbo-core should already be a dependency. If not, add:

```toml
sbo-core = { path = "../sbo-core" }
```

**Step 4: Fix compilation errors**

Find all places that call `Repo::new` and update them. Search with:

Run: `cd reference_impl && grep -rn "Repo::new" sbo-daemon/src/`

Update each call site to pass `display_uri` as first argument. The main one is in `main.rs` in the `RepoAdd` handler.

**Step 5: Run tests**

Run: `cd reference_impl && cargo test -p sbo-daemon`
Expected: All tests pass

**Step 6: Commit**

```bash
git add reference_impl/sbo-daemon/src/repo.rs reference_impl/sbo-daemon/src/main.rs
git commit -m "feat(daemon): add display_uri and dns_checked_at to Repo struct"
```

---

## Task 5: Update CLI repo add to resolve DNS

**Files:**
- Modify: `reference_impl/sbo-cli/src/main.rs`

**Step 1: Update RepoAdd handler**

Find `RepoCommands::Add` handler in `main.rs` and update to resolve DNS:

```rust
                RepoCommands::Add { uri, path, from_block } => {
                    let path = canonicalize_path(&path)?;

                    // Resolve sbo:// URIs via DNS
                    let (display_uri, resolved_uri) = if sbo_core::dns::is_dns_uri(&uri) {
                        print!("Resolving {}...", uri);
                        std::io::Write::flush(&mut std::io::stdout())?;

                        match sbo_core::dns::resolve_uri(&uri).await {
                            Ok(resolved) => {
                                println!(" → {}", resolved);
                                (uri.clone(), resolved)
                            }
                            Err(e) => {
                                println!();
                                eprintln!("Error: Failed to resolve DNS for {}: {}", uri, e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        (uri.clone(), uri.clone())
                    };

                    match client.request(Request::RepoAdd {
                        display_uri,
                        resolved_uri,
                        path: path.clone(),
                        from_block,
                    }).await {
                        Ok(Response::Ok { data }) => {
                            println!("Added repository:");
                            println!("  URI:  {}", data["display_uri"].as_str().unwrap_or("?"));
                            if data["display_uri"] != data["resolved_uri"] {
                                println!("  Chain: {}", data["resolved_uri"].as_str().unwrap_or("?"));
                            }
                            println!("  Path: {}", path.display());
                            println!("  Head: {}", data["head"].as_u64().unwrap_or(0));
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                            eprintln!("Is the daemon running? Try: sbo daemon start");
                        }
                    }
                }
```

**Step 2: Update IPC Request type**

In `reference_impl/sbo-daemon/src/ipc.rs`, update `RepoAdd`:

```rust
    RepoAdd {
        display_uri: String,
        resolved_uri: String,
        path: PathBuf,
        from_block: Option<i64>,
    },
```

**Step 3: Update daemon handler for RepoAdd**

In `reference_impl/sbo-daemon/src/main.rs`, update the `RepoAdd` handler:

```rust
        Request::RepoAdd { display_uri, resolved_uri, path, from_block } => {
            // Parse the resolved URI (always sbo+raw://)
            let uri = match SboUri::parse(&resolved_uri) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid URI: {}", e)),
            };

            // Check for duplicates
            {
                let state = state.read().await;
                for repo in state.repos.list() {
                    if repo.uri.to_string() == uri.to_string() {
                        return Response::error(format!(
                            "Already tracking this chain as {}",
                            repo.display_uri
                        ));
                    }
                }
            }

            // ... rest of handler, using display_uri in Repo::new
            let repo = Repo::new(display_uri.clone(), uri, path.clone(), adjusted_from);
```

**Step 4: Verify compilation**

Run: `cd reference_impl && cargo build -p sbo-cli -p sbo-daemon`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add reference_impl/sbo-cli/src/main.rs reference_impl/sbo-daemon/src/ipc.rs reference_impl/sbo-daemon/src/main.rs
git commit -m "feat(cli): resolve sbo:// URIs via DNS on repo add"
```

---

## Task 6: Update repo list to show display_uri and check DNS

**Files:**
- Modify: `reference_impl/sbo-cli/src/main.rs`
- Modify: `reference_impl/sbo-daemon/src/main.rs`

**Step 1: Update daemon RepoList response**

In daemon's `RepoList` handler, include both URIs:

```rust
        Request::RepoList => {
            let state = state.read().await;
            let repos: Vec<_> = state.repos.list().iter().map(|r| {
                serde_json::json!({
                    "display_uri": r.display_uri,
                    "resolved_uri": r.uri.to_string(),
                    "path": r.path.to_string_lossy(),
                    "head": r.head,
                    "dns_checked_at": r.dns_checked_at,
                })
            }).collect();
            Response::ok(serde_json::json!({ "repos": repos }))
        }
```

**Step 2: Update CLI repo list to check DNS and show warnings**

```rust
                RepoCommands::List => {
                    match client.request(Request::RepoList).await {
                        Ok(Response::Ok { data }) => {
                            let repos = data["repos"].as_array().unwrap();
                            if repos.is_empty() {
                                println!("No repositories configured.");
                                println!("Add one with: sbo repo add <uri> <path>");
                            } else {
                                println!("{:<40} {:<30} {:>10}", "URI", "PATH", "HEAD");
                                println!("{}", "-".repeat(82));

                                let mut mismatches = Vec::new();

                                for repo in repos {
                                    let display_uri = repo["display_uri"].as_str().unwrap_or("?");
                                    let resolved_uri = repo["resolved_uri"].as_str().unwrap_or("?");
                                    let path = repo["path"].as_str().unwrap_or("?");
                                    let head = repo["head"].as_u64().unwrap_or(0);

                                    // Truncate path for display
                                    let path_display = if path.len() > 28 {
                                        format!("...{}", &path[path.len()-25..])
                                    } else {
                                        path.to_string()
                                    };

                                    println!("{:<40} {:<30} {:>10}", display_uri, path_display, head);

                                    // Check DNS for sbo:// URIs
                                    if sbo_core::dns::is_dns_uri(display_uri) {
                                        if let Ok(current) = sbo_core::dns::resolve_uri(display_uri).await {
                                            if current != resolved_uri {
                                                mismatches.push((display_uri.to_string(), resolved_uri.to_string(), current, path.to_string()));
                                            }
                                        }
                                    }
                                }

                                // Show warnings for mismatches
                                for (display, old, new, path) in mismatches {
                                    println!();
                                    println!("⚠ DNS mismatch: {} now resolves to {}", display, new);
                                    println!("  (currently tracking {})", old);
                                    println!("  Run 'sbo repo relink {}' to update", path);
                                }
                            }
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                }
```

**Step 3: Verify compilation**

Run: `cd reference_impl && cargo build -p sbo-cli`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-cli/src/main.rs reference_impl/sbo-daemon/src/main.rs
git commit -m "feat(cli): show display_uri in repo list, check DNS for mismatches"
```

---

## Task 7: Add repo relink command

**Files:**
- Modify: `reference_impl/sbo-cli/src/main.rs`
- Modify: `reference_impl/sbo-daemon/src/ipc.rs`
- Modify: `reference_impl/sbo-daemon/src/main.rs`

**Step 1: Add RepoRelink to CLI commands**

In `main.rs`, add to `RepoCommands` enum:

```rust
    /// Re-resolve DNS and update chain reference for a repo
    ///
    /// Use when DNS has changed and you want to follow the new chain.
    /// Warning: This will re-sync from the new chain's firstBlock.
    Relink {
        /// Local path of the repo to relink
        path: PathBuf,
    },
```

**Step 2: Add IPC request type**

In `ipc.rs`:

```rust
    RepoRelink {
        path: PathBuf,
    },
```

**Step 3: Add daemon handler**

In daemon `main.rs`:

```rust
        Request::RepoRelink { path } => {
            let mut state = state.write().await;

            // Find repo by path
            let repo = match state.repos.find_by_path(&path) {
                Some(r) => r.clone(),
                None => return Response::error(format!("No repo at path: {}", path.display())),
            };

            // Check if it's a DNS-based URI
            if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
                return Response::error("Repo is not using a DNS-based URI (sbo://)");
            }

            // Re-resolve DNS
            let new_resolved = match sbo_core::dns::resolve_uri(&repo.display_uri).await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("DNS resolution failed: {}", e)),
            };

            // Parse new URI
            let new_uri = match SboUri::parse(&new_resolved) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid resolved URI: {}", e)),
            };

            let old_resolved = repo.uri.to_string();

            // Update repo
            if let Err(e) = state.repos.update_uri(&repo.id, repo.display_uri.clone(), new_uri) {
                return Response::error(format!("Failed to update repo: {}", e));
            }

            Response::ok(serde_json::json!({
                "display_uri": repo.display_uri,
                "old_resolved": old_resolved,
                "new_resolved": new_resolved,
                "message": "Repo relinked. Will re-sync from new chain."
            }))
        }
```

**Step 4: Add update_uri to RepoManager**

In `repo.rs`, add method to `RepoManager`:

```rust
    /// Update a repo's resolved URI (for DNS relink)
    pub fn update_uri(&mut self, id: &str, display_uri: String, new_uri: SboUri) -> crate::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let repo = self.repos.get_mut(id)
            .ok_or_else(|| crate::DaemonError::Repo(format!("Repo not found: {}", id)))?;

        repo.display_uri = display_uri;
        repo.uri = new_uri;
        repo.head = 0; // Reset to re-sync
        repo.dns_checked_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        self.save()
    }
```

**Step 5: Add CLI handler**

In CLI `main.rs`:

```rust
                RepoCommands::Relink { path } => {
                    let path = canonicalize_path(&path)?;

                    match client.request(Request::RepoRelink { path: path.clone() }).await {
                        Ok(Response::Ok { data }) => {
                            println!("✓ Repo relinked");
                            println!("  URI:      {}", data["display_uri"].as_str().unwrap_or("?"));
                            println!("  Old chain: {}", data["old_resolved"].as_str().unwrap_or("?"));
                            println!("  New chain: {}", data["new_resolved"].as_str().unwrap_or("?"));
                            println!();
                            println!("  Note: Data will be re-synced from new chain.");
                        }
                        Ok(Response::Error { message }) => {
                            eprintln!("Error: {}", message);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                }
```

**Step 6: Verify compilation**

Run: `cd reference_impl && cargo build -p sbo-cli -p sbo-daemon`
Expected: Compiles successfully

**Step 7: Commit**

```bash
git add reference_impl/sbo-cli/src/main.rs reference_impl/sbo-daemon/src/ipc.rs reference_impl/sbo-daemon/src/main.rs reference_impl/sbo-daemon/src/repo.rs
git commit -m "feat(cli): add sbo repo relink command for DNS changes"
```

---

## Task 8: Add DNS check on daemon startup

**Files:**
- Modify: `reference_impl/sbo-daemon/src/main.rs`

**Step 1: Add DNS check function**

Add helper function in daemon `main.rs`:

```rust
/// Check DNS for all sbo:// repos and log warnings for mismatches
async fn check_dns_on_startup(repos: &RepoManager) {
    for repo in repos.list() {
        if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
            continue;
        }

        match sbo_core::dns::resolve_uri(&repo.display_uri).await {
            Ok(current_resolved) => {
                let stored_resolved = repo.uri.to_string();
                if current_resolved == stored_resolved {
                    tracing::info!("DNS check: {} → {} ✓", repo.display_uri, stored_resolved);
                } else {
                    tracing::warn!(
                        "DNS mismatch: {} resolves to {} but repo is tracking {}. Run 'sbo repo relink {}' to update",
                        repo.display_uri,
                        current_resolved,
                        stored_resolved,
                        repo.path.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "DNS check failed for {}: {} (continuing with cached resolution)",
                    repo.display_uri,
                    e
                );
            }
        }
    }
}
```

**Step 2: Call on startup**

In the daemon startup code, after loading repos but before starting sync:

```rust
    // Check DNS for sbo:// repos
    {
        let state = state.read().await;
        check_dns_on_startup(&state.repos).await;
    }

    tracing::info!("Starting sync...");
```

**Step 3: Verify compilation**

Run: `cd reference_impl && cargo build -p sbo-daemon`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-daemon/src/main.rs
git commit -m "feat(daemon): check DNS on startup, warn on mismatches"
```

---

## Task 9: Update URI specification

**Files:**
- Modify: `specs/SBO URI Specification v0.3.md`

**Step 1: Update DNS TXT record section**

Update the DNS TXT Record Format section to include new fields:

```markdown
### DNS TXT Record Format

\`\`\`
_sbo.myapp.com TXT "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123... firstBlock=1000 checkpoint=https://myapp.com/sbo/checkpoint.json node=https://sbo.myapp.com"
\`\`\`

| Field | Required | Description |
|-------|----------|-------------|
| `sbo` | Yes | Version identifier (v1) |
| `chain` | Yes | CAIP-2 chain identifier |
| `appId` | Yes | Application ID on the chain |
| `genesis` | No | Genesis hash for database identity |
| `firstBlock` | No | Block number containing genesis (for sync-from-start) |
| `checkpoint` | No | URL for bootstrap checkpoint (preferred for mature databases) |
| `node` | No | URL of full node for data fetching |
```

**Step 2: Commit**

```bash
git add specs/SBO\ URI\ Specification\ v0.3.md
git commit -m "docs(spec): add node and firstBlock fields to DNS record format"
```

---

## Task 10: Run full test suite

**Step 1: Run all tests**

Run: `cd reference_impl && cargo test`
Expected: All tests pass

**Step 2: Build release binaries**

Run: `cd reference_impl && cargo build --release`
Expected: Builds successfully

**Step 3: Manual smoke test (optional)**

If you have a test domain with DNS configured:

```bash
./target/release/sbo repo add sbo://testdomain.com/ ./test-repo
./target/release/sbo repo list
./target/release/sbo repo status
```

---

## Summary

After completing all tasks:

1. ✅ `sbo-core` has DNS resolution library
2. ✅ Repos store `display_uri` and `resolved_uri`
3. ✅ `sbo repo add` resolves `sbo://` URIs via DNS
4. ✅ `sbo repo list` shows display URIs and warns on DNS mismatches
5. ✅ `sbo repo relink` accepts DNS changes
6. ✅ Daemon checks DNS on startup
7. ✅ URI spec updated with new fields
