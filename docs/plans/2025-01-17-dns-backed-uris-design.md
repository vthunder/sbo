# DNS-Backed SBO URIs Design

**Date:** 2025-01-17
**Status:** Approved

## Overview

Allow users to reference SBO databases using human-readable domain names instead of chain identifiers.

**URI mapping:**
```
sbo://myapp.com/alice/nft-123
    ↓ DNS resolve
sbo+raw://avail:mainnet:13/alice/nft-123
```

**Key principles:**
- `sbo://` URIs are resolved via DNS TXT records at `_sbo.{domain}`
- Resolution happens in CLI before sending to daemon (shared library for future daemon use)
- Repos store both display URI (what user typed) and resolved URI (chain reference)
- DNS is re-checked on daemon startup, `sbo repo list`, and `sbo repo status`
- Mismatches warn but don't block syncing; user runs `sbo repo relink` to accept changes
- No migration needed for existing data

---

## DNS Record Format

**Record location:** `_sbo.{domain}` TXT record

**Format:**
```
_sbo.myapp.com TXT "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123... firstBlock=1000 checkpoint=https://myapp.com/checkpoint.json node=https://sbo.myapp.com"
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `sbo` | Yes | Version identifier, must be `v1` |
| `chain` | Yes | CAIP-2 chain ID (e.g., `avail:mainnet`) |
| `appId` | Yes | Application ID on the chain |
| `genesis` | No | Genesis hash for database verification |
| `firstBlock` | No | Block number containing genesis (for sync-from-start) |
| `checkpoint` | No | URL for bootstrap checkpoint (preferred for mature databases) |
| `node` | No | URL of full node for data fetching |

**Parsing rules:**
- Space-separated key=value pairs
- Unknown fields are ignored (forward compatibility)
- Missing required fields → error
- Unknown version → error

**Sync priority:**
1. If `checkpoint` available → use it (fast)
2. Else if `firstBlock` available → sync from there
3. Else → error or scan from chain start (slow)

---

## Library API

**Location:** `sbo-core/src/dns.rs`

**Dependencies:** `hickory-resolver` for async DNS lookups

**Core types:**

```rust
pub struct SboRecord {
    pub chain: String,              // "avail:mainnet"
    pub app_id: u32,
    pub genesis: Option<String>,    // "sha256:abc123..."
    pub first_block: Option<u64>,
    pub checkpoint: Option<String>, // URL
    pub node: Option<String>,       // URL
}

pub enum DnsError {
    NoRecord,                 // No _sbo. TXT record found
    MalformedRecord(String),  // Parse error
    UnsupportedVersion(String), // sbo=v2 etc
    LookupFailed(String),     // Network/timeout
}
```

**Functions:**

```rust
/// Resolve domain to SBO record (no caching)
pub async fn resolve(domain: &str) -> Result<SboRecord, DnsError>;

/// Parse TXT record content into SboRecord
pub fn parse_record(txt: &str) -> Result<SboRecord, DnsError>;

/// Convert sbo:// URI to sbo+raw:// using DNS
pub async fn resolve_uri(uri: &str) -> Result<String, DnsError>;
```

---

## Repo Storage

**Updated structure:**

```rust
pub struct Repo {
    pub id: String,

    /// What user provided (string, could be sbo:// or sbo+raw://)
    pub display_uri: String,

    /// Resolved and parsed URI (always sbo+raw:// form)
    pub uri: SboUri,

    /// When DNS was last checked (None for sbo+raw:// URIs)
    pub dns_checked_at: Option<u64>,

    pub path: PathBuf,
    pub head: u64,
    pub created_at: u64,
}
```

**Storage file:** `~/.sbo/repos.json`

```json
[
  {
    "id": "abc123",
    "display_uri": "sbo://myapp.com/",
    "uri": {"chain": {"namespace": "avail", "reference": "mainnet"}, "app_id": 13, "path_prefix": null},
    "dns_checked_at": 1702500000,
    "path": "/home/user/my-repo",
    "head": 12345,
    "created_at": 1702400000
  }
]
```

---

## CLI Commands

### `sbo repo add`

```
sbo repo add sbo://myapp.com/ ./my-repo
```

1. Detect `sbo://` prefix
2. Resolve DNS: `_sbo.myapp.com` → `SboRecord`
3. Build `sbo+raw://` URI from record
4. Check for duplicates (error if same chain already tracked)
5. Store both `display_uri` and resolved `uri`
6. Show: "Resolved sbo://myapp.com/ → sbo+raw://avail:mainnet:13/"

### `sbo repo list`

Show display_uri, re-check DNS, warn on mismatch:

```
URI                          PATH              HEAD
sbo://myapp.com/             /home/user/repo1  12345
sbo+raw://avail:turing:506/  /home/user/repo2  9999

⚠ DNS mismatch: sbo://other.com/ now resolves to sbo+raw://avail:mainnet:99/
  (currently tracking sbo+raw://avail:mainnet:13/)
  Run 'sbo repo relink /home/user/other' to update
```

### `sbo repo status`

Re-check DNS, warn on mismatch:

```
sbo://myapp.com/
  Resolved:    sbo+raw://avail:mainnet:13/
  Path:        /home/user/repo1
  Head:        12345
  DNS checked: 2 hours ago ✓

⚠ DNS mismatch detected for sbo://other.com/
  Currently tracking: sbo+raw://avail:mainnet:13/
  DNS now resolves:   sbo+raw://avail:mainnet:99/
  Run 'sbo repo relink /home/user/other' to update
```

### `sbo repo relink <path>`

Accept DNS change:

1. Re-resolve DNS for that repo's `display_uri`
2. Update `uri` to new resolution
3. Reset `head` to 0 (or `firstBlock` from DNS record)
4. Warn: "Data will be re-synced from new chain"

---

## Daemon Startup

**On daemon start:**

1. Load repos from `repos.json`
2. For each repo with `sbo://` display_uri:
   - Re-resolve DNS
   - If mismatch: log warning, continue syncing old chain
   - Update `dns_checked_at` timestamp
3. Begin normal sync loop

**Log output example:**

```
INFO  Loaded 3 repositories
INFO  DNS check: sbo://myapp.com/ → sbo+raw://avail:mainnet:13/ ✓
WARN  DNS mismatch: sbo://other.com/ resolves to sbo+raw://avail:mainnet:99/
      but repo is tracking sbo+raw://avail:mainnet:13/
      Run 'sbo repo relink' to update
INFO  Starting sync...
```

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No `_sbo.` TXT record | Error: "Domain does not have SBO configured" |
| Malformed record | Error: "Invalid SBO record: missing {field}" |
| DNS timeout | Error: "DNS lookup failed (timeout)" |
| Multiple TXT records | Use first valid one, warn if multiple |
| `sbo=v2` (unknown version) | Error: "Unsupported SBO record version: v2" |
| Duplicate chain on add | Error: "Already tracking this chain as sbo+raw://..." |
| DNS unreachable (existing repo) | Use cached resolution, continue syncing |
| DNS unreachable (new repo add) | Error: "Cannot resolve DNS" |

---

## Files to Modify

| File | Changes |
|------|---------|
| `sbo-core/Cargo.toml` | Add `hickory-resolver` dependency |
| `sbo-core/src/lib.rs` | Export `dns` module |
| `sbo-core/src/dns.rs` | **New** - DNS resolution logic |
| `sbo-daemon/src/repo.rs` | Add `display_uri`, `dns_checked_at` to `Repo` |
| `sbo-daemon/src/main.rs` | DNS check on startup, handle `RepoRelink` IPC |
| `sbo-daemon/src/ipc.rs` | Add `RepoRelink` request type |
| `sbo-cli/src/main.rs` | Update `repo add/list/status`, add `repo relink` |
| `specs/SBO URI Specification v0.3.md` | Add `node`, `firstBlock` fields |

---

## Future Considerations

- **Caching:** DNS cache in `~/.sbo/dns-cache.json` with TTL (deferred)
- **Daemon DNS resolution:** When daemon becomes central service for auth, it will use same `sbo-core::dns` module
- **Browser extension:** Will talk to daemon for signing; daemon will need DNS resolution for identity URIs
