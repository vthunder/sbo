# SBO Reference Implementation Design

## Overview

A Rust implementation of the SBO specification serving three purposes:
1. **Spec validation** - Test that specs are implementable, find gaps
2. **Demo/showcase** - Working demo of SBO concepts
3. **Production foundation** - Starting point for real deployments

## Requirements

| Aspect | Choice |
|--------|--------|
| Language | Rust |
| Scope | Full client (parse, verify, index, sign, post, query) |
| DA Layer | Avail light client (app mode) |
| Crypto | ed25519 (initially) |
| Storage | RocksDB |
| Policies | Full policy.v2 evaluation |
| Structure | Cargo workspace (monorepo) |

## Architecture

Hybrid approach with three crates:

```
reference_impl/
├── Cargo.toml              # Workspace manifest
├── sbo-core/               # Everything spec-related
├── sbo-avail/              # DA layer integration
└── sbo-cli/                # Command-line interface
```

## Crate: sbo-core

Core library containing all SBO logic.

### Module Structure

```
sbo-core/src/
├── lib.rs              # Public API re-exports
├── wire/               # Wire format parsing/serialization
│   ├── mod.rs
│   ├── parser.rs       # Parse raw bytes → Message
│   ├── serializer.rs   # Message → raw bytes
│   └── headers.rs      # Header types and validation
├── crypto/             # Cryptographic operations
│   ├── mod.rs
│   ├── ed25519.rs      # Signing and verification
│   └── hash.rs         # SHA256, content hashing
├── message/            # Message types and validation
│   ├── mod.rs
│   ├── envelope.rs     # SBO message envelope
│   ├── actions.rs      # post, transfer, delete, import
│   └── validate.rs     # Message-level validation
├── policy/             # Policy evaluation
│   ├── mod.rs
│   ├── types.rs        # Grant, Restriction, Role
│   ├── evaluate.rs     # Policy evaluation logic
│   └── path.rs         # Path pattern matching
├── state/              # State management
│   ├── mod.rs
│   ├── db.rs           # RocksDB wrapper
│   ├── objects.rs      # Object CRUD
│   └── names.rs        # Identity resolution
├── indexer.rs          # Block processing
├── genesis.rs          # Genesis block handling
└── error.rs            # Error types
```

### Core Types

```rust
// Identifiers (validated at construction)
pub struct Id(String);           // 1-256 chars, RFC 3986 unreserved
pub struct Path(Vec<Id>);        // e.g., "/alice/nfts/"
pub struct ObjectRef { path: Path, creator: Option<Id>, id: Id }

// Actions
pub enum Action {
    Post,
    Transfer { new_owner: Option<Id>, new_path: Option<Path>, new_id: Option<Id> },
    Delete,
    Import { origin: String, registry_path: Path, object_path: Path, attestation: Vec<u8> },
}

// Message envelope
pub struct Message {
    pub action: Action,
    pub path: Path,
    pub id: Id,
    pub object_type: ObjectType,  // Object | Collection
    pub content_type: Option<String>,
    pub content_hash: Option<ContentHash>,
    pub payload: Option<Vec<u8>>,
    pub signing_key: PublicKey,
    pub signature: Signature,
    // Optional headers
    pub owner: Option<Id>,
    pub creator: Option<Id>,
    pub policy_ref: Option<String>,
    pub related: Option<Vec<Related>>,
}

// Crypto
pub struct PublicKey { algo: KeyAlgo, bytes: [u8; 32] }
pub struct Signature([u8; 64]);
pub struct ContentHash { algo: HashAlgo, bytes: [u8; 32] }

// Stored state
pub struct StoredObject {
    pub path: Path,
    pub id: Id,
    pub creator: Id,
    pub owner: Id,
    pub content_hash: ContentHash,
    pub payload: Vec<u8>,
    pub policy_ref: Option<String>,
    pub block_number: u64,
}
```

### Wire Format

Parser converts raw bytes to validated Message:
1. Split at blank line (double LF)
2. Parse headers line by line (reject CRLF)
3. Validate required headers exist
4. Build Message from headers
5. Validate payload (Content-Length, Content-Hash)

Serializer outputs headers in canonical order per Wire Format spec.

### Signature Verification

1. Reconstruct canonical header block (without Signature header)
2. Append blank line
3. Verify ed25519 signature over those bytes
4. Content hash already verified during parsing

### Policy Evaluation

Order: deny → grants → restrictions

```rust
pub struct Policy {
    pub roles: HashMap<String, Vec<Identity>>,
    pub deny: Vec<PathPattern>,
    pub grants: Vec<Grant>,
    pub restrictions: Vec<Restriction>,
}

pub fn evaluate(policy, actor, action, target, message) -> PolicyResult {
    // 1. Check deny list
    // 2. Find matching grant
    // 3. Check restrictions
}
```

Path patterns like `/$owner/**` resolved dynamically.

### State Management

RocksDB with column families:
- `objects`: (path, creator, id) → StoredObject
- `by_owner`: (owner, path, id) → () [index]
- `policies`: path → Policy [cached]
- `names`: name → IdentityClaim
- `meta`: last_block, genesis_hash

### Indexer

```rust
pub struct Indexer<D: DataAvailability> {
    da: D,
    state: StateDb,
}

// For each block:
// 1. Parse wire format
// 2. Verify signature
// 3. Resolve policy (walk up path hierarchy)
// 4. Determine actor (signer's identity)
// 5. Evaluate policy
// 6. Apply state change
// Invalid messages are skipped per spec
```

## Crate: sbo-avail

DA layer integration.

```rust
pub trait DataAvailability {
    async fn stream_blocks(&self, from: u64) -> impl Stream<Item = Block>;
    async fn submit(&self, data: &[u8]) -> Result<SubmitResult, DaError>;
    async fn get_block(&self, number: u64) -> Result<Option<Block>, DaError>;
}

pub struct AvailClient {
    light_client: LightClient,  // avail-light-client-lib
    app_id: u32,
}
```

Trait allows mocking for tests. TurboDA would be a separate implementation.

## Crate: sbo-cli

Command-line interface.

### URI Commands (Object Operations)

```
sbo uri get <uri>                              # Get an object by SBO URI
sbo uri post <uri> <file> [--content-type]     # Post an object
sbo uri list <uri>                             # List objects at path
sbo uri transfer <uri> [--new-path] [--new-id] # Transfer/move/rename
```

Example URIs: `sbo+raw://avail:turing:506/alice/nfts/token1`

### Debug Commands

```
sbo debug da stream --from <N> [--limit <N>] [--raw]   # Stream raw blocks
sbo debug da submit --preset <NAME>                     # Submit test payload
sbo debug da submit --file <PATH>                       # Submit custom payload
sbo debug da ping                                       # Check DA connection
sbo debug da scan <block>                               # Scan a specific block
sbo debug da status <submission-id>                     # Check TurboDA status
```

DA test presets:
- `hello` - Simple bytes (not SBO)
- `genesis` - Valid genesis (/sys/names/sys + /sys/policies/root)
- `post` - Valid SBO post message
- `transfer` - Valid SBO transfer message
- `collection` - Valid SBO collection creation
- `invalid` - Intentionally malformed SBO

## Dependencies

```toml
[workspace.dependencies]
ed25519-dalek = "2"
sha2 = "0.10"
rocksdb = "0.22"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
thiserror = "1"
tracing = "0.1"
clap = { version = "4", features = ["derive"] }
hex = "0.4"
```

## Testing Strategy

- Unit tests per module (wire parsing, crypto, policy evaluation)
- Integration tests with mock DA layer
- Golden tests with canonical test vectors
- Property tests for roundtrip parsing/serialization

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum SboError {
    Parse(ParseError),
    Validation(ValidationError),
    Crypto(CryptoError),
    PolicyDenied(String),
    Db(DbError),
    Da(DaError),
}
```

Each module has specific error types with detailed variants.
