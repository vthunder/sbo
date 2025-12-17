# SBO Identity Specification v0.1

**Status:** Draft
**Date:** 2024-12-13

## Abstract

This specification defines a protocol for web authentication using SBO (Signed Blockchain Objects) identities. It enables users to authenticate to web applications using cryptographic signatures, with identity discovery via DNS and HTTPS, and identity data stored on SBO.

## Overview

The protocol has three layers:

1. **Discovery Layer** - DNS and HTTPS endpoints that map email-style identifiers to SBO URIs
2. **Identity Layer** - SBO objects containing signing keys and optional profile data
3. **Authentication Layer** - Challenge-response protocol proving key ownership

## 1. Discovery Layer

### 1.1 DNS Record

Domains that support SBO identity discovery MUST publish a DNS TXT record:

```
_sbo-id.domain.com TXT "v=sbo-id1 host=<hostname>"
```

**Fields:**
- `v=sbo-id1` - Protocol version (required)
- `host=<hostname>` - Host serving the identity discovery endpoint (required)

**Examples:**
```
_sbo-id.example.com TXT "v=sbo-id1 host=example.com"
_sbo-id.bigcorp.com TXT "v=sbo-id1 host=identity.bigcorp.com"
```

The DNS record serves two purposes:
1. Indicates the domain supports SBO identity discovery
2. Specifies which host handles discovery requests (may differ from the email domain)

### 1.2 Well-Known Endpoint

The discovery host MUST serve an HTTPS endpoint at:

```
GET https://<host>/.well-known/sbo-identity?user=<username>
```

**Request:**
- Method: GET
- Query parameter `user`: The local part of the email address (before @)

**Response (Success):**
```json
{
  "version": 1,
  "sbo_uri": "sbo://avail:mainnet:123/path/to/identity"
}
```

**Response (User Not Found):**
```json
{
  "version": 1,
  "error": "not_found",
  "message": "User not found"
}
```

**Response (Feature Disabled):**
```json
{
  "version": 1,
  "error": "disabled",
  "message": "SBO identity not configured for this user"
}
```

**HTTP Status Codes:**
- `200 OK` - Success (includes error responses in JSON body)
- `400 Bad Request` - Missing or invalid user parameter
- `404 Not Found` - Endpoint not implemented
- `429 Too Many Requests` - Rate limited
- `500 Internal Server Error` - Server error

**CORS:**
The endpoint SHOULD include CORS headers to allow browser-based discovery:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET
```

### 1.3 Discovery Flow

To discover the SBO identity for `alice@domain.com`:

1. Query DNS for `_sbo-id.domain.com` TXT record
2. If no record exists, discovery fails (domain does not support SBO identity)
3. Parse the `host` field from the DNS record
4. Request `https://<host>/.well-known/sbo-identity?user=alice`
5. Parse the `sbo_uri` from the response

**Security Note:** Implementations MUST NOT trust `.well-known` responses without first verifying the DNS record exists. This prevents attacks where a malicious actor on shared hosting creates fake discovery responses.

## 2. Identity Layer

### 2.1 Identity Object

The SBO object at the discovered URI contains the user's identity information.

**Schema:** `identity.v1`

**Required Fields:**
```json
{
  "public_key": "ed25519:<hex-encoded-public-key>"
}
```

**All Fields:**
```json
{
  "public_key": "ed25519:abc123...",
  "display_name": "Alice Smith",
  "description": "Main identity for Alice",
  "avatar": "/alice/avatar.png",
  "links": {
    "website": "https://alice.example.com",
    "github": "https://github.com/alice"
  },
  "binding": "sbo://avail:mainnet:42/sys/names/alice"
}
```

**Field Definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | Public key in `algorithm:hex` format (e.g., `ed25519:abc...`) |
| `display_name` | string | No | Human-readable name |
| `description` | string | No | Text description of this identity |
| `avatar` | string | No | Relative SBO path or absolute URL to avatar image |
| `links` | object | No | Key-value pairs of named links |
| `binding` | string | No | SBO URI to a canonical identity on another chain/app (for cross-chain resolution) |

**Example SBO Message:**
```
SBO-Version: 1
Action: Create
Path: /alice/
Id: identity
Content-Type: application/json
Content-Schema: identity.v1
Public-Key: ed25519:abc123...
Signature: <signature>

{
  "public_key": "ed25519:abc123...",
  "display_name": "Alice",
  "avatar": "/alice/avatar.png"
}
```

### 2.2 Identity Ownership

The identity object MUST be signed by the private key associated with `public_key`. This proves the identity creator controls the private key.

Verifiers MUST check that the SBO message's `Public-Key` header matches the `public_key` field in the payload.

### 2.3 Domain Identity (Optional)

Domains MAY publish their own identity object for domain-level operations:

**Path Convention:** `/sys/domain/identity`

**Schema:** `domain.v1`

```json
{
  "domain": "example.com",
  "public_key": "ed25519:def456...",
  "admin_contact": "admin@example.com"
}
```

This enables:
- Domain-level attestations
- Verifying domain signatures
- Trust chain establishment

## 3. Authentication Layer

### 3.1 Challenge-Response Protocol

Authentication uses a challenge-response protocol:

1. **App generates challenge** - Random nonce with expiration
2. **User signs assertion** - Signs challenge with identity key
3. **App verifies assertion** - Checks signature against identity object

### 3.2 Challenge Format

Apps SHOULD generate challenges as:

```json
{
  "challenge": "<random-nonce>",
  "origin": "https://app.example.com",
  "expires_at": 1702500300
}
```

**Requirements:**
- `challenge`: Minimum 16 bytes of cryptographically random data, hex or base64 encoded
- `origin`: The requesting application's origin
- `expires_at`: Unix timestamp, SHOULD be 5 minutes or less from issuance

### 3.3 Assertion Format

The signed assertion contains:

```json
{
  "version": 1,
  "identity_uri": "sbo://avail:mainnet:123/alice/identity",
  "origin": "https://app.example.com",
  "challenge": "<challenge-from-app>",
  "issued_at": 1702500000,
  "expires_at": 1702500300,
  "public_key": "ed25519:abc123...",
  "signature": "<hex-encoded-signature>"
}
```

**Field Definitions:**

| Field | Type | Description |
|-------|------|-------------|
| `version` | number | Protocol version (1) |
| `identity_uri` | string | Full SBO URI of identity object |
| `origin` | string | Origin of requesting application |
| `challenge` | string | Challenge from application |
| `issued_at` | number | Unix timestamp of assertion creation |
| `expires_at` | number | Unix timestamp of assertion expiration |
| `public_key` | string | Public key used to sign |
| `signature` | string | Hex-encoded signature |

**Signature Computation:**

The signature is computed over the canonical JSON encoding of all fields except `signature`:

```
message = canonical_json({
  "version": 1,
  "identity_uri": "...",
  "origin": "...",
  "challenge": "...",
  "issued_at": ...,
  "expires_at": ...,
  "public_key": "..."
})
signature = ed25519_sign(private_key, message)
```

Canonical JSON: Keys sorted alphabetically, no whitespace, UTF-8 encoded.

### 3.4 Verification Steps

To verify an assertion:

1. **Check expiration:** `expires_at` > current time
2. **Check origin:** `origin` matches the verifying application's origin
3. **Check challenge:** `challenge` matches what the application issued
4. **Fetch identity:** Retrieve SBO object at `identity_uri`
5. **Check key match:** `public_key` in assertion matches `public_key` in identity object
6. **Verify signature:** Ed25519 signature is valid for the assertion message

If any check fails, reject the authentication.

## 4. Browser Integration

### 4.1 JavaScript API

Implementations SHOULD provide a `navigator.credentials`-compatible API:

```javascript
// Request authentication
const assertion = await navigator.credentials.get({
  sbo: {
    identity: "sbo://avail:mainnet:123/alice/identity",
    challenge: "server-provided-nonce"
  }
});

// Check if SBO credentials are available
if ('sbo' in CredentialRequestOptions) {
  // SBO identity supported
}
```

### 4.2 Polyfill Architecture

Browser support MAY be provided via polyfill with the following architecture:

```
┌─────────────────────────────────────────┐
│ Web Application                         │
│                                         │
│   navigator.credentials.get({sbo:...})  │
│              │                          │
│              ▼                          │
│   ┌─────────────────────────────────┐   │
│   │ sbo-identity-polyfill.js        │   │
│   │                                 │   │
│   │ Communicates via postMessage    │   │
│   └───────────────┬─────────────────┘   │
│                   │                     │
│   ┌───────────────▼─────────────────┐   │
│   │ <iframe src="https://           │   │
│   │   sbo-identity-provider.com/    │   │
│   │   signer">                      │   │
│   │                                 │   │
│   │ - Stores encrypted keyring      │   │
│   │ - Signs assertions              │   │
│   │ - Prompts for password          │   │
│   └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

The iframe-based signer:
- Stores the encrypted keyring in its origin's localStorage
- Receives signing requests via postMessage
- Returns signed assertions
- Provides UI for key management

### 4.3 Auto-Login

For automatic authentication on return visits:

**Site Declaration:**
```html
<meta name="sbo-auth" content="challenge-endpoint=/api/sbo/challenge">
```

Or HTTP header:
```
SBO-Auth: challenge-endpoint=/api/sbo/challenge
```

**Challenge Endpoint Response:**
```json
{
  "challenge": "<nonce>",
  "expires_at": 1702500300
}
```

**Flow:**
1. User configures "auto-login" for a site in their identity provider
2. On page load, polyfill detects site supports SBO auth
3. If site is in auto-login list, polyfill fetches challenge
4. Polyfill signs assertion and submits to site
5. Site verifies and establishes session

## 5. Security Considerations

### 5.1 DNS Security

- DNSSEC SHOULD be used to protect DNS records from spoofing
- Implementations SHOULD cache DNS results per standard TTL rules
- DNS lookup failures SHOULD be treated as "identity discovery not supported"

### 5.2 HTTPS Security

- All discovery endpoints MUST use HTTPS
- Certificate validation MUST be performed
- Implementations SHOULD reject self-signed certificates

### 5.3 Challenge Freshness

- Challenges MUST be single-use
- Challenges SHOULD expire within 5 minutes
- Servers MUST track issued challenges to prevent replay

### 5.4 Key Storage

- Private keys SHOULD be encrypted at rest
- Keys SHOULD NOT be extractable by web pages
- Hardware security modules or platform authenticators MAY be used

### 5.5 Phishing Resistance

- Assertions are bound to origin, preventing use on other sites
- Users SHOULD verify the origin before signing
- Identity providers SHOULD display the requesting origin prominently

## 6. Privacy Considerations

### 6.1 Identity Correlation

- SBO identities are public and linkable across sites
- Users concerned about correlation SHOULD use different identities per site
- Identity providers MAY offer derived identities per origin

### 6.2 Discovery Privacy

- DNS and .well-known queries may reveal user identity to network observers
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) SHOULD be used
- Discovery requests could be proxied for additional privacy

## 7. Examples

### 7.1 Complete Authentication Flow

```
User: alice@example.com

1. DNS Query
   _sbo-id.example.com → "v=sbo-id1 host=id.example.com"

2. Discovery Request
   GET https://id.example.com/.well-known/sbo-identity?user=alice
   Response: {"version":1,"sbo_uri":"sbo://avail:mainnet:42/alice/identity"}

3. Fetch Identity
   GET sbo://avail:mainnet:42/alice/identity
   Response: {"public_key":"ed25519:abc123...","display_name":"Alice"}

4. Generate Challenge
   App creates: {"challenge":"x7k9m2...","origin":"https://app.com","expires_at":1702500300}

5. User Signs Assertion
   Assertion: {
     "version": 1,
     "identity_uri": "sbo://avail:mainnet:42/alice/identity",
     "origin": "https://app.com",
     "challenge": "x7k9m2...",
     "issued_at": 1702500000,
     "expires_at": 1702500300,
     "public_key": "ed25519:abc123...",
     "signature": "def456..."
   }

6. App Verifies
   - Check timestamps ✓
   - Check origin matches ✓
   - Check challenge matches ✓
   - Fetch identity, check key matches ✓
   - Verify signature ✓

7. Authentication Complete
   App creates session for alice@example.com
```

### 7.2 DNS and Well-Known Setup

**DNS Record:**
```
_sbo-id.example.com. 3600 IN TXT "v=sbo-id1 host=example.com"
```

**Nginx Configuration:**
```nginx
location /.well-known/sbo-identity {
    add_header Access-Control-Allow-Origin *;
    add_header Content-Type application/json;

    # Proxy to identity service or serve static files
    proxy_pass http://identity-service/lookup;
}
```

**Static File Structure:**
```
/.well-known/sbo-identity/
  alice.json  → {"version":1,"sbo_uri":"sbo://..."}
  bob.json    → {"version":1,"sbo_uri":"sbo://..."}
```

With URL rewriting:
```nginx
location /.well-known/sbo-identity {
    rewrite ^/.well-known/sbo-identity$ /.well-known/sbo-identity/index.php?user=$arg_user last;
    # Or for static:
    try_files /.well-known/sbo-identity/$arg_user.json =404;
}
```

## 8. References

- [SBO Specification](./SBO%20Specification%20v0.4.md)
- [SBO URI Specification](./SBO%20URI%20Specification%20v0.3.md)
- [RFC 8615 - Well-Known URIs](https://tools.ietf.org/html/rfc8615)
- [Web Authentication (WebAuthn)](https://www.w3.org/TR/webauthn/)
- [Ed25519 Signatures](https://ed25519.cr.yp.to/)

## Appendix A: Comparison with Existing Standards

| Feature | SBO Identity | WebAuthn | OAuth/OIDC |
|---------|--------------|----------|------------|
| Key storage | User-controlled | Platform | Provider |
| Identity portability | High | Low | Medium |
| Requires provider | No | No | Yes |
| Phishing resistance | Yes (origin-bound) | Yes | Partial |
| Setup complexity | Medium | Low | Low |
| Decentralized | Yes | No | No |

## Appendix B: Future Extensions

The following features are planned for future versions:

1. **Attestations** - Third-party attestations about identity properties
2. **Delegation** - Authorizing applications to act on behalf of user
3. **Key Rotation** - Protocol for rotating signing keys
4. **Recovery** - Social or backup key recovery mechanisms
5. **Encryption** - Adding encryption keys for private messaging
