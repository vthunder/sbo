---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Identity Specification v0.1

**Status:** Draft

## Abstract

This specification defines how identities are established and resolved in SBO. It covers identity objects at `/sys/names/*`, domain objects at `/sys/domains/*`, and profile objects. Identities use a unified JWT format with a typed issuer field that distinguishes self-signed identities from domain-certified identities.

## Overview

SBO identities establish the binding between a human-readable name and a public key. The system supports two trust models:

- **Self-signed identities** - The identity holder signs their own identity claim. Used by sys, sovereign users, and repos not requiring domain certification.
- **Domain-certified identities** - A domain certifies the binding between an email address and a public key. Used for email-based authentication.

Both types use the same JWT schema, distinguished by the `iss` (issuer) field.

## Trust Hierarchy

```
Genesis
   │
   ├── Mode A: Self-signed sys
   │      │
   │      └── sys (iss: "self")
   │             │
   │             └── /sys/domains/* (policy-controlled)
   │                    │
   │                    └── /sys/names/* (domain-certified users)
   │
   └── Mode B: Domain-certified sys
          │
          └── /sys/domains/org.com (iss: "self", root of trust)
                 │
                 └── sys (iss: "domain:org.com")
                        │
                        └── /sys/names/* (domain-certified users)
```

See [SBO Genesis Specification](./SBO%20Genesis%20Specification%20v0.1.md) for bootstrap details.

## Identity Schema (`identity.v1`)

All identities use JWT format with `Content-Type: application/jwt` and `Content-Schema: identity.v1`.

### JWT Payload

```json
{
  "iss": "self" | "domain:<domain>",
  "sub": "<identifier>",
  "public_key": "ed25519:<hex>",
  "profile": "/path/to/profile",
  "iat": <unix-timestamp>
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | Issuer type: `"self"` or `"domain:<domain>"` |
| `sub` | string | Yes | Subject identifier (name or email) |
| `public_key` | string | Yes | Public key with algorithm prefix |
| `profile` | string | No | Path to profile object |
| `iat` | number | Yes | Issued-at timestamp (Unix seconds) |

### Issuer Types

| `iss` Value | Meaning | Verification |
|-------------|---------|--------------|
| `"self"` | Self-signed identity | JWT signed by `public_key` in payload |
| `"domain:example.com"` | Domain-certified | JWT signed by key from `/sys/domains/example.com` |

### Subject Format

| `iss` Type | `sub` Format | Example |
|------------|--------------|---------|
| `"self"` | Name only | `"alice"` |
| `"domain:X"` | Email address | `"alice@example.com"` |

### SBO Message

```
SBO-Version: 0.5
Action: post
Path: /sys/names/
ID: alice
Type: object
Content-Type: application/jwt
Content-Schema: identity.v1
Public-Key: ed25519:<USER_KEY>
Signature: <envelope-signature>

<JWT>
```

### Validation Rules

1. `Public-Key` header MUST match `public_key` in JWT payload
2. If `iss: "self"`:
   - JWT MUST be signed by `public_key` in payload
3. If `iss: "domain:<domain>"`:
   - Fetch `/sys/domains/<domain>`
   - JWT MUST be signed by that domain's public key
   - `sub` email domain MUST match `iss` domain
4. `ID` in SBO envelope SHOULD match the local part of `sub`

### Examples

**Self-signed identity:**

```json
{
  "iss": "self",
  "sub": "alice",
  "public_key": "ed25519:a1b2c3d4e5f6...",
  "profile": "/alice/profile",
  "iat": 1703001234
}
```

**Domain-certified identity:**

```json
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "public_key": "ed25519:a1b2c3d4e5f6...",
  "profile": "/alice/profile",
  "iat": 1703001234
}
```

## Domain Schema (`domain.v1`)

Domains establish public keys for organizations that certify user identities. Domain objects live at `/sys/domains/{domain}`.

### JWT Payload

```json
{
  "iss": "self",
  "sub": "<domain>",
  "public_key": "ed25519:<hex>",
  "iat": <unix-timestamp>
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | Always `"self"` (domains are self-signed) |
| `sub` | string | Yes | Domain name (e.g., `"example.com"`) |
| `public_key` | string | Yes | Domain's public key with algorithm prefix |
| `iat` | number | Yes | Issued-at timestamp (Unix seconds) |

### SBO Message

```
SBO-Version: 0.5
Action: post
Path: /sys/domains/
ID: example.com
Type: object
Content-Type: application/jwt
Content-Schema: domain.v1
Public-Key: ed25519:<DOMAIN_KEY>
Signature: <signature>

<JWT>
```

### Validation Rules

1. `iss` MUST be `"self"`
2. `sub` MUST match `ID` in SBO envelope
3. JWT MUST be signed by `public_key` in payload
4. `Public-Key` header MUST match `public_key` in payload

### Access Control

Creation of `/sys/domains/*` is policy-controlled. The default root policy grants this to sys only. Domains may be added by:
- sys directly creating the domain object
- Policy rules granting creation rights to other identities

## Profile Schema (`profile.v1`)

Profiles contain display information about an identity. The identity object's `profile` field points to the profile location.

### Payload

```json
{
  "display_name": "Alice Smith",
  "bio": "Software developer and open source enthusiast",
  "avatar": "/alice/avatar.png",
  "banner": "/alice/banner.jpg",
  "location": "San Francisco, CA",
  "links": {
    "website": "https://alice.example.com",
    "github": "https://github.com/alice"
  },
  "metadata": {
    "pronouns": "she/her"
  }
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | string | No | Human-readable name (max 100 chars) |
| `bio` | string | No | Short biography (max 500 chars) |
| `avatar` | string | No | SBO path or URL to avatar image |
| `banner` | string | No | SBO path or URL to banner image |
| `location` | string | No | Free-text location |
| `links` | object | No | Key-value pairs of named links |
| `metadata` | object | No | Arbitrary key-value pairs |

### SBO Message

```
SBO-Version: 0.5
Action: post
Path: /alice/
ID: profile
Type: object
Content-Type: application/json
Content-Schema: profile.v1
Public-Key: ed25519:<USER_KEY>
Signature: <signature>

<JSON payload>
```

### Validation Rules

1. Profile MUST be signed by the identity's public key
2. The signer's `Public-Key` MUST match the `public_key` in the identity that references this profile

### Path Conventions

Profiles may be stored at various paths. Common conventions:

| Pattern | Example | Use Case |
|---------|---------|----------|
| `/{name}/profile` | `/alice/profile` | User namespace |
| `/profiles/{name}` | `/profiles/alice` | Centralized collection |

The identity's `profile` field specifies the actual location.

## Resolution

### Resolving an Identity

```python
def resolve_identity(repo, name):
    # 1. Fetch identity object
    identity = fetch(repo, f"/sys/names/{name}")
    jwt = parse_jwt(identity.payload)

    # 2. Verify based on issuer type
    if jwt["iss"] == "self":
        # Self-signed: verify JWT signed by its own public_key
        verify_jwt_signature(identity.payload, jwt["public_key"])
    else:
        # Domain-certified: extract domain, verify against domain key
        domain = jwt["iss"].removeprefix("domain:")
        domain_key = resolve_domain(repo, domain)
        verify_jwt_signature(identity.payload, domain_key)

    # 3. Verify envelope matches JWT
    assert identity.headers["Public-Key"] == jwt["public_key"]

    return {
        "public_key": jwt["public_key"],
        "profile": jwt.get("profile")
    }
```

### Resolving a Domain

```python
def resolve_domain(repo, domain):
    # 1. Fetch domain object
    domain_obj = fetch(repo, f"/sys/domains/{domain}")
    jwt = parse_jwt(domain_obj.payload)

    # 2. Domains are always self-signed
    assert jwt["iss"] == "self"
    verify_jwt_signature(domain_obj.payload, jwt["public_key"])

    # 3. Verify envelope matches JWT
    assert domain_obj.headers["Public-Key"] == jwt["public_key"]

    return jwt["public_key"]
```

### Resolving a Profile

```python
def resolve_profile(repo, name):
    # 1. Resolve identity first
    identity = resolve_identity(repo, name)

    # 2. Check for profile link
    if not identity.get("profile"):
        return None

    # 3. Fetch and verify profile
    profile = fetch(repo, identity["profile"])
    assert profile.headers["Public-Key"] == identity["public_key"]

    return parse_json(profile.payload)
```

## DNS Discovery

Applications discover a domain's SBO repository and services via DNS:

```
_sbo.example.com. IN TXT "v=sbo1 r=sbo+raw://avail:turing:506/ h=https://sbo.example.com"
```

**Fields:**
- `v`: Protocol version (`sbo1`)
- `r`: Repository URI (required)
- `h`: Discovery host for `.well-known/sbo` (optional, defaults to domain itself)

**Resolution flow:**
1. Parse email domain from identity's `sub` field
2. Query DNS for `_sbo.<domain>` TXT record
3. Parse `r=` to get repository URI
4. Fetch identity and domain objects from that repository

## Service Discovery

The discovery host (from `h=` field, or the domain itself if omitted) serves a JSON document at `/.well-known/sbo`:

```
GET https://sbo.example.com/.well-known/sbo
```

```json
{
  "version": "1",
  "authentication": "/sbo/login",
  "provisioning": "/sbo/session",
  "provisioning_poll": "/sbo/session/poll"
}
```

**Fields:**
- `version`: Discovery document version (`"1"`)
- `authentication`: Path to user-visible login page
- `provisioning`: Path to session binding initiation endpoint
- `provisioning_poll`: Path to session binding poll endpoint (optional; defaults to `{provisioning}/poll`)

**Delegation:**

A domain may delegate authentication to another host by including an `authority` field:

```json
{
  "version": "1",
  "authority": "login.provider.com"
}
```

When `authority` is present, clients MUST fetch `/.well-known/sbo` from that host instead and use its endpoints.

**Multi-tenant hosts:**

When a discovery host serves multiple domains, endpoints accept a `?domain=` query parameter:

```
GET https://sbo.example.com/sbo/login?domain=example.com
POST https://sbo.example.com/sbo/session?domain=example.com
POST https://sbo.example.com/sbo/session/poll?domain=example.com
```

See [SBO Auth Specification](./SBO%20Auth%20Specification%20v0.1.md) for session binding details.

## Security Considerations

### Key Compromise

| Compromised Key | Impact | Recovery |
|-----------------|--------|----------|
| User key | Attacker can sign as user | Update identity with new key |
| Domain key | Attacker can certify identities | sys updates `/sys/domains/*` |
| sys key | Full compromise | No recovery (root of trust) |

### Recommendations

- Domain keys SHOULD be stored in HSMs
- sys key SHOULD be stored offline (cold storage)
- Users SHOULD store keys securely (hardware key, password manager)
- Applications SHOULD verify identity signatures before trusting content

## Privacy Considerations

- Identity objects are public (stored on-chain)
- Email addresses in domain-certified identities are visible
- Profile data is public by default
- Users should not include sensitive information in profiles

## References

- [SBO Specification v0.4](./SBO%20Specification%20v0.4.md)
- [SBO Wire Format Specification v0.1](./SBO%20Wire%20Format%20Specification%20v0.1.md)
- [SBO Genesis Specification v0.1](./SBO%20Genesis%20Specification%20v0.1.md)
- [SBO Auth Specification v0.1](./SBO%20Auth%20Specification%20v0.1.md)
- RFC 7519: JSON Web Token (JWT)
- RFC 8037: EdDSA Signatures in JOSE
