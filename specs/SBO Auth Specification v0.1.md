---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Auth Specification v0.1

**Status:** Draft

## Abstract

This specification defines a protocol for web authentication using SBO identities. Users authenticate using email addresses as identifiers, with nested JWT structures where user delegations are wrapped by domain endorsements. The protocol provides:

- Flexible custody models (domain-custodied to full self-custody)
- Privacy preservation (domains don't see which apps users visit)
- Short-lived sessions without on-chain transactions
- User's key cryptographically involved in all modes
- Domain endorsement of session bindings

This specification builds on the [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md) which defines identity and domain objects.

## Overview

SBO Auth uses **nested JWTs** for web authentication. The user signs a delegation to an ephemeral session key, and the domain wraps that delegation in a **session binding certificate** that endorses it.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   TRUSTED ROOTS (on-chain)                                               │
│                                                                          │
│   /sys/names/alice ─────────────── /sys/domains/example.com              │
│   (contains user's public key)     (contains domain's public key)        │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   SESSION BINDING CERTIFICATE (off-chain, short-lived)                   │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────┐     │
│   │  Domain Wrapper (signed by DOMAIN_KEY)                         │     │
│   │  { iss: domain, sub: email, user_delegation: ... }             │     │
│   │                                                                │     │
│   │   ┌────────────────────────────────────────────────────────┐   │     │
│   │   │  User Delegation (signed by USER_KEY)                  │   │     │
│   │   │  { iss: user_key, delegate_to: ephemeral_key }         │   │     │
│   │   └────────────────────────────────────────────────────────┘   │     │
│   └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   AUTH ASSERTION (per-request)                                           │
│                                                                          │
│   EPHEMERAL_KEY signs { iss: email, aud, nonce, iat }                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Terminology

| Term | Definition |
|------|------------|
| **User delegation** | A JWT signed by the user's key, delegating to an ephemeral key |
| **Session binding certificate** | A JWT signed by the domain, wrapping a user delegation |
| **Ephemeral key** | A short-lived key generated per-session for signing assertions |
| **Auth assertion** | A JWT signed by the ephemeral key proving identity to an application |
| **Trusted root** | A user key or domain key that can be verified on-chain |

For identity-related terms (domain, identity, user key), see the [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md).

## Identity and Custody

A user's identity object at `/sys/names/<name>` contains their public key. The identity JWT is always signed by the domain's key (as specified in the Identity Specification).

**Custody** refers to who controls the private key corresponding to the public key in the identity:

| Mode | Who controls user's private key |
|------|--------------------------------|
| Self-custody | User (via CLI, extension, etc.) |
| Domain-custodied | Domain (on behalf of user) |

The protocol is identical in both modes. The only difference is who signs the user delegation JWT.

## User Delegation

The user delegation is a JWT that authorizes an ephemeral key to act on the user's behalf.

### JWT Format

**Signed by USER_KEY:**
```json
{
  "iss": "ed25519:<USER_PUBLIC_KEY>",
  "delegate_to": "ed25519:<EPHEMERAL_KEY>",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | User's public key with algorithm prefix |
| `delegate_to` | string | Yes | Ephemeral key with algorithm prefix |
| `iat` | number | Yes | Issued-at timestamp |
| `exp` | number | Yes | Expiration timestamp |

### Requirements

- `iss` MUST be the user's public key (from their identity object)
- `delegate_to` MUST be the ephemeral key that will sign assertions
- `exp` SHOULD be no more than 24 hours from `iat`
- The JWT MUST be signed by the private key corresponding to `iss`

## Session Binding Certificate

The session binding certificate is a JWT signed by the domain that wraps and endorses a user delegation.

### JWT Format

**Signed by DOMAIN_KEY:**
```json
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "user_delegation": "<USER_DELEGATION_JWT>",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | Domain identifier: `"domain:<domain>"` |
| `sub` | string | Yes | User's email address |
| `user_delegation` | string | Yes | The user delegation JWT (complete, signed) |
| `iat` | number | Yes | Issued-at timestamp |
| `exp` | number | Yes | Expiration timestamp |

### Requirements

- `iss` MUST be `domain:<domain>` where `<domain>` matches the email domain in `sub`
- `sub` MUST be the user's email address
- `user_delegation` MUST be a valid, signed user delegation JWT
- `exp` SHOULD be no more than 24 hours from `iat`
- `exp` SHOULD NOT exceed the `exp` of the wrapped user delegation
- The JWT MUST be signed by the domain's key (from `/sys/domains/<domain>`)

## Auth Assertion

The assertion is what the user presents to authenticate to an application. It is signed by the ephemeral key.

### JWT Format

**Signed by EPHEMERAL_KEY:**
```json
{
  "iss": "alice@example.com",
  "aud": "https://app.example.com",
  "nonce": "xyz789",
  "iat": 1703001300
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | User's email address |
| `aud` | string | Yes | Application origin (audience) |
| `nonce` | string | Yes | Challenge provided by application |
| `iat` | number | Yes | Issued-at timestamp |

### Requirements

- `aud` MUST match the requesting application's origin
- `nonce` MUST match the challenge provided by the application
- `iat` MUST be recent (applications SHOULD reject assertions older than 5 minutes)
- `iss` MUST match the `sub` field from the session binding certificate

## Flows

### Session Binding Issuance

The session binding flow works identically for browser and CLI clients. The only difference is how the client handles the verification step.

```
┌──────────┐                              ┌──────────────┐
│  Client  │                              │  domain.com  │
│(Browser/ │                              │              │
│  CLI)    │                              │              │
└────┬─────┘                              └──────┬───────┘
     │                                           │
     │  1. Generate ephemeral keypair            │
     │                                           │
     │  2. Request session binding               │
     │     POST /.well-known/sbo/session         │
     │     { email, ephemeral_public_key,        │
     │       user_delegation? }                  │
     │  ─────────────────────────────────────────>
     │                                           │
     │  3. Receive request_id + verification_uri │
     │  <─────────────────────────────────────────
     │                                           │
     │  4. Direct user to verification_uri       │
     │     Browser: open popup                   │
     │     CLI: print URL for user               │
     │                                           │
     │  5. User authenticates at domain          │
     │     (if not already logged in)            │
     │                                           │
     │  6. Poll for result                       │
     │     POST /.well-known/sbo/session/poll    │
     │     { request_id }                        │
     │  ─────────────────────────────────────────>
     │                                           │
     │  7. Receive session_binding (when ready)  │
     │  <─────────────────────────────────────────
     │                                           │
     │  8. Client stores:                        │
     │     - ephemeral private key               │
     │     - session binding certificate         │
     │                                           │
```

**Domain-custodied mode:** Omit `user_delegation`. Domain signs both user delegation and session binding.

**Self-custody mode:** Include `user_delegation` (signed by user's key). Domain verifies and wraps it.

### Authentication

Once the client has a session binding certificate, it can authenticate to applications:

```
┌──────────┐                    ┌─────────┐                    ┌───────┐
│  Client  │                    │   App   │                    │  SBO  │
└────┬─────┘                    └────┬────┘                    └───┬───┘
     │                               │                             │
     │  1. Click "Login with SBO"    │                             │
     │  ─────────────────────────────>                             │
     │                               │                             │
     │  2. Challenge                 │                             │
     │     { nonce, origin }         │                             │
     │  <─────────────────────────────                             │
     │                               │                             │
     │  3. Sign assertion with       │                             │
     │     EPHEMERAL_KEY             │                             │
     │                               │                             │
     │  4. Send:                     │                             │
     │     - assertion JWT           │                             │
     │     - session binding cert    │                             │
     │  ─────────────────────────────>                             │
     │                               │                             │
     │                               │  5. Verify session binding: │
     │                               │     - Fetch domain key      │
     │                               │  ─────────────────────────────>
     │                               │                             │
     │                               │  6. Verify user key:        │
     │                               │     - Find identity by key  │
     │                               │  ─────────────────────────────>
     │                               │                             │
     │                               │  7. Verify nested structure │
     │                               │     + assertion             │
     │                               │                             │
     │  8. Auth success              │                             │
     │     user = alice@example.com  │                             │
     │  <─────────────────────────────                             │
     │                               │                             │
```

## Verification Algorithm

```python
def verify_auth(assertion_jwt, session_binding_cert, expected_nonce, expected_aud):
    # 1. Parse session binding certificate (outer JWT)
    session_binding = decode_jwt(session_binding_cert)

    # 2. Verify domain signature
    assert session_binding["iss"].startswith("domain:"), "Invalid issuer"
    domain = session_binding["iss"].removeprefix("domain:")
    domain_key = fetch_domain_key(domain)  # From /sys/domains/<domain>
    verify_jwt_signature(session_binding_cert, domain_key)

    # 3. Check session binding expiry
    assert session_binding["exp"] > now(), "Session binding expired"

    # 4. Extract and parse user delegation (inner JWT)
    user_delegation_jwt = session_binding["user_delegation"]
    user_delegation = decode_jwt(user_delegation_jwt)

    # 5. Verify user signature
    user_key = user_delegation["iss"]
    assert user_key.startswith("ed25519:"), "Invalid user key format"
    verify_jwt_signature(user_delegation_jwt, parse_public_key(user_key))

    # 6. Check user delegation expiry
    assert user_delegation["exp"] > now(), "User delegation expired"

    # 7. Verify user key is registered on-chain
    identity = fetch_identity_by_public_key(user_key)  # From /sys/names/*
    assert identity is not None, "Unknown user key"

    # 8. Verify email domain matches
    email = session_binding["sub"]
    email_domain = email.split("@")[1]
    assert email_domain == domain, "Email domain mismatch"

    # 9. Parse and verify assertion
    assertion = decode_jwt(assertion_jwt)
    ephemeral_key = get_signing_key(assertion_jwt)
    verify_jwt_signature(assertion_jwt, ephemeral_key)

    # 10. Verify assertion claims
    assert assertion["nonce"] == expected_nonce, "Nonce mismatch"
    assert assertion["aud"] == expected_aud, "Audience mismatch"
    assert assertion["iat"] > now() - 300, "Assertion too old"
    assert assertion["iss"] == email, "Email mismatch"

    # 11. Verify ephemeral key matches delegation
    assert user_delegation["delegate_to"] == f"ed25519:{ephemeral_key}", \
        "Ephemeral key mismatch"

    return {
        "email": email,
        "user_key": user_key,
        "domain": domain
    }


def fetch_domain_key(domain):
    """Fetch domain's public key from SBO repository."""
    dns_record = lookup_dns(f"_sbo.{domain}")
    repo_uri = parse_sbo_dns(dns_record)
    return fetch_key_from_repo(repo_uri, f"/sys/domains/{domain}")
```

## Service Discovery

Applications discover a domain's SBO services via DNS and the `.well-known/sbo` document. See [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md#dns-discovery) for the full discovery flow.

The discovery document provides:
- `authentication`: Path to user-visible login page
- `provisioning`: Path to session binding endpoint

For multi-tenant hosts, all endpoints accept a `?domain=` query parameter.

## Session Endpoint

The session endpoint issues session binding certificates. It uses a two-phase flow that works identically for browsers and CLI clients.

### Phase 1: Request Session Binding

```
POST /.well-known/sbo/session?domain=example.com
Content-Type: application/json

{
  "email": "alice@example.com",
  "ephemeral_public_key": "ed25519:abc123...",
  "user_delegation": "<optional: user-signed delegation JWT>"
}
```

**Response:**
```json
{
  "request_id": "Gmh8f3xK...",
  "verification_uri": "https://auth.example.com/verify?domain=example.com&req=Gmh8f3xK...",
  "expires_in": 900
}
```

The client must direct the user to `verification_uri` to authenticate (if not already authenticated).

### Phase 2: Poll for Result

```
POST /.well-known/sbo/session/poll?domain=example.com
Content-Type: application/json

{
  "request_id": "Gmh8f3xK..."
}
```

**Response (pending):**
```json
{
  "status": "pending"
}
```

**Response (success):**
```json
{
  "status": "complete",
  "session_binding": "<session binding certificate JWT>"
}
```

**Response (expired/error):**
```json
{
  "status": "expired"
}
```

### Custody Modes

| `user_delegation` | Mode | Domain behavior |
|-------------------|------|-----------------|
| Omitted | Domain-custodied | Domain signs user delegation, wraps in session binding |
| Provided | Self-custody | Domain verifies user delegation, wraps in session binding |

When `user_delegation` is provided (self-custody):
- Domain MUST verify the signature is valid
- Domain MUST verify `iss` matches the user's registered public key
- Domain MUST verify `delegate_to` matches `ephemeral_public_key`
- Domain MUST verify the delegation is not expired

## Revocation

### Session Binding Revocation

Session binding certificates are short-lived (recommended 24h maximum). Revocation is handled by expiry. If immediate revocation is required:

1. Domain rotates domain key (updates `/sys/domains/<domain>`)
2. All outstanding session bindings become invalid
3. Users must obtain new session binding certificates

### User Key Revocation

For self-custody users who need to revoke their key:

1. User updates their identity at `/sys/names/<name>` with new key
2. Old user delegations fail verification (key no longer matches on-chain)

## Browser Integration

### Polyfill Architecture

Browser support MAY be provided via polyfill:

```
┌─────────────────────────────────────────┐
│ Web Application                         │
│                                         │
│   sboAuth.login("alice@domain.com")     │
│              │                          │
│              ▼                          │
│   ┌─────────────────────────────────┐   │
│   │ sbo-auth-polyfill.js            │   │
│   │                                 │   │
│   │ - Discovers domain services     │   │
│   │ - Opens verification popup      │   │
│   │ - Polls for session binding     │   │
│   │ - Signs assertions              │   │
│   └───────────────┬─────────────────┘   │
│                   │                     │
│   ┌───────────────▼─────────────────┐   │
│   │ <iframe src="https://           │   │
│   │   sbo-auth-provider.com/        │   │
│   │   signer">                      │   │
│   │                                 │   │
│   │ - Stores ephemeral keys         │   │
│   │ - Manages session bindings      │   │
│   └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

The polyfill:
1. Fetches `.well-known/sbo` from the domain's discovery host
2. Posts to provisioning endpoint, gets `request_id` + `verification_uri`
3. Opens `verification_uri` in a popup for user authentication
4. Polls until session binding is ready
5. Closes popup, stores session binding in iframe

### JavaScript API

```javascript
// Initialize
const sbo = new SBOAuth({
  provider: "https://sbo-auth-provider.com"
});

// Request authentication
const result = await sbo.login({
  email: "alice@domain.com",
  audience: window.location.origin,
  nonce: serverProvidedNonce
});

// Returns: { assertion_jwt, session_binding }
// Send to server for verification
```

### CLI Integration

CLI clients use the same flow:

```
$ sbo auth login alice@example.com

Requesting session binding...
Please visit: https://auth.example.com/verify?domain=example.com&req=Gmh8f3xK...

Waiting for authentication... (press Ctrl+C to cancel)
✓ Session binding received
```

The CLI:
1. Generates ephemeral keypair
2. Posts to provisioning endpoint
3. Prints `verification_uri` for user to open in browser
4. Polls until session binding is ready
5. Stores session binding locally

### Auto-Login

For automatic authentication on return visits:

**Site Declaration:**
```html
<meta name="sbo-auth" content="challenge-endpoint=/api/sbo/challenge">
```

**Flow:**
1. User configures "auto-login" for a site in their provider
2. On page load, polyfill detects site supports SBO auth
3. If site is in auto-login list and session binding is valid, polyfill fetches challenge
4. Polyfill signs assertion and submits to site
5. Site verifies and establishes session

## Security Considerations

### Key Compromise

| Compromised Key | Impact | Recovery |
|-----------------|--------|----------|
| Ephemeral key | Attacker can auth until delegation expires | Wait for expiry (max 24h) |
| Domain key | Attacker can issue session bindings | Rotate `/sys/domains/*` |
| User key | Attacker can create delegations | Rotate identity at `/sys/names/*` |

### Recommendations

- Session bindings SHOULD expire within 24 hours
- User delegations SHOULD expire within 24 hours
- Applications SHOULD verify assertions are recent (within 5 minutes)
- Ephemeral keys SHOULD be stored in origin-isolated storage
- Keys SHOULD NOT be extractable by web pages outside the provider origin

### DNS Security

- DNSSEC SHOULD be used to protect DNS records from spoofing
- Implementations SHOULD cache DNS results per standard TTL rules
- DNS lookup failures SHOULD be treated as "domain does not support SBO auth"

### HTTPS Security

- Session endpoints MUST use HTTPS
- Certificate validation MUST be performed
- Implementations SHOULD reject self-signed certificates

### Challenge Freshness

- Challenges (nonces) MUST be single-use
- Applications SHOULD reject assertions older than 5 minutes
- Servers MUST track issued challenges to prevent replay

### Phishing Resistance

- Assertions are bound to audience (origin), preventing use on other sites
- Users SHOULD verify the requesting origin before authenticating
- Providers SHOULD display the requesting origin prominently

## Privacy Considerations

### Session Binding Privacy

- Domains see when users request session bindings
- Domains do NOT see which applications users authenticate to
- This mirrors the privacy model of BrowserID/Mozilla Persona

### Identity Correlation

- Email addresses are linkable across sites by design
- Users concerned about correlation SHOULD use different email addresses per context

### Discovery Privacy

- DNS queries may reveal user's domain to network observers
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) SHOULD be used

## References

- [SBO Identity Specification v0.1](./SBO%20Identity%20Specification%20v0.1.md)
- [SBO Specification v0.4](./SBO%20Specification%20v0.4.md)
- RFC 7519: JSON Web Token (JWT)
- RFC 8037: EdDSA Signatures in JOSE

## Appendix A: JWT Examples

### User Delegation JWT

**Signed by USER_KEY:**
```
Header:
{
  "alg": "EdDSA",
  "typ": "JWT"
}

Payload:
{
  "iss": "ed25519:a1b2c3d4e5f6...",
  "delegate_to": "ed25519:f9e8d7c6b5a4...",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Session Binding Certificate

**Signed by DOMAIN_KEY:**
```
Header:
{
  "alg": "EdDSA",
  "typ": "JWT"
}

Payload:
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "user_delegation": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Auth Assertion JWT

**Signed by EPHEMERAL_KEY:**
```
Header:
{
  "alg": "EdDSA",
  "typ": "JWT"
}

Payload:
{
  "iss": "alice@example.com",
  "aud": "https://app.example.com",
  "nonce": "8f4e2a1b9c3d7e6f",
  "iat": 1703001300
}
```

## Appendix B: Example Session Binding Certificates

### Domain-Custodied

Domain holds user's private key and signs both JWTs:

```
Session Binding Certificate (signed by domain key):
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "user_delegation": "<jwt signed by domain using custodied user key>",
  "iat": ...,
  "exp": ...
}

Where user_delegation decodes to:
{
  "iss": "ed25519:<user_public_key>",
  "delegate_to": "ed25519:<ephemeral_key>",
  "iat": ...,
  "exp": ...
}
```

### Self-Custody

User signs their own delegation, domain wraps it:

```
Session Binding Certificate (signed by domain key):
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "user_delegation": "<jwt signed by user's own key>",
  "iat": ...,
  "exp": ...
}

Where user_delegation decodes to:
{
  "iss": "ed25519:<user_public_key>",
  "delegate_to": "ed25519:<ephemeral_key>",
  "iat": ...,
  "exp": ...
}
```

Note: The structure is identical. The difference is who signed the inner user_delegation JWT.
