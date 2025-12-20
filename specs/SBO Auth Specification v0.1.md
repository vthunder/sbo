---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Auth Specification v0.1

**Status:** Draft

## Abstract

This specification defines a protocol for web authentication using SBO identities. Users authenticate using email addresses as identifiers, with session bindings issued by domains. The protocol provides:

- Zero key management for most users (domain-custodied)
- Privacy preservation (domain doesn't see which apps users visit)
- Short-lived sessions without on-chain transactions

This specification builds on the [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md) which defines identity and domain objects.

## Overview

SBO Auth uses session bindings for web authentication. Session bindings are short-lived credentials issued by domains that delegate authentication to ephemeral session keys.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   IDENTITY (permanent, on-chain)                                         │
│   See: SBO Identity Specification                                        │
│                                                                          │
│   /sys/names/alice ──── certified by ──── /sys/domains/example.com       │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   SESSION BINDING (short-lived, off-chain)                               │
│                                                                          │
│   SESSION_KEY ──── certified by DOMAIN_KEY ──── /sys/domains/example.com │
│                    (session binding JWT)                                 │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Terminology

| Term | Definition |
|------|------------|
| **Session binding** | A short-lived JWT credential delegating auth to a session key |
| **Session key** | An ephemeral key generated per-session for authentication |
| **Auth assertion** | A JWT signed by the session key proving identity to an application |

For identity-related terms (domain, identity binding, user key), see the [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md).

## Session Binding

Session bindings are short-lived credentials for web authentication. They are signed by the domain key and NOT stored on-chain.

### JWT Format

**Signed by DOMAIN_KEY:**
```json
{
  "iss": "domain:example.com",
  "sub": "alice@example.com",
  "delegate_key": "ed25519:<SESSION_KEY>",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | Domain issuer in format `"domain:<domain>"` |
| `sub` | string | Yes | User's email address |
| `delegate_key` | string | Yes | Session public key with algorithm prefix |
| `iat` | number | Yes | Issued-at timestamp |
| `exp` | number | Yes | Expiration timestamp |

### Requirements

- `exp` MUST be set and SHOULD be no more than 24 hours from `iat`
- `iss` domain MUST match the email domain in `sub`
- Session binding MUST be signed by the domain key from `/sys/domains/<domain>`

## Auth Assertion

The assertion is what the user presents to authenticate to an application.

### JWT Format

**Signed by SESSION_KEY:**
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

## Flows

### Session Binding Issuance

```
┌──────────┐                              ┌──────────────┐
│  Browser │                              │  domain.com  │
└────┬─────┘                              └──────┬───────┘
     │                                           │
     │  1. Generate session keypair              │
     │     (SESSION_KEY, ephemeral)              │
     │                                           │
     │  2. Request session binding               │
     │     POST /.well-known/sbo/session         │
     │     { email, session_public_key }         │
     │  ─────────────────────────────────────────>
     │                                           │
     │         3. Authenticate user              │
     │            (if no valid session)          │
     │  <─────────────────────────────────────────
     │                                           │
     │  4. Domain issues session binding JWT     │
     │     { iss, sub, delegate_key, exp }       │
     │     signed by DOMAIN_KEY                  │
     │  <─────────────────────────────────────────
     │                                           │
     │  5. Browser stores:                       │
     │     - session private key                 │
     │     - session binding JWT                 │
     │                                           │
```

### Authentication

```
┌──────────┐                    ┌─────────┐                    ┌───────┐
│  Browser │                    │   App   │                    │  SBO  │
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
     │     SESSION_KEY               │                             │
     │                               │                             │
     │  4. Send:                     │                             │
     │     - assertion JWT           │                             │
     │     - session binding JWT     │                             │
     │  ─────────────────────────────>                             │
     │                               │                             │
     │                               │  5. DNS lookup              │
     │                               │     _sbo.domain.com         │
     │                               │                             │
     │                               │  6. Fetch domain key        │
     │                               │     /sys/domains/domain.com │
     │                               │  ─────────────────────────────>
     │                               │                             │
     │                               │  7. Verify:                 │
     │                               │     - session binding       │
     │                               │       signed by DOMAIN_KEY  │
     │                               │     - assertion signed by   │
     │                               │       delegate_key          │
     │                               │     - nonce matches         │
     │                               │     - not expired           │
     │                               │                             │
     │  8. Auth success              │                             │
     │     user = alice@domain.com   │                             │
     │  <─────────────────────────────                             │
     │                               │                             │
```

## Verification Algorithm

```python
def verify_auth(assertion_jwt, session_binding_jwt, expected_nonce, expected_aud):
    # 1. Parse JWTs
    assertion = decode_jwt(assertion_jwt)
    session_binding = decode_jwt(session_binding_jwt)

    # 2. Extract domain from issuer
    assert session_binding["iss"].startswith("domain:")
    domain = session_binding["iss"].removeprefix("domain:")

    # 3. Resolve domain's SBO repository via DNS
    dns_record = lookup_dns(f"_sbo.{domain}")
    repo_uri = parse_sbo_dns(dns_record)

    # 4. Fetch domain key (see SBO Identity Specification)
    domain_key = resolve_domain(repo_uri, domain)

    # 5. Verify session binding
    verify_jwt_signature(session_binding_jwt, domain_key)
    assert session_binding["exp"] > now(), "Session expired"

    # 6. Verify assertion
    session_key = session_binding["delegate_key"]
    verify_jwt_signature(assertion_jwt, session_key)
    assert assertion["nonce"] == expected_nonce, "Nonce mismatch"
    assert assertion["aud"] == expected_aud, "Audience mismatch"
    assert assertion["iat"] > now() - 300, "Assertion too old"

    # 7. Success
    return {
        "email": session_binding["sub"],
        "verified_at": now()
    }
```

## DNS Discovery

Applications discover a domain's SBO repository via DNS. See [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md#dns-discovery) for the DNS record format.

## Session Binding Endpoint

Domains MUST provide a session binding endpoint:

```
POST /.well-known/sbo/session
Content-Type: application/json

{
  "email": "alice@example.com",
  "session_public_key": "ed25519:abc123..."
}
```

**Response (Success):**
```json
{
  "session_binding": "<JWT>"
}
```

**Response (Auth Required):**
```
HTTP 401 Unauthorized
WWW-Authenticate: <domain's auth method>
```

## Revocation

### Session Binding Revocation

Session bindings are short-lived (recommended 24h maximum). Revocation is handled by expiry. If immediate revocation is required:

1. Domain rotates domain key (updates `/sys/domains/<domain>`)
2. All outstanding session bindings become invalid
3. Users must obtain new session bindings

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
│   │ Communicates via postMessage    │   │
│   └───────────────┬─────────────────┘   │
│                   │                     │
│   ┌───────────────▼─────────────────┐   │
│   │ <iframe src="https://           │   │
│   │   sbo-auth-provider.com/        │   │
│   │   signer">                      │   │
│   │                                 │   │
│   │ - Stores encrypted session keys │   │
│   │ - Signs assertions              │   │
│   │ - Manages session bindings      │   │
│   └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

The iframe-based signer:
- Stores session keys in its origin's storage
- Receives signing requests via postMessage
- Returns signed assertions
- Handles session binding refresh

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

// Returns: { assertion_jwt, session_binding_jwt }
// Send both to server for verification
```

### Auto-Login

For automatic authentication on return visits:

**Site Declaration:**
```html
<meta name="sbo-auth" content="challenge-endpoint=/api/sbo/challenge">
```

**Flow:**
1. User configures "auto-login" for a site in their provider
2. On page load, polyfill detects site supports SBO auth
3. If site is in auto-login list, polyfill fetches challenge
4. Polyfill signs assertion and submits to site
5. Site verifies and establishes session

## Security Considerations

### Key Compromise

| Compromised Key | Impact | Recovery |
|-----------------|--------|----------|
| Session key | Attacker can auth until expiry | Wait for expiry (max 24h) |
| Domain key | Attacker can issue session bindings | Rotate `/sys/domains/*` |

### Recommendations

- Session bindings SHOULD expire within 24 hours
- Applications SHOULD verify assertions are recent (within 5 minutes)
- Session keys SHOULD be stored in origin-isolated storage
- Keys SHOULD NOT be extractable by web pages outside the provider origin

### DNS Security

- DNSSEC SHOULD be used to protect DNS records from spoofing
- Implementations SHOULD cache DNS results per standard TTL rules
- DNS lookup failures SHOULD be treated as "domain does not support SBO auth"

### HTTPS Security

- Session binding endpoints MUST use HTTPS
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

### Session Binding JWT

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
  "delegate_key": "ed25519:b7a3c1d4e5f6...",
  "iat": 1703001234,
  "exp": 1703087634
}
```

### Auth Assertion JWT

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
