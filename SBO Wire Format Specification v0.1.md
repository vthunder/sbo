
# SBO Wire Format Specification (v0.1)

## Status
Draft

## Overview

This document defines the canonical wire format for SBO (Simple Blockchain Objects) messages. It specifies exact byte-level encoding for envelopes, cryptographic formats, and signature computation. Conforming implementations MUST follow this specification exactly to ensure interoperability and signature verification across clients.

---

## Message Structure

An SBO message consists of three parts:

1. **Header block** - Key-value pairs, one per line
2. **Blank line** - Single LF separator
3. **Payload** - Raw bytes

```
Header-Name: value
Another-Header: value

<payload bytes>
```

### Encoding Rules

| Element | Specification |
|---------|---------------|
| Character encoding | UTF-8 |
| Line ending | LF only (`\n`, 0x0A). CRLF is invalid. |
| Header format | `Name: value` (colon + single ASCII space) |
| Header names | Kebab-Case (e.g., `Content-Type`, `Signing-Key`) |
| Header values | UTF-8 string, no embedded newlines |
| Blank line | Exactly one LF byte between headers and payload |
| Payload | Raw bytes, length specified by `Content-Length` |

### Parsing Algorithm

```
function parse(message: bytes) -> (headers, payload):
    lines = []
    pos = 0

    # Parse header lines
    while pos < len(message):
        line_end = message.index(0x0A, pos)  # Find LF
        line = message[pos:line_end]
        pos = line_end + 1

        if len(line) == 0:  # Blank line
            break

        colon = line.index(": ")
        key = line[0:colon]
        value = line[colon+2:]
        lines.append((key, value))

    # Rest is payload
    content_length = int(headers["Content-Length"])
    payload = message[pos : pos + content_length]

    return (headers, payload)
```

---

## Header Reference

### Required Headers

All messages MUST include these headers in this exact order:

| Header | Format | Description |
|--------|--------|-------------|
| `SBO-Version` | `0.5` | Wire format version |
| `Action` | enum | One of: `post`, `transfer`, `delete`, `import` |
| `Path` | string | Collection path with trailing slash (e.g., `/art/`) |
| `ID` | string | Object identifier |
| `Type` | enum | One of: `object`, `collection` |
| `Content-Type` | MIME | Payload MIME type (if payload present) |
| `Content-Length` | integer | Payload size in bytes (if payload present) |
| `Content-Hash` | prefixed | Hash of payload bytes (if payload present) |
| `Signing-Key` | prefixed | Public key that signed the message |
| `Signature` | hex | Signature bytes |

**Payload rules:**
- `Type: object` — payload required, content headers required
- `Type: collection` — payload optional (for metadata), content headers required only if payload present

**Path conventions:**
- `Path` header: Always ends with `/` (the container). Examples: `/`, `/alice/`, `/alice/nfts/`
- `ID` header: Never contains `/`. Examples: `alice`, `nft-123`

### Conditionally Required Headers

| Header | Required When | Format |
|--------|---------------|--------|
| `New-ID` | `Action: transfer` (optional) | New object identifier |
| `New-Path` | `Action: transfer` (optional) | New collection path |
| `New-Owner` | `Action: transfer` (optional) | New owner identity reference |
| `Origin` | `Action: import` | External origin identifier |
| `Registry-Path` | `Action: import` | Path for registry entry |
| `Object-Path` | `Action: import` | Destination path for object |
| `Attestation` | `Action: import` | Base64-encoded oracle attestation |

**Note:** For `transfer`, at least one of `New-ID`, `New-Path`, or `New-Owner` must be present.

### Optional Headers

Optional headers appear after required headers, in alphabetical order:

| Header | Format | Description |
|--------|--------|-------------|
| `Content-Encoding` | enum | `utf-8`, `gzip`, or `base64` |
| `Content-Schema` | string | Payload schema identifier (e.g., `nft.v1`) |
| `Creator` | identity ref | Original creator (defaults to signer) |
| `Owner` | identity ref | Current owner (defaults to creator) |
| `Policy-Ref` | SBO URI | Reference to governing policy object |
| `Proof` | base64 | Proof data for bridge unlocks |
| `Proof-Type` | string | Type of proof (e.g., `burn`) |
| `Related` | JSON array | Related object references (see below) |

### Canonical Header Order

For signature computation, headers MUST appear in this order:

1. `SBO-Version`
2. `Action`
3. `Path`
4. `ID`
5. `Type`
6. `Content-Type` (if present)
7. `Content-Encoding` (if present)
8. `Content-Length`
9. `Content-Hash`
10. `Attestation` (if present)
11. `Content-Schema` (if present)
12. `Creator` (if present)
13. `New-ID` (if present)
14. `New-Owner` (if present)
15. `New-Path` (if present)
16. `Object-Path` (if present)
17. `Origin` (if present)
18. `Owner` (if present)
19. `Policy-Ref` (if present)
20. `Proof` (if present)
21. `Proof-Type` (if present)
22. `Registry-Path` (if present)
23. `Related` (if present)
24. `Signing-Key`
25. `Signature`

---

## Cryptographic Formats

### Algorithm Identifiers

Cryptographic values use a prefix to identify the algorithm:

```
algorithm:value
```

### Supported Signature Algorithms

| Identifier | Curve | Signing Hash | Key Size | Signature Size |
|------------|-------|--------------|----------|----------------|
| `secp256k1` | secp256k1 | SHA-256 | 33 bytes (compressed) | 64 bytes (r‖s) |
| `ed25519` | Ed25519 | SHA-512 (built-in) | 32 bytes | 64 bytes |

### Supported Hash Algorithms

| Identifier | Algorithm | Output Size |
|------------|-----------|-------------|
| `sha256` | SHA-256 | 32 bytes |
| `keccak256` | Keccak-256 | 32 bytes |

### Encoding Rules

| Element | Format |
|---------|--------|
| Hex encoding | Lowercase, no `0x` prefix |
| secp256k1 public key | SEC1 compressed (33 bytes = 66 hex chars) |
| ed25519 public key | Raw public key (32 bytes = 64 hex chars) |
| Signatures | Raw bytes (64 bytes = 128 hex chars) |
| Hashes | Raw bytes (32 bytes = 64 hex chars) |

### Examples

```
Content-Hash: sha256:7d0a4b3c8f2e1d6a5b9c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b
Signing-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a
Signing-Key: ed25519:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Signature: 1a2b3c4d5e6f...  (no prefix, algorithm from Signing-Key)
```

---

## Signature Computation

### Signed Content

The signature covers all header bytes **excluding the `Signature` header**, plus the trailing blank line.

### Algorithm

```
function compute_signature(message, private_key):
    # 1. Build canonical header block without Signature
    canonical = ""
    for header in CANONICAL_ORDER:
        if header == "Signature":
            continue  # Skip entirely
        if header in message.headers:
            canonical += header + ": " + message.headers[header] + "\n"
    canonical += "\n"  # Blank line

    # 2. Hash the canonical bytes
    if key_algorithm(private_key) == "secp256k1":
        hash = sha256(canonical.as_bytes())
    else if key_algorithm(private_key) == "ed25519":
        # Ed25519 handles hashing internally
        return ed25519_sign(private_key, canonical.as_bytes())

    # 3. Sign the hash
    return ecdsa_sign(private_key, hash)
```

### Verification Algorithm

```
function verify_message(message):
    # 1. Parse headers and payload
    headers, payload = parse(message)

    # 2. Verify Content-Length
    if len(payload) != int(headers["Content-Length"]):
        return INVALID("Content-Length mismatch")

    # 3. Verify Content-Hash
    algo, expected = parse_prefixed(headers["Content-Hash"])
    actual = hash(algo, payload)
    if actual != expected:
        return INVALID("Content-Hash mismatch")

    # 4. Reconstruct canonical header block (without Signature)
    canonical = reconstruct_canonical(headers, exclude=["Signature"])
    canonical += "\n"  # Blank line

    # 5. Verify signature
    key_algo, public_key = parse_prefixed(headers["Signing-Key"])
    signature = hex_decode(headers["Signature"])

    if not verify_signature(key_algo, public_key, canonical, signature):
        return INVALID("Signature verification failed")

    return VALID
```

### Payload Integrity

The payload is NOT directly signed. Instead:

1. `Content-Hash` contains the hash of the payload bytes
2. `Content-Hash` is included in the signed header block
3. Clients verify payload by computing and comparing the hash

This design allows streaming: the payload can be processed without buffering the entire message for signature verification.

---

## Identity References

Identity references point to name objects in the `/sys/names/` namespace.

### Local Reference
```
alice
```
Resolves to `/sys/names/alice` in the current SBO database.

### Cross-Chain Reference
```
avail:mainnet:13/alice
```
Resolves to `sbo+raw://avail:mainnet:13/sys/names/alice`.

### Usage

Identity references appear in:
- `Owner` header
- `Creator` header
- `New-Owner` header

---

## Related Objects

The `Related` header contains a JSON array of relationship objects:

```
Related: [{"rel":"license","ref":"sbo://Avail:13/licenses/cc-by"},{"rel":"collection","ref":"/art/"}]
```

Each object has:
- `rel`: Relationship type (string)
- `ref`: Target reference (SBO URI or relative path)

Common relationship types:
- `license` - Licensing terms
- `collection` - Parent collection
- `policy` - Governing policy
- `origin` - Original source (for bridged objects)

---

## Complete Example

### Message

```
SBO-Version: 0.5
Action: post
Path: /art/
ID: sunset-1
Type: object
Content-Type: application/json
Content-Length: 42
Content-Hash: sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
Signing-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a
Signature: 1a2b3c4d5e6f70819203a4b5c6d7e8f901a2b3c4d5e6f70819203a4b5c6d7e8f901a2b3c4d5e6f70819203a4b5c6d7e8f901a2b3c4d5e6f70819203a4b5c6d7e8f9

{"name":"Sunset #1","artist":"alice"}
```

### Payload (42 bytes)

```json
{"name":"Sunset #1","artist":"alice"}
```

### Content-Hash Computation

```
sha256('{"name":"Sunset #1","artist":"alice"}')
  = 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
```

### Signed Bytes

All bytes from `SBO-Version` through the blank line, excluding `Signature`:

```
SBO-Version: 0.5
Action: post
Path: /art/
ID: sunset-1
Type: object
Content-Type: application/json
Content-Length: 42
Content-Hash: sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
Signing-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a

```

(Ends with blank line = two LF bytes)

---

## Validation Rules

A message is **invalid** and MUST be rejected if:

1. Line endings include CR (0x0D)
2. Headers are not in canonical order
3. Required headers are missing
4. `Content-Length` doesn't match actual payload size
5. `Content-Hash` doesn't match computed hash of payload
6. Signature verification fails
7. Unknown `SBO-Version` (forward compatibility)
8. `Action` is not a known value
9. `Type` is not `object` or `collection`
10. Hex values contain non-hex characters or wrong length
11. Algorithm prefix is unknown or unsupported

A message SHOULD be accepted with warnings if:

1. Unknown optional headers are present (ignore them)
2. Unknown relationship types in `Related` (pass through)

---

## Future Extensions

- Additional signature algorithms can be added with new prefixes
- Additional hash algorithms can be added with new prefixes
- New optional headers can be added (will be ignored by older clients)
- `SBO-Version` will increment for breaking changes

---

## Test Vectors

See `test-vectors/wire-format-v0.1.json` for canonical test cases including:

- Minimal valid message
- Message with all optional headers
- Each action type (post, move, transfer, delete)
- Both signature algorithms (secp256k1, ed25519)
- Both hash algorithms (sha256, keccak256)
- Edge cases (empty payload, unicode in headers, max sizes)

---
