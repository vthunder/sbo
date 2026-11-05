---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Wire Format Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.5 (2026-11, audit)**: Batch submissions are per-message with strict order and state threading (no atomicity). `Auth-Warrant` removed (never a header; the warrant lives in the `Auth-Cert` presentation). Signing content is the received header block minus `Signature`; unknown headers are valid iff signed and placed after the modelled headers; consumers never reserialize; `Critical` header; `X-` prefix for experimental headers. `ed25519`/`sha256` REQUIRED, `secp256k1`/`keccak256` reserved. Encoding rules restated as MUST-reject. Size bounds on `Content-Length`, the header block and the submission.

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
| Header names | Kebab-Case (e.g., `Content-Type`, `Public-Key`) |
| Header values | UTF-8 string, no embedded newlines |
| Blank line | Exactly one LF byte between headers and payload |
| Payload | Raw bytes, length specified by `Content-Length` |

### Parsing Algorithm

```
function parse_one(data: bytes, start: int) -> (headers, payload, end_pos):
    lines = []
    pos = start

    # Parse header lines
    while pos < len(data):
        line_end = data.index(0x0A, pos)  # Find LF
        line = data[pos:line_end]
        pos = line_end + 1

        if len(line) == 0:  # Blank line
            break

        colon = line.index(": ")
        key = line[0:colon]
        value = line[colon+2:]
        lines.append((key, value))

    # Payload length from Content-Length header (0 if absent)
    content_length = parse_canonical_uint(headers.get("Content-Length", "0"))
    if content_length > MAX_MESSAGE_BYTES or content_length > len(data) - pos:
        reject("Content-Length out of bounds")   # checked, never wrapping
    payload = data[pos : pos + content_length]
    end_pos = pos + content_length

    return (headers, payload, end_pos)
```

`parse_canonical_uint` accepts only the canonical decimal form (see [Validation Rules](#validation-rules)); `+5`, `007` and an empty value are rejected. The length arithmetic MUST be checked: a `Content-Length` larger than the bytes remaining in the submission, or larger than `MAX_MESSAGE_BYTES`, rejects the message before any slice is taken (see [Size Bounds](#size-bounds)).

---

## Batch Submissions

A DA layer submission MAY contain multiple SBO messages concatenated directly. Messages are self-delimiting: the `Content-Length` header specifies exactly how many bytes follow the blank line separator.

### Batch Structure

```
[Message 1 headers]
[blank line]
[Message 1 payload - exactly Content-Length bytes]
[Message 2 headers]
[blank line]
[Message 2 payload - exactly Content-Length bytes]
...
```

No separator is required between messages. After reading `Content-Length` bytes of payload, if more data remains, it is the start of the next message (beginning with `SBO-Version:`).

### Batch Parsing Algorithm

```
function parse_batch(data: bytes) -> List[Message]:
    messages = []
    pos = 0

    if len(data) > MAX_SUBMISSION_BYTES:
        reject("submission too large")       # the whole submission is ignored

    while pos < len(data):
        headers, payload, end_pos = parse_one(data, pos)   # rejects ⇒ whole submission ignored
        messages.append(Message(headers, payload))
        pos = end_pos

    return messages
```

### Size Bounds

| Bound | Reference value | Applies to |
|-------|-----------------|------------|
| `MAX_MESSAGE_BYTES` | 2 MiB (2,097,152 bytes) | One message: header block + payload. `Content-Length` MUST NOT exceed it. |
| `MAX_SUBMISSION_BYTES` | 4 MiB (4,194,304 bytes) | One DA submission after any transport decoding (e.g. gzip inflation). |
| `MAX_HEADER_BLOCK_BYTES` | 64 KiB (65,536 bytes) | The header block of one message. |

A DA layer's own submission limit, where lower, governs. Every length computation in a parser MUST be checked arithmetic: a `Content-Length` larger than the bytes remaining, a submission larger than `MAX_SUBMISSION_BYTES`, or an inflated size past the bound is a parse failure, never a wrap-around, an allocation of the declared size, or a panic. A parser is a total function over untrusted bytes: it returns either a message list or a rejection.

### Per-Message Validation and Ordering

Messages within a single DA submission are **not** atomic. The submission is one unit for *parsing*; after that each message is validated and applied on its own, in order. The rules:

1. **Parse as a unit.** A submission that fails to parse (any message of it, or a size bound) is ignored whole. No message from it is applied.
2. **Strict submission order, state threaded.** Messages are validated in the order they appear. Message N is validated against the state left by messages 1..N-1 of the same submission (and every earlier submission in DA order). An intra-submission dependency (a `Policy-Ref`, an `Auth-Evidence` `ref:`, a `_config` followed by the items it governs, a transfer followed by an update) is satisfied exactly when the earlier message was applied.
3. **A rejected message is invisible.** An invalid message leaves state unchanged and is not visible to any later message, in the same submission or after it. Later messages that depended on it fail closed or fall back as if it had never been sent.
4. **An LWW loser is valid.** A message that is valid but loses the write-model ordering (see the [Content Specification](./SBO%20Content%20Specification.md)) is applied with no effect on the current value; it is not a rejection and does not affect later messages' validity.
5. **Index is the slot tiebreak.** Two valid creates of the same `(path, id)` in one submission are resolved by position: the lower message index wins, as in the State Commitment specification's *lower message index wins* rule.
6. **Commitment per block.** `object_hash` is computed per message over the bytes as included on chain; the state root commits once per DA block, after every submission in it has been processed.
7. **Genesis is not an exception.** The genesis submission follows the same per-message rules. Fail-closed bootstrap comes from the [Genesis Specification](./SBO%20Genesis%20Specification.md)'s strict rule (the mode objects first, in order, at the anchor; a root policy present by the end of the anchor submission; everything after it validated normally), not from atomicity.
8. **No multi-message atomicity.** There is no all-or-nothing operation (no atomic collection-plus-items, no atomic multi-object transfer). A client that needs all of a set to land validates the set at submit time against the tip and submits in dependency order; submit-time validation is advisory (see [Validity Layers](./SBO%20Specification.md#validity-layers)), and replay validation is the only boundary.

Submissions from different DA transactions are ordered by DA layer sequencing. The rationale for per-message semantics: atomicity buys nothing without transactional execution, and it would let one expired credential in a shared submission veto every other writer's message and every evidence refresh batched with it. The residual (an I/O failure mid-block half-applying a block on one node) is an implementation defect, not a protocol state.

### Example: Genesis Batch

```
SBO-Version: 0.5
Action: post
Path: /sys/names/
ID: sys
Type: object
Content-Type: application/json
Content-Length: 89
Content-Hash: sha256:...
Public-Key: ed25519:...
Signature: ...

{"public_key":"ed25519:...","display_name":"System"}SBO-Version: 0.5
Action: post
Path: /sys/policies/
ID: root
Type: object
Content-Type: application/json
Content-Length: 166
Content-Hash: sha256:...
Public-Key: ed25519:...
Signature: ...

{"grants":[{"to":"*","can":["create"],"on":"/sys/names/"},...]}
```

Note: The second message starts immediately after the first payload ends (no newline separator).

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
| `Public-Key` | prefixed | Public key of the signer |
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
| `Auth-Cert` | JWT (base64url) | Authentication certificate binding `Public-Key` to an identity (see below) |
| `Auth-Evidence` | string | DNSSEC evidence anchoring the provider key — `inline:<base64>` or `ref:<sbo-ref>` (see below) |
| `Content-Encoding` | enum | `utf-8`, `gzip`, or `base64` |
| `Content-Schema` | string | Payload schema identifier (e.g., `nft.v1`) |
| `Creator` | identity ref | Original creator (defaults to signer) |
| `Critical` | comma-separated header names | Headers a consumer MUST understand to accept this message (see [Unknown Headers](#unknown-headers)) |
| `HLC` | `<physical>.<counter>` | Author hybrid logical clock — ordering key for the write model (see the [Content Specification](./SBO%20Content%20Specification.md#author-clock-hlc)) |
| `Owner` | identity ref | Current owner (defaults to creator) |
| `Policy-Ref` | SBO URI | Reference to governing policy object |
| `Prev` | prefixed | `object_hash` of the prior observed version — causal link for mutable write-model objects (see the [Content Specification](./SBO%20Content%20Specification.md#causal-links-prev)) |
| `Proof` | base64 | Proof data for bridge unlocks |
| `Proof-Type` | string | Type of proof (e.g., `burn`) |
| `Related` | JSON array | Related object references (see below) |

There is no `Auth-Warrant` header. The agent warrant travels inside the `Auth-Cert` device presentation (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)); a message carrying an `Auth-Warrant` line is treated as carrying an unknown header (below), and nothing reads it.

### Unknown Headers

A consumer MAY encounter headers it does not model. The rule is **sign what was sent, ignore what you do not understand**:

- An unknown header is valid **if and only if** it is inside the signed header block (it precedes `Public-Key`, so the signature covers it) **and** it is placed after every modelled header listed in the canonical order (slot 27 below, between `Critical` and `Auth-Cert`). Unknown headers are sorted among themselves in byte order of their names.
- An unknown header that is **not** covered by the signature (a line after `Signature`, or any line a relay appended) makes the message **invalid**. This is what keeps the received bytes, the signing content and `object_hash` in agreement: nothing can be injected into an accepted message without the signer's key.
- A consumer that does not model a header **keeps its bytes** (for signature verification, hashing, storage and forwarding) and **ignores its meaning**.
- `Critical` lists header names (comma-separated, no spaces) whose meaning a consumer must apply to accept the message. A consumer that does not model every header named in `Critical` MUST reject the message. A header not named in `Critical` is safe to skip. A semantics change that an old client cannot safely skip is either a `Critical` header or an `SBO-Version` bump.
- Experimental headers use the `X-` prefix (`X-Mingo-Draft`). They are signed like any other header, ignored by consumers that do not know them, and several can be live on one chain at once. A name without the `X-` prefix is reserved for this specification.

Canonical order is a **producer** rule. A consumer checks it on the headers it models and on the placement of unknown headers after them; it never reorders or rewrites anything.

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
13. `HLC` (if present)
14. `New-ID` (if present)
15. `New-Owner` (if present)
16. `New-Path` (if present)
17. `Object-Path` (if present)
18. `Origin` (if present)
19. `Owner` (if present)
20. `Policy-Ref` (if present)
21. `Prev` (if present)
22. `Proof` (if present)
23. `Proof-Type` (if present)
24. `Registry-Path` (if present)
25. `Related` (if present)
26. `Critical` (if present)
27. unknown and `X-` headers (if present), in byte order of name
28. `Auth-Cert` (if present)
29. `Auth-Evidence` (if present)
30. `Public-Key`
31. `Signature`

`Auth-Cert` and `Auth-Evidence` precede `Public-Key`, so they are inside the signed header block: the signer commits to its own authentication certificate and DNSSEC evidence, and neither can be stripped or substituted. `Auth-Warrant` is not in the order and is not a header (see above).

---

## Cryptographic Formats

### Algorithm Identifiers

Cryptographic values use a prefix to identify the algorithm:

```
algorithm:value
```

### Signature Algorithms

| Identifier | Status | Curve | Signing Hash | Key Size | Signature Size |
|------------|--------|-------|--------------|----------|----------------|
| `ed25519` | **REQUIRED** | Ed25519 | SHA-512 (built-in) | 32 bytes | 64 bytes |
| `secp256k1` | Reserved | secp256k1 | SHA-256 | 33 bytes (compressed) | 64 bytes (r‖s) |

### Hash Algorithms

| Identifier | Status | Algorithm | Output Size |
|------------|--------|-----------|-------------|
| `sha256` | **REQUIRED** | SHA-256 | 32 bytes |
| `keccak256` | Reserved | Keccak-256 | 32 bytes |

`ed25519` and `sha256` are the only algorithms a conforming implementation MUST support, and the only ones valid on the wire in SBO Protocol v0.5. `secp256k1` and `keccak256` are **reserved** identifiers: their encoding is fixed here so a future version can enable them without ambiguity, but a message that uses them today is invalid (Validation Rule 11). Ed25519 verification MUST reject non-canonical scalars (`S ≥ L`).

### Encoding Rules

| Element | Format |
|---------|--------|
| Hex encoding | Lowercase, no `0x` prefix. Uppercase or mixed-case hex is invalid. |
| Integers (`Content-Length`) | Canonical decimal: ASCII digits only, no sign, no leading zeros (`0` alone is the only value that starts with `0`), no whitespace. |
| ed25519 public key | Raw public key (32 bytes = 64 hex chars) |
| secp256k1 public key (reserved) | SEC1 compressed (33 bytes = 66 hex chars) |
| Signatures | Raw bytes (64 bytes = 128 hex chars) |
| Hashes | Raw bytes (32 bytes = 64 hex chars) |

These are MUST-reject rules, not formatting advice: a value that is not in the stated form makes the message invalid (Validation Rules 10 and 12). Accepting `+5`, `007` or uppercase hex would let two byte strings carry one meaning, which breaks the one-hash-per-message property that `object_hash` depends on.

### Examples

```
Content-Hash: sha256:7d0a4b3c8f2e1d6a5b9c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b
Public-Key: ed25519:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Signature: 1a2b3c4d5e6f...  (no prefix, algorithm from Public-Key)
Public-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a   (reserved form; invalid in v0.5)
```

---

## Signature Computation

### Signed Content

The **signing content** is the header block **as received**, minus the `Signature` line, plus the trailing blank line: every header line that precedes `Signature`, in the bytes in which it arrived, including any unknown or `X-` headers. The signer commits to exactly the bytes it sent. There is no canonicalization step on the consumer side.

Only the producer serializes, once, when it signs. The canonical order is what the producer MUST emit; a consumer checks that the modelled headers it sees are in that order (Validation Rule 2) and that unknown headers sit after them, and otherwise treats the header block as opaque bytes.

### Algorithm

```
function compute_signature(message, private_key):
    # 1. Serialize the header block in canonical order, without Signature
    #    (the only place in the protocol where a header block is built)
    block = ""
    for header in CANONICAL_ORDER:            # unknown/X- headers in their slot, byte order
        if header == "Signature":
            continue  # Skip entirely
        if header in message.headers:
            block += header + ": " + message.headers[header] + "\n"
    block += "\n"  # Blank line

    # 2. Sign the bytes (Ed25519 hashes internally)
    return ed25519_sign(private_key, block.as_bytes())
```

(The reserved `secp256k1` form would sign `sha256(block)` with ECDSA; it is not valid in v0.5.)

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

    # 4. Check header placement on the received bytes (no reconstruction)
    if not modelled_headers_in_canonical_order(headers):
        return INVALID("Non-canonical header order")
    if any unknown header precedes a modelled header, or follows Signature:
        return INVALID("Unsigned or misplaced header")
    if any header named in headers.get("Critical") is not modelled:
        return INVALID("Critical header not understood")

    # 5. Signing content = received header block minus the Signature line
    signed = received_header_bytes(message, exclude_line="Signature")
    # (ends with the blank line; identical bytes to what the signer built)

    # 6. Verify signature
    key_algo, public_key = parse_prefixed(headers["Public-Key"])
    signature = hex_decode(headers["Signature"])

    if not verify_signature(key_algo, public_key, signed, signature):
        return INVALID("Signature verification failed")

    return VALID
```

### Consumers Never Reserialize

**Bytes in, bytes out.** A consumer (node, indexer, client, relay, snapshot or proof builder) verifies the signature over the bytes it received, computes `object_hash` over the bytes it received (see the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#object-hash)), stores those bytes, and forwards those same bytes. It MUST NOT rebuild a header block from a parsed structure for any of these purposes: a parsed structure holds only the headers that consumer models, so two consumers modelling different subsets would disagree on the signature and the hash. Because an accepted message is one whose received bytes verify, the raw bytes, the signing content and the canonical serialization coincide for every accepted message by construction.

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

## Authentication Certificate

The `Auth-Cert` header carries the evidence that binds the signing key (`Public-Key`) to an identity — the **attribution** evidence required by the Validity Layers model in the [Core Specification](./SBO%20Specification.md). For email-rooted identities, its value is an authentication certificate (a JWT issued by an external identity provider) asserting that the signing key speaks for a given email address. The SBO envelope itself serves as the proof-of-possession: the identity provider issues the certificate over the signing key, and that key signs the message — so no separate, audience-bound assertion is needed, and a signature cannot be replayed to authorize a different message.

The certificate is verified together with **DNSSEC evidence**, carried in the `Auth-Evidence` header, that anchors the issuing provider's key to the pinned DNS root KSK (see Attribution Capture in the [Core Specification](./SBO%20Specification.md)). `Auth-Evidence` is either `inline:<base64>` (the DNSSEC chain in the message) or `ref:<sbo-ref>` (a reference to a self-authenticating evidence object already on chain); either way attribution is verifiable from the replayable record alone, with no network access.

`Auth-Cert` and `Auth-Evidence` are OPTIONAL at the wire level (genesis roots and key-rooted identities authorize directly via `Public-Key` and need neither). When attribution is required to authorize a message, the certificate MUST be present and its evidence MUST be on chain (inline or referenced). The certificate and DNSSEC-evidence formats, issuance, validity windows, and verification are defined in the [SBO Authorization Specification](./SBO%20Authorization%20Specification.md).

## Related Objects

The `Related` header contains a JSON array of relationship objects:

```
Related: [{"rel":"license","ref":"sbo+raw://avail:mainnet:13/licenses/cc-by"},{"rel":"collection","ref":"/art/"}]
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
Public-Key: ed25519:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
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
Public-Key: ed25519:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90

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
10. Hex values contain non-hex characters, uppercase characters, or wrong length
11. Algorithm prefix is unknown, reserved (`secp256k1`, `keccak256`) or otherwise unsupported
12. `Content-Length` (or any integer-valued header) is not in canonical decimal form (`+5`, `007`, ` 5`, empty)
13. `Content-Length` exceeds `MAX_MESSAGE_BYTES` or the bytes remaining in the submission, the header block exceeds `MAX_HEADER_BLOCK_BYTES`, or the submission exceeds `MAX_SUBMISSION_BYTES`
14. A header name appears more than once
15. A header appears after `Signature`, or an unknown header appears before a modelled header (it is outside the signed, canonical placement)
16. A header named in `Critical` is not modelled by the consumer

A message MUST be accepted (its meaning ignored where unknown) if:

1. Unknown or `X-` headers are present, signed, placed after the modelled headers, and not named in `Critical` (keep their bytes, ignore their meaning)
2. Unknown relationship types in `Related` (pass through)

---

## Future Extensions

- Additional signature algorithms can be added with new prefixes (`secp256k1` is reserved); enabling one is an `SBO-Version` bump
- Additional hash algorithms can be added with new prefixes (`keccak256` is reserved); enabling one is an `SBO-Version` bump
- New optional headers can be added; signed and placed after the modelled headers they are ignored by older clients, unless named in `Critical`, in which case older clients reject the message
- Experimental headers use the `X-` prefix and need no specification change
- `SBO-Version` will increment for breaking changes

---

## Test Vectors

See `test-vectors/wire-format-v0.1.json` for canonical test cases including:

- Minimal valid message
- Message with all optional headers
- Each action type (post, move, transfer, delete)
- `ed25519` signatures and `sha256` hashes; reserved `secp256k1`/`keccak256` prefixes rejected
- Non-canonical integers and uppercase hex rejected; unsigned unknown headers rejected; signed `X-` headers accepted
- Edge cases (empty payload, unicode in headers, max sizes)

---
