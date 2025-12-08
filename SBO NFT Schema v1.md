
# SBO NFT Schema: `nft.v1`

## Status
Draft

## Overview

This document defines `nft.v1`, a schema for representing media-based non-fungible tokens (NFTs) directly within SBO objects. This version supports embedded media, with optional metadata and attributes, and is designed for simplicity, portability, and on-chain verifiability.

---

## Content Schema

NFT objects use these headers:

```
Content-Type: application/json
Content-Schema: nft.v1
```

---

## Fields

| Field         | Type     | Description |
|---------------|----------|-------------|
| `name`        | `string` | Display name of the NFT |
| `description` | `string` | Optional human-readable description |
| `media`       | `object` | Embedded media file |
| `attributes`  | `array`  | Optional list of traits (display/filtering) |
| `created_by`  | `string` | SBO URI of creator or artist |
| `created_at`  | `string` | ISO 8601 timestamp of creation (optional) |

### `media` Object Fields

| Field           | Type     | Description |
|------------------|----------|-------------|
| `content_type`   | `string` | MIME type (e.g., `image/png`, `audio/mp3`) |
| `encoding`       | `string` | Encoding of the `data` field (e.g., `base64`) |
| `data`           | `string` | Embedded media data (string-encoded) |
| `size`           | `number` | Size of the encoded media in bytes |

---

## Example

```json
{
  "name": "Sunset #42",
  "description": "A one-of-a-kind digital painting by Jane Artist.",
  "media": {
    "content_type": "image/png",
    "encoding": "base64",
    "data": "<BASE64_ENCODED_IMAGE_DATA>",
    "size": 83217
  },
  "attributes": [
    { "trait_type": "Mood", "value": "Serene" },
    { "trait_type": "Palette", "value": "Warm" }
  ],
  "created_by": "sbo://names/jane-artist",
  "created_at": "2025-03-26T15:00:00Z"
}
```

---

## Design Notes

- Media is embedded directly in the SBO object to ensure portability and immutability.
- This version is ideal for demos, smaller assets, or use cases where full decentralization is not yet required.
- Future versions may include:
  - External `media.uri` with `content_hash`
  - Links to collection objects via `Related` header
  - Custom transfer or royalty logic via `Policy-Ref` header

---

## Compatibility

- The full payload (including embedded media) is protected by `Content-Hash`, which is covered by the SBO signature.
- Objects using this schema can be referenced, transferred, or bridged according to the core SBO rules.
- See the [Wire Format Specification](./SBO%20Wire%20Format%20Specification%20v0.1.md) for signature computation details.

---
