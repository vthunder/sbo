# SBO: Sovereign Blockchain Objects

**Blockchain objects that are actually objects.**

---

## The Problem

On Ethereum, an NFT isn't an object—it's a row in a contract's mapping. You don't own the asset; you own the right to call a function that says you own an entry at index 42. The "object" doesn't exist on chain. Only the API does.

This is backwards.

We've built an entire ecosystem where data is a side effect of computation, not a first-class thing. Want to store a profile? Deploy a contract. Want to update it? Call a method. Want to prove you own it? Query an RPC endpoint that reads contract state.

Smart contracts are great for **logic**—swaps, auctions, DAOs. But most on-chain data doesn't need logic. It needs:

- **Existence** — the data is on chain
- **Ownership** — signed by a key, not managed by a contract
- **Validation** — who can change it, verified by any client, designed for based rollups and sovereign execution

---

## The Solution

**SBO** makes data the primitive. The object is the thing on chain—not a contract method, not a storage slot, not an abstraction.

```
SBO-Version: 0.5
Action: post
Path: /nfts/
ID: punk-001
Type: object
Content-Type: application/json
Content-Hash: sha256:abc123...
Public-Key: ed25519:19d76fbd...
Signature: dd1aebf779dd5752...

{"name":"CryptoPunk #001","attributes":{"type":"alien","accessories":["pipe"]}}
```

That's it. A signed envelope with headers and content. Human-readable. Verifiable. The object itself, on chain.

---

## Why SBO is Different

### 1. No Smart Contracts Required

SBO runs on data availability layers like [Avail](https://availproject.org). You post signed messages; clients validate them locally. The blockchain just guarantees the data is available and ordered—the cheapest possible on-chain footprint.

**Cost comparison:**
| Platform | 1KB storage |
|----------|-------------|
| Ethereum | ~$5-50 |
| Solana | ~$0.01 |
| Avail DA | ~$0.0001 |

### 2. Ownership Without Execution

Every object has an owner. Only the owner can update or transfer it. This is enforced by signatures, not by calling a contract method. Your private key is your access control.

```
# Alice creates an NFT
Path: /nfts/
ID: my-art
Owner: alice
Public-Key: ed25519:<alice-pubkey>

# Only Alice can transfer or update it
Action: transfer
New-Owner: bob
```

### 3. Hierarchical Like a Filesystem

SBO organizes data in paths, just like files and folders:

```
/
├── sys/
│   ├── names/
│   │   ├── alice         (alice's identity)
│   │   └── bob           (bob's identity)
│   └── policies/
│       └── root          (global rules)
├── nfts/
│   ├── alice:punk-001    (alice's NFT)
│   └── bob:punk-002      (bob's NFT)
└── apps/
    └── my-app/
        └── config        (app settings)
```

Policies cascade down the hierarchy. Set rules at `/nfts/` and they apply to everything inside.

### 4. Sync to Your Filesystem

Run the SBO daemon and it syncs blockchain data to your local filesystem:

```bash
$ sbo repo add sbo+raw://avail:turing:506
$ ls my-sbo-repo/
nfts/  sys/  apps/

$ cat my-sbo-repo/sys/names/alice
{"display_name":"Alice","public_key":"ed25519:19d76fbd..."}
```

Your data. Your filesystem. Verified against the blockchain.

### 5. Cross-Chain by Design

Every SBO object has a URI. Direct chain references use `sbo+raw://`:

```
sbo+raw://avail:mainnet:42/nfts/punk-001
sbo+raw://ethereum:1/nfts/bridged-punk
```

Or use DNS to give your database a human-readable name with `sbo://`:

```
sbo://alice.eth/nfts/my-art      ← DNS TXT record resolves to sbo+raw://avail:mainnet:42
sbo://myapp.com/users/bob        ← Your domain, your objects
```

**Bridging** lets you move objects between chains. Lock an NFT on Avail, mint it on Ethereum as an ERC-721. Burn the ERC-721, unlock the original. The object's history and ownership travel with it—verified by oracle attestations.

```
# On Avail: lock object for bridge
Action: transfer
New-Owner: bridge:ethereum

# On Ethereum: mint ERC-721 with attestation
# ...later, burn ERC-721...

# On Avail: unlock with burn proof
Action: transfer
Proof-Type: burn
Proof: <oracle attestation>
New-Owner: alice
```

---

## What You Can Build

### Digital Ownership (NFTs, but better)

Create NFTs with programmable policies—not smart contracts. Define who can mint, transfer conditions, royalty rules. All in declarative JSON.

```json
{
  "rules": [{
    "action": "post",
    "allow": [{"identity": "/sys/names/artist"}],
    "require": {"schema": "nft.v1"}
  }]
}
```

### Decentralized Identity

Claim your name. Link your keys across chains. Build a verifiable identity that you control—and use it to log in to web apps.

```
/sys/names/alice
→ {"display_name":"Alice","public_key":"ed25519:..."}

/alice/profile
→ {"bio":"Building the future","links":{"twitter":"@alice"}}
```

Web apps can authenticate users via SBO identities using email-style discovery (`alice@domain.com` → SBO identity) and challenge-response signatures. No passwords, no OAuth providers—just your key.

### User-Controlled Data

Let users own their data while your app uses it. They can revoke access, export it, or take it to a competitor.

```
/users/alice/
├── preferences      (alice controls)
├── saved-items      (alice controls)
└── app-data/        (your app writes here with permission)
```

### Governed Namespaces

Create namespaces with custom rules. A DAO can govern `/grants/`. A game can control `/items/`. An organization can manage `/members/`.

### Cheap Application State

Store application configuration, feature flags, or content on-chain for pennies. Clients sync it locally.

---

## Reference Implementation

See [reference_impl/](./reference_impl/) for the working implementation including:

- **sbo-cli** - Command-line tool for posting and querying objects
- **sbo-daemon** - Background service that syncs from DA layers
- **sbo-core** - Core library with validation and state management
- **sbo-crypto** - Cryptographic primitives and proofs

The [reference implementation README](./reference_impl/README.md) includes quick start instructions, proof verification examples, and API documentation.

---

## Specifications

| Spec | What it covers |
|------|----------------|
| [Core Spec](./specs/SBO%20Specification%20v0.4.md) | Object model, actions, paths, ownership |
| [Wire Format](./specs/SBO%20Wire%20Format%20Specification%20v0.1.md) | Message serialization, signatures |
| [URI Spec](./specs/SBO%20URI%20Specification%20v0.3.md) | Cross-chain references |
| [Policy Spec](./specs/SBO%20Policy%20Specification%20v0.2.md) | Declarative access control |
| [Name Resolution](./specs/SBO%20Name%20Resolution%20Specification%20v0.1.md) | Identity and naming |
| [Identity Spec](./specs/SBO%20Identity%20Specification%20v0.1.md) | Web authentication, identity schema |
| [Genesis Spec](./specs/SBO%20Genesis%20Specification%20v0.1.md) | Bootstrap sequence |
| [Bridge Spec](./specs/SBO%20Bridge%20Specification%20v0.2.md) | Cross-chain imports |
| [State Commitment](./specs/SBO%20State%20Commitment%20Specification%20v0.2.md) | Trie proofs |

---

## Status

SBO is under active development. The spec is stabilizing, and we have a working reference implementation with:

- CLI for posting and querying (`sbo`)
- Daemon for syncing from Avail (`sbo-daemon`)
- Core library with validation (`sbo-core`)

Want to contribute? Open an issue or jump into the code.

---

## Philosophy

We believe:

- **Data should be cheap to store on-chain.** DA layers make this possible.
- **Ownership should be simple.** Sign with your key. That's it.
- **Governance should be declarative.** JSON policies, not Solidity.
- **Interoperability should be built-in.** URIs and bridges from day one.
- **Users should control their data.** Not platforms. Not protocols.

SBO is infrastructure for a world where your digital stuff is truly yours.

---

*Questions? Ideas? [Open an issue](https://github.com/availproject/sbo/issues).*
