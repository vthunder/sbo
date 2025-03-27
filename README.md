# Simple Blockchain Objects (SBO)

**Version: v0.4 (Draft)**

Simple Blockchain Objects (SBO) define a minimal, flexible, and human-readable system for posting, updating, and managing structured data on-chain. SBOs provide composable building blocks for decentralized data, identity, and governance — without requiring smart contracts.

---

## 🧱 Core Concepts

- **Objects & Collections** — Hierarchical data model similar to a filesystem
- **Signed Envelopes** — Canonical serialization, content hashing, and signatures
- **Policy Enforcement** — Path-scoped governance with programmable rules
- **Name Resolution** — Human-readable identities and cross-chain bindings
- **URIs** — Durable, linkable, versioned references to SBO objects, even cross-chain

---

## 📚 Specifications

| Spec | Description |
|------|-------------|
| [SBO Specification v0.4](./SBO%20Specification%20v0.4.md) | Core object model, envelope format, actions, paths, and rules |
| [SBO URI Spec v0.2](./SBO%20URI%20Specification%20v0.2.md) | Cross-chain, versioned object URIs |
| [SBO Name Resolution v0.1](./SBO%20Name%20Resolution%20Specification%20v0.1.md) | Naming system and identity bindings |
| [SBO Policy Spec v0.1](./SBO%20Policy%20Specification%20v0.1.md) | Executable path-level policy rules |
| [SBO Bridge Spec v0.1](./SBO%20Bridge%20Specification%20v0.1.md) | Cross-blockchain object transfer |
| [SBO NFT Schema v1](./SBO%20NFT%20Schema%20v1.md) | Schema for NFT objects |

---

## 🧩 Example Use Cases

- **NFTs** with programmable minting and transfer policies
- **Cross-chain objects** that are versioned and verifiable
- **Decentralized identities** tied to human-readable names
- **Application-layer state** anchored to data availability layers
- **Governed namespaces** where paths are managed by identity or DAO

---

## 🛠️ Extensibility Roadmap

- Bridging to other blockchains (as ERC-721)
- Verifiable off-chain computation (ZK policy conditions)
- Signed collections, indexes, snapshots
- WASM-based and declarative policies
- Merge strategies (CRDTs, diffs, etc.)
- Support for content-addressed payloads (IPFS, Arweave)

---

## 🧪 Status

This is a **draft specification**, under active development. Expect changes as the model is refined and tested with SDK implementations and real-world use cases.

---

## 🧵 Contact / Discussion

For feedback, ideas, or questions, open an issue or start a discussion in this repository.

---

