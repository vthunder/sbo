---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Content Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Abstract

This specification defines SBO's **content layer** — thin schemas for posts, comments, and reactions — and the **local-first write model** beneath them: an author clock (HLC) for ordering, causal links (`Prev`) for concurrency detection, last-writer-wins conflict resolution, **confirmed-vs-tip** read semantics, and per-collection **durability tiers**.

The goal is that a write should feel like **saving a file** — instant and offline-capable — while still reconciling to a verifiable shared state. The model achieves this by cleanly separating two things that the base protocol conflated: **attribution** (*who* authored a write — validated at inclusion time, unchanged from the [Authorization Specification](./SBO%20Authorization%20Specification.md)) and **ordering** (*when* a write sorts — the author's HLC, which carries no authority). Because ordering grants no authority, the optimistic local experience needs no trust concession; the chain still decides what is real.

Content objects live in community spaces (`/spaces/...`, see the [Community Specification](./SBO%20Community%20Specification.md)) but the write model applies to any collection that adopts it.

## The Write-Model Layer

A content write is an ordinary SBO object (envelope + payload, signed, attributed) with two added envelope headers:

| Header | Meaning |
|--------|---------|
| `HLC` | The author's hybrid logical clock timestamp — the **ordering** key (see [Author Clock](#author-clock-hlc)). |
| `Prev` | The `object_hash` of the prior version this write was based on — the **causal** link, for mutable objects (see [Causal Links](#causal-links-prev)). |

Both are covered by the envelope signature. A collection that does not use the write model omits them and falls back to base ordering (see [Relationship to Core Ordering](#relationship-to-core-ordering)).

The layer is deliberately **not a CRDT**: there is no automatic state merge. Append-only content (posts, comments) never conflicts; mutable objects are last-writer-wins registers; reactions are LWW toggles. `Prev` provides *detection* of concurrency and a verifiable per-object history, not *resolution* — resolution is always the simple, deterministic LWW rule below.

## Author Clock (HLC)

Every write carries a **hybrid logical clock** timestamp, combining wall-clock time with a logical counter so that causally related writes order correctly even without synchronized clocks.

### Encoding

```
HLC: <physical>.<counter>
```

- `physical` — Unix milliseconds (the author's wall clock at write time).
- `counter` — a non-negative integer, incremented to break ties when multiple writes share a `physical` value, and advanced to preserve monotonicity against observed timestamps (standard HLC update rule).

Example: `HLC: 1703001234567.0`.

### Total order

Writes order by `physical`, then `counter`, then — for a fully deterministic total order across distinct authors — by signer public key, then `object_hash`. All terms are on-chain and deterministic, so every client computes the same order.

### Validity bound

To keep the clock honest, the `physical` component MUST satisfy, against the write's DA block inclusion time `T_b`:

```
T_b − W  ≤  physical  ≤  T_b + ε
```

- `ε` — a small fixed skew tolerance (a few minutes), preventing **future-dating** (a write claiming a future time to win LWW indefinitely).
- `W` — the collection's **maximum authoring lag**: how far in the past a write may claim to have been authored. It bounds **back-dated insertion** of content into history, and equals the collection's offline/batch window. Live collections set `W` small; collections expecting offline or batched authoring set it larger.

A write whose `HLC` falls outside the bound is invalid (disregarded on replay). The bound is an **ordering-integrity** rule only — it does not touch attribution. Because a back-dated write only *loses* LWW (a lower HLC never wins), `W` chiefly matters for append-only content, where a back-dated entry could otherwise be inserted into the past; pure LWW-register collections MAY set `W` generously.

### Ordering carries no authority

The `HLC` decides only where a write sorts. It can never authorize anything: a forged or back-dated `HLC` cannot override another author's write (LWW takes the *highest* HLC, so a lie only demotes the liar's own write). Authority comes solely from attribution (see [Attribution and Offline Writes](#attribution-and-offline-writes)).

## Causal Links (`Prev`)

For a **mutable** object, each write SHOULD set `Prev` to the `object_hash` (see the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#object-hash)) of the version the author observed and is updating. A create sets no `Prev`.

`Prev` yields:

- **Concurrency detection.** Two writes with the same `Prev`, where neither descends from the other, are **concurrent** — they were authored against the same base without seeing each other.
- **A verifiable per-object history.** The chain of `Prev` links is a tamper-evident op-log, which the confirmed-vs-tip distinction reads.

`Prev` does **not** resolve conflicts; concurrent writes are resolved by LWW.

Append-only content (`post.v1`, `comment.v1`) does not use `Prev` on the object itself — each post is a new immutable object — and threads via a `parent` reference instead.

## Conflict Resolution (LWW)

- **Immutable creates** (posts, comments) never conflict: each is a distinct object with its own identity.
- **Mutable objects and reactions** are **last-writer-wins registers**: among all writes to the same object (or the same reaction key), the one with the **highest `HLC`** in the total order is the current value. Concurrent writes (detected via `Prev`) resolve the same way — highest HLC wins; the deterministic tiebreak guarantees convergence.

There is no merge function and no per-field reconciliation; the winning write's value is the value. This keeps the model declarative and out of expressive/computed-state territory (Fork D).

## Confirmed vs Tip

Because writes are authored locally before they are durable, a reader has two views:

| View | Includes | Property |
|------|----------|----------|
| **tip** | all known writes, including locally-authored ones not yet durable | instant, optimistic; **may roll back** |
| **confirmed** | only writes whose durability is realized for their tier (see [Durability Tiers](#durability-tiers)) | stable; never rolls back |

The **tip** is what delivers the instant, save-a-file feel: a client applies a write immediately and shows it. The **confirmed** view lags but is authoritative. A tip write can be superseded when confirmed state arrives — e.g. a concurrent write with a higher `HLC` is confirmed first — so a client treats tip as a prediction and reconciles to confirmed as durability lands. Both views are computed by the same deterministic LWW rules; they differ only in which writes are eligible.

## Attribution and Offline Writes

Attribution is unchanged from the [Authorization Specification](./SBO%20Authorization%20Specification.md): a write must carry an `Auth-Cert` valid at its **DA block inclusion time**. The write model adds no exception — a posted write is attributed exactly as any other.

This makes the offline story simple and honest:

- **Authoring** offline is instant: the client signs writes with its session key and queues them; they appear in the tip immediately.
- **Posting** them requires a certificate valid at inclusion time. As long as the session's certificate is still valid when the batch is posted, the queued writes attribute normally — and their `HLC` places them in authoring order (subject to the collection's `W`).
- If the certificate has expired by posting time, the writes are **re-issued** under a fresh certificate. For append-only content this is lossless (a re-issued post is simply posted now). For a mutable object, a re-issued write is stamped at re-issue time and so may lose LWW to edits made during the offline period — which is the correct outcome: an edit authored before a long absence should not silently override everything that happened since.

The **offline budget is therefore the provider's certificate lifetime** (browserid certificates range from ~1 hour ephemeral to ~24 hours for a primary IdP to ~30 days; the lifetime is the provider's choice, not SBO's). The protocol never honors a certificate outside its validity window — there is no author-time attribution and no back-dating of authority.

> Certificate and DNSSEC evidence are **reused** across many writes within their validity windows (post the evidence once as a self-authenticating object and reference it), so high-write content does not attach a DNSSEC chain per message. See the [Authorization Specification](./SBO%20Authorization%20Specification.md).

## Durability Tiers

A collection declares **how** its writes reach durability. Two tiers are native to SBO because their data lives on the DA layer; a third is noted but deferred.

| Tier | Data location | Confirmed when | Guarantees | Cost |
|------|---------------|----------------|------------|------|
| **on-chain** | full bytes on DA, one write per submission | the write's DA block is included | full: availability, ordering, censorship-resistance | highest |
| **batched** | full bytes on DA, many writes per periodic submission | the batch's DA block is included | **identical to on-chain** | amortized |
| *log-anchored* (deferred) | off-DA log; only roots anchored on DA | a covering anchor is included | integrity + proof-of-existence + bounded equivocation detection; **not availability** | lowest |

### on-chain and batched

These differ only in **submission cadence**, not guarantees. In **on-chain**, each write is its own DA submission (lowest latency, highest cost). In **batched**, a client or aggregator bundles many writes into one periodic DA submission (e.g. every few seconds); the full bytes are still on DA, so availability, replayability, and censorship-resistance are **the same as on-chain** — only per-submission overhead is amortized and confirmation waits for the next flush. Intra-batch order is by `HLC`.

A **batcher/aggregator is trust-minimized**: it submits bytes that clients still validate independently, so it cannot forge, alter, or equivocate — at worst it can delay or decline to submit a write, which is detectable and routable around (submit elsewhere). This is the property that keeps batched SBO-native: **as long as the full data is on DA, any helper is a convenience, not a trusted party.** Batched is expected to be the **workhorse tier** for durable social content (posts, comments, votes that drive ranking).

### Declaring a tier

A collection declares its tier with an optional `collection.v1` descriptor at the collection root:

```
Content-Schema: collection.v1
Path: /spaces/general/
ID: _config

{"durability":"batched","batch_interval_s":5,"max_authoring_lag_s":3600,"schema":"post.v1"}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `durability` | string | No | `on-chain` (default) or `batched` |
| `batch_interval_s` | number | No | Target flush interval for `batched` |
| `max_authoring_lag_s` | number | No | The collection's `W` (default small) |
| `schema` | string | No | Expected content schema for the collection |

Absent a descriptor, a collection defaults to **on-chain** with a small `W`. The tier is a submission/read concern, not a validity rule — a batched write is a perfectly valid envelope; the descriptor tells clients how to submit and when to consider a write confirmed.

### Beyond the DA-native tiers (deferred)

High-write, low-stakes content (live chat, presence, bulk casual reactions) may be too voluminous to place fully on DA even when batched. Such content can be served **off-DA**, with only periodic roots anchored on chain (**log-anchored**), and a specific item **materialized on demand** — posted to DA later and proven against an anchored root — when durability or censorship-resistance is needed.

This tier is **deferred, not rejected**, and SBO does not specify its off-DA log protocol here, for a deliberate reason. Serving an off-DA log well wants either a peer-to-peer network (trustless but poor UX) or a **sequencer** (better UX in every dimension). A sequencer is a *different architecture* than SBO's current based, no-sequencer design — and note that a **ZK-proving sequencer can be mostly trustless**, removing trust in correctness and leaving only censorship and data-withholding as the residual, which is precisely what a DA layer solves. So the honest boundary is narrow: **the DA layer is the censorship-resistance + data-availability boundary**, not an absolute trust boundary. Off-DA, high-write content is simply not what SBO is built for today; it may converge later with SBO's own ZK roadmap. Until then, content that genuinely needs the chain belongs in the on-chain or batched tiers; content that does not need the chain at all (drafts, read-state, presence, private messages) should live **off-chain entirely**, outside SBO.

## Content Schemas

The schemas are intentionally thin. All carry `HLC` (and `Prev` where mutable) as envelope headers; only payload fields are listed here.

### `post.v1`

A top-level post.

```json
{
  "body": "Anyone have a good sourdough starter routine?",
  "parent": null,
  "created_at": 1703001234
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `body` | string | Yes | Content (text/Markdown by convention) |
| `parent` | string | No | URI of a post this references (e.g. a cross-post); absent for a plain top-level post |
| `created_at` | number | No | Cosmetic author wall-clock (Unix seconds); **unverified** — ordering uses `HLC` |

### `comment.v1`

A reply. Identical to a post but `parent` is required.

```json
{
  "body": "I feed mine 1:5:5 every morning.",
  "parent": "/spaces/general/alice@gmail.com/post-abc",
  "created_at": 1703001300
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `body` | string | Yes | Content |
| `parent` | string | Yes | URI of the post or comment being replied to (threading) |
| `created_at` | number | No | Cosmetic; unverified |

Threading is by `parent` reference; depth and ordering of a thread are computed by readers/indexers from the `parent` graph and `HLC`.

### `reaction.v1`

A toggle-able reaction (emoji, upvote/downvote) by one author on one target.

```json
{
  "target": "/spaces/general/alice@gmail.com/post-abc",
  "kind": "upvote",
  "state": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | URI of the reacted-to object |
| `kind` | string | Yes | Reaction kind (e.g. `upvote`, `❤️`) |
| `state` | boolean | No | `true` = present (default), `false` = removed (tombstone) |

A reaction is **author-owned** and keyed by `(author, target, kind)` — at most one active reaction per author per target per kind — stored at a deterministic path in the author's namespace (e.g. `/<author>/reactions/<target-hash>/<kind>`). Toggling is an LWW register on that key: the highest-`HLC` write decides `state`.

**Aggregation is off-chain.** Vote counts, score, and ranking are computed by indexers as subjective views over the raw reactions — the protocol stores individual, attributable reactions and nothing else. This is the same line held for attestation scoring (see the [Attestation Specification](./SBO%20Attestation%20Specification.md#indexing-and-off-chain-scoring)): raw facts on chain, aggregate views off chain.

## Relationship to Core Ordering

DA block inclusion order remains the substrate and the bound: every write is still an ordered, attributed object, and the `HLC` validity bound ties authoring order to inclusion time. For collections that adopt the write model, **`HLC` provides the intra-collection authoring order used by LWW**, layered on top of (and constrained by) inclusion order. Objects without an `HLC` continue to use base inclusion-order semantics unchanged. The State Commitment trie is unaffected — content objects are ordinary leaves keyed by `(path, creator, id)`.

## Worked Example

A post and a reaction in a batched space, seen through tip then confirmed.

1. Alice composes a post offline at wall-clock 9:05. Her client signs it (`HLC: 1703...100.0`), queues it, and shows it in her **tip** immediately.
2. Bob, online, upvotes a different post; his `reaction.v1` enters his tip at once.
3. At 9:06 Alice reconnects. Her client posts the queued write in the space's next **batch**; the batch lands at block time `T_b ≈ 9:06`. The `HLC` bound holds (`9:06 − W ≤ 9:05 ≤ 9:06 + ε` for any `W ≥ ~1m`); the certificate is still valid at `T_b`, so the post attributes to `alice@gmail.com`.
4. Once the batch's block is included, the post moves from tip to **confirmed** for every reader; it is now as durable and censorship-resistant as any on-chain object.
5. An indexer tallies Bob's upvote into the post's score — a view it computes, not a number on chain.

## Security Considerations

- **Clock abuse is bounded and self-defeating.** Future-dating is rejected by `ε`; back-dating only lowers a write's LWW position, so it cannot override another author. The residual — inserting back-dated append-only content into the past — is bounded by the collection's `W`.
- **Attribution is never weakened for convenience.** A posted write always carries a certificate valid at inclusion; there is no author-time validity to exploit. Offline beyond the certificate lifetime forces re-issuance, not a relaxed check.
- **Tip is untrusted.** A tip view includes not-yet-durable writes and may roll back; security-relevant decisions (e.g. acting on a moderation state) should read **confirmed** state.
- **Batched aggregators cannot forge or hide**, only delay; a censored write can be submitted through another path. Off-DA (log-anchored) content forgoes this — its availability rests on the off-DA host (see [Beyond the DA-native tiers](#beyond-the-da-native-tiers-deferred)).

## Privacy Considerations

- All content in on-chain and batched tiers is public and permanent on chain. `created_at` and `body` are visible to everyone; do not place private data in content objects.
- Reactions are individually attributable on chain — who upvoted what is public. Deployments wanting private voting need a privacy mechanism (deferred; see the roadmap notes in the Core and Identity specifications).
- Content that does not need third-party verification (drafts, read-state, direct messages) should live off-chain entirely.

## References

- [SBO Specification](./SBO%20Specification.md) — object model, actions, base ordering, last-writer-wins
- [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) — `HLC` and `Prev` headers, envelope, signatures
- [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) — inclusion-time attribution, the block clock, evidence reuse
- [SBO State Commitment Specification](./SBO%20State%20Commitment%20Specification.md) — `object_hash`, anchoring
- [SBO Community Specification](./SBO%20Community%20Specification.md) — spaces, where content lives
- [SBO Attestation Specification](./SBO%20Attestation%20Specification.md) — off-chain aggregation precedent
