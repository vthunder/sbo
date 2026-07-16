# Proposal: Global `(path, id)` Uniqueness

Status: **Approved (design)** — decisions resolved with reviewer; ready to apply to the
normative specs. See *Decisions (resolved)*. Tracking: sbo-qv95, mingo-jyzt (also resolves the
`/sys/dnssec` fork problem the latter documents).

## Summary

Make an SBO object's identity **`(path, id)` globally unique**: at most one object may
occupy a given `(path, id)` slot across *all* creators. The **first valid write to a slot
wins**; a later `create` at an already-occupied slot by a *different* creator is **invalid**
(disregarded on replay). The create race is resolved by **inclusion order** — the DA block
order — the same rule that `/sys/names` first-claim and genesis block-ordering already use,
and which is *not grindable*.

`creator` is **dropped from the state-trie key** (the trie leaf moves from
`[path…, creator, id]` to `[path…, id]`) but is **retained** as a stored object attribute and
as the wire `Creator` header. `creator` remains **immutable** — preserved across transfer —
and continues to gate creator-integrity authorization. Multi-writer coexistence is preserved
by the existing **identity-in-path** convention (`/<issuer>/attestations/…`, `/u/<email>/…`,
`/<author>/reactions/…`), not by the trie key.

### The invariant (crisp statement)

> For any `(path, id)`, the confirmed state contains **at most one** object. The object
> occupying the slot is the one created by the **first valid `post`** (in DA inclusion order)
> at that slot; it stays until deleted or transferred away. A `post` that would *create* a new
> object at a slot already occupied by a **valid object with a different creator** is **invalid**.
> A `post` by the slot's own creator is an ordinary update. `creator` is an immutable attribute
> of the occupying object, not part of its state-key.

"Already in use" means **occupied by a valid object**. Invalid writes never occupy a slot, so
a slot squatted by an unauthorized (policy-rejected) write is *not* occupied and remains free
for the first authorized creator.

---

## Motivation

### The singleton gap

"One canonical object per path" is a recurring, first-class need — community/board
descriptors, policy objects, `_config`, the bridge import registry, `/sys/names` records,
NFTs. Non-unique `(path, creator, id)` identity, though the correct default for a
*multi-writer* core, cannot express it directly, so the codebase currently synthesizes
singletons **~5 different ad-hoc ways**:

1. A hard-coded **`is_name_claim_path`** branch that special-cases `/sys/names/*` create
   semantics.
2. The bridge's **bespoke atomic existence-checked `import`** (Bridge spec: "Check registry —
   Verify `/sys/bridge/imported/{origin-hash}` doesn't exist"; "Path can only be created once").
3. **Genesis block-ordering + sys-locked paths** to guarantee a single root policy / domain
   object.
4. "**Assume there's one**" for `/sys/domains` (and community descriptors) — a convention the
   trie does not enforce.
5. An **unspecified, load-bearing `get_first_object_at_path_id`** lexicographic-first-*creator*
   tiebreak, used even for **root-policy lookup**.

Mechanism (5) is the dangerous one: it is **grindable**. Because the trie sorts creator
segments lexicographically and resolution returns the *first* creator's object, an attacker
can **mint a low-sorting creator key to squat a shared slot** (mingo-jyzt) — including the
slot a policy or domain object is read from. This is a passive attack, exploitable at any time
by anyone permitted to create at the path.

### The `/sys/dnssec` fork problem (mingo-jyzt)

`/sys/dnssec/<D>` is read as a singleton (domain self-certification and user-attribution
evidence both resolve "the" object at that path). Under `(path, creator, id)` identity, two
creators can both file `/sys/dnssec/<D>`, and the lexicographic-first tiebreak silently picks
one — a **grindable fork** of the evidence a verifier depends on. The uniqueness invariant
closes this: the first valid writer owns `/sys/dnssec/<D>` and no second creator can shadow it.

### Why the original non-uniqueness motivations no longer hold

Non-unique `(path, creator, id)` was chosen for two reasons; both are now judged weak:

- **(a) Verify-in-isolation / idempotent writes.** The idea was that a write's validity should
  depend only on the message, not on slot occupancy. But current state **already requires
  replay**: LWW, transfer, and delete all mean *validity-at-inclusion ≠ validity-now*. Isolation
  therefore only ever paid rent at write time, while readers already reconstruct state. Adding a
  slot-occupancy check to `create` costs nothing readers do not already pay.

- **(b) Fire-and-forget writes** (e.g. "send to `/U2/inbox/<id>` without checking state").
  This is **preserved in practice**: a collision-resistant `id` (content-hash or random) makes
  such a write valid *by construction* — no other creator can already hold a random slot — so no
  state or inclusion check is forced. The uniqueness rule only bites **contended, human-chosen
  ids**, which is *exactly* where first-come-first-served is the desired semantics.

### Multi-writer semantics are not lost

Per-author coexistence is already expressed by **identity in the path**:
`/<issuer>/attestations/<subject>/<type>`, `/u/<email>/…`, `/<author>/reactions/…`. The
uniqueness invariant plus this convention cover **both** the single-canonical and the
multi-writer need with **one rule and no per-collection mode**.

We **explicitly reject a per-collection "multi-creator" opt-out mode**: it adds an ongoing
multi-implementation maintenance surface (every validator, indexer, and proof path must branch
on collection mode) and is **redundant** — identity-in-path already yields per-author
coexistence wherever it is wanted.

### The `creator`-in-key decision

Dropping `creator` from the trie key is only **marginally** cheaper for proofs/zk: the state
trie is a sparse path-segment trie, so `creator` is *one* level — one in-circuit SHA-256 out of
~`path_depth + 2`. There *is* a real RISC Zero zkVM target, but `creator` is not a cost driver.

The real win is **code simplification**: the ~21 `get_first_object_at_path_id` /
`object_exists_at_path_id` scan sites collapse to **point lookups**; the transfer
destination-collision becomes a single global check; the `is_name_claim_path` special case and
the grindable tiebreak **disappear**. Because `creator` already exists as `StoredObject.creator`
+ the wire `Creator` header, **no new metadata is introduced** by moving it out of the key.

---

## The New Rules (precisely)

1. **Object identity is `(path, id)`.** The state-trie leaf is keyed by `[path_segments…, id]`.
2. **Uniqueness = first-valid-write-wins.** For a given `(path, id)`, the occupying object is
   the one created by the first valid `post` in DA inclusion order. A `create` (a `post` at a
   currently-empty slot) is a normal creation; a `post` at a slot occupied by a valid object is
   an **update** iff the signer is authorized for the occupying object, otherwise **invalid**.
   Occupancy is a **point-in-time** property: once the occupant is **deleted** (Rule 7) or
   **transferred away** (its source slot vacated, Rule 5), the slot is empty again and a
   subsequent `create` by **any** authorized creator is valid and becomes the new occupant.
   "First valid write wins" therefore means "first among the writes contending for the slot
   *while it is empty*," not "first ever."
3. **The create race is resolved by inclusion order.** Two `post`s that both try to create the
   same slot in the same or different blocks: the earlier in DA order wins; the later is invalid.
   This is the identical, non-grindable rule already used by `/sys/names` first-claim and by
   genesis block-ordering.
4. **`creator` is dropped from the trie key** but **retained** as an immutable stored attribute
   (`StoredObject.creator`) and the wire `Creator` header. It still gates creator-integrity
   authorization (a writer must be authorized for a declared `Creator`).
5. **Transfer destination-collision is global.** A `transfer` to `(New-Path, New-ID)` is valid
   only if that destination slot is **empty** (occupied by *no* valid object, regardless of
   creator) — not merely "empty for this creator".
6. **`creator` is preserved across transfer.** A transfer re-homes the leaf and carries the
   original `creator` unchanged; only `owner`, `path`, and/or `id` change.
7. **Delete frees the slot.** After a `delete`, `(path, id)` is empty and may be re-created by
   **any** authorized creator — i.e. **id recycling becomes possible** (the same consideration
   `/sys/names` records already carry). See *Open Questions* on an optional cooldown.
8. **Invalid writes never occupy.** "Already in use" = occupied by a *valid* object; a
   policy-rejected or malformed write neither occupies nor blocks the slot.
9. **Create-race resolution is inclusion-order, and occupancy tracks the canonical chain.**
   The occupant of a `(path, id)` slot is determined by DA inclusion order over all *valid*
   creates: within a block the lower message index wins; across blocks the earlier block wins.
   A create's validity is evaluated against confirmed+pending state **as of its own inclusion
   point** — a create targeting a slot occupied by a valid object at that point is invalid
   unless the signer is authorized to update the occupant. In the optimistic-tip overlay a
   **pending** create MUST be *superseded* (dropped, not merged) by any create/transfer that
   occupies the same slot earlier in inclusion order once confirmed. On a **reorg** that evicts
   the create establishing the current occupant, the slot **re-opens** as of the reorg point and
   is re-resolved by this same rule over the surviving valid creates — so a previously-preempted
   create MAY become the occupant, and a previously-valid occupant MAY become invalid. Occupancy
   is thus a function of the canonical chain at the read height, exactly as content value is
   under LWW; consumers needing stability across reorgs pin by `object_hash` / `as_of`, not by
   slot alone. (This is the create-side analog of LWW's tolerance of content reordering; it is
   new normative text for the State Commitment spec — see §1 edit (1h).)

---

## Per-Spec Change List (exact before→after)

Eight specs change substantively; one (Attestation) is confirmed unchanged with a rationale.

### 1. `SBO State Commitment Specification.md`

**(1a) "Creator as Path Segment" — the identity + full-segments statement.**
Section *Creator as Path Segment*, current text:

> In SBO, objects are uniquely identified by `(path, creator, id)` rather than just `(path, id)`. Multiple creators can post objects with the same ID at the same path. To handle this in the trie, the **creator** is included as a path segment between the path and the ID.
>
> **Full path segments:** `[path_segments..., creator, id]`

Replace with:

> In SBO, objects are **globally uniquely identified by `(path, id)`**: at most one object may
> occupy a given `(path, id)` across all creators (see the [SBO Specification]
> (./SBO%20Specification.md#object-identity)). The trie is keyed on the path and id alone.
>
> **Full path segments:** `[path_segments..., id]`
>
> `creator` is **not** a trie segment. It is retained as an immutable object attribute (the
> wire `Creator` header, resolved to the author's controller — see below), used for
> creator-integrity authorization and provenance, but it does not disambiguate identity.

*Consistency note:* this is the load-bearing reversal; every other edit in this spec follows.

**(1b) The "resolved controller" paragraph.** Current text (retained but re-scoped):

> **The creator segment is the author's resolved controller, not the signing key.** It is derived deterministically from the message and chain state at inclusion time: the explicit `Creator` header if present, else … a stable encoding of the signing key. …a from-genesis replayer reconstructs the identical trie.

Change "**The creator segment**…" → "**The stored creator attribute**…", and drop "reconstructs
the identical trie" dependence on the segment (it is now an attribute of the leaf object, still
deterministic). *Consistency note:* keeps the resolved-controller derivation, only its *role*
(attribute, not key segment) changes.

**(1c) "Transfer is creator-invariant."** Current text:

> **Transfer is creator-invariant.** A `transfer` re-homes the existing `(path, creator, id)` leaf to `(new_path, creator, new_id)` — deleting the source leaf and inserting the destination leaf with the **same object hash**. The creator segment does not change (only `path`, `id`, and/or the object's `owner` may). The destination-collision rule ("does not exist by the same creator at the destination") is evaluated against this preserved creator.

Replace with:

> **Transfer is creator-invariant.** A `transfer` re-homes the existing `(path, id)` leaf to
> `(new_path, new_id)` — deleting the source leaf and inserting the destination leaf with the
> **same object hash** and the **same immutable `creator` attribute**. The destination-collision
> rule is now **global**: the transfer is valid only if the destination `(new_path, new_id)` slot
> is occupied by **no valid object** (regardless of creator).

**(1d) The example tree.** Current `/sys/names` node example shows two creator subtrees:

> ```
> /sys/names node:
> {
>   "children": {
>     "user123": "sha256:...",
>     "user456": "sha256:..."   // Different creator
>   }
> }
>
> /sys/names/user123 node:
> {
>   "children": {
>     "alice": "sha256:111...",   // object_hash
>     "bob": "sha256:222..."      // another object by same creator
>   }
> }
> ```
> An object at `/sys/names/` with ID `alice` created by `user123` has trie segments:
> `["sys", "names", "user123", "alice"]`

Replace with a single-level node keyed by id:

> ```
> /sys/names node:
> {
>   "children": {
>     "alice": "sha256:111...",   // object_hash; creator is a leaf attribute
>     "bob":   "sha256:222..."
>   }
> }
> ```
> An object at `/sys/names/` with ID `alice` has trie segments `["sys", "names", "alice"]`.
> Its creator (`user123`) is recorded on the object, not in the key; a second creator cannot
> file a second `alice` here.

**(1e) The enumerated benefits list.** Current:

> This design:
> 1. Allows multiple creators at the same path to have objects with the same ID
> 2. Enables proofs for all objects by a specific creator under a path
> 3. Maintains the trie's hierarchical structure
> 4. Makes proofs slightly larger due to the extra segment, but keeps them efficient (O(depth))

Replace with:

> This design:
> 1. Enforces one canonical object per `(path, id)` (first-valid-write-wins by inclusion order)
> 2. Turns every existence/first-object lookup into a point lookup (no per-creator scan)
> 3. Maintains the trie's hierarchical structure
> 4. Keeps proofs one segment shorter (`[path…, id]`), O(depth)
>
> (Per-creator enumeration is no longer a trie affordance; where per-author collections are
> wanted, the author is a **path** segment — e.g. `/<issuer>/attestations/…` — so a creator's
> objects remain a subtree by construction.)

**(1f) Proof format / segments.** The Inclusion Proof example and *Verification Algorithm*
walk `proof` steps by `segment`. No structural change is required (already generic over
segments), but the **fixtures change**: any proof whose path passed through a `creator` segment
loses that step. *Consistency note:* update proof test fixtures; the algorithm text is unchanged.

**(1g) Snapshot reconstruction.** Current:

> 2. Reconstruct the state trie by inserting each object at its
>    [path, creator, id] segments (see State Tree Structure) with leaf = object_hash.

Replace `[path, creator, id]` → `[path, id]`.

**(1h) New normative section — "Slot occupancy and create-race resolution."** Add (there is no
current text for this; it is the one genuinely new rule the change introduces):

> **Slot occupancy.** Each `(path, id)` slot holds at most one object. Its occupant is
> determined by DA inclusion order over all *valid* creates targeting the slot while it is empty:
> within a block the lower message index wins; across blocks the earlier block wins. A create's
> validity is evaluated against confirmed+pending state **as of its own inclusion point** — a
> create into a slot occupied by a valid object at that point is invalid unless the signer is
> authorized to update the occupant. A **delete** or a **transfer away** vacates the slot; a
> later create by any authorized creator may then occupy it. In the optimistic-tip overlay a
> **pending** create MUST be superseded (dropped, not merged) once a create/transfer earlier in
> inclusion order is confirmed for the same slot. On a **reorg** that evicts the create
> establishing the occupant, the slot re-opens as of the reorg point and is re-resolved by this
> same rule; a previously-preempted create MAY become the occupant and a previously-valid one MAY
> become invalid. Occupancy is a function of the canonical chain at the read height (as content
> value is under LWW); consumers needing cross-reorg stability pin by `object_hash` / `as_of`.

*Consistency note:* this is the create-side analog of the existing LWW content-resolution rule;
it belongs in State Commitment alongside the LWW description.

### 2. `SBO Specification.md`

**(2a) Object Identity.** Current:

> Each object in the system is identified by an ID, a creator, and a path. The fully qualified ID of an object is as follows … `[path/][creator:]id`

Replace with — **`creator` is removed from the reference syntax entirely** (it becomes an
ordinary attribute, addressed like any other, not embedded in object references):

> Each object is identified by a **path** and an **ID**. The fully qualified reference to an
> object is `[path/]id`. An object's **identity in state is `(path, id)`, globally unique** — at
> most one object per `(path, id)` across all creators. `creator` is an immutable **attribute**
> (the original author), carried on the object for provenance and authorization and *checkable*
> against expectation out-of-band, but it is **not** part of the reference/addressing grammar and
> never selects among objects (none coexist at a slot).

*Consistency note:* dropping `creator:` from the reference grammar is a deliberate
simplification — every parser/implementation stops having to model a `creator:` element. All
`[path/][creator:]id` grammar productions in this spec are reduced to `[path/]id`.

**(2b) The "same ID … unless different creators" line.** Current (line 161):

> The same ID in the same collection may only refer to one object (or collection), unless the objects (or collections) have different creators.

Replace with:

> The same ID in the same collection may refer to **only one object (or collection), globally**.
> The **first valid write** (in DA inclusion order) to a `(path, id)` slot wins; a later
> `create` at an occupied slot by a **different creator is invalid**. Per-author coexistence is
> expressed by putting the author in the **path** (e.g. `/<author>/reactions/<id>`), not by
> sharing a slot.

**(2c) Ownership vs creator.** Line 224 ("If `Owner` is absent, the owner is the creator.")
is **unchanged** — creator still exists and still defaults ownership. Add one clarifying
sentence to *post*: object *creation* is valid only if the target slot is empty **or** the
signer is authorized for the object already occupying it (an update). *Consistency note:*
write-validity now explicitly includes slot-uniqueness.

**(2d) `post` rules (line 237–242).** Current bullet:

> - Object creation is idempotent: it may create a new object or update an existing one.

Append:

> - Creation targets a **globally unique** `(path, id)` slot: a `post` that would create a *new*
>   object at a slot already occupied by a valid object of a **different creator** is invalid
>   (the incumbent, established by earlier inclusion order, wins). A `post` by the incumbent's
>   own creator/owner is an ordinary update.

**(2e) `transfer` destination-collision (line 250).** Current:

> - Only valid if the destination does not exist by the same creator at the destination path.

Replace with:

> - Only valid if the destination slot `(New-Path, New-ID)` is occupied by **no valid object**
>   (a **global** check, not per-creator). The transfer preserves the object's immutable
>   `creator`.

### 3. `SBO URI Specification.md`

**(3a) Remove `creator:` from the URI grammar.** `sbo://[domain]/[path/][creator:][id][?query]`
(line 31) and the raw form (line 85) **drop the `creator:` element**:

> `sbo://[domain]/[path/][id][?query]` (and the raw form correspondingly). Because `(path, id)`
> is globally unique, an object reference needs only its path and id; `creator` is an object
> **attribute**, not an addressing element. Verifying authorship is done by resolving the object
> and comparing its `creator` attribute to expectation — not through the URI grammar.

*Consistency note:* removing `creator:` simplifies every URI parser and matches the core-spec
reference change (2a). The bare-`repo=` rule (which already forbids `creator` in `repo=`) is
unaffected. **This moots former Open Question 5** (there is no `creator:` in a reference to
mismatch).

### 4. `SBO Identity Specification.md`

**(4a) `/sys/names/` first-claim is now the general rule.** The namespace description (line 124)
and the *Anti-hijack* note (246–250) describe name-claim uniqueness as a bespoke first-come
mechanism. Reframe: name-claim uniqueness is now a **direct instance** of the global invariant,
not a special mechanism. Add to line 124's paragraph:

> First-come name creation is exactly the **global `(path, id)` first-valid-write-wins** rule
> (see the [State Commitment](./SBO%20State%20Commitment%20Specification.md#creator-as-path-segment)
> and [Core](./SBO%20Specification.md#object-identity) specs): the first valid claimant of
> `/sys/names/<name>` owns the slot; no second creator can shadow it. This is no longer a
> name-specific rule — it is the same invariant every path obeys.

**(4b) The stored creator paragraph (line 118)** keeps the resolved-controller derivation but
change "recorded in the state trie" wording to "recorded as the object's immutable `creator`
attribute (see State Commitment spec)". *Consistency note:* the derivation is unchanged; only
its storage location (attribute, not key segment) is corrected.

### 5. `SBO Community Specification.md`

**(5a) Single descriptor per community is now native.** Aggregated layout (line 37): "each a
`community.v1` at `/communities/<id>`". Add:

> Under global `(path, id)` uniqueness, the descriptor slot `(/communities/, <id>)` (and the
> repository-per-community `/sys/community`) holds **exactly one** `community.v1` — the
> single-canonical-descriptor guarantee is now **native**, not a convention. The first valid
> writer owns the community's descriptor slot; a competing creator cannot fork it. This resolves
> the board/descriptor case (a board is a singleton descriptor object per community id).

*Consistency note:* removes the implicit "assume there's one descriptor" reliance.

### 6. `SBO Bridge Specification.md`

**(6a) Import registry create-once is native.** The atomic-import steps (line 139–146) and the
Notes (line 306–308: "Path can only be created once", "Same origin cannot be imported twice")
currently describe a **bespoke** existence check. Reframe:

> **Registry create-once is now the global invariant, not bridge-specific machinery.** Because
> `(/sys/bridge/imported/, {origin-hash})` is a globally unique slot, "Check registry — verify
> it doesn't exist" is simply the ordinary first-valid-write-wins rule; a second `import` of the
> same origin is invalid because the slot is occupied. The `import` action still atomically
> creates *both* the registry entry and the object (so the pair is all-or-nothing), but the
> uniqueness guarantee for the registry entry no longer needs a bespoke atomic existence check —
> it is the same slot-uniqueness every `post` obeys.

*Consistency note:* keep the atomicity (two-object-in-one-action) requirement; only the
uniqueness enforcement is delegated to the core invariant.

### 7. `SBO Content Specification.md`

**(7a) `[path, creator, id]` leaf reference (line 225).** Current:

> The State Commitment trie is unaffected — content objects are ordinary leaves keyed by `(path, creator, id)`.

Replace `(path, creator, id)` → `(path, id)`.

**(7b) Collision-safe id guidance for shared paths.** Add a short note near the write model:

> **Shared-path ids must be collision-safe.** Because `(path, id)` is globally unique, multiple
> authors writing to a *shared* collection path (e.g. a community space
> `/communities/{c}/spaces/{s}/`) MUST mint ids that will not collide across authors — a content
> hash, or `author + random` — otherwise two concurrent writes to the same id collide and one is
> dropped (first-valid-write-wins). Wall-clock ids alone (`Date.now()`) are **not** collision-safe.
> Where per-author coexistence is intended, prefer putting the author in the path.

### 8. `SBO Attestation Specification.md` — **confirmed UNCHANGED**

Attestations are stored under the **issuer's namespace**: `Path: /<issuer>/attestations/<subject>/`,
`ID: <type>` (line 107–114). The primary key `<issuer>/<subject>/<type>` already embeds the
issuer (author) in the **path**. Under global `(path, id)` uniqueness this is already a
per-issuer subtree, so:

- Two different issuers asserting the same `(subject, type)` live at **different paths** — no
  collision.
- Re-issuing the same `(issuer, subject, type)` is the *same* creator updating its own slot —
  an ordinary LWW `post`, exactly as the spec states.

No text changes. *(Add one sentence to the Storage decision noting that issuer-in-path is what
makes attestations compatible with the global uniqueness invariant — coexistence comes from the
path, not from sharing a slot.)*

### 9. `SBO Authorization Specification.md`

**(9a) Creator integrity (line 344–357).** The rule "when a message declares a `Creator`, the
signer MUST also be authorized for it" is **retained** — `creator` still exists as an attribute
and still must not be forged. Update the justification text (line 348–350) that ties creator to
the trie segment:

> But `Creator` independently determines the object's **identity in state** — its
> `(path, creator, id)` trie segment …

Replace with:

> But `Creator` is the object's immutable **author attribute** and gates provenance/ownership
> defaulting (`effective_owner = Owner → else Creator → else signer`). A writer must not be able
> to file an object under another identity's `Creator`.

**(9b) Transfer destination-collision.** Wherever the authorization/transfer text references the
per-creator destination rule, align to the **global** check (mirrors edit 2e / 1c).

**(9c) Name-claim anti-hijack (line 359–368).** **Unchanged in force** — creating
`/sys/names/<local>` on a primary-domain repo still requires authorization as `<local>@D`, and
off-primary-domain claims are first-come. Add a one-line note that "first-come" here is now the
global invariant, and that the anti-hijack authorization requirement layers *on top of* it
(policy makes the slot claimable only by the rightful email; uniqueness makes the first valid
claim final).

---

## Consistency Map

Cross-spec claims that MUST change together:

| Claim / phrase | Locations | Change |
|---|---|---|
| Trie key `(path, creator, id)` / `[path…, creator, id]` | State Commitment §Creator-as-Path-Segment (122–128, 132–134), §Snapshot (526), Content (225) | → `(path, id)` / `[path…, id]` |
| "Multiple creators … same ID at same path" / "unless … different creators" | State Commitment (122, 157, 171), Core (161) | → global uniqueness, first-valid-write-wins |
| `creator:` in reference/URI grammar (`[path/][creator:]id`) | Core Object Identity (25–33, 87), URI (31, 85) | → **removed from the grammar**; `creator` is an attribute only, `[path/]id` references |
| Slot occupancy / create-race + reorg resolution | State Commitment (NEW §, edit 1h; Rule 9) | new normative text (create-side analog of LWW) |
| Transfer destination-collision "by the same creator" | Core (250), State Commitment (128), Authorization (transfer) | → **global** empty-slot check |
| creator preserved across transfer | Core (246), State Commitment (128) | unchanged (now an attribute, still preserved) |
| creator = author's resolved controller (derivation) | State Commitment (126), Identity (118) | derivation unchanged; storage = attribute not key segment |
| Creator-integrity authorization (declare `Creator` ⇒ authorize) | Authorization (344–357) | rule retained; justification reworded (attribute, not trie segment) |
| `/sys/names` first-claim mechanism | Identity (124, 246–250), Authorization (359–368) | reframed as instance of global invariant; anti-hijack policy retained |
| Import "created once" / registry existence check | Bridge (142, 306–308) | reframed as native slot-uniqueness; atomicity retained |
| Single descriptor per community | Community (36–37) | native, not convention |

---

## Security Analysis

- **Grindable → front-runnable.** OLD: an attacker mints a **low-sorting creator key** to
  passively **squat any shared slot** (the lexicographic-first tiebreak returns their object) —
  exploitable anytime, no race needed (mingo-jyzt). NEW: first-*valid*-write-wins by **inclusion
  order** — the slot is only **front-runnable by active racing**, which is exactly the accepted
  `/sys/names` first-claim model. The passive grind is eliminated.
- **Personal / issuer / sys paths are unaffected.** Creation there is **policy-locked** or
  **identity-in-path** (`/u/<email>/…`, `/<issuer>/attestations/…`, `sys`-owned genesis paths).
  An unauthorized write is **invalid** and therefore **never occupies** a slot, so it cannot deny
  the rightful creator. The invariant only changes behavior on genuinely **permissionless** paths.
- **Permissionless-path squatting is intended and policy-gated.** On a path whose policy grants
  `create` to everyone (e.g. default `/sys/names/*`), first-come squatting is the *designed*
  semantics; deployments that want stricter allocation tighten the path policy (already noted in
  Identity §Name squatting).
- **Recycling.** `delete` frees the slot → a subsequent creator (possibly different) may re-use
  `(path, id)`. This is the **same recycling consideration `/sys/names` already carries** (a
  deleted name can be re-registered). Consumers that pin an object should pin by `object_hash` /
  `as_of`, not by slot alone. See *Open Questions* for an optional cooldown.

---

## Migration

Dropping `creator` from the trie key **changes every leaf's position**, so the **state root
changes** for any database with objects. Options:

1. **Re-genesis** (recommended for mingo). Mingo's chain is nearly empty, so re-deriving the
   state root under the new keying is cheap. A fresh genesis simply computes leaves at
   `[path…, id]`.
2. **Coordinated migration** for a populated chain: re-key all leaves at a checkpoint height,
   publish a new root + snapshot, and require clients to adopt at that height. Heavier; not
   needed for mingo.

**One client data-loss fix in the same change (soft blocker from the sweep):** mingo-web mints
post/comment/reaction ids from `Date.now()` at the shared
`/communities/{c}/spaces/{s}/` path. Under uniqueness, two same-millisecond writes collide and
one is dropped. **Fix:** collision-safe ids (append `author + random`, or a content hash) — the
pattern `mingo-app/src/seed.rs` already uses.

**Code touchpoints:**

- `object_to_segments` / `encode_object_key` (sbo-core `state/db.rs`): drop the `creator`
  segment; key on `[path…, id]`.
- Collapse the **~21** `get_first_object_at_path_id` / `object_exists_at_path_id` scan sites
  (sbo-core `state/db.rs`; sbo-daemon `state_view.rs`, `sync.rs`, `snapshot.rs`, `main.rs`,
  `validate.rs`) into **point lookups**.
- Transfer destination-collision → **global** empty-slot check.
- SBOQ segment construction + **proof test fixtures** (drop the creator step).
- **Retire `is_name_claim_path`** (name-claim uniqueness is now the general rule).
- **Retire the `dnssec_hlc` grind stopgap** (sbo-cli `examples/dnssec_hlc.rs`) — the fork it
  worked around is closed by the invariant.
- Ensure `StoredObject.creator` / wire `Creator` continue to be populated (unchanged) as the
  immutable attribute + preserved on transfer.

**Sweep result (due diligence):** NO hard blockers. No test asserts two-creators-one-slot; no
transfer test expects cross-creator destination coexistence; no proof asserts creator-as-authority;
mingo never reconstructs state keys *with* creator. The only soft path is the `Date.now()` id
minting above.

---

## What This Resolves / Removes

- **mingo-jyzt** — the grindable low-sorting-key squat on shared slots.
- **`/sys/dnssec` forks** — a second creator can no longer shadow the evidence object.
- **`is_name_claim_path`** — deleted; name uniqueness is the general rule.
- **Bridge bespoke existence check** — delegated to core slot-uniqueness (atomicity retained).
- **The unspecified, load-bearing `get_first_object_at_path_id` lexicographic tiebreak** — gone;
  replaced by point lookup + inclusion-order first-write.
- The "assume there's one" descriptor convention for `/sys/domains` and community descriptors —
  now enforced.

---

## Decisions (resolved with reviewer)

1. **Point-key, not creator-scoped subtree proofs.** No consumer needs "prove all objects by
   creator C under path P"; identity-in-path (`/<author>/…`) covers the genuine cases. The trie
   is keyed `[path…, id]`.
2. **Inclusion-order tie resolution + reorg semantics are specified** — see Rule 9 and edit (1h),
   which add the normative paragraph to the State Commitment spec (create-race by inclusion order;
   pending creates superseded not merged; reorg re-opens and re-resolves the slot; pin by
   `object_hash`/`as_of` for stability).
3. **No protocol delete cooldown.** A deleted `(path, id)` is immediately re-creatable (as
   `/sys/names` already tolerates); recycling-sensitive namespaces restrict re-creation via path
   *policy*, and consumers pin by `object_hash`/`as_of` rather than by slot.
4. **Invariant subsumes genesis singleton guarantees** — sys-locked creates are policy-authorized
   and first-valid-write-wins matches genesis block-ordering. *Implementation must verify* genesis
   root computation never assumed a `creator` trie segment (a code check, not a design question).
5. **`creator` removed from reference/URI syntax** (edits 2a, 3a). This *supersedes* the earlier
   "creator: MUST match" question — there is no `creator:` in a reference. Authorship is verified
   by resolving the object and comparing its `creator` attribute out-of-band.
