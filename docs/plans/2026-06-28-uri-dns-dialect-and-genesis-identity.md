# URI / DNS dialect + genesis-anchored identity — spec lock & implementation plan

**Status:** Spec updated (this commit); implementation pending. Prepared 2026-06-28.

Goal: make the implementation **comprehensive** for the newly-locked URI/DNS surface so
there is **no gap** between spec and code. Specs already updated: `SBO URI
Specification.md` (canonical), `SBO Genesis Specification.md`, `SBO Identity
Specification.md`, `crates/README.md`.

## The locked surface (what the code must implement)

**`sbo+raw://` grammar:**
```
sbo+raw://chain:appId[@firstBlock]/[path/][creator:][id][?query]
```
- Authority is exactly `chain:appId` (CAIP-2 + appId) — never grows, so an opaque
  `appId` stays unambiguous.
- `@firstBlock` = genesis **anchor** (database-level; inherited by every composed
  path; **not** a snapshot). Redefines the old `@block`-means-snapshot.
- Query selectors: `genesis=<hash>` (identity verify/disambiguate, hash-only),
  `as_of=<block>` (historical snapshot — the read-time block selector that replaces
  `@block`), plus existing `content_hash`/`content_type`/`content_schema`/`encoding`/`size`.

**Database identity (canonical 4-tuple):** `{chain}:{appId}:{firstBlock}:{genesisHash}`
where `genesisHash = sha256(all_genesis_objects_bytes)` (verifying, reproducible) and
`firstBlock` is the locator.

**Reference vs identity:** a reference may carry `@firstBlock` only, `?genesis=hash`
only, or both. Anchor-only resolves but **MUST error if >1 genesis exists at
`(chain, appId, firstBlock)`** (ambiguous — never guess). Hash-only locates by
scan/checkpoint. After resolving any reference, the client confirms `genesisHash`.

**DNS `_sbo` record (data-only; no identity/trust root):**
```
v=sbo1 repo=sbo+raw://chain:appId@firstBlock/ genesis=sha256:<hash> node=<url> checkpoint=<url>
```
- `r=`→`repo=`; drop `h=`. `repo=` MUST be **bare** (no path/creator/query — ignored).
- Identity discovery is on-chain only (browserid broker pinned in genesis + `/sys/names`).
  `_sbo-id` is dead.

## Current implementation gaps (audit)

1. **No canonical URI type.** Parsing is scattered: `SboUri::parse`
   (`daemon/src/repo.rs:101`, 3-part authority only, no `@block`, no query) + four
   ad-hoc CLI parsers (`cli/src/main.rs:1604 parse_object_path`, `:1808
   parse_sbo_uri_prefix`, `:1822 parse_sbo_uri_path`, `cli/commands/identity.rs:694
   parse_identity_uri`). Spec↔impl drift is structural.
2. **DNS parser** (`core/src/dns.rs`) reads only `v`/`r`/`h`; ignores
   `genesis`/`firstBlock`/`node`; has dead `discovery_host`/`get_discovery_host`;
   `resolve_uri` returns a bare string, dropping the anchor; stale `_sbo-id` module doc.
3. **`from_block` not wired from DNS** — comes from the operator at `RepoAdd`
   (`daemon/src/main.rs:873`); the record's anchor is never consumed.
4. **No genesis-identity function** — nothing computes `sha256(all_genesis_objects_bytes)`
   or the 4-tuple; no verify-on-sync; no block-only ambiguity check.
5. **No `as_of` read path** — `/v1/object` has no historical-snapshot selector (the
   state DB *does* expose `get_state_root_at_block`, `state/db.rs:327`, so the
   primitive exists; it's just not plumbed to a URI selector).

## Implementation plan

### Phase A — canonical URI type in `sbo-core` (single source of truth)
- New `core/src/uri.rs`: `SboRawUri { chain: ChainId, app_id: AppId, first_block:
  Option<u64>, path: Option<String>, creator: Option<String>, id: Option<String>,
  query: UriQuery }` where `UriQuery { genesis: Option<Hash>, as_of: Option<u64>,
  content_hash, content_type, content_schema, encoding, size }`.
  - `parse(&str)` handling `@firstBlock` (after appId, before `/`), path/creator/id,
    and the `?k=v&...` query. `to_string()`/`to_canonical_string()` re-emit `@firstBlock`.
  - `authority()` → `{chain}:{appId}` only (opaqueness-safe); `compose(path)` inherits
    the anchor; `is_bare()` for the DNS rule.
  - `AppId` as a newtype that is numeric **today** but opaque-ready (decision (3)
    follow-up: keep the type, relax the inner repr later).
- Move `ChainId` (currently `daemon/src/repo.rs`) into `core` and reuse.
- `daemon`'s `SboUri` becomes a thin wrapper/alias over the core type (or is replaced);
  delete the 3-part-only parser. Re-point the four CLI parsers at the core type.

### Phase B — DNS record parser (`core/src/dns.rs`)
- `SboRecord { repo: String, genesis: Option<String>, node: Option<String>,
  checkpoint: Option<String> }`. Parse `v`(=sbo1)/`repo`/`genesis`/`node`/`checkpoint`;
  keep ignoring unknown keys.
- Enforce **bare-`repo=`**: parse via `SboRawUri::parse` and reject if not `is_bare()`.
- `resolve_uri`: compose record `repo` (anchor preserved) + path → component-aware,
  not naive string concat. Returns a `SboRawUri` (or canonical string **with** anchor).
- Delete `discovery_host`/`get_discovery_host`/`h=`; fix the `_sbo-id` module doc (line 4).

### Phase C — genesis identity (`core`)
- `fn genesis_hash(objects: &[Message]) -> Hash` = `sha256(all_genesis_objects_bytes)`.
  **Define the byte canonicalization precisely** (wire-encode each genesis object in
  batch order, concatenate; document it in the Genesis Spec's identity section so it's
  reproducible offline). Add a roundtrip test (`mingo genesis` output → hash stable).
- `fn database_identity(chain, app_id, first_block, genesis_hash) -> String` →
  `{chain}:{appId}:{firstBlock}:{genesisHash}`.

### Phase D — daemon wiring (`daemon/src/main.rs`, `sync.rs`)
- DNS repo-add: derive `from_block` from the resolved `repo`'s `@firstBlock` (operator
  flag becomes an override, not the source).
- On sync past genesis: reconstruct genesis, compute `genesis_hash`, and **verify**
  against the record's `genesis=` if present; on mismatch, refuse the repo.
- **Block-only ambiguity:** when registering with an anchor but no genesis hash, detect
  >1 genesis object set at `(chain, appId, first_block)` and error (don't guess).

### Phase E — `as_of` read path (`daemon/src/http.rs`)
- Add `as_of` to the `/v1/object` (and `/v1/list`) query params; resolve against
  `get_state_root_at_block(as_of)` (`state/db.rs:327`). Without `as_of`, latest (LWW).
- Confirm the `@firstBlock` anchor is treated as database selection, never as `as_of`.

### Phase F — CLI surface (`sbo-cli`)
- `repo add` / `uri get|list` / `id import`: accept `@firstBlock` + the new query
  params via the core parser; emit anchored URIs in output.
- Fix `id resolve` command doc (`main.rs:394-395`) — drop the dead `_sbo-id` flow
  (impl at `identity.rs:923` already email-rooted).

### Phase G — tests (no-gap gate)
- Core: `SboRawUri` parse/emit roundtrips (anchor present/absent; each query param;
  `creator:id`); bare-`repo=` accept/reject; DNS record parse (all fields + unknown
  ignored + `repo` non-bare rejected); `genesis_hash` stability; `database_identity`.
- Daemon: `from_block` derived from anchor; genesis verify pass/mismatch; block-only
  ambiguity error; `as_of` returns historical state; anchor ≠ snapshot.
- Migrate existing tests off the old `r=`/`@block`-snapshot assertions.

### Follow-up (tracked, not this pass)
- **`appId` opaqueness** (decision (3)): the `AppId` newtype lands now; relaxing its
  inner repr for non-Avail DA layers (Celestia namespace, EVM address) is a later step.
- **Prover/proof discovery**: SBOP validity proofs are generated but unserved/undiscovered
  (no `/v1/proof`, no DNS field — by design, trust is on-chain). Separate effort.

## Sequencing
A → B/C (parallel) → D → E → F → G. A is the keystone (everything else depends on the
core URI type). Each phase compiles + tests green before the next; commit per phase.
