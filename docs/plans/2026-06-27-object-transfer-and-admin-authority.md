# Object Transfer/Move + Sys-Level Admin Authority — Implementation Spec

**Status:** Locked (design). Implementation in progress on branch `feat/uri-commands-and-transfer`.
**Author:** generated overnight session, 2026-06-27.
**Tracking:** mingo epic `mingo-0jkl` (children `mingo-46oy`, `mingo-e13s`, `mingo-j1q6`).

> **For the reviewer (Dan):** This pins down implementation-level decisions so the
> overnight build is unambiguous. Where it resolves something the canonical specs
> left implicit, that is called out as **[DECISION]** with rationale. Nothing here
> contradicts the canonical specs; it implements rules they already state. Two tiny
> clarifying edits to canonical specs are proposed in §8 — those are the only
> normative-text changes, and they are additive.

---

## 0. Motivation & Scope

Two user-facing gaps:

1. The `sbo` CLI `uri` command group (`get`/`post`/`list`/`transfer`) is `todo!()`
   end-to-end — there is no way to read, write, or move an arbitrary object from the
   CLI even though the daemon already exposes the primitives.
2. Object **transfer/move** (`Action: transfer` with `New-Path`/`New-ID`/`New-Owner`)
   is a **stub end-to-end** in the reference implementation despite being fully
   specified in `SBO Specification.md` §transfer:
   - `message/actions.rs:36` parses `"transfer"` to `Action::Transfer { new_owner: None, new_path: None, new_id: None }` — the `New-*` headers are never read.
   - `validate.rs:625 validate_transfer` authorizes **only** the current owner, and
     ignores `new_path`/`new_owner`/`new_id` (no destination policy, no collision check).
   - `sync.rs:958` applies only Create/Update/Delete to state; there is no move logic,
     so a transfer never relocates an object in the trie or the filesystem mirror.
3. There is **no superuser** in SBO. "Sys-level admin can move/remove user objects"
   must be expressed as a policy grant and signed by an authorized key.

This spec covers all three. Layout redesign (`/u/<handle>@mingo.place/`) is a **separate**
chunk and is out of scope here, but the `uri` commands built here are the tool that will
script that migration.

Canonical references (do not duplicate — conform to them):
- `specs/SBO Specification.md` §Action Specific Rules → *post / transfer / delete*; §Policies (cascade).
- `specs/SBO Wire Format Specification.md` §Header Reference (`New-ID`/`New-Path`/`New-Owner`, `Owner`, `Creator`).
- `specs/SBO Policy Specification.md` §Action Types (`transfer`, `delete`, `*`), §Grants, §roles, §Attestation-Defined Roles.
- `specs/SBO State Commitment Specification.md` §Creator as Path Segment (`(path, creator, id)`).

---

## 1. Object identity & the creator invariant

State is keyed by **`(path, creator, id)`** (State Commitment §Creator as Path Segment).
`creator` is the author's **resolved controller** (explicit `Creator` header → attributed
email → claimed name → stable key encoding), pinned at inclusion time. `owner` (the
`owner_ref` recorded at write time) is who currently controls the object and is who an
ownership check authorizes against.

**[DECISION] A transfer/move preserves `creator`.** Only `path`, `id`, and/or `owner_ref`
may change. Rationale:
- The destination-collision rule in `SBO Specification.md` §transfer is phrased "does not
  exist **by the same creator** at the destination path" — i.e. the move keeps the creator
  segment and re-homes that creator's leaf.
- Preserving `creator` keeps provenance/authorship stable and avoids trie-key churn.
- `New-Owner` changes only `owner_ref` (control), never authorship.

Consequence: after `mv /a/ x → /b/ y` by creator C, the state key goes from
`/a/ · C · x` to `/b/ · C · y`; the leaf's object bytes (and thus `object_hash`) are the
**original** stored object's bytes, with `owner_ref` updated iff `New-Owner` was present.

---

## 2. Wire parsing (sbo-core)

`Action::parse` cannot read headers (it only sees the action string), so parsing of the
`New-*` headers moves to envelope construction.

- `message/actions.rs`: keep the `Action::Transfer { new_owner, new_path, new_id }` shape.
- `message/envelope.rs` (the place that already reads `Owner`, `Creator`, `Path`, `ID`):
  when `Action: transfer`, populate the `Action::Transfer` fields from `New-Owner`
  (parse as an identity `Id`/owner ref), `New-Path` (parse as `Path`, must end `/`),
  `New-ID` (parse as `Id`, must not contain `/`).
- Enforce the wire rule: **at least one** of `New-Owner`/`New-Path`/`New-ID` present, else
  `ValidationError` (`error.rs:61` already defines the message). This is a *wire/parse*
  error (malformed), distinct from a policy denial.
- `New-Owner: null:` is the canonical **delete** spelling. Parsing keeps it as
  `Action::Transfer { new_owner: Some(null) }`; §4 routes a null new-owner through the
  delete path. `Action: delete` remains an accepted alias with identical semantics.
- Serializer (`wire/serializer.rs`) already lists `New-Path` etc. in header order; ensure
  it emits all three when present (alphabetical within the conditional block, per Wire spec).

---

## 3. Message builder (sbo-core `presets`)

Add a builder mirroring `presets::post` (`presets.rs:331`) and `signed_object`
(`presets.rs:738`):

```rust
pub fn transfer(
    signing_key: &SigningKey,
    path: &str, id: &str,                 // source object
    new_path: Option<&str>,
    new_id: Option<&str>,
    new_owner: Option<&str>,              // identity ref; "null:" to delete
) -> Vec<u8>
```

- Emits a `Type:`-correct, signed transfer envelope. No payload (transfer carries no
  content; `Content-*` headers omitted).
- The CLI may also need to attach attribution (`Auth-Cert` + `Auth-Evidence`) for
  email-rooted signers; reuse whatever `id`/`domain` commands already do for attributed
  writes (they build attributed envelopes today). **[DECISION]** v1 of the builder targets
  **direct (key-rooted) signers** (admin/sys keys, self-sovereign users). Attributed
  transfer by an email-rooted owner reuses the existing attribution-capture path; if that
  plumbing isn't trivially reusable, attributed transfer is deferred to a follow-up bean
  and noted in the CLI help. (Admin moves — the headline use case — are key-rooted.)

---

## 4. Validation (sbo-daemon `validate.rs`)

Replace the owner-only `validate_transfer` (`validate.rs:625`) with the full rule set from
`SBO Specification.md` §transfer. Pseudocode:

```
validate_transfer(msg, state, root_policy_exists, l2):
  if !root_policy_exists: Invalid(State, "Cannot transfer before genesis")
  creator  = resolve_creator(msg, state, l2)
  existing = state.get_object(msg.path, creator, msg.id)
  if existing is None: Invalid(State, "Cannot transfer non-existent object")
  owner_ref = stored_owner_ref(existing)

  // (A) SOURCE AUTHORIZATION — owner OR policy override
  signer_is_owner = l2_authorize(msg, state, l2, owner_ref).is_ok()
  action = (new_owner == null:) ? Delete : Transfer
  if !signer_is_owner:
      // "unless allowed by the object's policy" — admin override
      check_policy(state, msg, action, Some(owner_ref), l2)?   // source path policy
  else:
      // owner still subject to source-path policy that may forbid moving out
      check_policy(state, msg, action, Some(owner_ref), l2)?   // returns Ok if no deny/grant needed

  // (B) DESTINATION (only if relocating)
  if new_path.is_some() || new_id.is_some():
      dest_path = new_path.unwrap_or(msg.path)
      dest_id   = new_id.unwrap_or(msg.id)
      // collision: destination must not already exist by the SAME creator
      if state.get_object(dest_path, creator, dest_id).is_some():
          Invalid(State, "Destination already exists for this creator")
      // destination must allow receiving: evaluate dest-path policy for a create-like admit
      check_policy_at(state, msg, Create, dest_path, owner_after, l2)?
  Valid { creator }
```

**[DECISION] Action verb mapping for policy:**
- A relocation/ownership change checks the **`transfer`** verb on the source path
  (Policy spec §Action Types: *"Move, rename, and/or change ownership"*).
- A `null:` new-owner checks the **`delete`** verb (delete is modeled as transfer-to-null).
- The **destination** admit checks the **`create`** verb on the destination path (the
  object is *appearing* there). Reuses `extract_namespace_owner(dest_path)` so a move into
  `/u/$owner/**` is allowed when the post-transfer owner matches the destination namespace.
  This makes "user pulls an object into their own namespace" and "admin files an object
  under a user's namespace" both expressible without special cases.

**[DECISION] `check_policy` currently is not called by `validate_transfer` at all** — wiring
it in (for both source-`transfer`/`delete` and destination-`create`) is the core of this
change. `check_policy` (`validate.rs:694`) already resolves the ancestor policy, the actor,
`signer_is_owner`, and attestation-defined roles, so the admin grant
`{to:{role:admin}, can:["transfer","delete"], on:"/**"}` is honored with no evaluator change.

Stages: source-auth failures → `Attribution` (signer doesn't control owner) or `Policy`
(no grant). Destination failures → `State` (collision) or `Policy` (dest forbids).

---

## 5. State application (sbo-daemon `sync.rs`)

`apply` (around `sync.rs:945-1016`) gains a transfer branch. A transfer touches **two**
trie leaves; the witness must record both so the state-root transition and ZK prover stay
correct.

```
on Action::Transfer (and Action::Delete):
  creator    = resolve_creator(...)
  src_segs   = object_to_segments(msg.path, creator, msg.id)
  existing   = get_object(msg.path, creator, msg.id)        // already required by validation
  if existing is None: skip (defensive; validation should have caught)

  if new_owner == null: OR Action::Delete:                  // delete
      touched.deletes.push({ src_segs, old_object_hash })
      remove src file from mirror
      db.delete_object(msg.path, creator, msg.id)
      return

  dest_path = new_path ?? msg.path
  dest_id   = new_id   ?? msg.id
  moved     = existing.with(path=dest_path, id=dest_id,
                            owner_ref = new_owner ?? existing.owner_ref)
              // object bytes/hash unchanged; creator unchanged
  dest_segs = object_to_segments(dest_path, creator, dest_id)

  // witness: delete at source + create at destination (same object_hash)
  touched.deletes.push({ src_segs, old_object_hash: existing.object_hash })
  touched.creates.push({ dest_segs, new_object_hash: existing.object_hash })

  // state db + filesystem mirror
  db.delete_object(msg.path, creator, msg.id)
  db.put_object(moved)
  fs: rename mirror file  src → dest (create parent dirs; atomic temp+rename)

  // mempool overlay: reconcile BOTH the removed source shadow and the new dest value
  pending.reconcile_applied(moved); pending.reconcile_removed(src key)

  // if source or dest is under /sys/names/, update the name-claim index accordingly
```

**[DECISION] LWW/HLC interaction.** Content posts are last-writer-wins by HLC
(`sync.rs:954-966`). **Transfers are not HLC-merged**: they are structural ownership/location
operations applied in inclusion order, gated solely by validation (owner/policy). A transfer
does not carry content HLC semantics; `lww_admits` is bypassed for `Action::Transfer`.
Rationale: two competing transfers of the same object can only both validate if both signers
are authorized at their inclusion time; inclusion order is the deterministic tie-break, same
as the base layer's ordering guarantee. (If this proves insufficient we add an explicit
transfer-sequence guard later; not needed for v1.)

**Collections:** moving a `Type: collection` object moves the collection node and its
`Policy-Ref`; **children are not cascaded** (each child is its own `(path, creator, id)` leaf
under the old path). **[DECISION]** v1 moves a single object. Moving a subtree = iterate
children via `ListObjects` and transfer each (the CLI can offer `--recursive` later; not in
v1). This is called out in `uri mv` help.

---

## 6. mingo admin authority (mingo genesis + policy)

SBO has no superuser; admin power is a policy grant. In `mingo-app/src/genesis.rs` root
policy (currently `genesis.rs:270-279`), add an `admin` role and grant:

```json
{
  "roles": {
    "admin": [ { "key": "ed25519:<sys-or-admin-pubkey>" } ]
  },
  "grants": [
    { "to": "*",       "can": ["create"],                       "on": "/sys/names/*" },
    { "to": "owner",   "can": ["update","delete"],              "on": "/sys/names/*" },
    { "to": "owner",   "can": ["*"],                            "on": "/$owner/**" },
    { "to": {"role":"admin"}, "can": ["post","transfer","delete"], "on": "/**" }
  ]
}
```

**[DECISION] Admin role membership = a literal key** (the sys/admin key) for v1, not an
attestation-defined role. Simpler, no bootstrapping cycle (the role that authorizes
attestations shouldn't itself depend on an attestation). An attestation-defined
`admin`/`moderator` for delegated, revocable moderation is a follow-up (the mechanism is
already specced in Policy spec §Attestation-Defined Roles).

**[DECISION] Scope of admin grant = `/**` with `post`/`transfer`/`delete`.** This lets the
admin relocate, re-own, and remove any object — exactly the "move objects around with sys
access" requirement. Deny-rules still win over grants, so we can still lock specific paths
(`deny: ["/system/**"]`) if desired. Note this is a *powerful* grant; it is the price of
"admin can fix anything". It is auditable (it's in the readable root policy) and every admin
action is a signed, replayable on-chain message.

**Migration note:** this changes genesis, so a repo created before this grant won't have it.
For the live mingo repo, the admin grant is added by **posting an updated `/sys/policies/root`**
signed by the current root owner (the existing sys key controls the root policy object) — not
by re-genesis. The `uri post` command (Tier 1) is exactly the tool for that.

---

## 7. CLI surface (sbo-cli)

All `uri` commands resolve the SBO URI → `(repo_path, path, id)` via the existing repo list
(URI spec parsing), then hit the daemon over IPC. The daemon already implements every
request needed.

| Command | IPC request | Notes |
|---|---|---|
| `uri get <uri> [--proof]` | `GetObject{with_proof}` | Prints headers + payload; `--proof` emits SBOQ. |
| `uri list <uri> [--schema S]` | `ListObjects{prefix,schema}` | `<uri>` path is the prefix. |
| `uri post <uri> --file F [--content-type T] [--schema S] [--key A]` | build `presets::post`/`signed_object` → `Submit{data}` | Create/update; signs with keyring key `A` (default key otherwise). |
| `uri transfer <uri> [--new-path P] [--new-id I] [--new-owner O] [--key A]` | build `presets::transfer` → `Submit{data}` | At least one `--new-*`. |
| `uri mv <src-uri> <dst-uri> [--key A]` | → transfer | Sugar: derives `--new-path`/`--new-id` from `dst-uri`. |
| `uri chown <uri> --to <owner> [--key A]` | → transfer | Sugar for `--new-owner`. |
| `uri rm <uri> [--key A]` | → transfer `--new-owner null:` | Delete. |

Key selection reuses the existing keyring resolution (`--key <alias>`, else default). No new
signing concepts. `uri mv`/`chown`/`rm` are thin front-ends over `uri transfer` so there is
one code path to the builder.

Existing arg surface already present for `uri transfer` (`--new-owner`, `--new-path`,
`--new-id`); `mv`/`chown`/`rm` are new subcommands.

---

## 8. Proposed canonical-spec edits (additive, minimal)

These make implicit rules explicit; they are the only normative-text changes.

1. **`SBO Specification.md` §transfer** — add a bullet:
   *"A transfer preserves the object's `creator`; only `owner`, `path`, and/or `id` change.
   The object's content (and `object_hash`) is carried unchanged."*
2. **`SBO State Commitment Specification.md` §Creator as Path Segment** — add a sentence:
   *"A transfer re-homes the existing `(path, creator, id)` leaf to `(new_path, creator,
   new_id)`, deleting the source leaf and inserting the destination leaf with the same object
   hash; the creator segment is invariant under transfer."*

No changes needed to the Wire, Policy, or Authorization specs — they already define the
`New-*` headers, the `transfer`/`delete` verbs, the role/grant model, and attribution.

---

## 9. Build order & test plan

Tier 1 (mingo-46oy) → Tier 2 (mingo-e13s) → Tier 3 (mingo-j1q6). Each tier commits
separately with tests; verified against the local daemon (`~/.sbo`, Avail turing app 506).

**Tier 1 — `uri get/list/post`:** unit-wire the IPC calls; integration test against the
running daemon: `uri get` a known genesis object (`/communities/cooks/ id=community`),
`uri list /communities/`, `uri post` a scratch object under a test namespace and read it back.

**Tier 2 — transfer/move:** sbo-core parser + builder unit tests (round-trip a transfer
envelope, all `New-*` combinations, the "at least one" rule, `null:` delete). Daemon
validate tests: owner-moves-own-object OK; non-owner denied without grant; non-owner allowed
with admin grant; destination collision rejected; destination policy denial. sync apply
tests: state-root before/after, source leaf gone, dest leaf present with same hash, mirror
file moved, mempool overlay reconciled. End-to-end against local daemon: post → mv → get
(old 404, new 200) → chown → rm.

**Tier 3 — admin authority:** genesis-policy unit test (admin grant present, role = sys key);
e2e: a non-owner admin key moves a user-namespace object (allowed); a non-admin non-owner is
denied; document the live-repo migration (post updated `/sys/policies/root`).

**Regression guard:** existing `post`/`delete` paths and HLC LWW behavior must be unchanged;
run the full `cargo test` workspace + a from-genesis resync of the local repo to confirm the
state root still matches after the validate/apply refactor.
