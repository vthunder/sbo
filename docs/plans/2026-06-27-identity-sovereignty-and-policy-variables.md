# SBO Identity Sovereignty, Canonical Identity, & Policy Variables — Design

**Status:** Phases 1–6 IMPLEMENTED (sbo `feat/identity-sovereignty-and-policy-vars`, mingo `feat/u-layout`), tested + specced + pushed. Phase 7 (production migration) is a runbook (mingo docs/plans/2026-06-28-u-layout-migration-runbook.md), not yet executed (needs sys key + live verification).
**Author:** design session, 2026-06-27.
**Why:** mingo is the proving ground for real SBO use cases. This locks the identity
model end-to-end (email onramp → self-sovereign over time), fixes the policy-variable
foundation it rests on, and migrates mingo's layout to a clean `/u/<id>/` namespace.

> Companion to the already-merged transfer/admin work
> (`2026-06-27-object-transfer-and-admin-authority.md`). This builds on `uri *` as the
> migration tooling.

---

## 0. The north star

One **identity** with one **namespace**, reachable by multiple **credentials over time**:

- Alice onboards at mingo.place via browserid → identity `alice@mingo.place`, controlled
  (initially) by the domain's IdP.
- Later she publishes `/sys/names/alice` pinning **her own key**. From then on
  `alice@mingo.place` is controlled by that key — the record **wins** over browserid. The
  domain can no longer silently impersonate her (a domain-minted cert resolves against the
  pinned key and fails), and the record is public, so any tampering is *evident*.
- Her objects never move. Same identity string (`alice@mingo.place`), same namespace
  (`/u/alice@mingo.place/`), same objects — only *how the string resolves to a controller*
  changes.

This only applies to a repo **authoritative for the email's domain** (a DNS-backed repo
with `/sys/domains/<D>`). A no-domain `sbo+raw://` repo has no email onramp; its identities
are key-rooted (sovereign) from the start.

---

## 1. Conceptual model: identity vs credential vs reference

- **Identity** — the durable party. Its **canonical id** is a single stable string. For a
  primary-domain identity that's the email `alice@mingo.place`; for a pure key identity
  (no-domain repo) it's the local name `alice` (or the key).
- **Credential** — a way to *prove* you are the identity *right now*: a browserid cert
  (→ attributed email) **or** a direct signature from a pinned key. An identity may, over
  time, switch which credential governs.
- **Reference** — how an object *names* its owner/creator in a header: an email
  (`alice@mingo.place`), a local name (`alice`), or a bare key. References are resolved to a
  **controller** for authorization.

Two layers, kept strictly separate (this separation is the spine of the whole design):

| Layer | Question | Mechanism | Uses |
|---|---|---|---|
| **Authorization** | does the signer *control* this owner reference? | `resolve_controller` → `is_authorized` | the `to: owner` check, transfer/delete auth |
| **Canonical identity** | what single stable string *is* this party? | `canonical_identity` (new) | the trie `creator` segment, `$user` |

Today these are tangled (creator resolution and owner resolution use overlapping ad-hoc
logic). We make them duals of one shared identity graph.

---

## 2. The identity graph & its two resolutions

The graph is the on-chain set of `/sys/names/*` records plus `/sys/domains/*` plus browserid
attribution. Both resolutions walk the same edges, in opposite directions.

### 2.1 `resolve_controller(reference)` — *authorization* (extend existing)

Current (`resolve.rs`): `@` → `Email(browserid)`; key → `Key`; name → look up record
(key-rooted → `Key`, email-rooted → recurse).

**Add the sovereignty override**, scoped to the repo's primary domain(s):

```
resolve_controller("alice@mingo.place"):
  if "/sys/domains/mingo.place" exists in this repo          # repo is authoritative for D
     and "/sys/names/alice" exists:                          # local part has a record
        resolve that record   # key-rooted -> Key(pinned);  email-rooted -> recurse
  else:
        Email("alice@mingo.place")                           # browserid fallback (today's behavior)
```

So before a key record exists → browserid (onramp). After → the pinned key (sovereign).
Emails at domains the repo is **not** authoritative for (e.g. `bob@gmail.com`) keep
short-circuiting to browserid — no `/sys/names` mapping applies.

### 2.2 `canonical_identity(signer, attribution)` — *namespace stability* (new, replaces ad-hoc `resolve_creator`)

The dual: map whatever credential the signer used back to the **same** canonical string, so
browserid-alice and sovereign-key-alice land on `alice@mingo.place` either way (no
post-upgrade namespace fragmentation).

```
canonical_identity(signer_key, attributed_email):
  if explicit Creator header present and signer controls it:  return Creator   # see §3
  if attributed_email = E and E is a primary-domain email:     return E
  if signer_key is the pinned key of /sys/names/<local>
       and <local> maps to a primary-domain email E:           return E         # reverse edge
  if signer_key/name resolves to a local name <local>:         return <local>   # no-domain identity
  else:                                                         return key-hash
```

The reverse edge (pinned key → local name → primary-domain email) is what keeps Alice's
creator segment stable across the browserid→key transition.

### 2.3 Primary domain & the name↔email mapping

- A repo is **authoritative for domain D** iff `/sys/domains/D` exists. (Already how domains
  are anchored — no new config.)
- `/sys/names/<local>` maps to `<local>@D` **when the repo has exactly one primary domain D.**
  **[DECISION/OPEN]** Single-primary-domain is assumed (mingo has one). Multi-domain repos
  need domain-qualified name records (`/sys/names/<local>@<D>`) or per-domain name trees —
  **deferred**, flagged as a known limitation. (mingo: `/sys/domains/mingo.place` only.)

---

## 3. `Creator` header validation (security fix, prerequisite)

Today `effective_owner_ref = Owner → else Creator → else signer`, so the L2 gate validates
`Creator` *only when there's no `Owner`*. A write with `Owner: me, Creator: alice@…` is
accepted and lands under Alice's creator segment unchecked.

**Fix:** the signer must control the declared `Creator` independently. In `validate_message`,
when `Creator` is present, require `resolve_controller(Creator)` to be authorized by the
signer (same `l2_authorize` check), regardless of `Owner`. This:
- closes the trie-spoofing gap (can't write under someone else's creator), and
- makes the explicit-`Creator` path of `canonical_identity` (§2.2) safe to honor.

(Transfer/delete remain exempt from the *owner* gate per the prior design, but a `Creator`
on them, if allowed at all, is validated the same way.)

---

## 4. Policy variables (the foundation, literal-reference model)

Interpolated into path patterns (`on`, `deny`, restriction `on`). Today only `$owner` exists
and is computed circularly (path segment 0); `$user` is specced but unimplemented (see the
audit in this session). Replace with four, all **literal references**, never resolved
controllers:

| Var | Value | Undefined when |
|---|---|---|
| `$owner` | the object's owner reference — create: the declared `Owner` header; update: stored `owner_ref` (verbatim, **not** path-derived) | owner absent (then no `$owner` grant matches) |
| `$user` | the acting signer's **canonical id** (§2.2) | never (≥ key-hash) |
| `$email` | the signer's attributed/canonical **email**, if any | key-only identity → fail-closed |
| `$name` | the signer's local **name**, if any | email-only identity (no record) → fail-closed |

- **De-circularized:** `$owner` on create comes from the declared `Owner`, so
  `/u/$owner/**` works. Security is intact: a forged `Owner` still fails the independent
  `to: owner` control check (`signer_is_owner`), so declaring a false owner buys nothing.
- **Self-write invariant:** `$owner == $user` (you own what you write), and the path segment
  equals the trie creator segment — consistent by construction.
- **Fail-closed:** an undefined variable makes its pattern match nothing (deny). So
  `$email`/`$name` are always well-defined; they simply exclude actors lacking that form.
- **Authoring guidance (spec):** use `$owner`/`$user` for identity-agnostic namespaces (the
  default; works for key and email users alike); reach for `$email`/`$name` only to
  *restrict* a namespace to one credential form.

Implementation: `resolve_variables` (path.rs) must accept a small struct of all four
(currently just `owner: Option<&str>`); `evaluate` computes them once from the message +
identity graph and passes them through deny/grant/restriction matching.

---

## 5. Anti-hijack: name-claim creation on a primary-domain repo

If `/sys/names/alice` governs `alice@mingo.place`, then *creating* it must require control of
`alice@mingo.place` — otherwise a stranger front-runs the claim and hijacks the identity.

**Rule:** on a repo authoritative for D, a create at `/sys/names/<local>` is valid only if the
signer is authorized as `<local>@D` (browserid attribution, or already the pinned key during a
key rotation). Replaces the current first-come `{to:"*", can:["create"], on:"/sys/names/*"}`
for primary-domain repos.

**Residual risk (documented, not solved):** the domain operator *can* attribute-as-alice, so a
malicious domain could front-run and pin a domain key, blocking Alice's escape. This is
*evident* (public record, a key Alice never made) and doesn't worsen the pre-upgrade trust
(the domain already controls her). Eliminating it entirely means giving up the email onramp;
out of scope.

---

## 6. The name record as a control policy (extensible)

v1 (this work): a key-rooted `identity.v1` record pins one key; that key wins over browserid.
Forward-compatible extension points (designed now, built later):
- multiple authorized keys;
- explicit `browserid_fallback: true` to keep the domain as a recovery path;
- recovery keys / social recovery.
These become fields of a richer identity/control record (`identity.v2`); `resolve_controller`
already centralizes the logic to honor them.

---

## 7. Layout migration: `/u/<canonical-id>/`

Move user namespaces out of the root into a reserved container, keyed on the **canonical id**
(the email for mingo):

```
/                                  /
├── sys/...               →        ├── sys/...
├── communities/...                ├── communities/...
└── dan@mingo.place/...            └── u/
                                      └── dan@mingo.place/
                                         └── attestations/.../membership-cooks
```

- **Genesis/root policy:** `/$owner/**` → `/u/$owner/**` (works once §4 lands). Admin grant
  already present. Optionally add `deny` for new root-level user writes post-migration.
- **App:** `app.js` + idp build/read user object paths under `/u/…`.
- **Live data migration:** for each existing root user object, `uri mv /<id>/... → /u/<id>/...`
  signed by sys (admin authority) or the owner. The policy update to `/sys/policies/root` is
  posted in place (sys owns it) — no re-genesis.
- **Transition safety:** N/A — **zero users (just the dev team)**. Hard switch, no dual-read:
  update genesis/app to `/u/…`, post the new root policy in place, and simply
  `uri rm` (or re-create) the few existing root test objects (`dan@mingo.place`,
  `danmills@mingo.place`). No transition window needed.

---

## 8. Build phases (each: implement + tests + commit; checkpoints for review)

1. **Policy variables foundation** (sbo-core): four-variable literal-reference model in
   `path.rs`/`evaluate.rs`; de-circularize `$owner`-create from declared `Owner`; implement
   `$user`/`$email`/`$name`; spec update (Policy spec). *Unblocks `/u/` and is independently
   correct.*
2. **`Creator` validation** (sbo-daemon): signer-controls-`Creator` check; tests for the
   spoofing gap. Spec update (Authorization spec).
3. **Canonical identity + resolver override** (sbo-core/daemon): `canonical_identity`;
   `resolve_controller` email→name override scoped to `/sys/domains/<D>`; the reverse edge.
   Spec update (Identity + Authorization specs: the sovereignty section). Heavy test matrix
   (browserid-only, key-only, pre/post upgrade, foreign-domain email, cycles/hops).
4. **Anti-hijack name-claim policy** (daemon validate): primary-domain name creation requires
   control of the corresponding email. Tests incl. front-run attempt.
5. **mingo genesis + app** (mingo): root policy `/u/$owner/**` (+ optional root deny); app.js
   + idp path changes; dual-read transition.
6. **Sovereignty end-to-end demo** (proving ground): a scripted lifecycle on a disposable
   identity — onboard via browserid → publish `/sys/names/<x>` key record → confirm control
   flips to the key, browserid no longer authorizes, objects unchanged.
7. **Production migration** (mingo, gated on explicit go-ahead): post updated root policy;
   `uri mv` existing user objects to `/u/…`; redeploy daemon + app.

Phases 1–4 are sbo-core/daemon protocol work (the bulk of the rigor). 5–7 are mingo + the live
migration.

---

## 9. Open decisions to confirm before building

1. **Canonical resolution** — honor explicit `Creator` (client asserts canonical, validated
   per §3) **and** the reverse pinned-key→email edge (§2.2)? (Recommended: both — Creator for
   directness, reverse edge so even a naive client stays stable.)
2. **Single primary domain** assumption (§2.3) — accept for now (mingo has one), defer
   multi-domain name records? (Recommended: yes, document the limit.)
3. **Tighten name-claim creation** now (§5) — change `/sys/names/*` from first-come to
   email-controlled on primary-domain repos? (Recommended: yes; it's required for the
   sovereignty guarantee to mean anything.)
4. **Control-record richness** (§6) — ship v1 single-pinned-key now, design `identity.v2`
   (multi-key/recovery) as a documented later increment? (Recommended: yes.)
5. **Layout cutover** — RESOLVED: **hard switch**. Zero users (just the dev team), so no
   dual-read/transition window; delete or re-create the handful of existing root test objects.
