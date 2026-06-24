# Demo UX Spec — "Commons"

**Date:** 2026-06-24
**Status:** Decisions locked (2026-06-24); spec/wireframe-first; no client code yet
**Purpose:** Define the end-user demo application — the product, the pitch, the
screens, the flows, and how each maps onto the (already-built) SBO stack. This is
the consumer-legible payoff of Phases 1–6 and the concrete target for Phase 7's
reference client.

## Locked decisions (2026-06-24 review)

1. **Name:** "Commons" (confirmed, no longer a placeholder).
2. **Layout:** aggregated — one repo, many communities. Crucially, **Commons is
   itself the meta-community and the T1 identity provider**: a user has **one
   pseudonymous handle `<name>@commons`** issued by Commons (Reddit-like), not an
   exposed external email. One identity covers the whole hub.
3. **Trust-weighted feed:** **cut from v1.** Start with a plain votes/recency
   feed; trust weighting is a documented fast-follow, not a launch feature.
4. **Tip / confirmed:** **not exercised in this demo.** For Reddit-style posting,
   waiting a couple seconds for durability is fine and the optimistic-echo
   complexity buys no real UX win here. The tip overlay is deferred to a future
   use case where instant-write latency actually matters (e.g. chat/live
   collaboration). Phase 6.5 is therefore **deferred by product decision**, not
   built. See §6.

---

## 1. The product, in one sentence

> **Commons** — topic communities where the reputation you earn is real,
> specific, and *yours*, and the communities are owned by the people in them, not
> a platform that can sell, kill, or rug them.

It looks and feels like **Reddit** (interest-based, pseudonymous, voted threads).
The differences are product differences a normal user can feel — not a blockchain
pitch. A user never has to hear "verifiable," "on-chain," or "wallet."

## 2. What we claim — and what we don't (honest framing)

Decided with the realism check in mind:

- ✅ **Claim: you keep what you build.** Your reputation and standing are yours and
  portable across the communities in the hub. The platform can't quietly delete
  or sell your history. Founders are invested because the community can't be
  rugged from under them.
- ✅ **Claim: reputation is specific and portable.** Not one fake karma number —
  earned badges/roles/vouches, each tied to a context, readable everywhere in the
  hub.
- ⚠️ **We do NOT claim to fix mod tyranny.** You can be banned in a Commons
  community exactly as on Reddit; moderation is still human and political. We
  don't pretend otherwise. (Self-ownership helps *founders* and *continuity*, not
  "never get banned.")
- ⚠️ **We do NOT lead with "migrate your subreddit."** Bulk migration is hard and
  Reddit would resist it. The realistic, honest version is **"bring your
  reputation"**: a lightweight way to carry earned standing in, not a bulk
  content export. Treated as a later/soft feature, not the spine.

**The spine of the demo is the Reputation Passport** (portable earned standing),
with a **trust-weighted feed** as the daily-use hook. Both are real, buildable,
and mostly already supported by the protocol.

## 3. Scope: a multi-community hub in ONE SBO repo

### Identity: one Commons-issued pseudonym (T1)

Commons is the **meta-community** and runs its own browserid provider, so every
user gets a single **community-issued T1 identity** `<name>@commons` (see [SBO
Identity Specification](../../specs/SBO%20Identity%20Specification.md#community-issued-identities-t1)).
This is the Reddit model: you sign up with Commons, you get a **pseudonymous
handle**, and your real email (if used to authenticate to the provider) is never
your public identity. One identity spans the whole hub — no per-community
accounts. T0 (external-email) identities are not needed for the demo; T1 keeps it
pseudonymous and gives Commons a clean onboarding funnel. (The provider half is
the same machinery as Phase 1's capture/broker, pointed at the Commons domain.)

### Aggregated layout

We use the Community spec's **aggregated layout** ([SBO Community
Specification](../../specs/SBO%20Community%20Specification.md#granularity-repository-or-object)):
several communities share one repository (one genesis, one root policy), each a
`community.v1` under `/communities/<id>`. Why this is the right demo substrate:

- A user's identity and **every attestation about them lives in the same repo**,
  so cross-community reputation (the passport) is a plain local read — **no
  cross-repo URI plumbing needed** for v1.
- One genesis, one daemon, one state DB — operationally simple to stand up.
- Still genuinely SBO: each community has its own `community.v1`, its own policy
  subtree, its own issuer, members, spaces.
- The sovereignty trade-off (hosted sub-communities aren't fully sovereign) is
  exactly the spec's documented aggregated-mode caveat, and fine for a demo /
  hosting-platform framing.

### Repo namespace layout

```
/
├── sys/
│   ├── policies/root                         hub root policy (cascades)
│   └── names/<name>                           optional T1 names
├── <user>@<provider>/                         per-user namespace (email-rooted identity)
│   ├── profile                                profile.v1 (display name, avatar, bio)
│   ├── reactions/<target-hash>/<kind>         reaction.v1 (LWW toggles)
│   └── attestations/<subject>/membership      self-issued membership (open communities)
├── communities/
│   ├── cooks/
│   │   ├── community                          community.v1 descriptor
│   │   ├── policies/root                      community policy (under hub root)
│   │   ├── members/<member>/...               (open-mode self-membership lives in user ns)
│   │   └── spaces/
│   │       └── general/
│   │           ├── _config                    collection.v1 (durability=batched, W, schema)
│   │           └── <author>/<post-id>         post.v1 / comment.v1
│   ├── woodworking/  ...
│   └── homelab/      ...
└── <community-issuer>/                        e.g. cooks@hub.example
    └── attestations/<subject>/<type>          role:*, badge:*, ban, vouch (issuer-owned)
```

The **Passport** for a user = read every `attestation.v1` whose `subject`
resolves to that user, across all community issuers in the repo. Already
expressible; the client just aggregates and renders.

## 4. Screens (wireframes)

### 4.1 Sign in

Sign up with Commons, pick a pseudonymous handle. Email is only used to
authenticate to the Commons provider — your public identity is the handle.

```
┌─────────────────────────────────────────────┐
│                  Commons                      │
│        communities you actually own           │
│                                               │
│   Pick your handle                            │
│   ┌─────────────────────────────────────┐    │
│   │ alice                        @commons│    │
│   └─────────────────────────────────────┘    │
│   ┌─────────────────────────────────────┐    │
│   │  Continue                           │    │
│   └─────────────────────────────────────┘    │
│   No wallet. No seed phrase. Pseudonymous.    │
└─────────────────────────────────────────────┘
```
→ Commons' browserid provider certifies `alice@commons`; the client posts an
`identity.email.v1` (Owner = `alice@commons`, a T1 community-issued identity),
session key captured.

### 4.2 Hub home — communities + your feed

```
┌───────────────┬─────────────────────────────────────────────┐
│  Commons      │   Your feed   ▸ trusted   ◦ everything        │
│               │ ─────────────────────────────────────────────│
│  COMMUNITIES  │  ▲ 142  r/cooks · alice                       │
│  • cooks   ✓  │      Sourdough starter routine that actually… │
│  • woodworking│      💬 38   · 2h · ✅ confirmed               │
│  • homelab    │ ─────────────────────────────────────────────│
│  + discover   │  ▲ 89   r/woodworking · bob  🛠 Verified maker │
│               │      First dovetail joint, be gentle          │
│  YOU          │      💬 12 · 4h                                │
│  🎖 Passport  │ ─────────────────────────────────────────────│
│  alice        │  ▲ 51   r/homelab · carol                     │
│               │      …                                         │
└───────────────┴─────────────────────────────────────────────┘
```

- **Trusted vs Everything toggle** = the trust-weighted feed. "Trusted" ranks by
  reactions from people/roles you or your communities trust (computed client-side
  over attributable `reaction.v1` + passport standing). "Everything" = raw.
- Badges (🛠 Verified maker) render inline next to authors — status, visible.

### 4.3 Community view (a space)

```
┌───────────────┬─────────────────────────────────────────────┐
│ r/cooks    ✓  │  general ▾    [ + New post ]                  │
│ 12.4k members │ ─────────────────────────────────────────────│
│               │  ▲ 142  alice · 🥇 Top contributor            │
│ ABOUT         │     Sourdough starter routine that actually…  │
│ A place for…  │     💬 38 · 2h                                 │
│               │ ─────────────────────────────────────────────│
│ YOUR ROLE     │  ▲ 7   dave (new)                             │
│ Member ·      │     Is bread flour necessary?                 │
│ since Apr     │     💬 3 · 5h                                  │
│               │                                               │
│ [ Joined ✓ ]  │                                               │
└───────────────┴─────────────────────────────────────────────┘
```

### 4.4 Compose

Plain compose-and-post. The post submits to the DA layer and appears in the feed
once its block lands (a couple seconds) — a simple `posting… → posted` spinner,
**no optimistic tip overlay** (see §6 for why we cut it).

```
┌─────────────────────────────┐
│ New post in r/cooks/general │
│ ┌─────────────────────────┐ │
│ │ My first loaf!          │ │
│ └─────────────────────────┘ │
│            [ Cancel ][Post] │   → posting…  → appears in feed
└─────────────────────────────┘
```

### 4.5 Thread (comments are the product)

```
▲ 142  alice · 🥇 Top contributor — Sourdough starter routine…
        Full body text here…                          ✅
   │
   ├─ ▲ 28  bob 🛠  I feed mine 1:5:5 every morning.   ✅
   │     └─ ▲ 9  alice  Same, works great.            ⟳
   ├─ ▲ 4   dave  Does temperature matter?            ✅
   [ Add a comment… ]
```
Threaded by `parent`; ranked by votes + trust weight; each is a `comment.v1`.

### 4.6 The Reputation Passport (the spine)

The screenshot-able, status-y, portable identity surface. Aggregates earned
standing across every community in the hub.

```
┌─────────────────────────────────────────────────────────┐
│  🎖  alice                                               │
│      on Commons since April 2026                         │
│ ────────────────────────────────────────────────────────│
│  BADGES & ROLES                                          │
│   🥇 Top contributor      r/cooks      issued by r/cooks │
│   🛠 Verified maker        r/woodworking                 │
│   🛡 Moderator             r/homelab                     │
│ ────────────────────────────────────────────────────────│
│  VOUCHED BY                                              │
│   bob 🛠 · carol 🛡 · 14 others                          │
│ ────────────────────────────────────────────────────────│
│  This is yours. It travels with you across every         │
│  community here — and you decide who sees it.            │
└─────────────────────────────────────────────────────────┘
```

Every row is an in-force `attestation.v1` about `alice` from some community
issuer. Walking into a new community, the community's policy can **grant instant
standing** by recognizing a badge (an attestation-defined role) — the
"bring your reputation" moment, in-hub.

### 4.7 Founder/mod actions (light, honest)

Not a control panel — a couple of buttons that mint attestations.

```
On bob's profile (as an admin of r/cooks):
   [ Make moderator ]   → issues role:moderator attestation about bob
   [ Give badge ▾ ]     → issues badge:* attestation
On a post (as a mod):
   [ Remove ] [ Ban author ]  → ban attestation; policy not_attested blocks them
```

We show the ban works and is a normal moderation action — **without** claiming it
"solves" mod power. It's the same human moderation, just that the *roster* (who's
a mod) is portable and the founder can't be rugged.

## 5. Core flows → SBO writes

| # | Flow | SBO write(s) | Built? |
|---|------|--------------|--------|
| 1 | Sign up → pick handle | `identity.email.v1` for `<name>@commons` (T1, Commons provider) | ✅ Ph1 |
| 2 | Join an open community | self-issued `membership` attestation | ✅ Ph3/5 |
| 3 | Post | `post.v1` (HLC, batched tier) | ✅ Ph6 |
| 4 | Comment | `comment.v1` (parent) | ✅ Ph6 |
| 5 | Upvote / react | `reaction.v1` (LWW toggle) | ✅ Ph6 |
| 6 | Earn a badge / role | community issues `badge:*` / `role:*` attestation | ✅ Ph3/4 |
| 7 | View passport | read all attestations about a subject in-repo | ✅ data; client aggregates |
| 8 | Appoint a mod | `role:moderator` attestation; policy role | ✅ Ph4/5 |
| 9 | Ban | `ban` attestation; policy `not_attested` | ✅ Ph4/5 |
| 10 | ~~Instant post feel (tip)~~ | — | ✂ cut (see §6) |
| 11 | ~~Trust-weighted feed~~ | — | ✂ cut from v1 (fast-follow) |

**The protocol is done for this demo.** What's missing is *client* work: the
passport aggregation (flow 7), a plain votes/recency feed, and the UI. No
remaining protocol-layer work is required to build Commons v1.

## 6. Tip / confirmed: cut for this demo (and why the analysis still matters)

**Decision: do not build the tip overlay for Commons v1.** For Reddit-style
posting, a couple-second wait for the post to land is perfectly acceptable; an
optimistic echo adds rollback/reconcile complexity for no felt UX gain here.

The architectural analysis that produced this decision still stands and is worth
keeping, because it tells us *exactly* where tip goes **when** we build it (a
future low-latency use case — chat, live collaboration, fast reactions):

```
tip(user) = confirmed (from daemon/indexer)  ⊕  user's own outbox
                                             └─ same deterministic LWW (hlc::lww_wins)
```

In SBO's based/no-sequencer model there is no shared mempool, so tip is strictly
the author's echo of *their own* writes — **client-side**, a pure
outbox+overlay module in `sbo-core`, consumed by a client. The **daemon stays the
confirmed-state authority with no mempool**, keeping confirmed state globally
deterministic. Sketch for the future: outbox entry
`{ object_hash, hlc, key:(path,id), status }`, status ∈
`queued → submitted → confirmed | rolled-back | needs-reissue`; reconcile when
confirmed advances. **Phase 6.5 is deferred to that future feature, not built
now.**

## 7. Build plan implication (Phase 7 — reference client)

Phase 6's protocol layer is **complete** for this demo (6.1–6.4, 6.6 done; 6.5
deferred by product decision). The remaining work is all **client + provider**:

1. **Commons provider + genesis:** stand up the Commons browserid provider
   (issues `<name>@commons` T1 identities) and the aggregated genesis repo with a
   hub root policy and the starter communities' `community.v1` + policies.
2. **Reference client (web):** sign-up (pick handle → T1 identity) → submit writes
   via the daemon → read confirmed state from the daemon/indexer → render the
   screens in §4 → **passport aggregation** (read all attestations about a
   subject in-repo) → plain votes/recency feed.
3. **Quiet verifiability affordance:** a "how do I know this is real?" panel
   (sboq proofs) for the sovereignty-curious minority — never the main pitch.

Deferred / fast-follow: trust-weighted feed (§4.2), tip overlay (§6),
repo-per-community sovereignty graduation, "bring your reputation" cross-repo.

## 8. Open questions — resolved (2026-06-24)

1. ~~Name~~ → **Commons** (locked).
2. ~~Aggregated vs repo-per-community~~ → **aggregated for v1**; Commons is the
   meta-community + T1 provider, one pseudonym per user. Repo-per-community is the
   graduation story.
3. **Starter communities + seed content** — proposed trio **cooks / woodworking /
   homelab** with enough seed posts to make the feed and a sample passport feel
   alive. *(Open: exact seed volume — settle at client-build time.)*
4. ~~Trust-weighted feed depth~~ → **cut from v1**, fast-follow.
5. ~~Confirmation chip~~ → moot; **no tip overlay**, just a plain `posting…`
   spinner.
```
