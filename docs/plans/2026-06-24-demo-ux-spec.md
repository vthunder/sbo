# Demo UX Spec — "Commons" (working title)

**Date:** 2026-06-24
**Status:** Draft for review (spec/wireframe-first; no client code yet)
**Purpose:** Define the end-user demo application — the product, the pitch, the
screens, the flows, and how each maps onto the (already-built) SBO stack. This is
the consumer-legible payoff of Phases 1–6 and the concrete target for Phase 7's
reference client.

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

Feels like "Sign in with Google." Browserid under the hood (Phase 1 capture).

```
┌─────────────────────────────────────────────┐
│                  Commons                      │
│        communities you actually own           │
│                                               │
│   ┌─────────────────────────────────────┐    │
│   │  ✉  Continue with email             │    │
│   └─────────────────────────────────────┘    │
│                                               │
│   No wallet. No seed phrase. Just your email. │
└─────────────────────────────────────────────┘
```
→ produces an `identity.email.v1` (Owner = email), session key captured.

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

### 4.4 Compose + the tip→confirmed moment

The save-a-file feel. The post appears **instantly** (tip), then a quiet status
chip resolves to confirmed when its DA block lands.

```
Compose:                          After hitting Post (optimistic):

┌─────────────────────────────┐   ▲ 1  alice                    ⟳ posting…
│ New post in r/cooks/general │      My first loaf!
│ ┌─────────────────────────┐ │      just now
│ │ My first loaf!          │ │
│ └─────────────────────────┘ │   …a few seconds later:
│            [ Cancel ][Post] │   ▲ 1  alice                    ✅ confirmed
└─────────────────────────────┘      My first loaf!
```

Status chip states: `⟳ posting…` (queued/submitted, in tip only) →
`✅ confirmed` (its block included) — or, rarely, `↩ updated` if a concurrent
higher-HLC write superseded a pending *edit* (rollback; spec's "tip is a
prediction"). For append-only posts/comments, confirmation is lossless and
rollback never happens — only edits/reactions can roll back.

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
| 1 | Sign in with email | `identity.email.v1` (capture cert + DNSSEC) | ✅ Ph1 |
| 2 | Join an open community | self-issued `membership` attestation | ✅ Ph3/5 |
| 3 | Post | `post.v1` (HLC, batched tier) | ✅ Ph6 |
| 4 | Comment | `comment.v1` (parent) | ✅ Ph6 |
| 5 | Upvote / react | `reaction.v1` (LWW toggle) | ✅ Ph6 |
| 6 | Earn a badge / role | community issues `badge:*` / `role:*` attestation | ✅ Ph3/4 |
| 7 | View passport | read all attestations about a subject in-repo | ✅ data; client aggregates |
| 8 | Appoint a mod | `role:moderator` attestation; policy role | ✅ Ph4/5 |
| 9 | Ban | `ban` attestation; policy `not_attested` | ✅ Ph4/5 |
| 10 | Instant post feel | tip overlay (confirmed ⊕ outbox) | ⏳ 6.5 (client-side) |
| 11 | Trust-weighted feed | client ranking over reactions + passport | ⏳ Ph7 (client view) |

**The protocol is essentially done for this demo.** What's missing is *client*
work: the tip overlay (flow 10), aggregation/ranking views (7, 11), and the UI.

## 6. Where "tip" lives (resolved by the UX)

The only screen where tip surfaces is **4.4 (compose)** — and it's strictly the
author's optimistic echo of *their own* write. In SBO's based/no-sequencer model
there's no shared mempool, so:

```
tip(user) = confirmed (from daemon/indexer)  ⊕  user's own outbox
                                             └─ same deterministic LWW (hlc::lww_wins)
```

→ Tip is **client-side**: a small outbox + overlay module, pure and testable, in
`sbo-core`, consumed by the web client. The **daemon stays the confirmed-state
authority** and submission relay; it gets **no mempool**. This keeps confirmed
state globally deterministic (different daemons must never disagree) while the
optimistic prediction stays at the edge where it belongs.

Outbox entry: `{ object_hash, hlc, key:(path,id), status }` where status ∈
`queued → submitted → confirmed | rolled-back | needs-reissue`. Reconcile when
confirmed advances: object_hash present in confirmed → `confirmed`; a higher-HLC
write confirmed for the same key → `rolled-back`; queued past cert window →
`needs-reissue`.

## 7. Build plan implication (for Phase 6.5 / Phase 7)

1. **6.5 — `sbo-core/src/tip.rs`**: the pure Outbox + `tip_value()` overlay +
   `reconcile()` state machine, unit-tested. No daemon/client I/O. *(This is the
   only remaining Phase 6 protocol-layer item; everything else 6.x is done.)*
2. **Phase 7 — reference client (web)**: browserid login → submit via daemon →
   read confirmed from daemon/indexer → tip overlay → render the screens above →
   passport aggregation → trust-weighted ranking. Plus verifiable query responses
   (sboq) behind a quiet "how do I know this is real?" affordance for the
   sovereignty-curious minority — never the main pitch.

## 8. Open questions for review

1. **Name.** "Commons" is a placeholder. Want something punchier / less earnest?
2. **Aggregated vs repo-per-community for the demo.** Spec recommends
   repo-per-community for real sovereignty; aggregated is far simpler to demo and
   makes the passport a local read. Proposal: **aggregated for v1 demo**, note the
   sovereignty caveat, leave repo-per-community as the "graduation" story. OK?
3. **How many communities + how much seed content** to make the feed and passport
   feel alive (cooks / woodworking / homelab as the starter trio)?
4. **Trust-weighted feed depth.** Full ranking algorithm, or a simple, legible
   "boosted by people you trust" v1? (Recommend simple + legible first.)
5. **Surface confirmation at all?** The tip→confirmed chip is honest and subtly
   reinforces "this is durable," but could also be invisible for max
   normal-app-feel. Show a quiet chip, or hide entirely?
```
