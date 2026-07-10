---
# sbo-8t4b
title: 'Warrant-authorized on-chain writes: sbo:// audiences'
status: todo
type: feature
priority: normal
created_at: 2026-07-10T18:30:21Z
updated_at: 2026-07-10T22:22:41Z
---

Coordination item from browserid-ng v0.4 (2026-07-10). Agent identities now present `agent_cert~warrant~assertion` chains where the warrant's `aud` is an opaque exact-match URI — non-HTTP schemes are explicitly valid (browserid-ng agent spec §5.2). The ledger should be a relying party with its own audience, so a principal grants "act at mingo.place the website" and "write to the ledger" as separate, separately-scoped warrants.

## Design questions

- **Audience convention**: what exact string does a validator expect? Candidates: `sbo://<network>` vs `sbo://<network>/<repo>` (per-repo grants) vs `sbo+raw://…`. Must be one exact string per verifier — pick and spec it in the SBO Attribution Specification.
- **Where warrants matter**: key-rooted identities authorize writes by signature (no per-write browserid material) — unchanged. The warrant path applies where browserid Auth-Certs appear today: email-rooted writes and the one-time attribution gate on domain repos. An *agent* performing those presents its typed agent cert + warrant; validators verify the chain offline (core §6.3 detached DNSSEC proofs) including warrant scope (e.g. `post`, `claim`).
- **Scope vocabulary** for ledger writes (write kinds? path prefixes?) — validator-enforced, so it must be deterministic.
- **Fail-closed**: validators must reject typed agent certs without warrants (v0.4 parse does this if they use browserid-core ≥ a849ade — requires the dep bump in sbo).

## Coordination

- sbo: validate.rs / attribution verification + SBO Attribution Specification update + browserid-core dep bump.
- browserid-ng: none needed (audience URIs already spec'd); maybe a worked sbo:// example in the agent spec.
- mingo: mint path already v0.4 (mingo-j2hy); attestor flows would request a second warrant with the sbo:// audience via the normal consent flow.

## Design settled (2026-07-10, with vthunder)

Grounded in: SBO writes have **no audience** today (envelope signature replaces the assertion; Authorization spec "Envelope-as-assertion"). An email-rooted write carries a bare `Auth-Cert` (key->email) + `Auth-Evidence` (DNSSEC), verified offline. Since `attestor@browserid.me` is a **typed agent cert** (browserid-agent-cert-v1), accepting it alone would author on-chain writes with no warrant/consent — the confused-deputy hole v0.4 closes for web RPs, open on-chain. So the warrant is what makes an agent write safe, and its audience is the per-ledger confinement the base contract lacks.

### 1. Audience = canonical `sbo+raw://`, never `sbo://`
DNS `_sbo` is discovery-only, not a trust root; validators verify offline. So `sbo://mingo.place` is NOT on-chain-verifiable; the warrant MUST carry the canonical `sbo+raw://` form. `sbo://` stays a display/discovery label (consent UI resolves it for the human; the agent signs the resolved canonical `aud`). Uniform for DNS and non-DNS chains — DNS only prettifies the label.

### 2. Bare OR pinned — agent's choice (settled)
The audience is any `sbo+raw://` reference that **identifies this database**. Validator rule (offline, exact-ish): parse `warrant.aud` as sbo+raw://; require authority == this DB's `chain:appId`; if it carries `@firstBlock`, require ==; if `?genesis=sha256:`, require ==. So:
- `sbo+raw://avail:turing:506/` (bare authority) — broad, **survives regenesis** (matches mingo's stable repo id f86a7b415defc6cf). 
- `sbo+raw://avail:turing:506@3567386/?genesis=sha256:7c42...` — pinned to one instance.
Agent picks per request. mingo live identity: chain avail:turing, appId 506, firstBlock 3567386, genesis sha256:7c429116...

### 3. Auth-Warrant header + verification branch
New signed-block header `Auth-Warrant` (base64url warrant JWS, browserid-agent-warrant-v1, embeds delegator `parent-cert`), placed adjacent to Auth-Cert/Auth-Evidence (message-bound, unstrippable). When `Auth-Cert.typ == browserid-agent-cert-v1`, a warrant is REQUIRED. Extended verify_attribution:
1. Agent cert as today (key==Public-Key, DNSSEC issuer, window, broker authority).
2. Warrant: typ ok; `agent`==cert email; `iss`==cert `agent.parent`; sig verifies vs embedded parent-cert key; parent-cert verifies vs its DNSSEC issuer (same browserid.me evidence covers both when same issuer); signing-time (warrant.iat in parent-cert window); inclusion_time in warrant [iat,exp].
3. Audience identifies this DB (rule above).
4. Scopes authorize the write (grammar below).
5. Attribution = agent email (attestor@browserid.me), attribution root = parent (vthunder@gmail.com).

### 4. Scopes — make them expressive (vthunder: as expressive as reasonable)
SBO defines the grammar (scopes are opaque to the broker/IdP, RP-interpreted). Each scope string = `<dim>:<value>`, deterministic + offline-enforceable:
- `path:<glob>` — write Path matches (e.g. `path:/attestor/*`)
- `action:<post|transfer|delete|import>` — write Action
- `schema:<content-schema>` — Content-Schema
Semantics: OR within a dimension, AND across dimensions; a missing dimension is unconstrained. Extensible (owner:, policy:, size:). Expressive (path x action x schema) yet a fixed grammar validators replay deterministically.

### 5. Ownership: email-rooted (confirmed)
attestor writes objects owned by attestor@browserid.me -> per-write agent-cert+warrant, preserving attribution + browserid revocation. (Key-rooted alternative rejected — loses per-write warrant confinement.)

### 6. Revocation -> sbo-vddl (on-chain signed revocation records; broker submits, must understand sbo audiences).

## Work order
1. sbo: bump browserid-core (currently rev 480a4be — pre-v0.4, no agent certs/warrants) to >= a849ade.
2. sbo: Authorization + Attribution spec updates (agent-cert+warrant path, Auth-Warrant header, canonical-audience rule, scope grammar).
3. sbo-core: attribution.rs warrant-aware branch; wire/parser Auth-Warrant header.
4. browserid-agent / consent: resolve sbo://->sbo+raw:// for display+signing; agent requests the ledger warrant.
5. mingo: attestor flow assembles the write (agent cert + warrant + evidence).

## On-behalf writes (as:) — added 2026-07-11

Two delegation models, both supported: (A) agent-as-itself (writes as attestor@…, needs an SBO policy to touch the user's objects) and (B) on-behalf (a warrant with an `as:<delegator>` scope makes the effective author the delegator — no policy edit; user is owner/Creator). B is required for 'set user as creator' and 'edit user-owned object w/o policy' (SBO's Creator-integrity + owner checks need authorization AS the user). Spec drafted in Authorization Spec (scope grammar `as:` row + On-behalf writes subsection + effective-author in the verify algorithm) and Attribution Spec §4a step 13.

Key properties: on-behalf ≤ delegator's own rights (never a policy bypass; only narrows); accountable (Auth-Warrant in the proof names the agent even though owner=delegator); guardrails — `as:` MUST carry a `path:` scope, and a repo MAY decline on-behalf (direct-writes-only, hook reserved).

`as:` is a **per-warrant mode** (one write, one author), not per-scope. Both models at once = **two warrants at the same audience**, distinguished by scopes → a grant's identity is (audience, scopes), not audience alone. Follow-up impl: g0ba batch-dedup and jipx registry key must include a scope fingerprint (broker hashes opaque scopes without interpreting them).
