---
# sbo-49su
title: Agent-native web-of-trust for dependency audits (sibling project idea)
status: draft
type: feature
priority: low
created_at: 2026-07-05T09:08:35Z
updated_at: 2026-07-05T09:08:35Z
---

A **sibling project to mingo** (not a mingo feature): an agent-native web-of-trust for **dependency audits**, built on SBO. The wedge is a real, worsening, self-felt pain — supply-chain attacks — and a consumer that genuinely didn't exist until now: the **coding agent making install decisions**.

## The pain
Choosing dev dependencies is getting riskier by the day (typosquats, compromised releases, malicious post-install scripts). Agents make it worse: coding agents add dependencies autonomously and at scale, and will happily `npm install` a typosquat. So both the volume and the recklessness of dependency selection are exploding.

## The loop (thin version)
Ride an existing action with zero extra steps — a Claude Code **PreToolUse hook** on `npm install` / `cargo add` / `pip install`:
1. About to add `foo@1.2.3`.
2. Check: is there a signed audit attestation for THIS exact `name@version + integrity-hash` from an identity in my trust set?
3. Hit → proceed, surface "audited by <you/someone you trust>".
4. Miss → agent runs the cheap, high-value behavioral audit (new/changed install scripts, new network calls, obfuscation, maintainer change since last version, typosquat distance — Socket-style, seconds not hours), emits a **signed attestation** (verdict + evidence + integrity hash), then proceeds or flags.

Friction killers: it's a hook (automatic, not a ritual); publishing is one call; the **trust set starts as just you** — your own accumulated self-audits are useful on the very next install of the same version. No market, no adoption needed for day-one value.

## Why this is novel (the incentive loop that killed the predecessors)
The web-of-trust-of-audits idea already exists — **cargo-vet** (org-shared audits, modest traction) and **cargo-crev** (individual reviews, languishes). Neither failed on substrate; they failed on **incentive/adoption**: nobody wants to do the reviews. The 2026 difference: **agents are both producer AND consumer.** Agents audit deps as a *byproduct* of already reading the code they're about to depend on, and other agents *consume* structured/verifiable attestations before installing (humans satisfice on download counts; an agent can actually check). That closes the produce→consume loop that humans never did.

## Competitive landscape (be honest — crowded)
- **Sigstore / Rekor** — append-only tamper-evident transparency log for signatures/attestations; npm provenance + PyPI attestations (PEP 740) run on it. So "signed, verifiable provenance" is shipped and adopted — tamper-evidence is NOT the differentiator.
- **SLSA / in-toto** — build provenance ("who built it, how").
- **Socket.dev / OSV / OpenSSF Scorecard / deps.dev** — package behavioral analysis + risk signals.
- **cargo-vet / cargo-crev** — the closest analogs (shared audits / web-of-trust reviews).
The substrate is largely solved. The bottleneck is producing trust signals — which the agent-byproduct model addresses.

## Where SBO earns its place (and it's a genuine fit, not a stretch)
- The **attestation primitive we already built for checkpoints** — signed `(subject, verdict)` claims + a **client-chosen set of trusted attestors + a threshold** — IS the dependency-trust model verbatim. Different `subject` (a package artifact instead of a state root), same verifier.
- **Sovereign, portable, cross-ecosystem identity** for auditors/maintainers (not a per-registry siloed account) — SBO's canonical-identity model.
- `/u/<attestor>/attestations/...` layout is already the home for author-namespaced attestations.
- **No trusted operator + client-chosen trust** — a git repo has a central host and no identity model; Rekor has a central operator and no web-of-trust semantics. SBO has the missing pieces.
- Correction to an earlier over-estimate: building v1 on SBO is NOT high-friction given these primitives already exist — the "start off-chain to avoid friction" caution is weaker than first argued.

## Staged path
- **v1** — hook + signed attestations + your own trust set; dogfood in Claude Code (you = first consumer, your agents = first producers). Substrate can be SBO from the start given the primitives exist, or a plain signed store — decide based on real ergonomics.
- **v2** — import audits from a handful of people/orgs you trust (cargo-vet, generalized past Rust; cross-ecosystem).
- **v3** — open, cross-ecosystem, client-chosen web-of-trust with sovereign portable identity and no trusted operator. This is where SBO is clearly the right substrate.

## Open questions / crux
- **Incentive still the crux**, just relocated: why does the first agent emit an audit, and why does the second trust it? (Bet: byproduct-cheap production + agent consumption closes it.)
- **Version granularity** — attestations are per-exact-version+hash (attacks are version-specific); reuse across versions needs diff-based trust inheritance ("1.2.3→1.2.4 diff is trivial → inherit").
- **Audit depth** — cheap behavioral check (high value, seconds) vs full semantic audit (expensive tail). Start behavioral.
- **Trust bootstrapping** — your own past audits + transitively people you trust; starts tiny, grows.
- **Substrate decision** — SBO vs off-chain for v1, given the primitives already exist.

## First move (de-risk cheaply)
Build v1 and dogfood it in Claude Code — PreToolUse hook + a tiny signed-attestation format + a local/own trust set, you as sole auditor. If after ~2 weeks the hook feels like a seatbelt not a nag, it's a real wedge with a clear graduation to the SBO web-of-trust. If it feels like ceremony, the thesis is cheaply disproven before any genesis block.

(Captured 2026-07-05 from a strategy discussion. Sibling to mingo; would live in its own repo. Draft — needs refinement before it's actionable.)
