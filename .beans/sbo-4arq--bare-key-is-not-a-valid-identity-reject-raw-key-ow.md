---
# sbo-4arq
title: 'Bare key is not a valid identity: reject raw-key owners; require /sys/names or email'
status: todo
type: bug
priority: high
created_at: 2026-07-07T10:00:25Z
updated_at: 2026-07-07T10:00:25Z
---

Per the identity-model decision (2026-07-07): an identity is EITHER a /sys/names/<handle> name OR an email; a BARE KEY is NOT a valid identity. Today authorization violates this: a write can declare `Owner: ed25519:<key>` and `authorize_owner` (sbo-core/authorize.rs) resolves it to `Controller::Key` and authorizes on direct signature — so a raw key can own a namespace (e.g. `/u/ed25519:<key>/**` via the `/u/$owner/**` grant) with NO /sys/names registration, no email, no DNSSEC. This bypasses the sovereignty model /u/ is meant to enforce (flagged by owner during mingo-hqp2 work).

## Fix
- Owner references must resolve via /sys/names (name or key-rooted handle) or email attribution. A bare `ed25519:<key>` / `{key:...}` literal as an Owner should NOT authorize by itself.
- Likely in `resolve_controller` / `authorize_owner`: only treat a key as controller when it is the PINNED key of a /sys/names identity (name-rooted or email-rooted record), not when supplied as a bare literal owner_ref.
- Audit `effective_owner_ref` (validate.rs:425) fallback to signing_key and the create-path $owner=None handling for related exposure.
- Add tests: bare-key owner rejected; /sys/names-backed key-rooted owner accepted; email-rooted accepted.

## Impact / caution
Core authorization + identity-model change with broad blast radius (touches every write's owner resolution). Needs careful spec + adversarial review. Relates to mingo-blpo (attestor), mingo-sux8 (full identity model epic).
