---
# sbo-hj98
title: The Related header is declared but never persisted or served
status: todo
type: bug
priority: normal
created_at: 2026-09-18T22:27:33Z
updated_at: 2026-09-18T22:27:33Z
---

`Message.related: Option<Vec<Related>>` (`sbo-core/src/message/envelope.rs:51`) is a declared header that goes nowhere:

- it is in the canonical header ordering (`envelope.rs:182`, `"Related"`), so it is signed
- it is **not** a field of `StoredObject` (`sbo-core/src/state/objects.rs`)
- it is **not** returned by `/v1/object` or `/v1/list`
- nothing in the daemon reads it — every construction site passes `related: None`

So a write may carry a `Related { rel, reference }`, and it is covered by the signature, but no reader can see it without re-fetching the raw wire from DA and re-parsing the envelope. In practice the header is write-only.

This is a trap for anyone reading the type and assuming it works — it reads exactly like the natural place to put an object-to-object reference. browserid-pay planned its agreement↔thread backlink on it (`browserid-pay-xnok`) before discovering it is not surfaced, and has fallen back to an application-level payload field.

**Value in fixing it:** a generic, schema-independent, signature-covered reference between objects, usable across object types without every application inventing its own payload convention. The reverse index (given B, which objects reference it?) is then something the daemon or an indexer can build once for everyone.

- [ ] persist `related` on `StoredObject`
- [ ] return it from `/v1/object` and `/v1/list`
- [ ] decide whether `reference` is validated at all (an existing path? a well-formed SBO URI? nothing?) — "nothing" is defensible but should be deliberate
- [ ] consider a reverse lookup (`/v1/referencing?ref=…`), or leave it to indexers
- [ ] until then, document in the type that it is not surfaced, so the next reader does not plan on it
