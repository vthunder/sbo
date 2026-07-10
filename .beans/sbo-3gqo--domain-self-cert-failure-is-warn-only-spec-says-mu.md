---
# sbo-3gqo
title: Domain self-cert failure is warn-only; spec says MUST reject; evidence not read as-of genesis block
status: todo
type: bug
priority: high
created_at: 2026-07-08T15:48:57Z
updated_at: 2026-07-08T15:48:57Z
parent: sbo-f5wn
---

sync.rs:1241 only tracing::warn!s on self-cert failure and applies the write (comment: 'flip to a hard reject once verified live'). Identity Spec Validation Rule 4: a domain.v1 whose self-cert is present but fails MUST be rejected. Also evidence is fetched from CURRENT state (validate.rs:191 get_first_object_at_path_id) not read as-of the genesis block, so a later user-attribution refresh could shadow genesis evidence (attack the proposal called out). Confirmed independently + by two agents.
- [ ] Make self-cert failure a hard reject
- [ ] Resolve the explicit ref: leaf as-of THIS object's block (point-in-time), not current state
- [ ] Tests: mismatched domain key rejected; refresh cannot shadow genesis evidence
