---
# sbo-pu34
title: 'Policy: match on object id, and value conditions on payload fields'
status: todo
type: feature
priority: normal
created_at: 2026-09-16T20:24:34Z
updated_at: 2026-09-16T20:24:34Z
---

Two gaps in the policy language, found while trying to express a chain-enforced minimum ecosystem contribution for browserid-pay (bean browserid-pay-er8j).

## 1. Patterns match path only, never the object id

\`check_policy\` passes \`&msg.path\` and nothing else (\`sbo-daemon/src/validate.rs:1769\`); \`Message\` carries \`path: Path\` and \`id: Id\` separately (\`sbo-core/src/message/envelope.rs:34-35\`), \`Path\` is \`Path(Vec<Id>)\`, and both grants and restrictions match \`Path::parse(target_path)\` (\`policy/evaluate.rs:47,79\`). So \`msg.id\` never reaches the evaluator.

That makes whole classes of rule inexpressible. browserid-pay keeps every object of an agreement in one container — \`/agreements/<id>/\` with ids \`proposal\`, \`acceptance\`, \`lock\`, \`ruling\`, evidence — so no rule can target only proposals. Consumers work around it by moving the discriminator into the path (see the provider-listing layout fix, browserid-pay-iovq), which distorts object layout to suit the policy language.

Proposal: an explicit \`id\` field alongside \`on\`, on **both grants and restrictions** — the matching language should be uniform unless there is an overwhelming reason to split it (Dan, 2026-09-16).

    { "on": "/agreements/*/", "id": "proposal", "require": { ... } }

- omitting \`id\` MUST mean "any id", so every existing policy keeps its exact current meaning
- \`id\` should support the same \`$user\` / \`$owner\` substitution the path patterns do, or it is an inconsistent half-language
- a separate field, not positional syntax: \`/agreements/*/proposal\` is ambiguous between the container \`/agreements/x/proposal/\` and id \`proposal\` at \`/agreements/x/\`

## 2. No condition on a payload field value

\`Requirements\` (\`policy/types.rs:146\`) has \`max_size\`, \`schema\`, \`content_type\`, \`require_payload_signed_by\`, \`attested\`, \`not_attested\`, \`dnssec_proof\` — nothing reads into the payload. The payload is already available to \`check_requirements\` (\`max_size\` reads \`payload.len()\`, \`evaluate.rs:147\`), so this is a new variant, not new plumbing.

Proposal: JSON-pointer conditions with scalar comparators.

    "require": { "fields": [
      { "pointer": "/contribution/fn",         "eq":  "max" },
      { "pointer": "/contribution/amount",     "min": 0.01  },
      { "pointer": "/contribution/percentage", "min": 0.01  } ] }

Keep it scalar deliberately: the *structure* of the payload carries any formula, the policy never evaluates one. Requirements are AND-ed, which is exact for a floor on \`min()\` and a cap on \`max()\`, and conservative (stricter than necessary) the other way round — acceptable, since the exact form would need an OR the language does not have.

Fail closed throughout: non-JSON payload, missing pointer, wrong type, NaN ⇒ denied.

- [ ] decide the surface: \`id\` field on grants + restrictions; \`fields\` conditions on \`Requirements\`
- [ ] sbo-core: id matching in \`evaluate.rs\` (grants and restrictions), backward compatible when absent
- [ ] sbo-core: \`fields\` conditions in \`check_requirements\`, failing closed
- [ ] Policy Specification text for both (the path-only rule is currently undocumented upstream — browserid-pay asserts it in its own comments)
- [ ] tests incl. old policies unchanged, ambiguity cases, malformed payloads
