# MNEME — Security Audit, Round 2: Authority After Quarantine

**Date:** 2026-07-21  
**Method:** Abductive Engineering (A–D–I) + adversarial red-team review  
**Base:** `5a2e1429bc28221fdca7df4950af007ff8cf502e`  
**Runtime:** Python 3.12.3  
**Scope:** `mcp_server.py` and the authority boundary around `store`,
`reinforce`, `quarantine_actor`, and `rehabilitate_memory`. This is a new
round; Round 1's custody, temporal, graph-influence, and bundle checks remain
out of scope except where a result depends on them.

## Threat model

- **Attacker CAN:** invoke MNEME mutator tools through an MCP client they
  control, choose the public `actor_id` / `initiated_by` arguments, and retain
  access after their actor has been quarantined.
- **Attacker CANNOT:** modify verifier code, forge SHA-256, alter a bundle
  after an honest party sealed and transmitted it, or bypass SQLite transaction
  rollback.
- **Trust boundary under test:** actor identity and recovery authority at the
  MCP/API boundary.

This is the shared-agent threat model. If the stdio MCP process is exposed only
to one fully trusted operator, the vectors below become a design limitation of
that deployment rather than a remote exploit. The public tool surface itself
does not implement that authority boundary.

## Epistemic legend

**CODE FACT** · **PLAUSIBLE HYPOTHESIS** · **CONFIRMED BY INDUCTION** ·
**FALSIFIED**

## Executive summary

| ID | Severity | Level | Bucket | Finding |
|---|---|---|---|---|
| R2-01 | High | CONFIRMED BY INDUCTION | Software vulnerability under the shared-agent threat model | A quarantined actor can continue to store new `CLEAN` memories and reinforce existing clean memories; a second sweep is refused. |
| R2-02 | High | CONFIRMED BY INDUCTION | Software vulnerability under the shared-agent threat model | Any registered MCP caller can self-rehabilitate tainted material or quarantine another actor's memories. Custody records the action but does not authorize it. |
| R2-03 | — | FALSIFIED | Invariant test | A forced failure between quarantine state mutation and custody append rolls back actor status, memory state, and sweep together. M2 held on the tested MCP path. |
| R2-04 | Low / boundary | CONFIRMED BY INDUCTION | Honest partial-evidence limitation | A one-sided supersession export verifies while naming its absent counterpart. The relationship is not silently erased, but the counterpart's consent is not independently provable in that partial bundle. |

## R2-01 — Quarantine is retrospective, not a write barrier

**Severity:** High  
**Epistemic level:** CONFIRMED BY INDUCTION  
**Bucket:** software vulnerability under the shared-agent threat model

### Surprise / expectation violated

MNEME presents actor quarantine as the containment action for a poisoned-memory
incident: all memories the actor touched are taint-flagged and excluded from
recall. A containment state is expected to stop the compromised actor from
creating or influencing further served memory.

### Code facts

- `trust.quarantine_actor()` sets `actors.status = 'QUARANTINED'` and sweeps
  existing custody events.
- `mcp_server._ensure_actor()` inserts only absent actors; it does not reject
  an existing `QUARANTINED` actor.
- `mneme_store()` and `mneme_reinforce()` accept caller-supplied `actor_id` and
  do not check actor status.
- A second `quarantine_actor()` call refuses an already quarantined actor to
  avoid splitting the original sweep.

### Deduction

If actor status is not enforced on later writes, then after an analyst
quarantines `evil_ingestor`, that actor can:

1. store a new memory that is born `CLEAN` and becomes recallable; and
2. reinforce a separate clean memory, increasing its confidence;
3. while a resweep is rejected because the actor is already quarantined.

### Induction

Against a fresh temporary SQLite database through the actual MCP wrapper:

```text
actor_status: QUARANTINED
sweep_flagged: [pre-existing evil memory]
post_memory: new memory stored by evil after quarantine
memory_statuses:
  post_memory       CLEAN
  pre-existing      TAINT_FLAGGED
recall.served: [post_memory]
```

For influence on an existing memory:

```text
REINFORCED by evil_ingestor after quarantine: confidence 0.5000000000 → 0.6250000000
trusted memory custody status: CLEAN
resweep result: "Actor 'evil_ingestor' is already QUARANTINED"
```

### Causal chain

```text
compromised actor is quarantined
        ↓
historical sweep taint-flags only prior custody events
        ↓
MCP accepts the same actor_id on a new STORE / REINFORCE
        ↓
new state is CLEAN or a clean memory is inflated
        ↓
custody gate serves the new/inflated result
        ↓
second sweep is refused
```

### Boundary

This does not break the chain: the post-quarantine event is recorded honestly.
It breaks the **containment meaning** of `QUARANTINED` when the same actor
retains mutation access. An audit trail is not an authorization system.

## R2-02 — MCP mutators have no recovery or quarantine authority policy

**Severity:** High  
**Epistemic level:** CONFIRMED BY INDUCTION  
**Bucket:** software vulnerability under the shared-agent threat model

### Surprise / expectation violated

Rehabilitation is described as an analyst's audited reversal of a false
positive; quarantine is a high-impact incident response action. Both change
what an agent can remember. A caller should not be able to grant itself those
effects merely by choosing an `actor_id` string and a reason.

### Code facts

- `mneme_rehabilitate()` calls `_ensure_actor()` for any supplied `actor_id`
  and then calls `trust.rehabilitate_memory()` with no role, ownership, or
  approval check.
- `mneme_quarantine_actor()` similarly accepts arbitrary `actor_id` and
  `initiated_by`; it verifies only that both identities exist.
- `_ensure_actor()` will register a previously unknown caller as an `AGENT`.

### Induction A — self-rehabilitation

The same actor stored a poisoned memory, an analyst quarantined that actor, and
the actor invoked `mneme_rehabilitate()` on its own taint-flagged memory:

```text
STORED         evil_ingestor   ingest
TAINT_FLAGGED  analyst         source compromised
REHABILITATED  evil_ingestor   self-declared false positive

final custody_status: CLEAN
recall.served: [that memory]
```

### Induction B — arbitrary quarantine

An `evil_agent` invoked `mneme_quarantine_actor("trusted_pipeline",
initiated_by="evil_agent")`:

```text
trusted_pipeline actor status: QUARANTINED
trusted memory status: TAINT_FLAGGED
recall excluded_custody: 1
```

### Causal chain

```text
untrusted MCP caller controls actor identity fields
        ↓
mutator validates presence, not authority
        ↓
caller may rehabilitate its own evidence or quarantine another actor
        ↓
custody chain accurately records the unauthorized action
        ↓
recall follows the resulting state
```

### Boundary

This is not a claim that any local stdio process is remotely reachable. It is
confirmed under the stated shared-agent model: once an untrusted or compromised
agent is allowed to call the MCP mutators, the application does not distinguish
it from an incident commander or reviewer.

## R2-03 — Transactional M2 rollback under an injected append failure

**Severity:** none  
**Epistemic level:** FALSIFIED

### Hypothesis

`quarantine_actor()` updates `actors.status` before it appends the first
`TAINT_FLAGGED` event. If the append fails, the MCP wrapper might leave the
actor quarantined or a partial sweep committed without a custody event.

### Prediction

Inject an exception at `trust.custody.append_event` after the actor status
update. If M2 is broken, the actor or memory state persists after the tool
returns an error.

### Induction

Observed after the actual `mneme_quarantine_actor()` wrapper returned
`{"error": "injected append failure"}`:

```text
actor_status: ACTIVE
memory_status: CLEAN
sweeps: 0
custody_events: 1  # only the pre-existing STORED event
```

The transaction rolled back completely. The hypothesis is **falsified** for
this path; M2 held.

## R2-04 — Partial supersession exports retain a claim but not bilateral proof

**Severity:** Low / evidence boundary  
**Epistemic level:** CONFIRMED BY INDUCTION  
**Bucket:** honest partial-evidence limitation, not a seal bypass

A full export of `old → new` verifies. Exporting only `new` also verifies while
its STORED payload names `old`; exporting only `old` verifies while its final
event names `new`.

This is consistent with the implementation's documented rule: bilateral
supersession is checked **when both parties are present**. The omitted endpoint
is named, so the relation is not erased; however, the verifier cannot prove
the absent endpoint's consent. Unlike taint sweeps, there is no
`excluded_lineage` declaration. Treat a partial bundle as proof of what it
carries, never proof that its lineage is complete.

## Discarded vectors and harness corrections

| Vector | Result | Why |
|---|---|---|
| Inject a non-canonical `Decimal("0.1")` to create lineage test data | FALSIFIED at input boundary | Canonicalization refused it before state mutation; the valid experiment used `Decimal("0.1000000000")`. |
| Crash between quarantine actor update and custody append | FALSIFIED | MCP rollback restored all tested state. |
| Partial one-sided lineage export | Not an integrity bypass | It verifies by declared design and names the missing endpoint; it is an evidence-completeness boundary. |

## Recommended protocol changes

These are recommendations, not applied changes in this audit branch.

1. **Make actor status a transactional write gate.** `store`, `reinforce`,
   supersession, and every future mutator must refuse a `QUARANTINED` actor
   before changing any memory or custody chain.
2. **Introduce explicit authority, not stringly actor identity.** Separate
   writer, incident-commander, and reviewer/recovery capabilities. Quarantine
   and rehabilitation must require a capability/role validated by the server,
   not an argument selected by the caller.
3. **Define a post-quarantine protocol.** Either refuse all writes from the
   actor, or append them as automatically tainted and immediately excluded.
   The choice must be explicit and tested. A rejected resweep must never leave
   later influence uncontained.
4. **For partial lineage exports, consider `excluded_lineage` declarations.**
   This would mirror B5's honest partial-sweep contract if consumers need to
   distinguish “counterpart not included” from “lineage ended here.”

## Implications for STIGMERGY

MNEME's result transfers directly to STIGMERGY's distributed setting:

- a hash-chained CockroachDB ledger does not authenticate a node;
- a quarantined/revoked node must be unable to write new memories, reinforce,
  emit recruitment signals, or claim another region;
- recovery/migration authority must not be inferred from caller-provided
  `node_id` or `origin_region` strings;
- the enforcement must run in the same CockroachDB transaction as the state
  mutation and its audit event; and
- Cloud MCP read-only defaults, service-account RBAC, and Lambda execution
  identities are useful only if domain-level node/region ownership is also
  checked in the application schema and write procedures.

These are the guarantees to port, then re-test, rather than merely copying
MNEME's syntax into STIGMERGY.
