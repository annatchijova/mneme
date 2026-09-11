# MNEME — Security Audit, Round 3: The Layers That Closed Round 2

**Date:** 2026-09-11
**Method:** Abductive Engineering (A–D–I) + adversarial red-team review
**Base:** `2b0cce17` (the authority, causal, counterfactual and epistemic layers)
**Runtime:** Python 3.11.15
**Scope:** `authority.py`, `causality.py`, `counterfactual.py`, `claims.py`,
and the export path in `bundle.py`. Rounds 1 and 2 remain out of scope except
where a result depends on them.

## Why this round has a different threat model

Round 2's attacker chose `actor_id` strings and the application could not tell
an incident commander from anyone else. The authority ledger made that attacker
impossible, so continuing to model it would be auditing a door that is now a
wall.

The realistic successor is narrower and worse:

- **Attacker CAN:** hold a real, legitimately issued, narrow grant — a
  compromised agent with `ASSERT`, or `DECIDE`, or `STORE` — and call the
  public API with it. Read any un-gated path. Observe its own results.
- **Attacker CANNOT:** forge SHA-256, edit a sealed bundle after an honest
  party transmitted it, obtain a capability nobody granted it, or bypass
  transaction rollback.
- **Trust boundary under test:** what a *correctly authorized* actor can do
  with the authority it legitimately has — and what the new read paths
  disclose to an actor with none.

This is the shape every capability system eventually gets audited against.
Round 2 asked whether authority existed; Round 3 asks whether it is bounded.

## Epistemic legend

**CODE FACT** · **PLAUSIBLE HYPOTHESIS** · **CONFIRMED BY INDUCTION** ·
**FALSIFIED**

## A note on the method, before the findings

`tests/test_semantic_mutants.py` reports 14/14 semantic mutants killed, and it
did **not** find R3-01 or R3-02. That is the most useful fact in this document.

The same author wrote the mutants and the defenses. An author who knows where
the defenses are writes mutants those defenses kill, and the metric measures
internal coherence rather than robustness. The two findings below were reached
by asking a different question — *what did the new code make reachable that was
not reachable before?* — rather than by mutating what it already checked.

Both are now mutants in that suite. They are kept as markers of the blind spot,
not as evidence of coverage.

## Executive summary

| ID | Severity | Level | Bucket | Status | Finding |
|---|---|---|---|---|---|
| R3-01 | High | CONFIRMED BY INDUCTION | Software vulnerability | **Fixed in this branch** | `custody_override` let any caller widen the custody gate and read the CONTENT of a quarantined memory. |
| R3-02 | Medium | CONFIRMED BY INDUCTION | Verification gap | **Fixed in this branch** | The export seeded its authority closure from a singular root, so a two-root ledger shipped one root and B7's "exactly one root" check passed. |
| R3-03 | Medium | CONFIRMED BY INDUCTION | Asymmetric denial of service | Reported | An `ASSERT`-only actor can drag settled claims into unbounded new constraints, each of which only an `ADJUDICATE` holder can clear. |
| R3-04 | Low–Medium | CONFIRMED BY INDUCTION | Evidence-quality limitation | Reported | Blast radius is inflatable by a `DECIDE` holder: `derived_from_decision` is self-asserted and the memory it descends from never corroborates it. |
| R3-05 | Low | CONFIRMED BY INDUCTION | Information disclosure | Reported | Several un-gated paths confirm the EXISTENCE and STATUS of memories the custody gate withholds, without disclosing content. |
| R3-06 | — | FALSIFIED (SQLite) / CONFIRMED (portability) | Concurrency defect | Reported | A6's "last GRANT" check is read-then-write. Both pre-checks pass concurrently; SQLite's write lock serializes them, and an MVCC engine would not. |

## R3-01 — The counterfactual is a disclosure oracle

**Severity:** High · **Level:** CONFIRMED BY INDUCTION · **Status:** fixed here

### Surprise / expectation violated

The custody gate is the thing MNEME is for: a QUARANTINED memory "remains in
the field but is invisible to the agent". The counterfactual layer was built to
measure containment — and to do that it needed to run a recall against a
*hypothetical* custody state, which is what `field.recall(custody_override=…)`
provides. Nobody asked what happens when the hypothetical state is **wider**
than the real one.

### Code facts

- `field.recall()` has never required a capability. Serving is a read, and
  Rounds 1 and 2 scoped authority to mutators.
- `custody_override` maps `memory_id -> custody_status` and is applied on top
  of the real status in either direction.
- `RecallHit` carries `content`.

### Deduction

If the override can force a non-CLEAN memory to CLEAN, and recall returns
content, and no capability is checked, then any caller who can invoke recall
can read anything the gate withheld — by naming it.

### Induction

Against a fresh in-memory field, with a quarantined memory holding a
credential:

```text
normal recall serves:   ['m-public']
with override serves:   [('m-secret', 'SECRET: the admin password is hu…')]
capability required:    NONE
```

### Causal chain

```text
counterfactual analysis needs to see the other world
        ↓
custody_override added to the read path, in both directions
        ↓
recall has no authority check, by design, since Round 1
        ↓
forcing QUARANTINED -> CLEAN returns withheld CONTENT
        ↓
the gate the whole system rests on is steppable by any reader
```

### Boundary

At the MCP surface this is weaker than it looks: `mneme_recall` does not expose
`custody_override`, and `mneme_counterfactual` returns served ids rather than
content. Under the shared-agent model the leak there is *which memories exist*,
not *what they say*. Embedded as a library, it is full content disclosure.

### Fix applied

A new capability, `COUNTERFACTUAL`, gates **widening only**, and the asymmetry
is the design rather than an implementation detail: an override that makes
something servable can reveal what the gate withheld; one that only makes
something UNservable can show a caller strictly less than it could already see.
So `exclusion_effect` ("what would quarantining these do?") stays open to
everyone and `containment_effect` ("what would they have shown?") does not.
`authority_protocol` 1.2.0. Fields with no ledger are unchanged.

Note what the fix does NOT do: the check happens, and nothing is written.
MNEME does not audit reads, and gating one does not start. The refusal
prevents disclosure; it does not record the attempt.

## R3-02 — A check that could not see what it checked

**Severity:** Medium · **Level:** CONFIRMED BY INDUCTION · **Status:** fixed here

### Surprise / expectation violated

B7 requires exactly one root grant, because the whole no-amplification argument
rests on authority hanging from one auditable act. A field with two roots has
two independent sources of power, and the check exists to refuse it.

### Code facts

- `export_bundle()` seeds its authority closure from actors appearing in
  exported custody events, plus `authority.root_subject()`.
- `root_subject()` returned the **first** root by `subject_id ASC`.
- A root actor that never wrote a memory appears in no custody event.
- B7 counts root grants among the chains the bundle **carries**.

### Deduction

A second root whose actor wrote nothing is reachable by neither seed. It never
travels. B7 counts one. The bundle verifies.

### Induction

A field with `root-a` and a second self-issued root `root-b`:

```text
two roots — bundle verdict: True []
```

The check was present, correct, and unreachable.

### Boundary

This is a verification gap, not a privilege escalation: reaching the two-root
state required either a race in `bootstrap_root` (a `COUNT` read followed by a
write) or direct database access.

### Fix applied

Two changes, at two levels:

1. `ledger_root`, a singleton table whose `PRIMARY KEY CHECK (singleton = 1)`
   makes a second root a **constraint violation rather than a race outcome** —
   the idiom `UNIQUE (memory_id, prev_hash)` already uses against forked chains.
2. `root_subjects()` (plural) seeds the export, so every root chain travels and
   B7 can count what it was written to count.

What remains, and it is the same boundary the sweep entries already state: a
*hostile exporter* can still omit a chain, and a verifier cannot detect the
absence of evidence it has no other pointer to. What changed is that MNEME's
own tooling no longer hides it — an honest export of a two-root field now
fails. Both facts are mutants in the suite, one killed, one declared surviving.

## R3-03 — Denial of epistemics: ASSERT is cheap, ADJUDICATE is not

**Severity:** Medium · **Level:** CONFIRMED BY INDUCTION · **Status:** reported

### Surprise / expectation violated

Claim sets were designed so that an open question reads as UNDETERMINED rather
than as agreement — "nobody has objected yet" must never be read as "true".
That deliberate conservatism is exactly what makes it weaponizable.

### Code facts

- `claims.assert_claim()` and `claims.declare_set()` both require only `ASSERT`.
- `declare_set` accepts any existing claims as members, including VALIDATED ones.
- `evaluate_constraint` returns UNDETERMINED while any member is still ASSERTED.
- Clearing a set requires `resolve_set`, which requires `ADJUDICATE`.
- `standing()` reports every set a claim belongs to.

### Deduction

An actor holding only `ASSERT` can mint junk hypotheses and bind a settled
claim into new EXACTLY_ONE sets with them. Each new set is UNDETERMINED and can
only be cleared by a privileged actor. The work is asymmetric by construction.

### Induction

A claim validated by an honest adjudication, then attacked three times:

```text
settled:                          SATISFIED | VALIDATED
after 3 hostile sets, state:      VALIDATED
its set evaluations:              SATISFIED, UNDETERMINED ×3
sets an ASSERT-only actor left open: 3
bundle verdict:                   True
```

### Causal chain

```text
an open hypothesis is UNDETERMINED, never "false by default"
        ↓
declaring a set needs only ASSERT
        ↓
a settled claim can be re-bound into new sets without limit
        ↓
each costs one ASSERT call and one ADJUDICATE call to clear
        ↓
a reader of standing() sees a growing wall of unresolved constraints
```

### Boundary

No state is corrupted. The claim stays VALIDATED, the bundle verifies, the
adjudicated set stays SATISFIED, and nothing is silently believed. What
degrades is the READABILITY of standing and the adjudicator's queue. This is
the epistemic analogue of the taint DoS `KNOWN_LIMITATIONS` already warns
about, one level up — and the influence budget's answer there suggests the
shape of the answer here.

### Recommendation (not applied)

Binding a VALIDATED claim into a new constraint is re-opening a settled
question, which is an adjudication-level act. Requiring `ADJUDICATE` to
declare a set containing an already-VALIDATED member would close it without
touching the conservative default that makes the layer worth having. Worth
designing alongside a per-actor rate discipline, since minting junk
hypotheses against un-settled claims stays cheap either way.

## R3-04 — Blast radius is inflatable by the actor it describes

**Severity:** Low–Medium · **Level:** CONFIRMED BY INDUCTION · **Status:** reported

### Surprise / expectation violated

`impact()` grades its output precisely because contact is not contamination.
DERIVED is meant to be the strong level: "this could not be what it is without
that memory", following edges the agent *declared*. The declaration was
designed as a guard against inference. It is also a guard against nothing.

### Code facts

- `derived_from_decision` is written into a STORED payload by the storing actor.
- Nothing on the named decision, or on the ancestor memory, corroborates it.
- `record_decision` accepts any subset of what a recall actually served.
- POSSIBLE includes every memory co-served in a receipt.

### Induction

One actor holding `STORE` + `DECIDE` cites every served memory in one decision
and stores a memory declaring descent from it:

```text
DIRECT decisions:   ('decision-a44…',)
DERIVED memories:   ('m-derived',)
POSSIBLE:           ('m-b', 'm-c')
every honest memory now appears in the radius of m-a: True
bundle verdict:     True
```

### Boundary

DIRECT is not falsified — those memories genuinely were served and genuinely
were cited. POSSIBLE is explicitly "contact, reported, never acted on". The
real finding is narrower and sharper: **DERIVED is unilateral**, alone among
MNEME's relations. Contradiction, lineage and decision-use are all bilateral;
descent is not, so an attacker can make its own memory look like a victim of
an honest one. `impact()` never quarantines, so the damage is to an analyst's
reading rather than to the field — but a report an attacker can shape is
weaker evidence than its seal suggests.

### Recommendation (not applied)

Either make descent bilateral (the cited decision's record names the memories
claimed to descend from it, checked in B8), or grade it: a DERIVED edge whose
declaring actor is not the decision's actor is a weaker claim and should say
so. The second is cheaper and preserves the honest use.

## R3-05 — Existence and status of withheld memories is un-gated

**Severity:** Low · **Level:** CONFIRMED BY INDUCTION · **Status:** reported

### Code facts and induction

Three paths confirm a withheld memory exists, to a caller that cannot see it:

```text
receipt.excluded_custody              1        (any caller, by design)
exclusion_effect(excluded=['m-secret']) succeeds, so the id is real
claims.standing().withheld_evidence   (('m-secret', 'QUARANTINED'),)
```

`_require_known` and `link_evidence` both distinguish "unknown memory" from a
known one, which turns either into an oracle over arbitrary ids.

### Boundary

No content is disclosed by any of these; R3-01 was the content path and is
fixed. `excluded_custody` is a deliberate transparency choice — *what was
withheld and why is a number, not a mystery* — and removing it would trade a
real property for a weak one. The finding is that the same transparency, plus
error messages that distinguish absence from denial, composes into id
enumeration for an actor with a narrow grant.

### Recommendation (not applied)

Accept and document, or make the not-found and not-permitted paths
indistinguishable in the claim and counterfactual APIs. The second costs
diagnostic quality, which in a forensic tool is not obviously the right trade —
which is why this is a boundary to state rather than a bug to fix by reflex.

## R3-06 — A6 is read-then-write; SQLite hides it

**Severity:** none on SQLite · **Level:** FALSIFIED (SQLite) / CONFIRMED (portability)

### Hypothesis

`revoke()` calls `_actors_holding_grant(skip=…)` and then appends. Two
concurrent revokes, each skipping a different holder, would both pass their
check and together leave the field with no GRANT — A6 defeated, exactly the
Round 2 H4 (supersede TOCTOU) pattern in code written after it.

### Induction

Two deferred transactions on one database file, checks interleaved before
either writes:

```text
holders before:                 ['a', 'root']
writer1 A6 pre-check passes:    True
writer2 A6 pre-check passes:    True
writer2 blocked by the engine:  OperationalError: database is locked
holders after:                  ['a']
VERDICT: field still governable
```

Both pre-checks pass, which is the defect. SQLite's single-writer lock refuses
the second transaction, which is why it is not exploitable **here**.

### Boundary

The hypothesis is **falsified for the SQLite Phase 1 deployment** and
**confirmed as a portability defect**. `ARCHITECTURE.md` states the schema is
written to port to CockroachDB with mechanical changes; under snapshot
isolation both transactions would commit and A6 would be an unenforced comment.
The same applies to `bootstrap_root`'s `COUNT` — which R3-02's `ledger_root`
constraint now closes structurally, and which is the pattern the rest should
follow.

### Recommendation (not applied)

Port A6 to a constraint or an atomic conditional write before the CockroachDB
port, not during it. Round 2's H4 fix — re-asserting the precondition inside
the write, with `rowcount` as the verdict — is the pattern already in this
codebase.

## Discarded vectors and harness corrections

| Vector | Result | Why |
|---|---|---|
| Force a claim's state by flooding contradicting evidence | FALSIFIED | `standing()` computes no verdict from counts; state moves only by adjudication. Evidence pollution degrades the report (folded into R3-03), not the state. |
| Cite a counterfactual receipt in a decision to launder a simulation | FALSIFIED | Refused at write and again in B8; the receipt declares its own world. |
| Grant oneself COUNTERFACTUAL after the fix | FALSIFIED | A3 — an issuer cannot confer what it does not hold, re-derived offline in B7. |
| Use a quarantined actor's COUNTERFACTUAL grant | FALSIFIED | A5 empties the capability set; the read gate uses the same `require()` path as every mutator. |
| Two concurrent `bootstrap_root` calls | FALSIFIED after the R3-02 fix | The `ledger_root` singleton makes the second a constraint violation. Before the fix this was the route to the two-root state. |
| Sequential double-revoke by one actor in one transaction | FALSIFIED | The second check sees the first write; A6 holds. Only concurrency defeats it (R3-06). |

## What this round says about the previous one

Round 2 found that *audited* does not imply *authorized*, and the answer was an
authority ledger. Round 3's two confirmed vulnerabilities are both consequences
of building it:

- R3-01 exists because the counterfactual layer needed to see past the custody
  gate, and a gate with a documented bypass is a gate with a bypass.
- R3-02 exists because B7 got a new global invariant ("exactly one root") while
  the export kept a local seeding rule, and the two stopped agreeing.

Neither is a flaw in the idea. Both are the ordinary cost of new surface, and
the useful generalisation is narrower than "audit new code": **when a check
becomes global, audit what the export makes visible to it**, and **when a
read path gains a parameter, ask what it now reveals that it did not before.**

## Implications for STIGMERGY

- A capability that gates a READ needs the same ceremony as one that gates a
  write, and is easier to forget precisely because reads feel harmless.
- A verifier's check is only as strong as the evidence the exporter ships it.
  Any global invariant ("exactly one X in the whole system") needs an export
  rule written against that invariant, not against local reachability.
- Asymmetric authority — cheap to create work, expensive to clear it — is a
  denial-of-service surface in any capability system, and the taint work's
  answer generalises: grade the claim, bound the propagation, and make the
  expensive operation the one that requires authority.
- Read-then-write preconditions that SQLite serialises for free become real
  defects under MVCC. Port them as constraints before the port, not during it.
