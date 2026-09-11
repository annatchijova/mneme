# MNEME — Architecture

**Status**: Phase 1 core frozen. Phase 1.5 adds the authority,
causal, counterfactual and epistemic layers described below.
**License**: Apache 2.0

## Thesis

Agent memory today is a trust hole: retrieval-augmented systems act on
memories whose origin, reinforcement history and contradictions are
unrecorded, unverifiable, and silently editable. When a poisoning
incident happens — a compromised ingestion pipeline, a hostile
document, a rogue tool — the operator cannot answer the three questions
that matter: *what did this source touch, what did that touching do to
the rest of the field, and can we prove the cleanup itself wasn't
tampered with?*

MNEME's answer: give every memory its own tamper-evident chain of
custody, make every state transition an audited event in the same
transaction, make quarantine a deterministic sealed sweep over custody
evidence, and make the whole field exportable as a bundle that a
distrusting third party verifies offline with one short stdlib file.

Round 2's audit then found the sentence that shaped everything after it:
**an audit trail is not an authorization system.** A perfect chain of an
unauthorized act is still a perfect chain. So a mutation now carries TWO
separable proofs over different evidence — integrity provenance (the
per-memory custody chain) and authority provenance (the per-actor
capability ledger) — and neither implies the other.

Three further questions follow from taking that seriously, and the same
discipline answers all three. *Which decisions did this memory
contaminate?* — a decision record, bilaterally bound to the recall that
fed it. *What did the poison actually DO?* — a counterfactual delta
between two sealed worlds, exact because the ranking is exact. *What is
the field's belief, as opposed to its contents?* — a claim, with its own
chain, whose standing is derived from evidence and never stored.

The adaptive-field mechanics (states, links, decay, rescue) are
inherited from raven-memory and are not the contribution. The
contribution is that **every claim the field makes about itself is
checkable by someone who distrusts it**.

## Non-negotiable invariants

Any change violating one of these requires an explicit architecture
decision, not a quiet patch.

- **M1 — Memory content is immutable.** Supersession is an event
  (`SUPERSEDED_BY`, naming the successor) plus a new memory; never an
  UPDATE of `content`. The content hash sealed in the STORED (birth)
  event is asserted once and re-asserted never.

- **M2 — No committed state transition without a custody event in the
  same transaction.** Every module takes a live cursor and never
  commits; the caller's transaction carries both the state change and
  its event or neither. `custody_chain.reason` is NOT NULL — an
  unreasoned custody event cannot exist.

- **M3 — Custody chains are per-memory, append-only, seq dense from
  0.** `PRIMARY KEY (memory_id, seq)` plus
  `UNIQUE (memory_id, prev_hash)` make both duplication and forking a
  constraint violation, not a race outcome. The event vocabulary is
  CLOSED and VERSIONED; a verifier meeting a word outside the
  vocabulary of the protocol version a bundle DECLARES fails, it does
  not shrug.

- **M4 — Nothing is deleted.** QUARANTINED, TAINT_FLAGGED and
  SUPERSEDED are states that preserve evidence. No foreign key declares
  ON DELETE anything: an accidental DELETE fails loudly instead of
  cascading destruction through the evidence. Rehabilitation is an
  audited event with a stated reason, never a row removal or column
  edit.

- **A1–A6 — Authority is delegated, never invented.** Every mutation
  names the grant it acted under (A1). Authority chains are per-actor,
  append-only, genesis bound to actor_id (A2). A grantor may only grant
  what it holds (A3), so every capability traces back by checkable
  grants to one root act. Revocation is an event, never a deletion, and
  acts authorized before it stay authorized (A4). A QUARANTINED actor
  holds NO capability — a write barrier enforced in the same transaction
  as the mutation, not a note in the margin (A5). And the last grant
  conferring GRANT cannot be revoked, because a field nobody can ever
  authorize anything in is indistinguishable from a successful attack
  (A6).

- **C1–C5 — A proposition is not a document.** A claim's statement is
  immutable; revision is supersession (C1). Claim chains are per-claim
  and genesis-bound (C2). A claim's STANDING is derived from evidence
  and never stored (C3) — a persisted confidence is a number whose
  derivation has been thrown away. Claim-to-claim relations are
  bilateral (C4). And a resolution must leave its constraint satisfied,
  checked in the same transaction that writes it (C5).

- **M5 — Floats never decide.** Confidence arithmetic, promotion
  thresholds and recall ranking are exact `Fraction`; `Decimal` at
  canonical scale 10 appears only at the hash/SQL boundary via one
  quantize function with one documented rounding mode. The one
  sanctioned float crossing is embedding ingestion (a measurement, not
  a decision), quantized exactly once at the boundary.

## The custody protocol

### Hash formula

    entry_hash = sha256(
        prev_hash
        || canonical_json({
             "memory_id":  memory_id,
             "seq":        seq,
             "event_type": event_type,
             "actor_id":   actor_id,
             "reason":     reason,
             "created_at": <canonical UTC microsecond ISO 8601>,
             "payload":    payload,
           })
    )

Canonical JSON: keys sorted ascending, no insignificant whitespace,
UTF-8 unescaped, floats rejected, Decimals verified at scale 10 by
EXPONENT (two representations of one value is what canonical form
exists to prevent) and emitted as fixed-point strings. The stored
`payload_json` is byte-identical to what was hashed. Timestamps are
app-generated so the hash covers them; one formatter serves writing and
verification.

### Genesis binding

    prev_hash(seq 0) = sha256("MNEME_CUSTODY_GENESIS:" || memory_id)

STIGMERGY's genesis is a global constant because its chains are
per-node and the node_id sits inside every hashed envelope. Here the
binding moves into genesis so that verifying a single *exported* chain
requires nothing but the chain and the memory_id it claims to describe
— and grafting one memory's internally-consistent history onto another
fails at seq 0 by construction.

### Event vocabulary (closed, and VERSIONED)

Closing a vocabulary and then quietly widening it is the same lie in slow
motion, so each `custody_protocol` version names exactly the words that
existed under it. A bundle sealed under 1.0.0 is checked against 1.0.0's
eight words; one that declares 1.0.0 while carrying a 1.1.0 event is
refused rather than silently accepted by a newer verifier that happens to
know the word.

Every event at or after a field's authority genesis also carries
`grant_id` — the authority proof, checked in B7 against the actor's own
chain.

| Event | Semantics | Payload contract |
|---|---|---|
| `STORED` | birth; seq 0 only, once | `content_sha256` (mandatory), `embedding_model`, optional `topic`/`claim`, optional `supersedes` (written by `supersede()`, checked bilaterally in B4) |
| `REINFORCED` | confidence raised | `confidence_before`, `confidence_after` (both replayed, B4) |
| `CONTRADICTED_BY` | conflict detected | `other_memory_id`, `topic` — written on BOTH chains |
| `SUPERSEDED_BY` | newer memory replaces this | `successor_memory_id` — written together with the successor's STORED, one transaction |
| `QUARANTINED` | direct action against this memory | — |
| `TAINT_FLAGGED` | transitive: an actor in this chain was quarantined | `sweep_id` (ties evidence to its sweep, B5, and under taint 2.0.0 the flagged set is re-derived from evidence rather than trusted to its own seal) |
| `REHABILITATED` | audited reversal of TAINT_FLAGGED | `from_status` |
| `STATE_CHANGED` | field-state transition | `from`, `to` (replayed, B4; under replay 1.1.0 a promotion must also be arithmetically DUE) |
| `DECISION_USED_MEMORY` (1.1.0) | a decision consumed this memory; changes no state | `decision_id`, `receipt_sha256`, `decision_sha256`, `policy_version` — bilateral with the decision record, B8 |

Contradictions are recorded on *both* chains because a contradiction is
a fact about both parties' history; recording it on one only would let
the other party's export hide it.

## Taint model

**Definition of "touched"** (deliberately broad): a memory is tainted
by actor X if any event in its custody chain names X — except the
NON_INFLUENCE_EVENTS, `CONTRADICTED_BY` and `DECISION_USED_MEMORY`. Not only STORED — a poisoned source that REINFORCED
a legitimate memory inflated its confidence, and that inflation is
part of the incident. The remedy for over-flagging is audited
rehabilitation; there is no remedy for under-flagging.

The `CONTRADICTED_BY` carve-out is itself an architecture decision:
when X's memory contradicts memory V, the event lands on V's chain
authored by X — the one event type through which an actor writes its
identity onto an arbitrary victim's chain. Counting it would let an
attacker contradict every truth it wants suppressed and have the
eventual quarantine sweep silence the victims — a validated truth
silenced by an unverified claim, which the rescue rule exists to
refuse. Taint tracks *influence* (events that created a memory or
raised its standing); being attacked by X is not influence by X. X's
own contradicting memory is still flagged via its STORED event, and
V's chain keeps the CONTRADICTED_BY evidence in plain sight.

`DECISION_USED_MEMORY` joins the carve-out for the same reason, one
level up: recording that a decision consumed a memory does not influence
that memory. Without it, a quarantined agent's own decision records
would taint everything they cite — a second version of the same lever
the first carve-out already denies.

**Determinism and sealing**: the flagged set is one SQL query with a
total ORDER BY; the sweep row seals
`sha256(canonical_json({"memory_ids": sorted_ids}))`, so "we flagged
exactly these" is a checkable claim (B5), and two replays of the same
database state produce byte-identical sweep evidence. Under taint 2.0.0
B5 goes further and RE-DERIVES the flagged set from the custody events
the bundle carries — because a sweep that over-flagged or under-flagged
was internally consistent with its own seal, and passed every 1.x check.

**Quarantine has two halves.** The retrospective sweep above, and the
prospective write barrier: the quarantined actor's authority chain gains
an `ACTOR_QUARANTINED` event, from which instant its effective
capability set is empty (A5). Both land in one transaction. Flagging the
past while the present stays open is not containment — Round 2's R2-01,
confirmed by induction and closed here.

**Graded exposure, never automatic.** `influence_exposure()` spends an
exact rational budget outward from the tainted set: a RESONANT edge
conveys 1/2, anything under the floor is dropped, the depth bound is
derived from the floor. Termination is structural, cycles are harmless,
INHIBITORY edges convey nothing. The result grades memories
DIRECT_TAINT / INFLUENCE_EXPOSED / CLEAN — and INFLUENCE_EXPOSED is a
finding, not a custody status. A system that quarantined on contact
would have an incident response indistinguishable from the incident.

**Precedence**: TAINT_FLAGGED applies only to CLEAN memories; stronger
statuses (QUARANTINED, SUPERSEDED) are retained — but the event is
still written, so the chain records that the sweep *saw* the memory.
Rehabilitation reverses TAINT_FLAGGED only; direct quarantine has its
own review path, and conflating the reversals would let a bulk
false-positive cleanup silently un-quarantine directly-incriminated
memories.

**Transitive taint is advisory** (one-hop RESONANT neighbours of the
flagged set are *reported*, never auto-flagged). Rationale in
KNOWN_LIMITATIONS.md.

## Recall: the gate and the exact ranking

**The gate is a WHERE clause, not a post-filter**: candidates load with
`custody_status = 'CLEAN'`, so a tainted memory cannot even become the
BFS seed. The gate extends to the GRAPH, not only to serving: a link is
traversed during BFS only when both endpoints are CLEAN, so a non-CLEAN
memory can neither inhibit nor resonate a served one — invisible to the
agent as a *result* and as an *influence* (security audit Round 1, H2;
gating serving alone left a quarantined node on a resonant path able to
perturb a clean memory's ranking). Every exclusion is counted in the
recall receipt — a sealed object (digest over canonical JSON) recording
query hash, seed, served ids in order, and the withheld counts by
cause. Recall itself is
read-only (serving is not a state transition); reinforcement driven by
recall is the caller's explicit audited act.

**Exact ranking.** The score is raven's formula with rational
constants:

    score(m) = sim(q,m) · (state_boost · (43/50)^hop + resonant_boost)
    sim(q,m) = dot(q,m) / sqrt(|q|²·|m|²)

Every factor except the square root is a `Fraction`. Ranking does not
need the square root: for t = dot·M ≤ 0 the score clamps to exactly 0
(anti-correlation carries no ranking information an agent should act
on — raven's clamp, made exact); for t > 0 the order of t/√n is the
order of t²/n, an exact Fraction. Ties break on memory_id ascending —
a total deterministic order. Consequence, tested: ranking is invariant
under insertion order, and identical databases produce byte-identical
receipt digests. The score *reported* to humans goes through
`math.isqrt` (exact integer arithmetic) and quantizes at scale 10 —
deterministic on every platform.

Field semantics preserved from raven: INHIBITORY links silence their
targets during BFS; RESONANT links extend the frontier and accumulate
+1/2 boost per in-edge; and the rescue rule holds — a REINFORCED memory
survives inhibition, and the hit declares `inhibition_rescued=True`
rather than hiding that it was contested.

**Reinforcement** uses the closed form c' = c + α(1−c) with α = 1/4,
exact; promotion to REINFORCED occurs at confidence ≥ 3/4 exactly, with
its own STATE_CHANGED event. Reinforcing a non-CLEAN memory is refused:
it would launder taint into confidence.

## Protocol versions: the semantics a seal commits to

A hash proves bytes did not change. It says nothing about what they
MEAN, and that left exactly one lie available: change a rule tomorrow,
and every bundle sealed today silently acquires it when a new verifier
reads it. So the rule goes in the bundle. A `MNEME_BUNDLE_V2` body
declares, by version, all seven semantics its checks depend on —
custody, replay, ranking, taint, authority, receipt, claim — and a
verifier meeting a version it does not implement REFUSES, naming it,
instead of assuming.

The table is a claim about implemented behaviour. A version stays
supported only while the code to check it is actually present; an entry
without that code is the one lie the mechanism exists to prevent.

## Evidence bundles (B0–B9)

One canonical JSON file: memories (content + declared final state +
full chains), sweeps — partitioned into `sweeps` (flagged evidence
carried in full, seal checked) and `excluded_sweeps` (evidence
declared absent, for partial exports: absence stated, never implied) —
a Merkle root over chain heads (leaves sorted by memory_id; odd leaf
promoted unpaired — duplicating the last leaf admits two leaf sets
with one root, an ambiguity we refuse), and a bundle seal.

| Check | Proves |
|---|---|
| B1 | the bundle as shipped is the bundle as sealed |
| B2 | every chain: genesis binding, density, linkage, recomputation, closed vocabulary, canonical payload bytes, canonical UTC timestamps non-decreasing along seq (integrity + order is not temporal plausibility) |
| B3 | the content shipped is the content born (STORED seal) |
| B4 | declared custody_status / field_state / confidence reproduce from replaying the chain — **state is derivable from evidence**; supersession lineage is bilateral when both parties travel in the bundle |
| B5 | every included sweep's flagged set matches its count and seal; a sweep not fully evidenced must be *declared* excluded — declaring away a fully-evidenced sweep, double-declaring, or referencing an undeclared sweep all fail |
| B6 | the cross-memory commitment recomputes |

The normative replay state machine is stated once, in
`mneme/bundle.py`'s header; `verify_offline.py` transcribes it.

### B7–B9, added in Phase 1.5

**B7 — authority provenance.** Every authority chain verifies and
replays; the declared actor status reproduces from it; exactly one
self-issued root grant confers the whole vocabulary; no-amplification is
re-derived offline (every authority event's issuer held, at that
instant, the capability it required and every capability it conferred);
and every custody event at or after the declared authority genesis names
a grant that was live for its actor and conferred the right capability.
Events before the genesis — and every event in a ledgerless field — are
UNAUTHORIZED BY DECLARATION: counted, named on a passing verdict, never
passed as authorized.

**B8 — causal provenance.** Receipts recompute from their own columns
under the bundle's declared ranking semantics. Every decision re-derives
its seal, cites a non-counterfactual receipt carried here, and claims
only memories that recall actually SERVED. Included decisions are
bilateral — each used memory's chain names the decision back — and
excluded ones must be genuinely partial.

**B9 — epistemic provenance.** Claim chains verify and replay, declared
states reproduce, statements hash to what their assertions sealed,
relations are bilateral, set membership is re-derived from the member
chains, and a declared constraint status is recomputed from the carried
claims and must agree.

## The two-verifier decision

`verify_offline.py` duplicates verification logic that also lives in
the package. This is a cost paid deliberately for a property valued
more: an auditor must be able to read ONE short stdlib-only file and
convince themselves of what "verified" means, with no import graph to
chase and nothing to install. The two implementations are held together
by the agreement section of `tests/test_bundle_pure.py`, which runs
both against the same honest and tampered bundles and demands identical
verdicts with the same B-codes. A protocol change updates three places
or the tests scream. That is the design, not an accident awaiting
refactoring.

## Failure philosophy

Inherited unchanged: refuse loudly at the boundary with our words
before SQL objects with its own; name leftover work instead of hiding
it; a limitation named is a decision, a limitation hidden is a bug
waiting for a better moment. Where behaviour emerged from tests rather
than intent (the original partial-bundle B5 failure), it was examined,
judged correct, promoted to documented behaviour — and later replaced
by design (the `excluded_sweeps` declaration), the full arc a
limitation is supposed to travel.

## Semantic mutation testing

Line coverage says which code ran; operator mutation says which
arithmetic a test would notice. Neither asks the question this system
lives on: if someone reimplemented MNEME and got a RULE wrong, would the
evidence still verify?

`tests/test_semantic_mutants.py` patches the semantics, lets the patched
code produce real evidence, and asks whether anything refuses it. A
survivor is acceptable only when declared with the boundary it
demonstrates; an undeclared survivor fails the suite. The two declared
survivors are the embedding boundary and a coherently fabricated field —
both of which were prose in KNOWN_LIMITATIONS and are now executable.

Writing it produced `replay_protocol` 1.1.0 and `taint_protocol` 2.0.0.
That is the argument for keeping it.

## Phase 2 sketch (not designed, only reserved)

CockroachDB port (schema is written for a mechanical translation;
custody appends keep the caller-owns-transaction contract), changefeed-
driven taint sweeps, k-NN graph for corpora where linear exact scan no
longer suffices, and CRONOS integration: recall receipts as first-class
trace events, closing the loop from "the agent decided X" to "because
recall served memory Y" to "which was born, reinforced and never
contradicted, as this chain proves."
