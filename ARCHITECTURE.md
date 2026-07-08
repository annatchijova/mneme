# MNEME — Architecture

**Status**: Phase 1 core frozen; API and demo pending.
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
  CLOSED (eight types); a verifier meeting an unknown type fails, it
  does not shrug.

- **M4 — Nothing is deleted.** QUARANTINED, TAINT_FLAGGED and
  SUPERSEDED are states that preserve evidence. No foreign key declares
  ON DELETE anything: an accidental DELETE fails loudly instead of
  cascading destruction through the evidence. Rehabilitation is an
  audited event with a stated reason, never a row removal or column
  edit.

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

### Event vocabulary (closed)

| Event | Semantics | Payload contract |
|---|---|---|
| `STORED` | birth; seq 0 only, once | `content_sha256` (mandatory), `embedding_model`, optional `topic`/`claim`, optional `supersedes` (written by `supersede()`, checked bilaterally in B4) |
| `REINFORCED` | confidence raised | `confidence_before`, `confidence_after` (both replayed, B4) |
| `CONTRADICTED_BY` | conflict detected | `other_memory_id`, `topic` — written on BOTH chains |
| `SUPERSEDED_BY` | newer memory replaces this | `successor_memory_id` — written together with the successor's STORED, one transaction |
| `QUARANTINED` | direct action against this memory | — |
| `TAINT_FLAGGED` | transitive: an actor in this chain was quarantined | `sweep_id` (ties evidence to its sweep, B5) |
| `REHABILITATED` | audited reversal of TAINT_FLAGGED | `from_status` |
| `STATE_CHANGED` | field-state transition | `from`, `to` (replayed, B4) |

Contradictions are recorded on *both* chains because a contradiction is
a fact about both parties' history; recording it on one only would let
the other party's export hide it.

## Taint model

**Definition of "touched"** (deliberately broad): a memory is tainted
by actor X if any event in its custody chain names X — except
`CONTRADICTED_BY`. Not only STORED — a poisoned source that REINFORCED
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

**Determinism and sealing**: the flagged set is one SQL query with a
total ORDER BY; the sweep row seals
`sha256(canonical_json({"memory_ids": sorted_ids}))`, so "we flagged
exactly these" is a checkable claim (B5), and two replays of the same
database state produce byte-identical sweep evidence.

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
BFS seed. Every exclusion is counted in the recall receipt — a sealed
object (digest over canonical JSON) recording query hash, seed, served
ids in order, and the withheld counts by cause. Recall itself is
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

## Evidence bundles (B1–B6)

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
| B2 | every chain: genesis binding, density, linkage, recomputation, closed vocabulary, canonical payload bytes |
| B3 | the content shipped is the content born (STORED seal) |
| B4 | declared custody_status / field_state / confidence reproduce from replaying the chain — **state is derivable from evidence**; supersession lineage is bilateral when both parties travel in the bundle |
| B5 | every included sweep's flagged set matches its count and seal; a sweep not fully evidenced must be *declared* excluded — declaring away a fully-evidenced sweep, double-declaring, or referencing an undeclared sweep all fail |
| B6 | the cross-memory commitment recomputes |

The normative replay state machine is stated once, in
`mneme/bundle.py`'s header; `verify_offline.py` transcribes it.

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

## Phase 2 sketch (not designed, only reserved)

CockroachDB port (schema is written for a mechanical translation;
custody appends keep the caller-owns-transaction contract), changefeed-
driven taint sweeps, k-NN graph for corpora where linear exact scan no
longer suffices, and CRONOS integration: recall receipts as first-class
trace events, closing the loop from "the agent decided X" to "because
recall served memory Y" to "which was born, reinforced and never
contradicted, as this chain proves."
