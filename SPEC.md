# MNEME Protocol Specification

**Version:** draft-1, describing the protocol versions in the table of §11.
**Status:** normative for the checks it states; see §13 for what it
deliberately leaves open.

---

## 0. What this document is, and why it exists

MNEME is a forensic memory substrate. It hash-chains what happened to a
memory, who was allowed to cause it, and which decisions consumed it, so
that an incident can be reconstructed offline from evidence rather than
from trust in the system that produced it.

Until now the protocol was the code. Two implementations existed — the
package and `verify_offline.py` — and they were held together by a test
that demands identical verdicts. That test is a good instrument and it
has one blind spot, stated plainly in this project's own audit
documents: **the same author wrote both.** A disagreement between them
would be found; an error they share would not.

This document exists so that someone who has never read the Python can
write a third implementation and disagree. When that happens, the
disagreement localises here: code cannot be ambiguous, only wrong, so
every ambiguity in MNEME lives in the gap between what the code does and
what anyone believed it did. Writing that belief down is the only way to
put it where it can be attacked.

### 0.1 Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, MAY are to be
interpreted as in RFC 2119.

A **conforming verifier** implements §§1–10 and refuses per §11. A
**conforming writer** produces evidence a conforming verifier accepts.
An implementation MAY be one or both.

### 0.2 How to prove conformance

`conformance/` contains a reference field expressed as an ordered
sequence of operations, together with every digest that field produces.
An implementation conforms to a protocol version when it reproduces
those digests byte-for-byte from that sequence. The vectors are the
arbiter of the bytes; this document is the arbiter of the rules. Where
they disagree, that disagreement is a defect in this project and MUST be
reported rather than resolved by a reader's judgement.

### 0.3 The one thing hashing does not buy

A MNEME bundle proves that a history was not edited after the fact. It
does not prove the history is true. An adversary who controls every
write can emit a monotonic, canonical, internally consistent field that
verifies perfectly and never happened. Binding time and identity to
something outside the field — an operator key, a notarised ceremony, an
external timestamp authority — is a deployment decision this
specification does not make. Every guarantee below is conditional on
that boundary being understood.

---

## 1. Foundations

Everything in MNEME that participates in a hash passes through §1.1
first. Two writers hashing "the same" object MUST produce the same
bytes, or chain of custody is fiction.

### 1.1 Canonical JSON

A canonical serialization of an object is produced as follows.

1. The top-level value MUST be a JSON object. A non-object at the top
   level MUST be refused.
2. Object keys MUST be strings. A non-string key MUST be refused.
3. Keys MUST be sorted in ascending order by Unicode code point, at
   every level.
4. There MUST be no insignificant whitespace. The separator between a
   key and its value is `:`; between members, `,`.
5. Non-ASCII characters MUST be emitted as UTF-8, not as `\uXXXX`
   escapes.
6. `NaN`, `Infinity` and `-Infinity` MUST NOT appear and MUST be
   refused.
7. The output is a UTF-8 byte string. It is this byte string that is
   hashed and, where the protocol says so, also the byte string that is
   stored.

Permitted value types, and their canonical forms:

| Type | Canonical form |
|---|---|
| string | JSON string, UTF-8 |
| integer | JSON number, no exponent, no fraction |
| boolean | `true` / `false` |
| null | `null` |
| array | JSON array, element order preserved |
| object | JSON object, keys sorted |
| exact decimal | see §1.2 — emitted as a **JSON string** |

**Floating-point numbers MUST be refused.** Not rounded, not serialized
carefully — refused, as a type error, at serialization time. A protocol
whose canonical form depends on a binary64 rounding mode is not a
canonical form.

Date and time values MUST be refused as types; timestamps travel as
strings in the form of §1.4.

### 1.2 Exact numbers

`CANONICAL_SCALE` is **10**. `CANONICAL_ROUNDING` is **round-half-even**.

Any value that participates in a hash and is not an integer MUST be an
exact decimal at exactly that scale, and MUST be serialized as a
**fixed-point string** with exactly 10 fractional digits — never in
scientific notation, which is a second representation of one value.

A decimal whose scale is not exactly 10 MUST be refused at serialization
time. Verification checks the *exponent*, not numeric equality:
`0.5` and `0.5000000000` are equal as numbers and are two
representations, and two representations of one value is precisely what
a canonical form exists to prevent.

Conversion from an exact rational to canonical decimal happens exactly
once per value, explicitly, with the rounding mode above. Implementations
MUST compute in exact rational arithmetic and quantize at the boundary;
they MUST NOT compute in floating point and quantize afterwards. This is
invariant **M5**: floats never decide.

Booleans MUST NOT be accepted as quantizable numbers (in many languages
a boolean is an integer subtype; the asymmetry with §1.1, which *does*
permit booleans as payload content, is deliberate — `{"root": true}` is
a legitimate flag, `quantize(true)` is a category error).

### 1.3 Identifiers

An identifier is a string matching:

```
^[a-zA-Z0-9_\-.:]{1,64}$
```

Identifiers participate in genesis hashes and Merkle leaf derivations. A
permissive charset is an ambiguity budget this protocol refuses to
spend. There is **one** identifier rule; every chain, every actor,
every claim and every decision uses it. Two subsystems that disagree
about what an identifier is will eventually disagree about whether two
identifiers are the same.

### 1.4 Timestamps

A protocol timestamp is a string matching:

```
^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$
```

UTC, microsecond precision, explicit `+00:00` offset, fixed width.

The fixed width is load-bearing: for this form and only this form, a
lexicographic comparison of two timestamps equals a chronological one.
An offset such as `+05:00` would make ordering a lie, so it MUST be
refused — at write **and** at verification. A discipline enforced only
at write is a discipline that is trusted rather than checked.

Timestamps are generated by the application and included in the hashed
envelope. They MUST NOT be left to a storage-layer default: the hash
must cover the value, and to cover it the value must exist before the
write.

**What a timestamp is evidence of.** It is evidence of a declared
instant, and of ordering *within a chain* (§2.5). It is not evidence of
when something actually happened. See §13.

---

## 2. Chains

MNEME hash-chains three kinds of subject. All three share one shape.

| Kind | Subject | Genesis prefix | Subject key | Actor key | Birth event |
|---|---|---|---|---|---|
| custody | a memory | `MNEME_CUSTODY_GENESIS:` | `memory_id` | `actor_id` | `STORED` |
| authority | an actor | `MNEME_AUTHORITY_GENESIS:` | `subject_id` | `issuer_id` | `ACTOR_REGISTERED` |
| claim | a proposition | `MNEME_CLAIM_GENESIS:` | `claim_id` | `actor_id` | `CLAIM_ASSERTED` |

The prefixes are ASCII bytes, including the trailing colon, with no
separator before the subject id.

### 2.1 Genesis

For a chain over subject `S` of kind `K`:

```
genesis(K, S) = SHA-256( prefix(K) || utf8(S) )        -> 64 lowercase hex
```

This value is the `prev_hash` of the entry at `seq` 0.

Binding the subject id into genesis is what makes **grafting**
structurally impossible rather than merely detectable: the history of
memory A cannot be presented as the history of memory B even if every
subsequent entry is internally consistent, because the graft fails at
seq 0. The three distinct prefixes extend the same property across
kinds: an authority chain cannot be presented as a claim chain.

### 2.2 The entry envelope

Each entry has these fields:

- the subject id, under the kind's subject key
- `seq` — integer, dense from 0
- `event_type` — a member of the kind's closed vocabulary
- the actor id, under the kind's actor key
- `reason` — a non-empty string
- `created_at` — a timestamp per §1.4
- `payload` — an object
- `prev_hash` — 64 lowercase hex
- `entry_hash` — 64 lowercase hex

The entry hash is:

```
entry_hash = SHA-256(
    ascii(prev_hash)
    || canonical_json({
         <subject_key>: <subject_id>,
         "seq":         <seq>,
         "event_type":  <event_type>,
         <actor_key>:   <actor_id>,
         "reason":      <reason>,
         "created_at":  <created_at>,
         "payload":     <payload>
       })
)
```

`prev_hash` is hashed as its 64 ASCII hex characters, **not** as 32
decoded bytes, and it is *prepended to* the canonical JSON rather than
included in it.

The stored `payload_json` MUST be `canonical_json(payload)` — the
payload serialized **separately** from the envelope. Storing the
separately-canonicalized payload is what lets a verifier re-embed the
stored bytes into the envelope and recompute the hash exactly. Stored
bytes and hashed bytes cannot drift, because they are produced by one
operation.

### 2.3 Append rules

To append an event to a chain:

1. The event type MUST be in the kind's closed vocabulary for the
   protocol version in force. An unknown type MUST be refused.
2. `reason` MUST be a non-empty, non-whitespace string. An unreasoned
   event MUST NOT exist: "why" travels with "what" or neither travels.
3. If the chain has no entries, the event MUST be the kind's birth
   event, and it takes `seq` 0 with `prev_hash = genesis(K, S)`. A
   non-birth event on an empty chain MUST be refused: a history begins
   at birth, not at the first incident.
4. If the chain has entries, the event MUST NOT be the birth event, and
   it takes `seq = head.seq + 1` with `prev_hash = head.entry_hash`.
5. Birth-payload rules are per-kind (§3.1, §4.4, §5.1) and are evaluated
   only for the event that actually lands at seq 0. A second birth event
   MUST be refused *as a second birth*, not as a malformed one.
6. The append MUST occur in the same transaction as whatever state
   change the event describes (invariant **M2**). An implementation
   whose chain write and state write can land separately does not
   implement this protocol.

### 2.4 Structural verification

Given a subject id and its entries in ascending `seq` order, a verifier
MUST check, and MUST stop at the first failure:

1. the entry list is non-empty;
2. `seq` is dense from 0;
3. every `event_type` is in the vocabulary of the version being
   verified — **the version the evidence declares**, not the verifier's
   own (§11);
4. the entry at index 0 is the birth event, and no later entry is;
5. `rows[0].prev_hash == genesis(K, S)`;
6. `rows[i].prev_hash == rows[i-1].entry_hash`;
7. `payload_json` parses as JSON and its canonical re-serialization
   equals the stored bytes exactly;
8. `entry_hash` recomputes from the entry's own fields per §2.2;
9. `created_at` matches §1.4 and is **non-decreasing** along `seq`.

Check 9 is not redundant with the hash chain. Integrity and insertion
order are not enough: a hash-valid chain whose seq-1 event is timestamped
before its seq-0 birth is a history that cannot have happened, and
evidence that cannot have happened is not evidence.

Structural verification says nothing about what the events **mean**.
That is replay, and replay is where the three kinds stop being the same
thing (§3.2, §4.5, §5.3).

### 2.5 What a chain proves and does not prove

A verifying chain proves: these events, in this order, with these
payloads and these declared timestamps, have not been altered since they
were written, and belong to this subject and no other.

It does not prove that the declared timestamps are true, that the actor
named is the party that acted, or that the content is accurate. Those
bind to things outside the field (§13).

---

## 3. Custody — what happened to a memory

Governed by `custody_protocol` (the envelope and vocabulary) and
`replay_protocol` (the state machine).

### 3.1 Vocabulary

`custody_protocol` **1.0.0** closes the vocabulary at eight words:

| Event | Meaning |
|---|---|
| `STORED` | birth; payload MUST carry `content_sha256` |
| `REINFORCED` | confidence raised |
| `CONTRADICTED_BY` | another memory conflicts; payload names it |
| `SUPERSEDED_BY` | a newer memory replaces this one; payload names it |
| `QUARANTINED` | direct action against this memory |
| `TAINT_FLAGGED` | transitive: an actor in this chain was quarantined |
| `REHABILITATED` | audited reversal of a taint flag |
| `STATE_CHANGED` | field-state transition |

`custody_protocol` **1.1.0** adds exactly one word:

| Event | Meaning |
|---|---|
| `DECISION_USED_MEMORY` | a decision consumed this memory (§7) |

`DECISION_USED_MEMORY` replays to **no state change** — no status, no
field state, no confidence. That is why the addition is MINOR: every
1.0.0 check still holds, on the same events, with the same outcomes.

The vocabulary is closed **on purpose**. A verifier that meets an unknown
event type MUST fail, not shrug. An open vocabulary is where unaudited
semantics are smuggled in.

**Birth rule.** A `STORED` payload MUST carry `content_sha256`: 64
lowercase hex, the SHA-256 of the UTF-8 bytes of the memory's content. A
birth event that does not seal the content seals nothing.

### 3.2 Replay (`replay_protocol`)

Replay interprets a *structurally verified* chain. Initial state:

- `custody_status` = `CLEAN`
- `field_state` = `NEUTRAL`
- `confidence` = `0.5000000000`

Transitions:

| Event | Effect |
|---|---|
| `QUARANTINED` | `custody_status` := `QUARANTINED` |
| `SUPERSEDED_BY` | `custody_status` := `SUPERSEDED` |
| `TAINT_FLAGGED` | `custody_status` := `TAINT_FLAGGED` **only if currently `CLEAN`** |
| `REHABILITATED` | `custody_status` := `CLEAN`; an error if the prior status was not `TAINT_FLAGGED` |
| `STATE_CHANGED` | `field_state` := `payload.to`; `payload.from` MUST equal the current field state; `to` MUST be one of `REINFORCED`, `NEUTRAL`, `FORGOTTEN` |
| `REINFORCED` | `payload.confidence_before` MUST equal the current confidence; `confidence` := `payload.confidence_after` |
| `CONTRADICTED_BY` | no state change |
| `DECISION_USED_MEMORY` | no state change |

On `TAINT_FLAGGED` against a stronger status, the event still exists and
the chain still records that the sweep saw the memory; only the status is
retained. A replay that moved state on `CONTRADICTED_BY` or
`DECISION_USED_MEMORY` would be inventing history.

**`replay_protocol` 1.1.0 adds one rule: promotion must be
arithmetically due.**

`PROMOTION_THRESHOLD` is the exact rational **3/4**.

- A `STATE_CHANGED` from `NEUTRAL` to `REINFORCED` is valid only when
  the replayed confidence has reached the threshold.
- A `REINFORCED` that carries confidence to or past the threshold while
  the field state is `NEUTRAL` MUST be followed by that promotion; a
  chain that ends with a promotion still owed is an error.

Under 1.0.0 replay only asked whether a *declared* state was derivable
from the events. A writer that quietly narrowed `>=` to `>` satisfied
that perfectly — it simply emitted fewer events, and every one of them
was consistent. This rule exists because that mutant survived every
check MNEME had.

1.0.0 remains implemented and supported. A bundle sealed under it is
checked under it, promotion rule and all. Applying a rule its sealer
never agreed to is the retroactive-semantics problem this protocol
refuses (§11).

### 3.3 Memory invariants

- **M1** Memory content is immutable. Supersession is an event, never an
  edit. Any "update" is a new memory whose `STORED` payload names its
  predecessor under `supersedes`.
- **M2** No committed state transition on a memory may exist without a
  custody event in the same transaction.
- **M3** Custody chains are append-only and per-memory; `seq` is dense
  from 0.
- **M4** Nothing is deleted. `QUARANTINED`, `TAINT_FLAGGED` and
  `SUPERSEDED` are states; rehabilitation is an audited event, not a row
  removal.
- **M5** Floats never decide (§1.2).

### 3.4 Bilateral relations

Two relations MUST be recorded on **both** chains or they do not exist:

- **Contradiction.** A `CONTRADICTED_BY` on A naming B requires one on B
  naming A.
- **Supersession lineage.** A `STORED` payload naming `supersedes: X`
  requires a `SUPERSEDED_BY` event on X's chain naming this memory back.

Bilaterality is what stops one party from shaping the record alone. A
third relation, **descent** (`derived_from_decision`, §7.3), is
unilateral, and that asymmetry is a stated limitation rather than an
oversight — see §13.

---

## 4. Authority — who was allowed

Governed by `authority_protocol`.

Custody says *what happened*. Authority says *who was allowed to cause
it*. A mutation carries two separable proofs over different evidence:
**integrity provenance** (the custody chain) and **authority provenance**
(the actor's chain). Neither implies the other: a chain can be perfect
and the act unauthorized; a grant can be valid and the chain forged.

This is a capability model, not a role model. "X is an admin" is
unfalsifiable in a bundle. "Grant `g-4f2` conferred `REHABILITATE` on
`analyst-anna` at 14:02:11, was issued by `root-operator` who held both
`REHABILITATE` and `GRANT`, and had not been revoked when the
`REHABILITATED` event was written at 14:03:17" is an arithmetic
statement an auditor can check offline with a hash function.
Capabilities are what fits in an evidence bundle.

### 4.1 Capabilities

The closed set, twelve words:

`STORE`, `REINFORCE`, `SUPERSEDE`, `QUARANTINE_ACTOR`,
`QUARANTINE_MEMORY`, `REHABILITATE`, `GRANT`, `REVOKE`, `DECIDE`,
`ASSERT`, `ADJUDICATE`, `COUNTERFACTUAL`.

Closed for the same reason the event vocabulary is closed: an open set is
where unaudited power is minted.

`ASSERT` and `ADJUDICATE` are separate from `STORE` and from each other
because the acts differ in kind — storing a document, asserting that a
proposition is true, and ruling between competing hypotheses are three
different authorities. A model that cannot tell them apart is a role
system wearing capability vocabulary.

`COUNTERFACTUAL` is the one capability that governs a **read** (§6.4).

### 4.2 Authority events

| Event | Payload | Requires of its issuer |
|---|---|---|
| `ACTOR_REGISTERED` | `display_name`, `kind`, optional `root` | `GRANT` |
| `GRANTED` | `grant_id`, `capabilities`, optional `root` | `GRANT` |
| `REVOKED` | `grant_id` | `REVOKE` |
| `ACTOR_QUARANTINED` | — | `QUARANTINE_ACTOR` |
| `ACTOR_REINSTATED` | — | `QUARANTINE_ACTOR` |

The ledger governs itself by the same rule it governs memories by: an
authority event is an act, and every act needs a grant behind it.

### 4.3 What each custody event costs

| Custody event | Required capability |
|---|---|
| `STORED` | `STORE` — but `SUPERSEDE` when the payload names `supersedes` |
| `REINFORCED` | `REINFORCE` |
| `CONTRADICTED_BY` | `STORE` |
| `SUPERSEDED_BY` | `SUPERSEDE` |
| `QUARANTINED` | `QUARANTINE_MEMORY` |
| `TAINT_FLAGGED` | `QUARANTINE_ACTOR` |
| `REHABILITATED` | `REHABILITATE` |
| `STATE_CHANGED` | `REINFORCE` |
| `DECISION_USED_MEMORY` | `DECIDE` |

The `STORED` special case is not an optimization. A `STORED` whose
payload names a predecessor is the successor half of a supersession, so
it costs `SUPERSEDE`. Without that rule an actor holding `STORE` alone
could retire any memory in the field by storing over it.

`DECISION_USED_MEMORY` costs `DECIDE` and nothing else. It changes no
memory state, but it is a claim about causation that an incident will
later be reconstructed from, so an actor that may merely read MUST NOT
be able to write one.

Changing any row in this table changes what old bundles are checked
against, and therefore changes `authority_protocol`.

### 4.4 The bootstrap

Authority has to start somewhere, and the first grant cannot itself be
authorized. The root bootstrap is that act: two self-issued events
(`ACTOR_REGISTERED` then `GRANTED`, both with `root: true`, the grant
conferring the entire capability vocabulary) on an empty ledger.

It MUST be refused if **any** authority chain already exists, so it can
happen exactly once per field, and the whole ledger hangs from it.

What this buys: the root act is a single, named, timestamped,
hash-chained event an auditor can point at. What it does not buy: proof
that the right party performed it. Whoever bootstraps an empty field is
its root. Binding that to an external identity is a deployment concern,
not a protocol one — and hiding this would be the one dishonest thing
this specification could do.

### 4.5 Replay and effective capability

An actor's capabilities are **replayed from its chain, never read from a
column**. Any status column is a cache a verifier re-derives; a
hand-edited status is self-revealing.

At an instant `t`, an actor's effective capability set is:

- empty, if the actor is under quarantine at `t` (invariant A5);
- otherwise the union of the capabilities of every grant issued at or
  before `t` and not revoked at or before `t`.

**An authority event is authorized by the ledger state IMMEDIATELY
BEFORE it, never by the state it creates.** This rule is not a detail.
Judging an event by the state it produces makes an ordinary key rotation
— an actor revoking its own grant — unverifiable: at the event's instant
the grant that authorized it is already dead. A writer and a verifier
that disagree on this produce fields that write successfully and cannot
be verified.

### 4.6 Authority invariants

- **A1** Every custody event sealed under an authority ledger names the
  grant it acted under. Both proofs travel or neither does.
- **A2** Authority chains are per-actor, append-only, hash-linked,
  genesis-bound to the actor id, `seq` dense from 0.
- **A3** **No amplification.** A grantor MAY only grant capabilities it
  itself holds. This is the invariant that makes the ledger a *tree*
  rooted at one auditable act rather than a graph where authority appears
  from nowhere. Its consequence: every capability any actor holds traces
  back, by a path of checkable grants, to the root bootstrap.
- **A4** Revocation is an event, never a deletion. A revoked grant stays
  on the chain with the instant it died.
- **A5** A quarantined actor's effective capability set is empty at every
  instant inside the quarantine interval. Quarantine is a **write
  barrier**, not merely a sweep trigger.
- **A6** The field always retains at least one active actor holding
  `GRANT`. **Every** path that could reduce that set MUST be guarded —
  revoking the last `GRANT`-conferring grant *and* quarantining its last
  holder. Without both, two individually legitimate acts (quarantine the
  only `GRANT` holder, then let the responder rotate itself off) leave a
  field that can never grant, register or reinstate again.

**A6 MUST be a constraint, not a read.** A check-then-write over the
current holder set is a race: both pre-checks pass concurrently, and
whether the field survives depends on the storage engine's isolation
level rather than on the protocol. Implementations MUST enforce A6 with
an atomic conditional write whose failure is observable — a counter under
a check constraint with the guard inside the update, or equivalent.

**A6 is a write-time invariant and evidence cannot carry it.** A bricked
field produces a bundle that verifies, correctly, because the chains are
honest evidence of a bricked field. A6 is therefore testable only by
refusal at write, never by verification. This is stated so that no
implementer concludes from a passing bundle that A6 held.

---

## 5. Claims — propositions as first-class objects

Governed by `claim_protocol`.

A memory is a document. A claim is a proposition *about* the world,
whose provenance is independent of anyone's confidence in it.

### 5.1 Vocabulary

| Event | Meaning |
|---|---|
| `CLAIM_ASSERTED` | birth; payload MUST carry `statement_sha256` |
| `EVIDENCE_LINKED` | a memory supports or contradicts this claim |
| `RELATED_TO` | one direction of a claim-to-claim relation |
| `SET_MEMBERSHIP` | this claim joined a mutually-constrained set |
| `CLAIM_VALIDATED` | adjudicated: it holds |
| `CLAIM_REFUTED` | adjudicated: it does not |
| `CLAIM_WITHDRAWN` | the asserter took it back |
| `CLAIM_SUPERSEDED` | a successor claim replaces it |

Evidence stances: `SUPPORTS`, `CONTRADICTS`.
Claim-to-claim relations: `SUPPORTS`, `CONTRADICTS`, `SUPERSEDES`,
`DERIVED_FROM`.
Set constraints: `AT_MOST_ONE`, `EXACTLY_ONE`, `INCOMPATIBLE`.
Claim states: `ASSERTED`, `VALIDATED`, `REFUTED`, `WITHDRAWN`,
`SUPERSEDED`.

### 5.2 What each claim event costs

| Event | Capability |
|---|---|
| `CLAIM_ASSERTED`, `EVIDENCE_LINKED`, `RELATED_TO`, `CLAIM_WITHDRAWN`, `CLAIM_SUPERSEDED` | `ASSERT` |
| `CLAIM_VALIDATED`, `CLAIM_REFUTED` | `ADJUDICATE` |
| `SET_MEMBERSHIP` | see C6 below |

### 5.3 Constraint sets

A set names members and a constraint type, and is evaluated from the
members' **replayed** states. "Holds" means `VALIDATED` — adjudicated to
hold. `ASSERTED` means *under consideration*, not believed.

Let `H` be the members currently `VALIDATED` and `O` the members
currently `ASSERTED`, over `n` members.

| Constraint | `VIOLATED` when | `SATISFIED` when | otherwise |
|---|---|---|---|
| `AT_MOST_ONE` | `\|H\| > 1` | `\|H\| <= 1` and `O` empty | `UNDETERMINED` |
| `EXACTLY_ONE` | `\|H\| > 1`, or `\|H\| = 0` and `O` empty | `\|H\| = 1` and `O` empty | `UNDETERMINED` |
| `INCOMPATIBLE` | `\|H\| = n` | `\|H\| < n` and `O` empty | `UNDETERMINED` |

A set with open hypotheses is `UNDETERMINED`, never satisfied by
default. A system that read "nobody has objected yet" as "true" would be
manufacturing agreement.

### 5.4 Claim invariants

- **C1** A claim's statement is immutable. Revision is supersession, an
  event, never an edit — the rule M1 holds memories to.
- **C2** Claim chains are per-claim, append-only, genesis-bound to the
  claim id, `seq` dense from 0.
- **C3** A claim's **standing is derived from evidence and never
  stored**.
- **C4** Claim-to-claim relations are bilateral: both chains record them,
  or the relation does not exist.
- **C5** A resolution MUST leave its set satisfied, checked in the same
  transaction that writes it.
- **C6** **Re-opening a settled question is an adjudication-level act.**
  Declaring a constraint over open hypotheses costs `ASSERT`; declaring
  one that drags an already-`VALIDATED` claim back into dispute costs
  `ADJUDICATE`.

C6 exists because without it, an actor holding only `ASSERT` could
re-open any adjudicated question by binding it into a new constraint —
an asymmetric denial of epistemics, cheap to mount and expensive to
settle. The capability required for a `SET_MEMBERSHIP` event MUST be
computed from the members' states **strictly before** the event, by one
rule shared between the write path and the verifier. A writer that
prices the act by live state while a verifier prices it by a fixed table
produces honest fields that fail verification.

---

## 6. Recall — what an agent was shown

Governed by `ranking_protocol` (the scoring) and `receipt_protocol` (the
receipt).

### 6.1 The custody gate

Only memories whose replayed `custody_status` is `CLEAN` are servable.

The gate MUST be applied as a **restriction on the candidate set, not as
a post-filter on results**, and it MUST extend to graph traversal: links
are followed only between `CLEAN` endpoints. A non-`CLEAN` memory
therefore exerts **zero** influence on the ranking of the memories that
are served — it cannot be a traversal seed and cannot be an
intermediary. A gate applied to serving but not to influence lets a
quarantined memory reshape what the agent sees while never appearing in
the results.

Memories whose `field_state` is `FORGOTTEN` do not score.

### 6.2 Scoring (`ranking_protocol` 1.0.0)

All arithmetic is exact rational.

```
STATE_BOOST          REINFORCED = 3/2, NEUTRAL = 1, FORGOTTEN = 0
DECAY_BASE           43/50            (exactly 0.86)
RESONANT_BOOST_STEP  1/2              (per resonant in-edge)
DEFAULT_HOPS         2
```

1. The seed is the exact-similarity argmax, compared by squared value,
   sign-aware, ties broken on `memory_id` ascending.
2. Breadth-first traversal from the seed: `INHIBITORY` edges silence
   their targets; `RESONANT` edges accumulate `RESONANT_BOOST_STEP` per
   in-edge and extend the frontier.
3. **The rescue rule:** a `REINFORCED` memory cannot be silenced by
   inhibition. A validated truth cannot be silenced by an unverified
   claim.
4. `multiplier = STATE_BOOST[state] · DECAY_BASE^hop + resonant_boost`,
   where `hop` is the traversal distance and an unreached memory uses a
   decay factor of 1.
5. `t = similarity · multiplier`; the ranking key is the exact rational
   `t²/n` (with `n` the candidate's squared norm), clamped to 0 when
   `t <= 0`.
6. Results sort by ranking key descending, then `memory_id` ascending.

Two recalls are comparable only under one `ranking_protocol`. A receipt
produced under other ranking semantics is not weaker evidence — it is a
category error, and a verifier MUST refuse to compare it (§9, B8).

### 6.3 Receipts (`receipt_protocol` 2.0.0)

A receipt's digest is `SHA-256(canonical_json(body))` over exactly:

```
query_sha256, seed_memory_id, served, excluded_custody,
excluded_forgotten, excluded_inhibited, top_k, hops,
ranking_protocol, custody_override, as_of
```

`receipt_protocol` 1.0.0 recorded what a recall **returned** but never
what it was **asked** — no `top_k`, no `hops`, no ranking semantics — so
it could not be replayed and could not anchor a counterfactual. Adding
those three fields changes the digest body, so a 1.0.0 receipt does not
recompute under the new rules. That is a different protocol, not an
extension of one, which is why the bump is MAJOR and why 1.0.0 is **not**
in the supported table: a verifier that claimed to check it would be
lying.

Recall is read-only. Serving is not a state transition, and it writes no
custody event. Reinforcement driven by recall results is the caller's
separate, audited act.

### 6.4 Custody override, and why widening is gated

A recall MAY run against a **hypothetical** custody state — a map from
memory id to status — applied over the real one. This is the primitive
the counterfactual analysis is built on (§8).

Three disciplines make it safe:

1. **It changes nothing.** No write, no status column touched; the
   override lives only in that call's arithmetic.
2. **The receipt says so.** The override is inside the digest body, so a
   counterfactual receipt is structurally distinguishable from a real one
   and cannot be laundered into evidence about the actual field. A
   decision MUST NOT cite one (§7.1) — no agent ever decided from a world
   that did not exist.
3. **Widening requires authority.** An override that makes servable a
   memory the base world would not serve can disclose exactly what the
   custody gate withheld. Such an override MUST require an actor holding
   `COUNTERFACTUAL`. A **narrowing** override requires nothing.

The asymmetry is the design, not an implementation shortcut: widening can
reveal what the gate withheld; narrowing can only ever show the caller
less than it could already see. So "what would quarantining these do?"
stays open to everyone, and "what would they have shown?" does not.

A field with no authority ledger is unchanged by this rule (§9, B7.6:
such a field declares its events unauthorized by declaration rather than
pretending otherwise).

Note what the gate does **not** do: the check happens and nothing is
written. MNEME does not audit reads. The refusal prevents disclosure; it
does not record the attempt.

---

## 7. Causality — recall to decision

Governed by `receipt_protocol`.

A receipt proves what an agent was **shown**. A decision record proves
what it **did** with it. Together they close the loop that lets an
incident answer: *which decisions were causally contaminated by this
memory?*

### 7.1 The decision record

A decision record binds:

- `receipt_sha256` — what the agent was shown
- `decision_sha256` — what it produced, **by hash**; MNEME never sees the
  decision artifact itself
- `policy_version` — the rules the agent was operating under
- `actor_id`, `reason`, `created_at`
- `used_memory_ids` — the memories cited

Its seal is `SHA-256(canonical_json(body))` over those fields.
`used_memory_ids` MUST be **sorted** in the sealed body: rank order is
the receipt's job, and citation order carries no fact the receipt does
not already hold, so leaving it free would admit two representations of
one claim.

A decision MUST cite a non-counterfactual receipt, and MUST claim only
memories that receipt actually served.

### 7.2 Bilaterality

Recording a decision MUST also write a `DECISION_USED_MEMORY` event on
each cited memory's custody chain, naming the decision back. Like
contradiction and lineage, neither side can hide the causal link alone.

### 7.3 Blast radius

Given a memory, an impact report grades reachable consequences:

| Level | Meaning |
|---|---|
| `DIRECT` | receipts that served it, and decisions that cited it |
| `DERIVED` | memories stored as descending from one of those decisions |
| `POSSIBLE` | memories co-served in the same receipts — contact, never established use |

The grading is the point. Indiscriminate transitive taint makes every
memory in a well-connected field a suspect, which is a denial of service
against the analyst rather than an answer.

`DERIVED` is further split by **who declared the descent**. Descent is
the one relation MNEME cannot make bilateral: a decision's record cannot
name memories that did not exist when it was sealed. So a `DERIVED` edge
whose declaring actor is not the decision's actor is a weaker claim and
MUST be reported as such (`derived_unattested`). An attacker can make its
own memory *look* like a victim of an honest one; the report must not
present that at the same strength as an attested descent.

Impact reports are advisory. They never quarantine.

---

## 8. Taint and influence

Governed by `taint_protocol`.

### 8.1 The direct sweep

Quarantining an actor flags every memory whose custody chain carries an
**influencing** event by that actor at or before the sweep instant.

`NON_INFLUENCE_EVENTS` — carved out, never flagged on:

- `CONTRADICTED_BY` — being contradicted by a bad actor is not evidence
  against you;
- `DECISION_USED_MEMORY` — recording that a decision consumed a memory
  does not influence that memory, and a quarantined agent's decision
  records must not taint what they cite.

A sweep seals its flagged set as
`SHA-256(canonical_json({"memory_ids": <sorted ids>}))`, so two replays
of one sweep produce one digest.

**`taint_protocol` 2.0.0 re-derives rather than trusts.** An included
sweep's flagged set MUST be recomputed from the custody evidence the
bundle carries, not merely checked against the sweep's own seal. Under
1.x a sweep that over-flagged or under-flagged passed every check,
because its seal was computed over whatever it chose to flag. This is a
MAJOR bump because a 1.x bundle can legitimately fail the new check.

**Transitive taint is never automatic.** Flagging is an event with an
actor and a reason, written into the chain.

### 8.2 Influence exposure

Suspicion propagates over `RESONANT` edges with an exact budget:

```
INFLUENCE_TRANSFER   1/2     a resonant edge conveys half of what reaches its source
EXPOSURE_FLOOR       1/64    below this, suspicion is noise and is dropped
MAX_INFLUENCE_DEPTH  6
```

Because transfer is `1/2` and the floor is `1/64`, no path longer than
six hops can contribute: **termination is by construction, not by a
visited set**. Cycles are harmless — a second visit carries strictly less
and eventually falls below the floor.

The report grades each memory `DIRECT_TAINT`, `INFLUENCE_EXPOSED` or
`CLEAN`, and seals itself over the exact rational parameters it used, so
a report produced under different constants is visibly a different
report.

---

## 9. Evidence bundles

A bundle is one canonical JSON file containing everything an auditor
needs, verifiable offline with nothing but a hash function.

### 9.1 Structure

```
{ "body": { ... }, "bundle_sha256": <64 hex> }
```

`bundle_sha256 = SHA-256(canonical_json(body))`.

The body carries:

| Key | Contents |
|---|---|
| `format` | `MNEME_BUNDLE_V2` |
| `protocols` | the version block (§11) |
| `created_at` | timestamp |
| `memories` | id, content, content hash, embedding hash, declared status/state/confidence, full custody chain |
| `sweeps` / `excluded_sweeps` | sweep evidence carried / declared absent |
| `heads_merkle_root` | §9.2 |
| `authority` / `authority_genesis_at` / `authority_merkle_root` | the ledger |
| `receipts` | recall receipts |
| `decisions` / `excluded_decisions` | decision records carried / declared absent |
| `claims` / `claim_sets` | the epistemic layer |
| `excluded_lineage` | lineage counterparties declared absent |

**Format V1 is deliberately unreadable by a V2 verifier.** A V1 body
sealed bytes without sealing the semantics those bytes were checked
under, which left exactly one lie available: change a rule tomorrow, and
every bundle sealed today silently acquires it. Verify a V1 bundle with a
verifier of its era.

### 9.2 The Merkle rule

Leaves are `SHA-256(utf8(f"{subject_id}:{head_entry_hash}"))`, sorted by
subject id ascending. Pairs are combined as
`SHA-256(ascii(left_hex || right_hex))`. **An odd leaf is promoted
unpaired — never duplicated.** Duplicating the last leaf, Bitcoin-style,
admits two distinct leaf sets with one root, an ambiguity this protocol
refuses. The empty root is `SHA-256(b"MNEME_EMPTY_HEADS")`.

### 9.3 The checks

A conforming verifier performs B0 through B9 and reports every failure.

**B0 — protocols.** The declared block is validated per §11 before any
other check. A bundle whose semantics this verifier cannot assert
anything about is refused here, not interpreted.

**B1 — seal.** `bundle_sha256` recomputes over the canonical body.

**B2 — chain integrity.** Every custody chain passes §2.4, against the
vocabulary of the **declared** `custody_protocol` version.

**B3 — content integrity.** `SHA-256(content)` equals the
`content_sha256` sealed in the `STORED` event, and equals the declared
value. The content shipped is the content born. Embedding provenance
records, where carried, are checked for internal consistency.

**B4 — state is derivable from evidence.** Replaying each chain through
§3.2 reproduces the declared `custody_status`, `field_state` and
`confidence`. A hand-edited status column without its corresponding
event is self-revealing. Supersession lineage is checked bilaterally when
both parties travel; when one is absent the cross-check has nothing to
compare and is skipped, and the absence must be declared in
`excluded_lineage`.

**B5 — sweep evidence.** In order:
1. no sweep id in both lists;
2. every included sweep's flagged set matches its count and hashes to
   its seal;
3. an excluded sweep MUST be genuinely partial — the bundle carries
   strictly fewer distinct flagged memories than its flagged count — so
   excluding a fully-evidenced sweep cannot dodge its seal check;
4. every sweep id referenced by a `TAINT_FLAGGED` event appears in one
   of the two lists;
5. under `taint_protocol` 2.0.0, the flagged set is re-derived per §8.1.

An excluded sweep's seal is **not** checked; its evidence lives outside
this bundle. Exclusion is a declared claim the auditor can see, not a
verified one.

**B6 — Merkle root** recomputes per §9.2.

**B7 — authority provenance.** In order:
1. every authority chain passes §2.4 and replays without contradiction;
2. the declared actor status reproduces from that replay (the authority
   analogue of B4);
3. the ledger has **exactly one** root grant, self-issued, conferring the
   whole capability vocabulary — and the exporter MUST seed its authority
   closure from *all* root subjects, since a check that cannot see a
   second root is not a check;
4. **no amplification, re-derived offline**: every non-root authority
   event names an issuer whose own chain travels in the bundle and who
   held, **immediately before** that event (§4.5), the capability the
   event required, and — for a grant — every capability it conferred;
5. every custody event at or after the declared authority genesis names
   a grant that was active for its actor at that event's instant,
   conferred the required capability (§4.3), and belonged to an actor not
   under quarantine then;
6. events **before** the declared genesis are *unauthorized by
   declaration* — counted, named on a successful verdict, never silently
   passed as authorized. A field with no ledger declares
   `authority_genesis_at: null` and every event is in this category.

The declared genesis MUST equal the earliest instant in the carried
authority evidence, so an exporter cannot raise it to excuse more events
than the ledger actually predates.

**B8 — causal provenance.** In order:
1. every receipt's digest recomputes, and its `ranking_protocol` matches
   the bundle's declaration;
2. no decision id in both lists;
3. every decision re-derives its seal, cites a **non-counterfactual**
   receipt carried here, and claims only memories that receipt served;
4. an included decision's used memories all travel here, and each one's
   chain carries a `DECISION_USED_MEMORY` naming that decision back;
5. an excluded decision MUST be genuinely partial — at least one used
   memory absent — so exclusion cannot dodge check 4;
6. every decision id referenced by a `DECISION_USED_MEMORY` appears in
   one of the two lists, and that event's memory appears in that
   decision's used list.

**B9 — epistemic provenance.** Every claim chain verifies and replays;
declared state reproduces; the shipped statement hashes to the one its
assertion sealed; claim-to-claim relations are bilateral; set membership
is re-derived from the member chains and hashes to its seal; a set's
declared status is recomputed from the carried claim states and must
agree; and every claim event at or after the authority genesis names a
grant conferring `ASSERT` or `ADJUDICATE` as the event requires (§5.2,
C6).

### 9.4 Absence stated, never implied

This is a contract, not a convention, and it runs through B4, B5, B8 and
B9. A partial export is legitimate and common. What is **not** legitimate
is a partial export that reads as complete.

So for every category where evidence can be missing, the body carries an
explicit exclusion list, and the verifier:

- refuses an item that appears in both the carried and excluded lists;
- requires an excluded item to be **genuinely partial**, so exclusion
  cannot be used to dodge a check the full evidence would have failed;
- requires every reference from carried evidence to resolve into one list
  or the other;
- **names every exclusion on a successful verdict.**

A passing verdict that buries what it could not check is worse than a
failing one, because it is believed.

---

## 10. Two implementations, on purpose

A conforming deployment SHOULD carry a second verifier that shares no
code with the first, and a test that runs both against the same valid and
tampered evidence and demands identical verdicts **and identical notes**.

This duplication is load-bearing and MUST NOT be "fixed". Its value is
demonstrable rather than theoretical: collapse the three genesis prefixes
of §2 into a single constant, and a single-implementation verifier
accepts its own field perfectly — writer and verifier share the error.
Only an independent implementation refuses.

The corollary bounds what deduplication is safe *inside* one
implementation: sharing code between a writer and its own verifier is
exactly the sharing that hides errors, while sharing code among three
chains of the same kind hides nothing that the independent verifier would
not still catch.

---

## 11. Protocol versions and refusal

A hash proves that bytes did not change. It says nothing about what
those bytes **mean**. So the meaning goes in the bundle.

### 11.1 The seven protocols

| Protocol | Governs |
|---|---|
| `custody_protocol` | the custody envelope, genesis, seq density, the closed vocabulary, canonical payload bytes, the timestamp rule |
| `replay_protocol` | the custody state machine and confidence arithmetic |
| `ranking_protocol` | recall scoring semantics and the custody gate's extension to traversal |
| `taint_protocol` | what a sweep flags, what it carves out, how it is sealed, and the influence budget |
| `authority_protocol` | the capability vocabulary, chain rules, no-amplification, and the event→capability maps |
| `receipt_protocol` | the receipt digest body and the decision record |
| `claim_protocol` | the claim chain, state machine, relation bilaterality, and set constraints |

### 11.2 Versioning discipline

- **MAJOR** — evidence sealed under the old version can no longer be
  verified by the new rules at all. The evidence means something
  different.
- **MINOR** — new checkable facts exist; everything the old version
  checked is still checked **identically**.
- **PATCH** — wording, messages, non-semantic refactors.

A MINOR bump is a promise, and it is testable: the conformance vectors of
§0.2 are how anyone holds an implementation to it.

### 11.3 Refusal

A verifier MUST refuse, loudly and by name, when:

- the `protocols` block is absent or is not an object — a bundle that
  declares no semantics commits to none;
- a protocol name is not declared — the bundle is silent about semantics
  its checks depend on;
- a declared version is not implemented by this verifier — it would be
  applying rules the sealer never agreed to;
- a name is declared that this verifier has never heard of — the bundle
  was sealed by a newer MNEME, and a verdict from an older verifier on
  newer evidence is the retroactive-semantics problem read backwards.

A verifier's supported-version table MUST be a claim about **implemented
behaviour**. A version belongs in it only when the code to check it is
actually present. An entry that claims otherwise is the one kind of lie
the table exists to prevent.

**A known defect in an old version is not grounds for removing it.**
Evidence is checked under the rules it was sealed with. Retroactively
re-judging old evidence under new rules is precisely what this mechanism
was built to stop, and the temptation is strongest exactly when the old
rule was wrong.

---

### 11.4 The version table this document describes

These are the versions the reference implementation currently writes.

| Protocol | Current |
|---|---|
| `custody_protocol` | 1.1.0 |
| `replay_protocol` | 1.1.0 |
| `ranking_protocol` | 1.0.0 |
| `taint_protocol` | 2.0.0 |
| `authority_protocol` | 1.3.0 |
| `receipt_protocol` | 2.0.0 |
| `claim_protocol` | 1.1.0 |

And these are the versions it can still **verify**:

| Protocol | Supported |
|---|---|
| `custody_protocol` | 1.0.0, 1.1.0 |
| `replay_protocol` | 1.0.0, 1.1.0 |
| `ranking_protocol` | 1.0.0 |
| `taint_protocol` | 1.0.0, 1.1.0, 2.0.0 |
| `authority_protocol` | 1.0.0, 1.1.0, 1.2.0, 1.3.0 |
| `receipt_protocol` | 2.0.0 |
| `claim_protocol` | 1.0.0, 1.1.0 |

Two entries in the supported table are worth reading closely, because
they are where the discipline of §11.3 costs something.

`receipt_protocol` 1.0.0 is **absent**. Its digest body differs (§6.3),
so this build genuinely cannot check a 1.0.0 receipt. Listing it would
be the exact lie the table prevents.

`authority_protocol` 1.2.0 is **present**, and it carries a known defect:
under 1.2.0 an authority event was judged by the state it creates, so an
actor rotating itself off produced an unverifiable bundle (§4.5). 1.3.0
corrects it. 1.2.0 stays supported anyway, because evidence sealed under
1.2.0 is checked under 1.2.0, defect included. A known defect is not a
reason to retroactively re-judge old evidence — and the temptation to do
so is strongest precisely when the old rule was wrong.

## 12. Conformance vectors

See `conformance/`. An implementation conforms to a protocol version when
it reproduces every digest in the vector file from the operation sequence
in the vector file.

The vectors pin: the three genesis derivations, chain heads for each
kind, the receipt digest, the decision seal, the impact seal, the
exposure seal, claim standing, the counterfactual delta, both Merkle
roots, the bundle body seal, and the protocol version table itself.

**What the vectors prove, stated narrowly** because the value depends on
the boundary: that a fixed input produces these exact digests. They do
**not** prove the digests are correct — a golden vector inherits whatever
was true the day it was generated. Correctness comes from two
independent implementations that must agree (§10) and from adversarial
testing. The vectors only guarantee that the protocol cannot move
silently.

And they cannot see everything. During the extraction of a shared chain
core in this project's own history, every vector stayed green while one
module carried two complete implementations of its chain, one shadowing
the other, producing identical bytes. Pinned bytes prove the protocol did
not move; they say nothing about whether the code that moved it is gone.

---

## 13. What this specification does not specify

Stated here rather than discovered later. Each of these is a real
boundary, and an implementation that silently closes one has changed the
protocol.

**Time.** Timestamps are declared by the writer. MNEME enforces their
*form* and their *ordering within a chain*, and proves neither their
truth nor any causal relationship between chains. Cross-chain ordering
by timestamp comparison is only as good as the clocks that produced them.

**Identity.** The root bootstrap names whoever performed it (§4.4).
Binding an actor id to a real party — a key, a ceremony, an external
directory — is a deployment concern.

**Truth.** Nothing here distinguishes an honest field from a coherently
fabricated one (§0.3).

**The embedding boundary.** Vectors arrive from outside. Provenance
records make model drift *detectable* — provider, model, revision,
dimension, preprocessing, input content hash, output vector hash — and do
not make a lying embedder impossible.

**Existence of withheld memories.** The custody gate hides content. It
does not make the *existence and status* of a withheld memory secret; a
caller can learn that something is there. Making the not-found and
not-permitted paths indistinguishable would cost diagnostic quality,
which in a forensic tool is not obviously the right trade. This is a
stated boundary, not an oversight.

**Non-interference scope.** A counterfactual delta is proven **per
query** and over **recall**. It is not a field-wide statement, and it
does not cover paths other than recall.

**Standing.** A claim's standing is derived from evidence (C3). Deriving
it does not adjudicate it; `VALIDATED` and `REFUTED` require an actor
holding `ADJUDICATE`, and no amount of evidence produces them on its
own.

**Storage, transport, key management, access control beyond the
capability model, and concurrency beyond A6's constraint requirement.**

---

## 14. Reporting a disagreement

If an independent implementation disagrees with this document, or with
the reference implementation, that disagreement is the most valuable
output this project can receive. Report it with: the protocol version,
the operation sequence, the digest you computed, and the digest you
expected.

A disagreement is not automatically a defect in the other
implementation. The three possibilities are ranked by how much they are
worth: this document is ambiguous (most valuable — it means the rule was
never actually decided), the reference implementation is wrong, or the
new implementation is wrong.
