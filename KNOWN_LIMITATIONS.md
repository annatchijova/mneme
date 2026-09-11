# MNEME — Known limitations

This file exists because `README.md` and `ARCHITECTURE.md` promise it
by name. Every entry is documented at its source too; this is the
consolidated ledger. The organizing principle is unchanged from
STIGMERGY: a limitation named is a decision; a limitation hidden is a
bug waiting for a better moment.

## Transitive taint is graded, and still never automatic

(Source: `trust.py`.) This entry used to say the bound was undesigned
and would have to arrive with its own invariant. It has:
`trust.influence_exposure()` spends an exact rational INFLUENCE BUDGET
outward from the tainted set — a RESONANT edge conveys
`INFLUENCE_TRANSFER` (1/2) of whatever reaches its source, anything
below `EXPOSURE_FLOOR` (1/64) is dropped, and `MAX_INFLUENCE_DEPTH` is
DERIVED from the floor rather than configured beside it. Termination is
structural, not a visited-set trick: influence strictly decreases per
edge, so cycles are harmless and no path beyond the depth bound can
contribute. INHIBITORY edges convey nothing (the CONTRADICTED_BY
carve-out, applied to the graph).

WHAT REMAINS, named. `INFLUENCE_EXPOSED` is a finding and NOT a custody
status: nothing is flagged, nothing is written, and the sweep still
flags only what it can demonstrate. That is the point — a system that
quarantined on contact would have an incident response
indistinguishable from the incident — but it does mean an analyst must
still act. And the two constants are a POLICY CHOICE, not a
measurement: 1/2 per edge and a floor of 1/64 are defensible and
arbitrary, they are sealed into every exposure report so two reports are
comparable, and changing them is a `taint_protocol` bump, not a config
flip.

## Recall receipts persist only by the caller's explicit act — and now bind to decisions

`recall()` returns a sealed `RecallReceipt` and stays read-only by
design — serving is not a state transition, so forcing a write into
every recall would quietly convert the hottest read path into a write
path and invert M2's intent. What Phase 1 now provides is the explicit
path: `field.persist_receipt()` writes the receipt into the
append-only `recall_receipts` table (digest recomputed before insert;
a receipt that does not recompute is refused), and
`field.verify_receipts()` re-derives every stored digest from its own
columns. Receipts now travel in evidence bundles and are re-derived there (B8),
and `causality.record_decision()` closes the loop the previous version
of this entry deferred to Phase 2: a decision record commits
receipt_sha256 + decision_sha256 + policy_version + the subset of the
served set it used, bilaterally (each used memory's chain carries a
`DECISION_USED_MEMORY` event naming it back).

WHAT REMAINS, named. `decision_sha256` is OPAQUE. MNEME commits to the
hash of a decision artifact it never sees, so it can prove the decision
is a fixed object and that it cited this recall — and it cannot prove
the artifact was actually PRODUCED from that recall. An agent that
recalls honestly and then answers from somewhere else leaves a perfect
record of a causal link that did not happen. Closing that needs the
reasoning trace itself (the CRONOS integration), not a bigger hash.

And recall is still read-only by default: a decision can only cite a
receipt the caller chose to persist. An agent that never persists
receipts leaves blast-radius reconstruction with nothing to reconstruct
from, and MNEME will not silently start writing on the read path to
prevent that.

## Linear exact scan; no k-NN graph, no vector index

Recall scores every CLEAN memory with exact rational arithmetic. This
is O(n·d) with big constants (Fraction arithmetic is not SIMD). It is
the correct trade for Phase 1 corpora (thousands of memories): the
determinism claim — byte-identical ranking on any machine — is
strongest when there is no index whose construction order could leak
into results. At scale, a k-NN candidate-selection stage can sit in
front *provided* the final ranking of the candidate set stays exact and
the candidate set itself is derived deterministically; that design is
reserved, not done. The CockroachDB port's vector index has the same
contract to meet.

## Deferred raven-memory mechanisms

Absent from Phase 1, each with a reason beyond "later":

- **STDP / synaptic pull** — raven's cross-turn weights are float
  accumulations with an epsilon prune. Porting them means designing
  exact-arithmetic synapse dynamics (bounded rationals with explicit
  quantization) so M5 holds; a straight port would smuggle floats into
  a ranking term.
- **Stylometry** — raven degrades memories to FORGOTTEN on fingerprint
  mismatch *during recall*. Under M2 that is a state transition inside
  a read path; MNEME's version must emit STATE_CHANGED custody events
  and therefore belongs to an explicit audited pipeline, not a recall
  side effect.
- **Recency bonus** — wall-clock-dependent scoring breaks "same state,
  same query, same ranking" (two recalls at different times would rank
  differently with no state change). If added, it must be a function of
  data in the database (e.g. last audited activation event), not of
  `time.time()` at query time.
- **Spectral resonance/coherence metadata** — raven reports these
  without letting them touch the score; MNEME can adopt them the same
  way, but Phase 1 ships nothing it does not verify.

## Direct quarantine has no reversal path

`trust.quarantine_memory()` records direct evidence against one memory;
`rehabilitate_memory()` deliberately reverses TAINT_FLAGGED only. The
asymmetry is the point — a sweep's false positive is a statistical
casualty with a lightweight audited reversal, while un-quarantining a
directly-incriminated memory is a stronger claim whose review path
(who may reverse, on what evidence, leaving what event) has not been
designed. The replay state machine (B4) enforces the same asymmetry:
REHABILITATED is valid only from TAINT_FLAGGED, so a chain that
"un-quarantines" is invalid evidence in both verifiers. When a
reversal path is designed it arrives as a protocol change (new replay
rule, both verifiers, agreement tests), not as a loosened check.

## Timestamps: order enforced, causal truth not proven — and more now rests on them

(Source: security audit Round 1, H1.) Chain verification now requires
`created_at` to be canonical UTC (`…+00:00`) and non-decreasing along
`seq` — a hash-valid chain that runs backwards in time is refused by
both verifiers. What this does NOT do: prove that the timestamps are
*true*. An attacker who fabricates an entire field controls every field
including `created_at`, and can emit a monotonic, canonical, entirely
fake history (the "a hash proves integrity, not truth" boundary). The
check closes the timestamp-only-tamper and accidental-impossibility
classes and moves the canonical-timestamp discipline from write-time
only to read-time too; binding time to an external, harder-to-forge
reference (a notarised clock, a CRONOS trace) is a Phase-2 decision, not
a Phase-1 promise.

MORE NOW RESTS ON THIS, which is the honest cost of the newer layers.
Authority provenance (B7) decides whether a grant was live *at an
event's timestamp*; the pre-authority carve-out excuses events *earlier
than the declared genesis*; `recall(as_of=T)` reconstructs history *by
timestamp comparison*. Each of those is exact and checkable against the
evidence, and each of them inherits this boundary whole: an adversary
who controls every write controls every timestamp, and can emit a
monotonic, canonical, internally consistent history that verifies
perfectly and never happened. `tests/test_semantic_mutants.py` carries
that as a declared surviving mutant, so the limit is executable rather
than merely written down.

## The embedding boundary is trusted — drift is now detectable, not prevented

`quantize_embedding()` makes model output exact *from that point on*;
it cannot make the model deterministic. Two runs of a nondeterministic
embedding model produce two different (each exactly-stored) vectors.
MNEME's guarantees are about what happens to a vector after ingestion,
never about the model that produced it. That has not changed and cannot.

What HAS changed is that the boundary is now instrumented.
`field.declare_embedding()` records provider, model, revision,
dimension, preprocessing, input_content_hash, output_vector_hash and
quantization_protocol, and `detect_embedding_drift()` reports any group
agreeing on (provider, model, revision, preprocessing, input) while
disagreeing on the output vector. That is a fact, not a heuristic: the
same declared model was given the same declared input and produced two
different vectors. `embedding_inventory()` makes mixing models a
visible migration rather than an accident.

WHAT REMAINS, named, and demonstrated rather than asserted:
`tests/test_semantic_mutants.py` carries a mutant in which the provider
returns a vector it never computed. It SURVIVES every check, by design,
and is declared there as a boundary. MNEME records what a provider
handed it. It cannot witness the model's arithmetic, and no hash can.
Provenance is also OPTIONAL: memories that declare none verify fine, and
every passing verdict counts and names them.

## SQLite Phase 1 concurrency

WAL mode gives one writer at a time; the caller-owns-transaction
contract means custody appends serialize on the database write lock.
Correct, and fine for a single-process agent; multi-writer deployments
are what the CockroachDB port is for. Note `INSERT OR IGNORE` in
contradiction-link creation is SQLite dialect and is on the port's
mechanical-translation list.

## Duplicated verification logic (by design)

`verify_offline.py` transcribes canonicalization, chain verification,
state replay, and the Merkle rule from the package. Named here so
nobody "fixes" it: the duplication is load-bearing (auditor reads one
file, installs nothing) and is held together by the agreement section
of `tests/test_bundle_pure.py`. A protocol change that does not update
verifier, package, and the normative statement in `bundle.py`'s header
together will fail those tests. If the agreement section is ever
weakened, the duplication stops being a decision and becomes the bug
this file warns about.

THE LINE BETWEEN DUPLICATION THAT EARNS ITS KEEP AND DUPLICATION THAT
DOES NOT is now drawn in code rather than argued in prose. custody,
authority and claims used to carry three near-identical implementations
of the chain shape; they share one (`mneme/chain.py`), each declaring a
`ChainSpec` with its own table, genesis prefix and refusal wording.
Those three copies bought nothing — same import graph, same readers,
same commits. `verify_offline.py`'s copy buys a property, and there is
now a semantic mutant that demonstrates exactly which one: collapse the
three genesis prefixes into a single constant and the package verifies
its own field perfectly, because writer and verifier share the mutated
code. Only the independent transcription refuses. Deduplicating inside
the package is safe precisely to the extent that an independent
implementation still disagrees when the package is wrong about itself.

What that refactor also showed, and what is worth carrying forward: the
golden vectors stayed green while `authority.py` held two complete
implementations of its chain, one shadowing the other, producing
identical bytes. Byte-level pinning proves the protocol did not move;
it cannot see whether the code that moved it is still there. A
duplicate-definition scan in `tests/test_protocol_vectors.py` covers
that now.

## Excluded sweeps are declared claims, not verified ones

(Successor to the former entry "Partial bundles fail B5 when sweeps
reference absent memories" — the `excluded_sweeps` declaration that
entry named as the clean fix now exists.) `export_bundle()` partitions
sweep rows: a sweep whose entire flagged set travels in the bundle goes
into `sweeps` and B5 checks its count and seal; any other sweep goes
into `excluded_sweeps` — absence stated, never implied — and B5
enforces that the exclusion is genuine (strictly fewer flagged
memories carried than claimed), unambiguous (no sweep in both lists),
and complete (every sweep_id referenced by a TAINT_FLAGGED event
appears in one of the two lists). Honest partial exports of swept
fields now verify, and the offline CLI names every declared exclusion
on success.

What remains, named: an excluded sweep's seal is NOT checked — its
evidence lives outside the bundle, so exclusion is a claim the auditor
sees and may act on (demand the full field), not a claim the verifier
proves. And a sweep none of whose flagged memories are in the export
leaves no referencing event behind, so a hostile exporter could omit
it entirely rather than declare it; `export_bundle()` always declares,
but the verifier cannot detect that omission. Partial exports prove
what they carry, never what they omit — the full-field export is the
only bundle that proves the absence of further sweeps.


## Authority begins with an act authority cannot authorize

(Source: `authority.py`.) The ledger is a tree rooted at
`bootstrap_root()`, and that call is refused once any authority chain
exists — so it happens exactly once per field and every capability
traces back to it by checkable grants (A3). What it does NOT prove is
that the right party performed it. **Whoever bootstraps an empty field
is its root.** Binding that to an external identity — an operator key, a
notarised ceremony, a hardware token — is a deployment decision, and
MNEME deliberately does not pretend to have made it.

A related and smaller boundary: a field with no ledger at all still
accepts writes. Those fields declare every event UNAUTHORIZED BY
DECLARATION in their bundles and every passing verdict says so in words,
which is the honest handling of pre-authority history — but it is
handling, not prevention. The regime is one-way: once a field is
bootstrapped, nothing removes a chain, so it can never return.

## Widening the custody gate is an authority-bearing READ

(Source: `counterfactual.py`, `field.recall`; Round 3, R3-01.) The
counterfactual needs to see the other world, and `custody_override`
is how. Forcing a QUARANTINED memory to CLEAN made its CONTENT
servable to anyone who could call recall — the gate this project exists
to hold, with a documented bypass. It is now gated by the
`COUNTERFACTUAL` capability, and only in the WIDENING direction:
narrowing can only ever show a caller less than it could already see.

WHAT REMAINS. The check happens and nothing is written. **MNEME does not
audit reads**, anywhere, and gating one did not start. So a refused
attempt to widen the gate leaves no trace, and a successful one leaves no
trace either — the grant is checked and never recorded, because recall is
read-only and making it write would invert M2's intent on the hottest
path. If who looked at what ever needs to be evidence, that is a
different design, not a flag on this one.

## Existence and status of withheld memories is not secret

(Round 3, R3-05.) Three un-gated paths confirm that a memory the custody
gate withholds EXISTS, to a caller who cannot see it:
`receipt.excluded_custody` counts it, `exclusion_effect` accepts its id
without error, and `claims.standing().withheld_evidence` names it with
its status. None discloses content — that was R3-01 and it is closed.

Two of the three are deliberate and would cost more to remove than they
cost to keep. *What was withheld and why is a number, not a mystery* is a
transparency property this project chose on purpose, and error messages
that distinguish "unknown memory" from "not permitted" are what make a
forensic tool debuggable. Together they compose into id enumeration for
an actor with a narrow grant, and that is the honest statement of the
trade rather than a bug anyone should fix by reflex.

## Denial of epistemics: priced, not eliminated

(Round 3, R3-03 — CONFIRMED, and since CLOSED for the case that mattered.) An actor holding only
`ASSERT` can mint junk hypotheses and bind an already-VALIDATED claim
into new EXACTLY_ONE sets with them. Each set reads UNDETERMINED —
correctly, because an open hypothesis must never be read as agreement —
and only an `ADJUDICATE` holder can clear it. One cheap call creates work
that only a privileged actor can do.

C6 now prices that act: binding an already-VALIDATED claim into a NEW
constraint requires `ADJUDICATE`, because re-opening a settled question
IS an adjudication. The conservative default that made it exploitable is
kept exactly as it was — an open hypothesis still reads UNDETERMINED,
never "false by default" — because reading "nobody has objected yet" as
"true" is how a memory system manufactures agreement.

WHAT REMAINS. Minting junk hypotheses against claims that are still OPEN
is still cheap, and still creates work. C6 protects settled questions,
not unsettled ones, and there is no principled way to protect the
unsettled ones without making disagreement itself expensive — which
would be a worse system. A per-actor rate discipline is the obvious next
tool and is deliberately not in the protocol: rate limits are a
deployment concern, and putting one in the evidence layer would make two
honest fields produce different verdicts on the same acts.

## DERIVED is the one relation MNEME cannot make bilateral

(Round 3, R3-04 — CONFIRMED, and since GRADED rather than fixed.) Contradiction, lineage and
decision-use are all bilateral: both sides record them or the relation
does not exist. Descent is not. `derived_from_decision` is written by the
storing actor into its own STORED payload, and neither the named decision
nor the ancestor memory corroborates it.

It CANNOT be made bilateral, and that is the honest statement rather than
a deferral: the decision was written before the derived memory existed
and cannot name back something that did not yet exist.

So the level is GRADED instead. `derived_memories` holds descent declared
by the cited decision's OWN actor — one actor's coherent account of its
own work. `derived_unattested` holds a third party's claim of descent
from someone else's decision, which is strictly weaker and is reported
apart so a shaped report cannot borrow the strong bucket's weight.

WHAT REMAINS. Both buckets are still self-assertions; the grading says
WHO asserted, not whether it is true. An actor can still inflate its own
attested bucket about its own decisions, and co-serving still inflates
POSSIBLE for free. `impact()` never quarantines, so the damage is to an
analyst's reading rather than to the field — but a blast radius is a
lead, never a proof, and the seal on it proves only that the report was
computed from this state, not that the state was not shaped.

## A6 is a write-time invariant, and evidence cannot carry it

(Round 3, R3-06 and R3-07 — both CLOSED.) A6 was a read inside
`revoke()`: non-atomic, and guarding only one of the two paths that can
lose a GRANT holder. QUARANTINE walked straight past it, and two
individually legitimate acts — quarantine the only GRANT holder, then let
the responder rotate itself off — left a field that could never grant,
register or reinstate again. It is now a `governance` counter under a
`CHECK`, decremented by a conditional `UPDATE` whose rowcount is the
verdict, on every losing path.

WHAT REMAINS, and it is a property of the idea rather than the
implementation: **A6 is a write-time invariant and cannot be an evidence
property.** A bricked field still exports a bundle that verifies —
correctly, because the chains are honest evidence of a bricked field. No
bundle check guards A6 and none should; it is tested by refusal in
`tests/test_authority_pure.py`, and the mutation suite says so in its own
header, because a mutation suite over evidence is the wrong instrument
for a rule about what may be written.

Second: the counter is a CACHE. It is derived from the chains, lazily
materialised for fields bootstrapped before it existed, and B7 re-derives
governance from evidence and never from it — the same contract
`actors.status` has. A hand-edited counter cannot authorize anything; it
can only refuse.

## Non-interference is proven per QUERY, and only over recall

(Source: `counterfactual.py`.) An empty delta licenses exactly this
sentence: *for this query, under this sealed state, the excluded
memories exerted no observable influence.* It does not license "no
interference", and the module refuses to extrapolate. Generalising
honestly means stating a query set and sealing a delta for each one;
MNEME gives you the primitive and no license to skip that work.

Two further bounds. The comparison is over RECALL OUTPUTS, not the
agent's reasoning: if two different served sets would have produced the
same decision anyway, that is a fact about the policy, not about MNEME.
And `decision_dependency_changed` names decisions whose INPUT moves — it
does not re-run them, because MNEME holds a decision's hash and never
its reasoning. It is reported beside the query-scoped verdict and
deliberately not folded into it; folding them made non-interference
unreachable for any memory that had ever informed a decision.

## Blast radius: DIRECT and DERIVED are evidence, POSSIBLE is a perimeter

(Source: `causality.py`.) DIRECT is rows — persisted receipts that
served a memory, decisions that used it. DERIVED follows declared
edges: supersession lineage, and memories whose STORED payload names a
contaminated decision (`derived_from_decision`), which the AGENT
declares rather than MNEME inferring.

POSSIBLE is neither. It is co-service in the same recall plus one-hop
RESONANT neighbours — contact, reported so an analyst can see the
perimeter, never acted on and never a custody status. It is also NOT
COMPLETE: a memory influenced through some path MNEME does not model
will not appear. Treat POSSIBLE as "start looking here", never as "this
is the boundary of the damage".

And a DERIVED edge exists only if the agent declared it. An agent that
writes a memory because of a contaminated decision and does not say so
leaves a derivation MNEME cannot see. The alternative — inferring
descent from timing or authorship — is the indiscriminate propagation
this project refuses everywhere else.

## Claims: evidence is one-sided, and standing waits for a human

(Source: `claims.py`.) Evidence links live on the CLAIM's chain and not
the memory's, breaking the bilaterality that contradiction, lineage and
decisions all follow. The reason is stated in the module and worth
repeating here: a claim is about memories, memories are not about
claims, and a document whose history grew with every proposition that
ever cited it would be carrying the epistemic unit's weight again. The
cost is real: a partial export of MEMORIES alone cannot show which
propositions cite them. Bundles carry claims whole, so this bites only
if someone builds a memory-only export path.

STANDING WAITS FOR AN ADJUDICATION. A claim "holds" only when it is
VALIDATED — adjudicated, by an actor holding ADJUDICATE. A claim with
overwhelming supporting evidence and no ruling is ASSERTED, and its set
evaluates to UNDETERMINED. That is deliberate: reading "nobody has
objected yet" as "true" is how a memory system manufactures agreement.
It does mean MNEME never concludes anything on its own, which is a
feature until you wanted an autonomous field, and then it is this
limitation.

Also: `field.store()`'s original topic+claim contradiction rule (raven's)
still exists and still creates INHIBITORY links. It is the cheap path
for the one-proposition-per-document case and is NOT wired to the claims
layer. Two mechanisms describe disagreement, at different levels, and
reconciling them is deferred rather than done.

## Bundle format V1 is unreadable, on purpose

`MNEME_BUNDLE_V1` bundles are refused, not reinterpreted. They were
sealed over bytes without sealing the SEMANTICS those bytes were checked
under, which is precisely the retroactive-semantics problem
`protocol.py` exists to close — so applying today's rules to them would
be the bug rather than a courtesy. The same rule bites inside V2:
`receipt_protocol` 1.0.0 is NOT in the supported table, because the
digest body changed and this build genuinely cannot check one.

If V1 or receipt-1.0.0 evidence ever needs verifying, the answer is a
verifier of its era, or those rules ported forward deliberately as code,
in both implementations, with tests. Never a widened `SUPPORTED_PROTOCOLS`
entry — that table is a claim about implemented behaviour, and an entry
without the code behind it is the one lie it exists to prevent.

## Sweep re-derivation covers what the bundle carries

(Source: `bundle.py` B5, taint_protocol 2.0.0.) An included sweep's
flagged set is now re-derived from custody evidence — for every memory
the bundle carries, an influencing event by the quarantined actor at or
before the sweep must correspond to a flag, and vice versa. This killed
the over-flagging and under-flagging mutants that passed every 1.x
check.

It is total on PRESENCE and silent on ABSENCE: a partial export cannot
be asked about memories it does not ship, so a sweep that under-flagged
a memory left out of the bundle is invisible there. The full-field
export is the only one that proves a sweep flagged everything it should
have — the same shape as the existing partial-export limitation below,
for the same reason.

## Semantic mutants: 16 killed, 3 declared survivors — and what they missed

`tests/test_semantic_mutants.py` patches MNEME's SEMANTICS, lets the
patched code produce real evidence, and asks whether anything refuses
it. The metric is mutants killed over total, and an UNDECLARED survivor
fails the suite — a metric that improves by lowering its standards is
not a metric.

The declared survivors are entries above: a model that returns a vector
it never computed, an adversary who fabricates a coherent field, and a
hostile exporter that omits an authority chain. All three were prose in
this file. They are now executable.

One mutant tests the two VERIFIERS against each other rather than the
protocol against a writer: collapsing the three chain kinds onto one
genesis prefix is invisible to the package and caught only by
`verify_offline.py`. It is the executable form of the argument in
"Duplicated verification logic", above.

Writing that suite found two real gaps, both since closed and both
visible in the protocol versions: `replay_protocol` 1.1.0 (a promotion
must be arithmetically DUE, not merely recorded — a writer that quietly
narrowed the comparison satisfied every check MNEME had) and
`taint_protocol` 2.0.0 (the sweep re-derivation above).

AND IT MISSED THE ONES THAT MATTERED MOST. Round 3 found the
counterfactual disclosure oracle, the unreachable root check, a
permanently brickable field and a self-revocation that produced
unverifiable evidence, and a perfect mutation score had nothing to say
about any of them. The reason is structural and worth
keeping in view: the same author wrote the mutants and the defenses, so
the metric measured internal coherence rather than robustness. Both are
mutants now — kept as markers of the blind spot, not as evidence of
coverage. A mutation score is a floor on what a suite would notice, never
a ceiling on what is there.