# MNEME — Known limitations

This file exists because `README.md` and `ARCHITECTURE.md` promise it
by name. Every entry is documented at its source too; this is the
consolidated ledger. The organizing principle is unchanged from
STIGMERGY: a limitation named is a decision; a limitation hidden is a
bug waiting for a better moment.

## Transitive taint is advisory, not automatic

(Source: `trust.py` header.) Direct taint — actor X appears in a
chain — is flagged automatically. Transitive taint — memory A is
tainted and A's RESONANT links may have inflated B — is real but
unbounded: resonance graphs are connected in practice, and automatic
propagation without a fixpoint bound turns one quarantine into a
self-inflicted denial of service on the whole field. Phase 1 therefore
*reports* the one-hop RESONANT neighbourhood of every sweep's flagged
set (`TaintSweep.advisory_resonant_neighbours`) for analyst review and
flags nothing beyond direct contact. If a principled bound is designed
later (hop-limited with decay-weighted thresholds is the obvious
candidate), it must arrive with its own invariant, not as a loop
someone added.

## Recall receipts are produced, not yet persisted

`recall()` returns a sealed `RecallReceipt` but Phase 1 has no receipts
table; persisting them (or forwarding them to a CRONOS-style tracer) is
the caller's job. Rationale: recall is read-only by design — serving is
not a state transition, so forcing a write into every recall would
quietly convert the hottest read path into a write path and invert M2's
intent. The Phase 2 CRONOS integration is where receipts become
first-class trace events. Until then, "why did the agent remember this"
is answerable for any recall whose receipt the caller kept, and for the
memory's full history always.

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

## The embedding boundary is trusted

`quantize_embedding()` makes model output exact *from that point on*;
it cannot make the model deterministic. Two runs of a nondeterministic
embedding model produce two different (each exactly-stored) vectors.
MNEME's guarantees are about what happens to a vector after ingestion,
never about the model that produced it. `embedding_model` is recorded
in every STORED event; mixing models in one field is semantically
meaningless even when dimensions coincide, and changing models is a
migration event, not a config flip (STIGMERGY's rule, unchanged).

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

## Partial bundles fail B5 when sweeps reference absent memories

Emergent behaviour, examined and kept: exporting a subset of memories
while the bundle carries a sweep whose flagged memories are outside the
subset makes B5 fail in both verifiers — a bundle cannot silently claim
sweep evidence it does not carry. The consequence is that honest
partial exports of swept fields are currently impossible without
shipping every swept memory. The clean fix is an explicit
`excluded_sweeps` declaration in the bundle body (absence stated, not
implied); until it exists, export the full field or expect B5 to say
why not.
