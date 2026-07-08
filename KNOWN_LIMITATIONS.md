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

## Recall receipts persist only by the caller's explicit act

`recall()` returns a sealed `RecallReceipt` and stays read-only by
design — serving is not a state transition, so forcing a write into
every recall would quietly convert the hottest read path into a write
path and invert M2's intent. What Phase 1 now provides is the explicit
path: `field.persist_receipt()` writes the receipt into the
append-only `recall_receipts` table (digest recomputed before insert;
a receipt that does not recompute is refused), and
`field.verify_receipts()` re-derives every stored digest from its own
columns. What it still does not provide: receipts are not custody
events, not in evidence bundles, and not linked to the decisions they
served — that is the Phase 2 CRONOS integration, where receipts become
first-class trace events. Until then, "why did the agent remember
this" is answerable for any recall whose receipt the caller persisted
or kept, and for the memory's full history always.

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
