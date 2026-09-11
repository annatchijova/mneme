# MNEME

**Every memory has a chain of custody.**

<!-- hero: capture ui/index.html at the CONTAINMENT beat and save as docs/field-viewer.png -->
<!-- ![The field, mid-quarantine](docs/field-viewer.png) -->

A memory layer for agentic systems where every memory carries its own
**verifiable chain of custody**. Not "who wrote to the log" — *who wrote
this memory, who reinforced it, what contradicted it, when it was
quarantined and why*, each event hash-chained to the last, each chain
bound to its memory at genesis, all of it exportable as a sealed
evidence bundle that anyone can verify **offline with one stdlib-only
Python file**.

The question MNEME answers is the one a poisoned-RAG incident actually
asks: *why does your agent remember this, and can you prove the answer?*

And then the three that follow it, because "we found the poison and
excluded it" says what was done, not what it did:

- **who was ALLOWED to cause this?** Custody proves an event happened.
  It says nothing about permission — an audit trail is not an
  authorization system. Every mutation now carries two separable proofs
  over different evidence: integrity provenance (the memory's chain) and
  authority provenance (the actor's capability ledger).
- **which DECISIONS did this memory contaminate?** A recall receipt
  proves what an agent was shown. A decision record proves what it did
  with it, bilaterally, and `mneme impact` reconstructs the blast radius
  graded DIRECT / DERIVED / POSSIBLE — because equating contact with
  contamination is how one quarantine silences a whole field.
- **what did the poison actually DO?** Two sealed worlds, one query, an
  exact enumerated delta. Sometimes the answer is *nothing* — damage
  measured at zero rather than assumed at unknown.

## The incident, in sixty seconds

No dependencies. If anything below imports something you had to
install, that is a bug.

```bash
python3 demo.py                      # one poisoned-RAG incident, end to
                                     #   end, narrated: poison, sweep,
                                     #   gated recall, sealed export,
                                     #   hostile audit
python3 verify_offline.py bundle.json
# VERIFIED: every check (B0-B9) passed.        (exit 0)
# FAILED: N problem(s). + one line per lie     (exit 1)
```

Watch the same incident instead of reading it:

```bash
open ui/index.html                   # the Field Viewer (below) — a
                                     #   cinematic replay of demo.py's
                                     #   incident, no server needed
```

And the pure test suites (SQLite `:memory:` only, no infrastructure):

```bash
python3 tests/test_custody_pure.py       # chains, grafting, forks, temporal
python3 tests/test_field_pure.py         # gate (serving AND influence),
                                         #   exact ranking, rescue, receipts
python3 tests/test_bundle_pure.py        # bundles, declared partial exports,
                                         #   lineage, verifier agreement
python3 tests/test_authority_pure.py     # what acting WITHOUT PERMISSION
                                         #   looks like, and protocol versions
python3 tests/test_causality_pure.py     # decision records, blast radius
python3 tests/test_counterfactual_pure.py# non-interference, measured
python3 tests/test_influence_pure.py     # the influence budget, on a graph
                                         #   built to punish a naive walk
python3 tests/test_provenance_pure.py    # embedding drift, "what did MNEME
                                         #   know at T?"
python3 tests/test_claims_pure.py        # propositions vs documents, n-ary
                                         #   contradiction
python3 tests/test_semantic_mutants.py   # 12 protocol mutants, 12 killed,
                                         #   2 boundaries declared
```

## What lying looks like

Every deception the design anticipates has a test asserting it is
caught, in both verifiers:

| The lie | Caught by |
|---|---|
| Edit a memory's content | B1 (seal), or B3 after resealing |
| Edit any custody event, however old | B2 — entry hash does not recompute |
| Drop or reorder events | B2 — seq density / linkage |
| Rehash a chain to run backwards in time | B2 — timestamps must be canonical UTC and non-decreasing |
| Graft memory A's chain onto memory B | B2 — genesis binding fails at seq 0 |
| Fork a chain (two events, one parent) | `UNIQUE(memory_id, prev_hash)` at write time |
| Un-taint by editing the status column | B4 — replay disagrees |
| Inflate confidence without events | B4 — REINFORCED arithmetic replayed |
| Claim supersession lineage the other chain never consented to | B4 — lineage is bilateral, both directions checked |
| Deny a sweep flagged what it flagged | B5 — flagged set hashes to the seal |
| Ship partial sweep evidence without declaring it | B5 — a referenced sweep is carried in full or declared excluded, never implied absent |
| Dodge a sweep's seal check by declaring it excluded | B5 — a fully-evidenced sweep may not be excluded |
| Forge the cross-memory commitment | B6 — Merkle root over heads |
| Write as an actor you quarantined an hour ago | B7 — a QUARANTINED actor holds no capability, at that event's timestamp |
| Nominate yourself the rehabilitation authority | B7 — the grant must exist, be live, and confer REHABILITATE |
| Grant a capability you never held | B7 — no amplification, re-derived offline |
| Claim a decision used a memory the recall never served | B8 — the subset check, at write and at verification |
| Delete the decision but leave its custody evidence | B8 — the causal link is bilateral |
| Cite a recall against a world that never existed | B8 — a counterfactual receipt declares its own world |
| Over-flag or under-flag a sweep and seal it consistently | B5 — the flagged set is re-derived from custody evidence |
| Promote a memory that was never arithmetically due | B4 — replay checks the threshold, not just derivability |
| Rewrite a proposition under its own seal | B9 — the statement hashes to what its assertion sealed |
| Declare a constraint satisfied while the shipped claims violate it | B9 — the status is recomputed, not read |
| Change a rule and let old bundles acquire it | B0 — a bundle declares the semantics it was checked under |
| Read a quarantined memory by pretending it is clean | Widening the custody gate needs COUNTERFACTUAL (Round 3, R3-01) |
| Stand up a second root and ship one of them | B7 — every root chain travels, so the count is the real count (R3-02) |
| Quarantine the last GRANT holder and brick the field | A6 is a constraint now, on every path that can lose one (R3-07) |
| Ship a lineage claim whose counterpart stayed behind | B4 — declared in `excluded_lineage` or refused (Round 2, R2-04) |
| Re-open a settled claim for the price of an ASSERT | C6 — re-opening an adjudicated question is an adjudication (R3-03) |

## The disciplines, in one paragraph

Floats never decide: state transitions and rankings are exact
`Fraction` arithmetic, quantized to scale-10 `Decimal` only at the
SQL/hash boundary (the one sanctioned float crossing is embedding
ingestion — a *measurement*, quantized once at the boundary and exact
thereafter). Every module takes a live cursor and never commits — the
state change and its custody event share one transaction or neither
happens (Invariant M2). Nothing is deleted: QUARANTINED, TAINT_FLAGGED
and SUPERSEDED are states that preserve evidence, not euphemisms for
removal (M4). Every custody event carries a non-null `reason` — an
unreasoned event cannot exist. And every claim the system makes about
itself is checkable by someone who distrusts it: the offline verifier
recomputes seals, relinks chains, and replays state from evidence.

Named for Mnemosyne's daughter, the muse of memory. Apache 2.0. Design
document: `ARCHITECTURE.md`. Consolidated ledger of accepted
limitations: `KNOWN_LIMITATIONS.md`. Schema (many invariants are
constraints, not conventions): `mneme/schema.sql`.

## The Field Viewer

`ui/index.html` is a single self-contained file — open it in a browser,
nothing to install, nothing to serve. It replays the same incident
`demo.py` narrates, as a living field: memories are born, link, and
breathe; a compromised pipeline writes a poisoned memory and inflates a
legitimate one; recall serves the lie; **CONTAIN INCIDENT** runs the
sealed sweep and everything the actor touched loses its light,
disconnects and sinks — flagged, never deleted; the custody gate
withholds it from recall and the receipt counts it; the false positive
returns by audited event; the bundle ships and the auditor runs its
checks; a forged status column fails B4 on screen. Click any memory at
any time to read its chain.

The Viewer replays the Phase 1 incident and has not been extended to the
authority, causal, counterfactual or epistemic layers. It was accurate
when it was written and is now a partial picture, which is worth saying
here rather than letting a demo imply completeness.

Two modes: **director** (auto-plays the whole incident, timed for a
demo recording) and **manual** (you fire each beat — built for live
questions). Space advances, R restarts.

Honesty note, because this project is about nothing else: the Field
Viewer is a *staged replay* of the scripted incident — same actors,
events, carve-outs and B-codes as `demo.py`, with display hashes. It
visualizes; it does not verify. The verifier of record is
`verify_offline.py` against a real exported bundle.

## Lineage

MNEME is the deliberate fusion of two prior systems by the same
authors:

- **STIGMERGY** contributes the forensic spine: canonical JSON,
  Fraction-only decision arithmetic quantized to `DECIMAL`-scale 10 at
  the boundary, hash chains where the caller owns the transaction,
  Merkle commitments, and the rule that nothing is ever deleted.
- **raven-memory** contributes the field mechanics: ternary memory
  states (REINFORCED / NEUTRAL / FORGOTTEN), RESONANT and INHIBITORY
  links, BFS hop expansion with decay, and the rescue rule — *a
  validated truth cannot be silenced by an unverified claim*.

  https://github.com/annatchijova/raven-memory

What neither had, and MNEME adds:

1. **Per-memory custody chains.** STIGMERGY chains per node; CRONOS
   chains per trace. MNEME chains per *memory*, with genesis
   `sha256("MNEME_CUSTODY_GENESIS:" ‖ memory_id)` — grafting memory A's
   history onto memory B fails at seq 0 by construction.
2. **Taint propagation.** Quarantine an actor and one deterministic,
   sealed sweep flags every memory that actor ever touched — including
   legitimate memories it merely REINFORCED, because that inflation is
   part of the incident. Being *contradicted* by the actor is not being
   touched: taint tracks influence, not enmity, so quarantining an
   attacker never silences the memories it attacked. False positives
   are REHABILITATED by audited event, never by column edit.
3. **Exact recall ranking.** raven bought determinism by pinning BLAS
   to one thread. MNEME removes the problem: ranking is exact rational
   arithmetic (`Fraction`), so the same database state and query yield
   a byte-identical ranking on any machine. No BLAS, no float, no seed.
4. **State derivable from evidence.** A memory's `custody_status`,
   `field_state` and `confidence` must reproduce from replaying its
   chain. Hand-editing a status column without its event is
   self-revealing (bundle check B4).
5. **Authority provenance, separable from integrity.** Capabilities, not
   roles: "Anna is an admin" does not fit in an evidence bundle; "grant
   g-4f2 conferred REHABILITATE at 14:02:11, issued by someone who held
   it, unrevoked at 14:03:17" is arithmetic an auditor checks offline.
6. **Causal closure.** Recall → decision → blast radius, each link
   bilateral and sealed, so "which decisions were contaminated by X" has
   an answer made of rows rather than inference.
7. **Counterfactual containment.** The observable effect of a poisoned
   memory, enumerated exactly and sealed — including the case where the
   effect is nothing at all.
8. **Propositions separate from documents.** A claim has its own chain
   and its own state; its standing is derived from evidence every time it
   is asked for, because a stored confidence is a number whose
   derivation has been thrown away.

## Layout

    mneme/canonical.py    canonical JSON + Fraction→Decimal quantization
                          (floats rejected, not serialized carefully)
    mneme/protocol.py     the seven protocol versions a seal commits to;
                          a verifier meeting a version it does not
                          implement refuses instead of assuming
    mneme/authority.py    the capability ledger: per-actor hash-chained
                          grants and revocations, no amplification,
                          quarantine as a write barrier
    mneme/causality.py    decision records binding receipt + decision hash
                          + policy version, and blast-radius
                          reconstruction graded DIRECT/DERIVED/POSSIBLE
    mneme/counterfactual.py
                          two sealed worlds, one query, an exact delta —
                          non-interference proven rather than asserted
    mneme/claims.py       propositions as first-class objects with their
                          own chains, n-ary contradiction sets, standing
                          derived from evidence and never stored
    mneme/chain.py        the shape all three chains share, once: genesis
                          bound to the subject, the hashed envelope, dense
                          seq, the birth-event rule, structural
                          verification. Each chain declares a ChainSpec —
                          its table, its prefix, its own words for
                          refusing. What the events MEAN stays in the
                          module that owns them.
    mneme/custody.py      per-memory hash chains: closed event vocabulary,
                          genesis bound to memory_id, append (caller owns
                          the transaction), pure verification, and replay
                          — the part no other chain shares
    mneme/trust.py        actor quarantine, deterministic taint sweeps
                          sealed by hash, direct memory quarantine,
                          audited rehabilitation
    mneme/field.py        store with bilateral contradiction events,
                          bilateral supersession (M1's path for new
                          content), exact reinforcement c' = c + α(1−c),
                          custody-gated recall with exact ranking and
                          sealed recall receipts, persisted only by the
                          caller's explicit act
    mneme/bundle.py       evidence bundle export + verification (B0–B9)
    mneme/schema.sql      SQLite WAL, Phase 1; written to port to
                          CockroachDB mechanically
    SPEC.md               the protocol as a normative document, written
                          so a third party can implement a conforming
                          verifier without reading the Python — and
                          disagree, which is the point
    conformance/          the reference field as an operation list plus
                          every digest it produces: language-agnostic,
                          tagged by which protocol each vector exercises,
                          so partial conformance is checkable from day one
    verify_offline.py     standalone stdlib-only verifier — send this
                          file plus a bundle to an auditor; they need
                          nothing else
    demo.py               narrated end-to-end incident: poison, sweep,
                          gated recall, sealed export, hostile audit
    ui/index.html         the Field Viewer: the same incident, watched
                          instead of read (single file, zero deps)
    SECURITY_AUDIT.md     Round-1 adversarial audit (A–D–I): findings
                          confirmed by induction, and discarded vectors
    SECURITY_AUDIT_ROUND_2.md
                          Round-2 authority-after-quarantine audit:
                          confirmed containment and recovery-boundary gaps,
                          a falsified rollback vector, and the guarantees
                          that must transfer to distributed memory systems
    SECURITY_AUDIT_ROUND_3.md
                          Round-3 audit of the layers that closed Round 2:
                          two confirmed vulnerabilities (both fixed), three
                          reported limitations, one falsified-on-SQLite
                          portability defect — and why the mutation suite
                          found none of them
    tests/                pure suites: no pip installs, no infrastructure,
                          SQLite :memory: only — including
                          test_semantic_mutants.py, which mutates the
                          PROTOCOL rather than the operators

## MCP Server (Model Context Protocol)

MNEME exposes its custody-gated memory operations as an MCP server:

```bash
python3 mcp_server.py    # stdio transport
```

**Tools available:**

| Tool | Description |
|------|-------------|
| `mneme_bootstrap_root` | Start this field's authority ledger. Once, ever |
| `mneme_register_actor` | Register an identity — it holds nothing until granted |
| `mneme_grant` / `mneme_revoke` | Confer or end capabilities, hash-chained |
| `mneme_reinstate_actor` | Close a quarantine interval, on the record |
| `mneme_authority` | Who may cause what, and on whose word |
| `mneme_store` | Store a memory with custody chain from genesis |
| `mneme_recall` | Custody-gated recall; `as_of` reconstructs history |
| `mneme_reinforce` | Increase confidence (exact closed-form arithmetic) |
| `mneme_quarantine_actor` | Sweep the past AND bar the actor from writing |
| `mneme_rehabilitate` | Restore TAINT_FLAGGED memory to CLEAN |
| `mneme_exposure` | Influence budget: DIRECT_TAINT / INFLUENCE_EXPOSED / CLEAN |
| `mneme_record_decision` | Close recall → action, bilaterally |
| `mneme_impact` | Blast radius, graded DIRECT / DERIVED / POSSIBLE |
| `mneme_counterfactual` | What excluding these memories actually changes |
| `mneme_assert_claim` | Assert a proposition, distinct from any document |
| `mneme_link_evidence` | A memory supports or contradicts a claim |
| `mneme_relate_claims` | SUPPORTS / CONTRADICTS / SUPERSEDES / DERIVED_FROM |
| `mneme_claim_set` | N-ary contradiction: AT_MOST_ONE / EXACTLY_ONE / INCOMPATIBLE |
| `mneme_resolve_set` | Decide between hypotheses, as one audited act |
| `mneme_claim` | A proposition's standing, recomputed from evidence |
| `mneme_embeddings` | Inventory and drift across the vector boundary |
| `mneme_export_bundle` | Export sealed evidence bundle (self-contained) |
| `mneme_verify_bundle` | Verify B0-B9 checks on any bundle |
| `mneme_custody_chain` | View full per-memory custody history |
| `mneme_info` | Architecture, invariants, and stats |

**Claude Code config** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "mneme": {
      "command": "python3",
      "args": ["/path/to/mneme/mcp_server.py"],
      "env": {
        "MNEME_DB_PATH": "/path/to/mneme.db"
      }
    }
  }
}
```

The MCP server uses deterministic SHA-256-seeded embeddings (non-semantic,
`is_semantic=False`). Rankings are reproducible but distances are not
meaningful — the same honesty discipline as STIGMERGY's deterministic
provider.

## Status

Phase 1 core complete. Phase 1.5 adds the authority ledger, causal
decision receipts, counterfactual contamination analysis, the influence
budget, embedding provenance, temporal replay, the epistemic claims
layer, and protocol versioning.

Round 3 then audited that new surface and found four confirmed
vulnerabilities in it — a disclosure oracle in the counterfactual read
path, a global check the export made unreachable, a permanently brickable
field, and a self-revocation that produced unverifiable evidence. All four
are fixed, together with the last outstanding Round 2 recommendation
(`excluded_lineage`, closing R2-04). What was not fixed is named in
`KNOWN_LIMITATIONS.md` with the reasoning, rather than quietly closed.

743/743 pure checks passing, plus 16/16 semantic mutants killed with
3 boundaries explicitly declared — and an audit that explains why that
second number is a floor and not a ceiling.

Round 2's findings are closed: a quarantined actor can no longer write
(R2-01), and nobody can nominate themselves the rehabilitation authority
by choosing a string (R2-02). The audit's own closing line — *you found
that "audited" does not imply "authorized"* — became the next invariant.
Round 3's lesson is smaller and just as portable: when a check becomes
global, audit what the export makes visible to it, and when a read path
gains a parameter, ask what it now reveals.

Not yet built: HTTP API, k-NN graph for large corpora, STDP synaptic
dynamics, stylometric authorship checks. And ten or so new limitations
that these additions CREATED, each named in `KNOWN_LIMITATIONS.md` with
what it costs — including the two mutants that survive on purpose,
because a metric that improves by lowering its standards is not a
metric.
