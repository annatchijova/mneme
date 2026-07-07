# MNEME

A memory layer for agentic systems where every memory carries its own
**verifiable chain of custody**. Not "who wrote to the log" — *who wrote
this memory, who reinforced it, what contradicted it, when it was
quarantined and why*, each event hash-chained to the last, each chain
bound to its memory at genesis, all of it exportable as a sealed
evidence bundle that anyone can verify **offline with one stdlib-only
Python file**.

The question MNEME answers is the one a poisoned-RAG incident actually
asks: *why does your agent remember this, and can you prove the answer?*

Named for Mnemosyne's daughter, the muse of memory. Apache 2.0. Design
document: `ARCHITECTURE.md`. Consolidated ledger of accepted
limitations: `KNOWN_LIMITATIONS.md`. Schema (many invariants are
constraints, not conventions): `mneme/schema.sql`.

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

What neither had, and MNEME adds:

1. **Per-memory custody chains.** STIGMERGY chains per node; CRONOS
   chains per trace. MNEME chains per *memory*, with genesis
   `sha256("MNEME_CUSTODY_GENESIS:" ‖ memory_id)` — grafting memory A's
   history onto memory B fails at seq 0 by construction.
2. **Taint propagation.** Quarantine an actor and one deterministic,
   sealed sweep flags every memory that actor ever touched — including
   legitimate memories it merely REINFORCED, because that inflation is
   part of the incident. False positives are REHABILITATED by audited
   event, never by column edit.
3. **Exact recall ranking.** raven bought determinism by pinning BLAS
   to one thread. MNEME removes the problem: ranking is exact rational
   arithmetic (`Fraction`), so the same database state and query yield
   a byte-identical ranking on any machine. No BLAS, no float, no seed.
4. **State derivable from evidence.** A memory's `custody_status`,
   `field_state` and `confidence` must reproduce from replaying its
   chain. Hand-editing a status column without its event is
   self-revealing (bundle check B4).

## Layout

    mneme/canonical.py    canonical JSON + Fraction→Decimal quantization
                          (floats rejected, not serialized carefully)
    mneme/custody.py      per-memory hash chains: closed event vocabulary,
                          genesis bound to memory_id, append (caller owns
                          the transaction), pure verification
    mneme/trust.py        actor quarantine, deterministic taint sweeps
                          sealed by hash, audited rehabilitation
    mneme/field.py        store with bilateral contradiction events,
                          exact reinforcement c' = c + α(1−c),
                          custody-gated recall with exact ranking and
                          sealed recall receipts
    mneme/bundle.py       evidence bundle export + verification (B1–B6)
    mneme/schema.sql      SQLite WAL, Phase 1; written to port to
                          CockroachDB mechanically
    verify_offline.py     standalone stdlib-only verifier — send this
                          file plus a bundle to an auditor; they need
                          nothing else
    tests/                pure suites: no pip installs, no infrastructure,
                          SQLite :memory: only

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

## Quick start

```bash
python3 tests/test_custody_pure.py   # 29 checks: chains, grafting, forks
python3 tests/test_field_pure.py     # 28 checks: gate, exact ranking, rescue
python3 tests/test_bundle_pure.py    # 47 checks: bundles + verifier agreement
```

No dependencies. If a test file imports something you had to install,
that is a bug in the test file.

Verify a bundle someone sent you:

```bash
python3 verify_offline.py bundle.json
# VERIFIED: every check (B1-B6) passed.        (exit 0)
# FAILED: N problem(s). + one line per lie     (exit 1)
```

## What lying looks like

Every deception the design anticipates has a test asserting it is
caught, in both verifiers:

| The lie | Caught by |
|---|---|
| Edit a memory's content | B1 (seal), or B3 after resealing |
| Edit any custody event, however old | B2 — entry hash does not recompute |
| Drop or reorder events | B2 — seq density / linkage |
| Graft memory A's chain onto memory B | B2 — genesis binding fails at seq 0 |
| Fork a chain (two events, one parent) | `UNIQUE(memory_id, prev_hash)` at write time |
| Un-taint by editing the status column | B4 — replay disagrees |
| Inflate confidence without events | B4 — REINFORCED arithmetic replayed |
| Deny a sweep flagged what it flagged | B5 — flagged set hashes to the seal |
| Ship a partial bundle claiming full sweeps | B5 — evidence absent, claim present |
| Forge the cross-memory commitment | B6 — Merkle root over heads |

## Status

Phase 1: core complete, 104/104 pure checks passing. Not yet built:
HTTP API, demo harness, k-NN graph for large corpora, STDP synaptic
dynamics, stylometric authorship checks (see `KNOWN_LIMITATIONS.md` —
every absence there is a decision with a rationale, not an oversight).
