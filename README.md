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

## The incident, in sixty seconds

No dependencies. If anything below imports something you had to
install, that is a bug.

```bash
python3 demo.py                      # one poisoned-RAG incident, end to
                                     #   end, narrated: poison, sweep,
                                     #   gated recall, sealed export,
                                     #   hostile audit
python3 verify_offline.py bundle.json
# VERIFIED: every check (B1-B6) passed.        (exit 0)
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
python3 tests/test_custody_pure.py   # 37 checks: chains, grafting, forks,
                                     #   temporal plausibility
python3 tests/test_field_pure.py     # 41 checks: gate (serving AND
                                     #   influence), exact ranking, rescue,
                                     #   supersession, receipts
python3 tests/test_bundle_pure.py    # 87 checks: bundles, declared partial
                                     #   exports, lineage, backward-time,
                                     #   verifier agreement
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
returns by audited event; the bundle ships and the auditor runs B1–B6;
a forged status column fails B4 on screen. Click any memory at any time
to read its chain.

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

## Layout

    mneme/canonical.py    canonical JSON + Fraction→Decimal quantization
                          (floats rejected, not serialized carefully)
    mneme/custody.py      per-memory hash chains: closed event vocabulary,
                          genesis bound to memory_id, append (caller owns
                          the transaction), pure verification
    mneme/trust.py        actor quarantine, deterministic taint sweeps
                          sealed by hash, direct memory quarantine,
                          audited rehabilitation
    mneme/field.py        store with bilateral contradiction events,
                          bilateral supersession (M1's path for new
                          content), exact reinforcement c' = c + α(1−c),
                          custody-gated recall with exact ranking and
                          sealed recall receipts, persisted only by the
                          caller's explicit act
    mneme/bundle.py       evidence bundle export + verification (B1–B6)
    mneme/schema.sql      SQLite WAL, Phase 1; written to port to
                          CockroachDB mechanically
    verify_offline.py     standalone stdlib-only verifier — send this
                          file plus a bundle to an auditor; they need
                          nothing else
    demo.py               narrated end-to-end incident: poison, sweep,
                          gated recall, sealed export, hostile audit
    ui/index.html         the Field Viewer: the same incident, watched
                          instead of read (single file, zero deps)
    SECURITY_AUDIT.md     Round-1 adversarial audit (A–D–I): findings
                          confirmed by induction, and discarded vectors
    tests/                pure suites: no pip installs, no infrastructure,
                          SQLite :memory: only

## MCP Server (Model Context Protocol)

MNEME exposes its custody-gated memory operations as an MCP server:

```bash
python3 mcp_server.py    # stdio transport
```

**Tools available:**

| Tool | Description |
|------|-------------|
| `mneme_store` | Store a memory with custody chain from genesis |
| `mneme_recall` | Custody-gated recall with exact Fraction ranking |
| `mneme_reinforce` | Increase confidence (exact closed-form arithmetic) |
| `mneme_quarantine_actor` | Taint-flag every memory an actor touched |
| `mneme_rehabilitate` | Restore TAINT_FLAGGED memory to CLEAN |
| `mneme_export_bundle` | Export sealed evidence bundle (self-contained) |
| `mneme_verify_bundle` | Verify B1-B6 checks on any bundle |
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

Phase 1: core complete, 165/165 pure checks passing, demo harness, the
Field Viewer, and a Round-1 security audit (`SECURITY_AUDIT.md`)
included. Not yet built: HTTP API, k-NN graph for large corpora, STDP
synaptic dynamics, stylometric authorship checks (see
`KNOWN_LIMITATIONS.md` — every absence there is a decision with a
rationale, not an oversight).
