"""
MNEME MCP Server
================
Exposes the MNEME per-memory chain-of-custody system as an MCP server,
so any MCP-capable agent (Claude, Claude Code, custom agents) can store,
recall, reinforce, quarantine, export bundles, and verify evidence
through the Model Context Protocol.

Design notes
------------
- FastMCP over stdio, same transport model as CRONOS, CORVUS, and
  raven-memory MCP servers.
- MNEME has no external dependencies (stdlib + SQLite only). This server
  adds only the `mcp` package.
- Every MNEME function takes a live cursor and never commits — the MCP
  server provides the cursor and commits after each tool call succeeds.
  A failing operation rolls back automatically (SQLite default behavior
  when a transaction is not committed).
- Embeddings: MNEME stores embeddings as quantized Decimal lists. For
  the MCP server, the caller passes text and the server generates a
  deterministic embedding (SHA-256-seeded, non-semantic) unless a real
  embedding provider is configured. This is honest: the deterministic
  provider declares is_semantic=False, so recall ranking is reproducible
  but not semantically meaningful — same discipline as STIGMERGY.
- Input sanitization follows VIGIA/CORVUS pattern.

Run
---
    python3 mcp_server.py            # stdio transport

Register (Claude Code settings.json)
-------------------------------------
    {
      "mcpServers": {
        "mneme": {
          "command": "python3",
          "args": ["/home/labestiadevigia/mneme/mcp_server.py"],
          "env": {
            "MNEME_DB_PATH": "/home/labestiadevigia/mneme/mneme.db"
          }
        }
      }
    }
"""

import hashlib
import json
import logging
import os
import sqlite3
import sys
import uuid
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Ensure the package resolves regardless of the invoking CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mneme import custody, field, trust, bundle
from mneme.canonical import canonical_json, quantize, CANONICAL_SCALE

log = logging.getLogger("mneme.mcp")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    stream=sys.stderr,
)

mcp = FastMCP("mneme")

# -- Config ------------------------------------------------------------------

_DB_PATH = Path(os.environ.get("MNEME_DB_PATH", "mneme.db"))
_EMBEDDING_DIM = 384  # matches raven-memory / STIGMERGY convention


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _init_db():
    """Apply schema if the database does not exist yet."""
    schema_path = Path(__file__).parent / "mneme" / "schema.sql"
    if schema_path.exists():
        conn = _get_conn()
        conn.executescript(schema_path.read_text())
        conn.close()


_init_db()

# -- Input limits (VIGIA pattern) --------------------------------------------

_MAX_TEXT = 50_000
_MAX_ID = 64


def _trunc(text: str, limit: int = _MAX_TEXT) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text if len(text) <= limit else text[:limit - 1] + "..."


def _sanitize_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string.")
    value = value.strip()
    if len(value) > _MAX_ID:
        raise ValueError(f"{name} too long (max {_MAX_ID} chars).")
    return value


# -- Deterministic embedding (SHA-256-seeded, non-semantic) ------------------

def _deterministic_embedding(text: str) -> list[Decimal]:
    """
    Generate a deterministic, reproducible embedding from text using
    SHA-256 seeding. NOT semantic — same text always yields same vector,
    different text yields different vector, but distances are meaningless.
    This is the honest-degradation path: the system works, declares its
    limitation, and does not fabricate semantic claims.
    """
    seed = hashlib.sha256(text.encode("utf-8")).digest()
    values = []
    for i in range(_EMBEDDING_DIM):
        h = hashlib.sha256(seed + i.to_bytes(2, "big")).digest()
        # Map first 4 bytes to [-1, 1] range
        raw = int.from_bytes(h[:4], "big", signed=False)
        normalized = (raw / 2147483647.5) - 1.0
        values.append(normalized)
    # Quantize to canonical Decimal scale
    return field.quantize_embedding(values)


# -- Ensure default actor exists ---------------------------------------------

def _ensure_actor(conn, actor_id: str, kind: str = "AGENT"):
    """Register actor if not already known."""
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,))
    if cur.fetchone() is None:
        ts = custody.now_ts()
        cur.execute(
            "INSERT INTO actors (actor_id, display_name, kind, status, created_at) "
            "VALUES (?, ?, ?, 'ACTIVE', ?)",
            (actor_id, actor_id, kind, ts),
        )
        conn.commit()


# -- MCP tools ---------------------------------------------------------------

@mcp.tool()
def mneme_store(
    content: str,
    actor_id: str = "mcp_agent",
    reason: str = "stored via MCP",
    topic: str = "",
    claim: str = "",
    memory_id: str = "",
) -> dict:
    """
    Store a memory with a custody chain bound to it from genesis.

    Every memory stored in MNEME carries its own SHA-256 hash chain from
    birth. Content is immutable (Invariant M1): an "update" is a new
    memory that supersedes the old one, not an edit.

    If topic + claim are provided and another memory with the same topic
    but a different claim exists, bidirectional INHIBITORY links are
    created and CONTRADICTED_BY custody events are written on BOTH chains.

    Args:
        content: The text content to store (immutable once stored).
        actor_id: Identity of the actor storing this memory.
        reason: Why this memory is being stored (mandatory, travels with custody).
        topic: Optional topic tag for contradiction detection.
        claim: Optional claim — same topic + different claim = INHIBITORY link.
        memory_id: Optional custom ID. Auto-generated if empty.

    Returns:
        memory_id, content_sha256, and any INHIBITORY links created.
    """
    content = _trunc(content)
    actor_id = _sanitize_id(actor_id, "actor_id")
    reason = _trunc(reason, 512)

    if not content.strip():
        return {"error": "content must be non-empty."}
    if not reason.strip():
        return {"error": "reason must be non-empty (M2: no unreasoned event)."}

    if not memory_id:
        memory_id = f"mem-{uuid.uuid4().hex[:16]}"
    else:
        memory_id = _sanitize_id(memory_id, "memory_id")

    embedding = _deterministic_embedding(content)

    conn = _get_conn()
    _ensure_actor(conn, actor_id)
    cur = conn.cursor()
    try:
        result = field.store(
            cur,
            memory_id=memory_id,
            content=content,
            embedding=embedding,
            embedding_model="deterministic-sha256-v1",
            actor_id=actor_id,
            reason=reason,
            topic=topic or None,
            claim=claim or None,
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return {"error": str(exc)}
    finally:
        conn.close()

    return {
        "memory_id": result.memory_id,
        "content_sha256": result.content_sha256,
        "inhibitory_links": list(result.inhibitory_links),
        "embedding_model": "deterministic-sha256-v1",
        "is_semantic": False,
    }


@mcp.tool()
def mneme_recall(
    query: str,
    top_k: int = 5,
    hops: int = 2,
) -> dict:
    """
    Custody-gated, exactly-ranked recall.

    Only memories with custody_status=CLEAN are servable. QUARANTINED,
    TAINT_FLAGGED, and SUPERSEDED memories are invisible — preserved as
    evidence but never served to the agent.

    Rankings are exact Fraction arithmetic: same DB state + same query =
    byte-identical results on any machine (no floats, no BLAS, no seed).

    Returns a sealed recall receipt (SHA-256 digest over the served set
    and exclusion counts) that proves what was served and what was withheld.

    Args:
        query: Text to search for (embedded deterministically).
        top_k: Maximum results (1-20).
        hops: BFS expansion depth (0=seed only, 2=default).

    Returns:
        Ranked results with scores, receipt digest, and exclusion counts.
    """
    query = _trunc(query)
    if not query.strip():
        return {"error": "query must be non-empty."}

    top_k = max(1, min(int(top_k), 20))
    hops = max(0, min(int(hops), 4))

    query_embedding = _deterministic_embedding(query)

    conn = _get_conn()
    cur = conn.cursor()
    try:
        hits, receipt = field.recall(
            cur,
            query_embedding=query_embedding,
            top_k=top_k,
            hops=hops,
        )
    except Exception as exc:
        conn.close()
        return {"error": str(exc)}
    conn.close()

    return {
        "count": len(hits),
        "results": [
            {
                "memory_id": h.memory_id,
                "content": h.content,
                "score": str(h.score),
                "hop_distance": h.hop_distance,
                "field_state": h.field_state,
                "inhibition_rescued": h.inhibition_rescued,
            }
            for h in hits
        ],
        "receipt": {
            "receipt_sha256": receipt.receipt_sha256,
            "seed_memory_id": receipt.seed_memory_id,
            "served": list(receipt.served),
            "excluded_custody": receipt.excluded_custody,
            "excluded_forgotten": receipt.excluded_forgotten,
            "excluded_inhibited": receipt.excluded_inhibited,
        },
        "embedding_model": "deterministic-sha256-v1",
        "is_semantic": False,
    }


@mcp.tool()
def mneme_reinforce(
    memory_id: str,
    actor_id: str = "mcp_agent",
    reason: str = "reinforced via MCP",
) -> dict:
    """
    Reinforce a memory — increases confidence via the exact closed-form
    c' = c + alpha*(1-c). Promotes to REINFORCED state when confidence
    crosses the promotion threshold.

    Only CLEAN memories can be reinforced — reinforcing a tainted memory
    would launder taint into confidence.

    Args:
        memory_id: The memory to reinforce.
        actor_id: Who is reinforcing (recorded in custody chain).
        reason: Why (mandatory — travels with the custody event).

    Returns:
        New confidence value and field state.
    """
    memory_id = _sanitize_id(memory_id, "memory_id")
    actor_id = _sanitize_id(actor_id, "actor_id")

    conn = _get_conn()
    _ensure_actor(conn, actor_id)
    cur = conn.cursor()
    try:
        conf, state = field.reinforce(
            cur, memory_id=memory_id, actor_id=actor_id, reason=reason,
        )
        conn.commit()
    except (ValueError, Exception) as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()

    return {
        "memory_id": memory_id,
        "confidence": str(conf),
        "field_state": state,
    }


@mcp.tool()
def mneme_quarantine_actor(
    actor_id: str,
    initiated_by: str = "mcp_agent",
    reason: str = "",
) -> dict:
    """
    Quarantine an actor and taint-flag every memory they ever touched.

    This is the nuclear option for a poisoned-RAG incident: one call
    deterministically flags every memory the compromised actor influenced.
    The flagged set is sealed with SHA-256 so tampering with it is
    self-revealing.

    Being CONTRADICTED BY the actor is NOT being touched — taint tracks
    influence, not enmity, so quarantining an attacker never silences the
    memories it attacked.

    Args:
        actor_id: The actor to quarantine.
        initiated_by: Who initiated the quarantine (must be a registered actor).
        reason: Why (mandatory — unreasoned quarantine cannot exist).

    Returns:
        Sweep ID, count of flagged memories, sealed digest, and advisory
        resonant neighbours (reported, not auto-flagged).
    """
    actor_id = _sanitize_id(actor_id, "actor_id")
    initiated_by = _sanitize_id(initiated_by, "initiated_by")

    if not reason.strip():
        return {"error": "reason must be non-empty."}

    conn = _get_conn()
    _ensure_actor(conn, initiated_by)
    cur = conn.cursor()
    try:
        sweep = trust.quarantine_actor(
            cur,
            actor_id=actor_id,
            initiated_by=initiated_by,
            reason=reason,
        )
        conn.commit()
    except (ValueError, Exception) as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()

    return {
        "sweep_id": sweep.sweep_id,
        "quarantined_actor": sweep.quarantined_actor,
        "flagged_count": len(sweep.flagged_memory_ids),
        "flagged_memory_ids": list(sweep.flagged_memory_ids),
        "flagged_ids_sha256": sweep.flagged_ids_sha256,
        "advisory_resonant_neighbours": list(sweep.advisory_resonant_neighbours),
    }


@mcp.tool()
def mneme_rehabilitate(
    memory_id: str,
    actor_id: str = "mcp_agent",
    reason: str = "",
) -> dict:
    """
    Rehabilitate a TAINT_FLAGGED memory back to CLEAN status.

    Only TAINT_FLAGGED memories can be rehabilitated (not directly
    QUARANTINED ones). Rehabilitation is an audited event — the reason
    explains why the taint was a false positive.

    Args:
        memory_id: The memory to rehabilitate.
        actor_id: Who is rehabilitating.
        reason: Why (mandatory).

    Returns:
        Confirmation of rehabilitation.
    """
    memory_id = _sanitize_id(memory_id, "memory_id")
    actor_id = _sanitize_id(actor_id, "actor_id")

    if not reason.strip():
        return {"error": "reason must be non-empty."}

    conn = _get_conn()
    _ensure_actor(conn, actor_id)
    cur = conn.cursor()
    try:
        trust.rehabilitate_memory(
            cur, memory_id=memory_id, actor_id=actor_id, reason=reason,
        )
        conn.commit()
    except (ValueError, Exception) as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()

    return {
        "memory_id": memory_id,
        "custody_status": "CLEAN",
        "rehabilitated": True,
    }


@mcp.tool()
def mneme_export_bundle(memory_ids: str = "") -> dict:
    """
    Export a sealed evidence bundle as JSON.

    The bundle is self-contained: nothing in it requires the database to
    interpret. It includes: each memory's content + custody chain, taint
    sweeps, and a Merkle root over all chain heads.

    Send the bundle + verify_offline.py to anyone who distrusts the
    system. They can verify B1-B6 checks with nothing but stdlib Python.

    Args:
        memory_ids: Comma-separated list of memory IDs to export.
            Empty = export the entire field.

    Returns:
        The sealed bundle JSON and its SHA-256 digest.
    """
    ids = [_sanitize_id(x.strip(), "memory_id")
           for x in memory_ids.split(",") if x.strip()] if memory_ids else None

    conn = _get_conn()
    cur = conn.cursor()
    try:
        bundle_json = bundle.export_bundle(cur, memory_ids=ids)
    except (ValueError, Exception) as exc:
        conn.close()
        return {"error": str(exc)}
    conn.close()

    outer = json.loads(bundle_json)
    return {
        "bundle_sha256": outer["bundle_sha256"],
        "memory_count": len(outer["body"]["memories"]),
        "sweeps_count": len(outer["body"]["sweeps"]),
        "heads_merkle_root": outer["body"]["heads_merkle_root"],
        "bundle_json": bundle_json,
    }


@mcp.tool()
def mneme_verify_bundle(bundle_json: str) -> dict:
    """
    Verify a MNEME evidence bundle (B1-B6 checks).

    This is the forensic handoff tool: an auditor who distrusts the
    entire deployment can call this with a bundle received from any
    source and get a structured verdict.

    Checks performed:
      B1 — Content hash matches stored content
      B2 — Custody chain linkage and temporal ordering
      B3 — Entry hash recomputes from its fields
      B4 — State is derivable from replaying the chain
      B5 — Taint sweep seals match the flagged sets
      B6 — Merkle root over chain heads

    Args:
        bundle_json: The full JSON bundle string to verify.

    Returns:
        pass/fail verdict and one line per detected lie.
    """
    if not bundle_json or not bundle_json.strip():
        return {"error": "bundle_json must be non-empty."}

    ok, errors = bundle.verify_bundle(bundle_json)
    return {
        "verified": ok,
        "errors": errors,
        "verdict": (
            "VERIFIED: every check (B1-B6) passed."
            if ok else
            f"FAILED: {len(errors)} problem(s) detected."
        ),
    }


@mcp.tool()
def mneme_custody_chain(memory_id: str) -> dict:
    """
    Return the full custody chain for a memory — every event from
    genesis (STORED) to the current head.

    Each entry includes: seq, event_type, actor_id, reason, timestamp,
    payload, and the hash linking it to the previous entry.

    Args:
        memory_id: The memory whose chain to retrieve.

    Returns:
        The ordered custody chain entries.
    """
    memory_id = _sanitize_id(memory_id, "memory_id")

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT memory_id, seq, event_type, actor_id, reason, created_at, "
        "payload_json, prev_hash, entry_hash FROM custody_chain "
        "WHERE memory_id = ? ORDER BY seq ASC", (memory_id,),
    )
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return {"error": f"No custody chain found for {memory_id}."}

    cols = ["memory_id", "seq", "event_type", "actor_id", "reason",
            "created_at", "payload_json", "prev_hash", "entry_hash"]
    entries = [dict(zip(cols, r)) for r in rows]

    return {
        "memory_id": memory_id,
        "chain_length": len(entries),
        "head_hash": entries[-1]["entry_hash"],
        "entries": entries,
    }


@mcp.tool()
def mneme_info() -> dict:
    """
    Describe MNEME's architecture, invariants, and guarantees.
    Call this first to understand how the memory system works.
    """
    conn = _get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM memories")
    total = cur.fetchone()[0]
    cur.execute("SELECT custody_status, COUNT(*) FROM memories GROUP BY custody_status")
    status_dist = dict(cur.fetchall())
    cur.execute("SELECT field_state, COUNT(*) FROM memories GROUP BY field_state")
    state_dist = dict(cur.fetchall())
    cur.execute("SELECT COUNT(*) FROM actors")
    actors = cur.fetchone()[0]
    conn.close()

    return {
        "name": "MNEME",
        "description": (
            "Memory layer with per-memory verifiable chain of custody. "
            "Every memory carries its own SHA-256 hash chain from genesis. "
            "Recall is custody-gated: tainted memories are invisible to agents "
            "but preserved as evidence. Rankings are exact Fraction arithmetic."
        ),
        "invariants": {
            "M1": "Memory content is immutable. Supersession is an event, not an edit.",
            "M2": "No state transition without a custody event in the same transaction.",
            "M3": "Custody chains are append-only, per-memory, seq dense from 0.",
            "M4": "Nothing is deleted. QUARANTINED/TAINT_FLAGGED/SUPERSEDED are states.",
            "M5": "Floats never decide. Confidence is Fraction; Decimal at hash boundary.",
        },
        "custody_statuses": {
            "CLEAN": "Servable — visible to recall",
            "TAINT_FLAGGED": "Actor quarantine propagated — invisible, rehabilitable",
            "QUARANTINED": "Direct evidence against this memory — invisible, not rehabilitable",
            "SUPERSEDED": "Replaced by a newer memory — invisible, preserved",
        },
        "embedding_model": "deterministic-sha256-v1 (non-semantic, reproducible)",
        "current_stats": {
            "total_memories": total,
            "custody_status_distribution": status_dist,
            "field_state_distribution": state_dist,
            "registered_actors": actors,
        },
    }


# -- Entry point --------------------------------------------------------------

if __name__ == "__main__":
    log.info("MNEME MCP server starting — db=%s", _DB_PATH)
    mcp.run()
