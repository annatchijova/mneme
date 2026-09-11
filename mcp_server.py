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

from mneme import authority, bundle, causality, custody, field, protocol, trust
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
    """
    Register an actor if not already known — ONLY in a field with no
    authority ledger.

    Security audit Round 2, R2-02: this function auto-registering an
    unknown caller as an AGENT, on the same call the caller then used to
    spend authority, was the confused-deputy root. Once a field has an
    authority ledger, minting an identity is itself an authorized act
    (it requires GRANT), so this function refuses and the caller is told
    to use mneme_register_actor with an issuer that actually holds the
    capability.

    In a ledgerless field the legacy behaviour is kept, deliberately and
    visibly: those fields declare every event UNAUTHORIZED BY DECLARATION
    in their bundles, so nothing here is quietly presented as authorized.
    """
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,))
    if cur.fetchone() is not None:
        return
    if authority.ledger_exists(cur):
        raise ValueError(
            f"Unknown actor {actor_id!r}. This field has an authority ledger, "
            "so identities are registered by an actor holding GRANT "
            "(mneme_register_actor) and empowered by an explicit grant "
            "(mneme_grant). Minting an identity on the same call that spends "
            "it is the pattern Round 2 confirmed."
        )
    ts = custody.now_ts()
    cur.execute(
        "INSERT INTO actors (actor_id, display_name, kind, status, created_at) "
        "VALUES (?, ?, ?, 'ACTIVE', ?)",
        (actor_id, actor_id, kind, ts),
    )
    conn.commit()


# -- MCP tools: authority ----------------------------------------------------

@mcp.tool()
def mneme_bootstrap_root(
    actor_id: str,
    display_name: str = "",
    kind: str = "HUMAN",
    reason: str = "field genesis",
) -> dict:
    """
    Create this field's authority ledger and its root actor. ONE TIME.

    Authority has to start somewhere and the first grant cannot itself be
    authorized. This is that act: refused if any authority chain already
    exists, so it happens exactly once per field and the entire ledger
    hangs from it as a single named, timestamped, hash-chained event.

    Until you call this, the field is in the LEDGERLESS regime: writes
    proceed and every evidence bundle it produces says, in words, that all
    of its events are UNAUTHORIZED BY DECLARATION. After you call it, every
    mutator requires a grant, permanently — nothing deletes a chain.

    What this does NOT prove: that the right party performed it. Whoever
    bootstraps an empty field is its root. Binding that to an external
    identity is a deployment concern.

    Args:
        actor_id: The root identity.
        display_name: Human-readable name (defaults to actor_id).
        kind: AGENT, PIPELINE, HUMAN or SYSTEM.
        reason: Why (mandatory — least of all skippable here).

    Returns:
        The root grant id and the full capability vocabulary it confers.
    """
    actor_id = _sanitize_id(actor_id, "actor_id")
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        grant_id = authority.bootstrap_root(
            cur, actor_id=actor_id, display_name=display_name or actor_id,
            kind=kind, reason=_trunc(reason, 512))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {"root_actor": actor_id, "grant_id": grant_id,
            "capabilities": sorted(authority.CAPABILITIES)}


@mcp.tool()
def mneme_register_actor(
    actor_id: str,
    issuer_id: str,
    kind: str = "AGENT",
    display_name: str = "",
    reason: str = "registered via MCP",
) -> dict:
    """
    Register an identity. It holds NOTHING until mneme_grant empowers it.

    Requires the issuer to hold GRANT: minting identities is the first
    half of minting power, so it is held to the same bar as the second.

    Args:
        actor_id: The identity to create.
        issuer_id: Who is registering it — must hold GRANT.
        kind: AGENT, PIPELINE, HUMAN or SYSTEM.
        display_name: Human-readable name (defaults to actor_id).
        reason: Why (mandatory).

    Returns:
        Confirmation, and the (empty) capability set the new identity holds.
    """
    actor_id = _sanitize_id(actor_id, "actor_id")
    issuer_id = _sanitize_id(issuer_id, "issuer_id")
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        authority.register_actor(
            cur, actor_id=actor_id, display_name=display_name or actor_id,
            kind=kind, issuer_id=issuer_id, reason=_trunc(reason, 512))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {"actor_id": actor_id, "registered_by": issuer_id,
            "capabilities": []}


@mcp.tool()
def mneme_grant(
    subject_id: str,
    capabilities: str,
    issuer_id: str,
    reason: str = "granted via MCP",
) -> dict:
    """
    Confer capabilities on an actor, as a hash-chained, revocable grant.

    Capability vocabulary (closed): STORE, REINFORCE, SUPERSEDE,
    QUARANTINE_ACTOR, QUARANTINE_MEMORY, REHABILITATE, GRANT, REVOKE,
    DECIDE.

    NO AMPLIFICATION (Invariant A3): the issuer must itself hold every
    capability it confers. Authority is delegated, never invented — which
    is what makes every capability in the field traceable, by a path of
    checkable grants, back to the root bootstrap.

    Args:
        subject_id: Who receives the capabilities.
        capabilities: Comma-separated capability names.
        issuer_id: Who is granting — must hold GRANT and every capability listed.
        reason: Why (mandatory — an unreasoned grant is one nobody can review).

    Returns:
        The grant id, which every custody event written under it will name.
    """
    subject_id = _sanitize_id(subject_id, "subject_id")
    issuer_id = _sanitize_id(issuer_id, "issuer_id")
    caps = [c.strip().upper() for c in capabilities.split(",") if c.strip()]
    if not caps:
        return {"error": "capabilities must name at least one capability."}
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        gid = authority.grant(cur, subject_id=subject_id, capabilities=caps,
                              issuer_id=issuer_id, reason=_trunc(reason, 512))
        conn.commit()
        effective = sorted(authority.effective_capabilities(cur, subject_id))
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {"grant_id": gid, "subject_id": subject_id,
            "granted": sorted(set(caps)), "effective_capabilities": effective}


@mcp.tool()
def mneme_revoke(
    subject_id: str,
    grant_id: str,
    issuer_id: str,
    reason: str = "revoked via MCP",
) -> dict:
    """
    End a grant. The grant stays on the chain forever with the instant it
    died (Invariant A4), so every act it authorized BEFORE that instant
    stays authorized and every bundle sealed then keeps verifying.

    Refused if it would revoke the last grant conferring GRANT (A6): a
    field nobody can ever authorize anything in again — including its own
    repair — is indistinguishable from a successful attack.

    Args:
        subject_id: Whose grant is being ended.
        grant_id: Which grant.
        issuer_id: Who is revoking — must hold REVOKE.
        reason: Why (mandatory).

    Returns:
        The subject's remaining effective capabilities.
    """
    subject_id = _sanitize_id(subject_id, "subject_id")
    issuer_id = _sanitize_id(issuer_id, "issuer_id")
    grant_id = _sanitize_id(grant_id, "grant_id")
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        authority.revoke(cur, subject_id=subject_id, grant_id=grant_id,
                         issuer_id=issuer_id, reason=_trunc(reason, 512))
        conn.commit()
        effective = sorted(authority.effective_capabilities(cur, subject_id))
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {"subject_id": subject_id, "revoked_grant": grant_id,
            "effective_capabilities": effective}


@mcp.tool()
def mneme_reinstate_actor(
    subject_id: str,
    issuer_id: str,
    reason: str = "investigation cleared the actor",
) -> dict:
    """
    Close a quarantine interval: the actor may write again.

    Requires QUARANTINE_ACTOR — the capability to contain is the
    capability to release. Self-reinstatement is refused: an actor under
    investigation is not its own reviewer.

    The memories the sweep flagged STAY flagged. Reinstating the actor and
    rehabilitating its memories are separate claims with separate
    evidence; conflating them would let one call quietly reverse a whole
    sweep.

    Args:
        subject_id: The quarantined actor.
        issuer_id: Who is reinstating — must hold QUARANTINE_ACTOR.
        reason: Why (mandatory).

    Returns:
        The actor's restored capabilities.
    """
    subject_id = _sanitize_id(subject_id, "subject_id")
    issuer_id = _sanitize_id(issuer_id, "issuer_id")
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        authority.reinstate_actor(cur, subject_id=subject_id,
                                  issuer_id=issuer_id,
                                  reason=_trunc(reason, 512))
        conn.commit()
        effective = sorted(authority.effective_capabilities(cur, subject_id))
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {"subject_id": subject_id, "status": "ACTIVE",
            "effective_capabilities": effective}


@mcp.tool()
def mneme_authority(actor_id: str = "") -> dict:
    """
    Inspect authority provenance: who may cause what, and on whose word.

    With no actor_id, describes the whole ledger. With one, returns that
    actor's full authority chain — every grant, every revocation, every
    quarantine interval — plus its effective capabilities right now.

    This is the authority half of mneme_custody_chain. Custody answers
    "what happened to this memory"; this answers "who was allowed to
    cause it".

    Args:
        actor_id: Optional — one actor's chain instead of the summary.

    Returns:
        The ledger summary, or one actor's chain and effective capabilities.
    """
    conn = _get_conn()
    cur = conn.cursor()
    try:
        if not authority.ledger_exists(cur):
            conn.close()
            return {
                "ledger": False,
                "note": ("This field has NO authority ledger. Writes proceed "
                         "and every bundle it exports declares its events "
                         "UNAUTHORIZED BY DECLARATION. Call "
                         "mneme_bootstrap_root to start one."),
            }
        if not actor_id:
            cur.execute("SELECT DISTINCT subject_id FROM authority_chain "
                        "ORDER BY subject_id ASC")
            subjects = [r[0] for r in cur.fetchall()]
            summary = []
            for sid in subjects:
                state = authority.load_state(cur, sid)
                summary.append({
                    "actor_id": sid,
                    "status": state.status,
                    "is_root": state.is_root,
                    "effective_capabilities": sorted(
                        authority.capabilities_at(state, custody.now_ts())),
                    "grants": len(state.grants),
                })
            result = {
                "ledger": True,
                "root_actor": authority.root_subject(cur),
                "genesis_at": authority.genesis_at(cur),
                "capability_vocabulary": sorted(authority.CAPABILITIES),
                "actors": summary,
            }
        else:
            actor_id = _sanitize_id(actor_id, "actor_id")
            rows = authority.load_authority_rows(cur, actor_id)
            if not rows:
                conn.close()
                return {"error": f"{actor_id} has no authority chain."}
            state = authority.load_state(cur, actor_id)
            result = {
                "ledger": True,
                "actor_id": actor_id,
                "status": state.status,
                "is_root": state.is_root,
                "registered_at": state.registered_at,
                "registered_by": state.registered_by,
                "effective_capabilities": sorted(
                    authority.capabilities_at(state, custody.now_ts())),
                "grants": {gid: {"capabilities": list(g["capabilities"]),
                                 "granted_at": g["granted_at"],
                                 "granted_by": g["granted_by"],
                                 "revoked_at": g["revoked_at"],
                                 "root": g["root"]}
                           for gid, g in sorted(state.grants.items())},
                "quarantine_intervals": state.quarantine_intervals,
                "chain": rows,
            }
    except Exception as exc:
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return result


# -- MCP tools: memory -------------------------------------------------------

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
    try:
        _ensure_actor(conn, actor_id)
    except ValueError as exc:
        conn.close()
        return {"error": str(exc)}
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
    persist_receipt: bool = False,
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
        persist_receipt: Keep the receipt as evidence. Recall stays
            read-only by default — serving is not a state transition, and
            forcing a write into the hottest read path would invert that.
            Set this when the recall is about to inform a decision:
            mneme_record_decision can only cite a receipt the field kept.

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
        if persist_receipt:
            field.persist_receipt(cur, receipt)
            conn.commit()
    except Exception as exc:
        conn.rollback()
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
            "top_k": receipt.top_k,
            "hops": receipt.hops,
            "ranking_protocol": receipt.ranking_protocol,
            "persisted": bool(persist_receipt),
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
    try:
        _ensure_actor(conn, actor_id)
    except ValueError as exc:
        conn.close()
        return {"error": str(exc)}
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
    initiated_by: str,
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

    Security audit Round 2: `initiated_by` MUST already be a registered,
    non-QUARANTINED actor — this tool does NOT auto-register it. Initiating
    a quarantine is authority-bearing; minting that identity on the same
    call that spends it is the confused-deputy pattern H3/H4 named. Trusted
    reviewer identities are provisioned out-of-band (e.g. inserted directly
    into `actors` by an operator), never through this tool's own call path.

    Args:
        actor_id: The actor to quarantine.
        initiated_by: Who initiated the quarantine — must already be a
            registered, non-QUARANTINED actor. Unknown values are refused.
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
    actor_id: str,
    reason: str = "",
) -> dict:
    """
    Rehabilitate a TAINT_FLAGGED memory back to CLEAN status.

    Only TAINT_FLAGGED memories can be rehabilitated (not directly
    QUARANTINED ones). Rehabilitation is an audited event — the reason
    explains why the taint was a false positive.

    Security audit Round 2, H3: `actor_id` MUST already be a registered,
    non-QUARANTINED actor — this tool does NOT auto-register it. Reversing
    a taint flag is exactly as authority-bearing as raising one; minting a
    trusted-sounding identity on the same call that spends it is the
    confused-deputy pattern this fix closes (it previously let the very
    actor a sweep quarantined rehabilitate its own flagged memories).

    Args:
        memory_id: The memory to rehabilitate.
        actor_id: Who is rehabilitating — must already be a registered,
            non-QUARANTINED actor. Unknown values are refused.
        reason: Why (mandatory).

    Returns:
        Confirmation of rehabilitation.
    """
    memory_id = _sanitize_id(memory_id, "memory_id")
    actor_id = _sanitize_id(actor_id, "actor_id")

    if not reason.strip():
        return {"error": "reason must be non-empty."}

    conn = _get_conn()
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
def mneme_record_decision(
    receipt_sha256: str,
    used_memory_ids: str,
    decision_text: str,
    policy_version: str,
    actor_id: str,
    reason: str = "decision recorded via MCP",
) -> dict:
    """
    Close the loop from recall to action: commit that THIS decision used
    THESE memories, from THAT recall, under THIS policy. Requires DECIDE.

    Without this, MNEME can answer "why did the agent remember X" and
    cannot answer the question an incident actually asks: "which
    decisions were causally contaminated by X". A receipt is evidence
    about a read; a decision record is evidence about an act.

    The decision's TEXT never leaves your process in a form MNEME stores:
    the field commits to sha256(decision_text) so the decision becomes a
    fixed object that cannot be quietly rewritten later, while its
    content stays yours.

    The cited receipt must already be persisted (mneme_recall with
    persist_receipt=true), and used_memory_ids must be a subset of what
    that recall actually served — a decision cannot claim a memory the
    recall never handed it.

    Args:
        receipt_sha256: The persisted recall receipt this decision consumed.
        used_memory_ids: Comma-separated ids the decision actually used.
        decision_text: The decision artifact. Hashed, never stored.
        policy_version: Which rules produced it (e.g. "deploy-policy@3").
        actor_id: Who decided — must hold DECIDE.
        reason: Why (mandatory).

    Returns:
        The decision id and its sealed record digest.
    """
    actor_id = _sanitize_id(actor_id, "actor_id")
    used = [_sanitize_id(m.strip(), "memory_id")
            for m in used_memory_ids.split(",") if m.strip()]
    if not used:
        return {"error": "used_memory_ids must name at least one memory."}
    if not decision_text.strip():
        return {"error": "decision_text must be non-empty."}
    if not reason.strip():
        return {"error": "reason must be non-empty."}
    conn = _get_conn()
    cur = conn.cursor()
    try:
        rec = causality.record_decision(
            cur, receipt=receipt_sha256.strip(), used_memory_ids=used,
            decision_sha256=causality.decision_hash(_trunc(decision_text)),
            policy_version=_trunc(policy_version, 128), actor_id=actor_id,
            reason=_trunc(reason, 512))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {
        "decision_id": rec.decision_id,
        "receipt_sha256": rec.receipt_sha256,
        "decision_sha256": rec.decision_sha256,
        "policy_version": rec.policy_version,
        "used_memory_ids": list(rec.used_memory_ids),
        "record_sha256": rec.record_sha256,
    }


@mcp.tool()
def mneme_impact(memory_id: str) -> dict:
    """
    Blast radius: everything that depended on one memory, reconstructed
    from evidence and GRADED — because equating contact with
    contamination is how one quarantine becomes a denial of service on
    your own field.

    Three levels, and the distinction is the whole point:

      DIRECT    rows, not inference: persisted recalls that served this
                memory, and decisions that used it.
      DERIVED   could not be what it is without it: supersession
                successors, and memories the agent itself declared it
                wrote because of a contaminated decision.
      POSSIBLE  contact only: memories co-served in the same recall, and
                RESONANT neighbours. Reported so an analyst sees the
                perimeter; never acted on, never a custody status.

    This measures and does not contain. Quarantining what it finds is a
    separate, authorized, audited act — a function that both measured and
    contained would make its own measurement impossible to trust.

    Args:
        memory_id: The memory to trace.

    Returns:
        The graded causal DAG and its reproducible seal.
    """
    memory_id = _sanitize_id(memory_id, "memory_id")
    conn = _get_conn()
    cur = conn.cursor()
    try:
        r = causality.impact(cur, memory_id)
    except Exception as exc:
        conn.close()
        return {"error": str(exc)}
    conn.close()
    return {
        "memory_id": r.memory_id,
        "DIRECT": {"receipts": list(r.direct_receipts),
                   "decisions": list(r.direct_decisions)},
        "DERIVED": {"memories": list(r.derived_memories),
                    "decisions": list(r.derived_decisions)},
        "POSSIBLE": {"memories": list(r.possible_memories),
                     "note": ("contact, not contamination — reported for "
                              "analyst review, never auto-flagged")},
        "edges": [list(e) for e in r.edges],
        "impact_sha256": r.impact_sha256,
    }


@mcp.tool()
def mneme_export_bundle(memory_ids: str = "") -> dict:
    """
    Export a sealed evidence bundle as JSON.

    The bundle is self-contained: nothing in it requires the database to
    interpret. It includes: each memory's content + custody chain, taint
    sweeps, and a Merkle root over all chain heads.

    Send the bundle + verify_offline.py to anyone who distrusts the
    system. They can verify B0-B8 checks with nothing but stdlib Python.

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
    Verify a MNEME evidence bundle (B0-B8 checks).

    This is the forensic handoff tool: an auditor who distrusts the
    entire deployment can call this with a bundle received from any
    source and get a structured verdict.

    Checks performed:
      B0 — the bundle declares the VERSION of every semantics its checks
           depend on, and this verifier implements each one
      B1 — bundle seal recomputes over the canonical body
      B2 — custody chain linkage, genesis binding, temporal ordering
      B3 — content hashes to the seal in its birth event
      B4 — state is derivable from replaying the chain
      B5 — taint sweep seals match the flagged sets
      B6 — Merkle root over chain heads
      B7 — AUTHORITY PROVENANCE: every event was not merely recorded but
           authorized, by a grant that was live at that instant, issued by
           someone who held it, traceable to the root

    Args:
        bundle_json: The full JSON bundle string to verify.

    Returns:
        pass/fail verdict and one line per detected lie.
    """
    if not bundle_json or not bundle_json.strip():
        return {"error": "bundle_json must be non-empty."}

    ok, errors, notes = bundle.verify_bundle_verbose(bundle_json)
    return {
        "verified": ok,
        "errors": errors,
        # Claims a PASSING verdict must SHOW rather than bury: declared
        # sweep exclusions, the semantics checked, and any events nobody
        # was ever authorized to cause.
        "notes": notes,
        "verdict": (
            "VERIFIED: every check (B0-B8) passed."
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
    ledger = authority.ledger_exists(cur)
    root_actor = authority.root_subject(cur) if ledger else None
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
        "authority": {
            "model": ("Capabilities, not roles. Every mutation carries two "
                      "separable proofs: integrity provenance (the per-memory "
                      "custody chain) and authority provenance (a grant that "
                      "was live at that instant, on the per-actor authority "
                      "chain). Neither implies the other."),
            "A1": "Every event sealed under the ledger names the grant it acted under.",
            "A2": "Authority chains are per-actor, append-only, genesis-bound to actor_id.",
            "A3": "No amplification: a grantor may only grant what it holds.",
            "A4": "Revocation is an event, never a deletion; past acts stay authorized.",
            "A5": "A QUARANTINED actor holds no capability — a write barrier, not a sweep note.",
            "A6": "The last grant conferring GRANT cannot be revoked.",
            "ledger": ledger,
            "root_actor": root_actor,
            "capability_vocabulary": sorted(authority.CAPABILITIES),
        },
        "protocols": dict(protocol.CURRENT_PROTOCOLS),
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
