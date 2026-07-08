"""
MNEME — Per-MEMORY chain of custody. The module that makes this project
a different project.

STIGMERGY chains events per NODE (who wrote what, in order, on this
machine). CRONOS chains events per TRACE (one decision cycle). Neither
answers the question a poisoned-RAG incident actually asks:

    "This memory influenced my agent's answer. Where did it come from,
     who reinforced it, what contradicted it, and can I prove none of
     that history was rewritten after the fact?"

That question is PER MEMORY. So the chain is per memory.

Design decisions, each load-bearing:

  GENESIS IS BOUND TO THE MEMORY ID.
      prev_hash of seq 0 is sha256(b"MNEME_CUSTODY_GENESIS:" || memory_id).
      A custody chain for memory A cannot be grafted onto memory B even
      if every subsequent entry is internally consistent — the graft
      fails at seq 0. (STIGMERGY's genesis is a global constant because
      its chains are per-node and node_id is inside every hashed
      envelope; here the binding moves to genesis so that verification
      of a single exported chain needs nothing but the chain itself and
      the memory_id it claims to describe.)

  THE CONTENT HASH IS SEALED AT BIRTH AND RE-ASSERTED NEVER.
      The STORED event's payload carries content_sha256. Memory content
      is immutable by design (Invariant M1 below); any "update" is a new
      memory whose STORED payload names its predecessor (supersedes).
      History is append-only all the way down.

  ACTOR IDENTITY IS INSIDE EVERY HASH.
      Every event names actor_id (the writer: an agent, a pipeline, a
      human operator). Tampering with attribution is tampering with the
      hash. This is what makes taint propagation (trust.py) meaningful:
      "everything actor X touched" is a verifiable set, not a log grep.

  REASON IS NOT NULL — an unreasoned custody event cannot exist.
      Same discipline as STIGMERGY Invariant 3. "Why" travels with
      "what" or neither travels.

  THE TRANSACTION BELONGS TO THE CALLER.
      append_event() takes a live cursor and never commits. The state
      change (memories table, links, taint flags) and its custody event
      land in the same transaction or not at all.

Invariants (M for MNEME):
  M1  Memory content is immutable. Supersession is an event, not an edit.
  M2  No committed state transition on a memory may exist without a
      custody event in the same transaction.
  M3  Custody chains are append-only and per-memory; seq is dense from 0.
  M4  Nothing is deleted. QUARANTINED / TAINT_FLAGGED / SUPERSEDED are
      states; rehabilitation is an audited event, not a row removal.
  M5  Floats never decide. Confidence and trust arithmetic is Fraction;
      Decimal only at the hash/SQL boundary via canonical.quantize.

Hash formula (verified in verify_custody_chain, tested in tests/):

    entry_hash = sha256(
        prev_hash
        || canonical_json({
             "memory_id":  memory_id,
             "seq":        seq,
             "event_type": event_type,
             "actor_id":   actor_id,
             "reason":     reason,
             "created_at": <canonical timestamp string>,
             "payload":    payload,
           })
    )                                              -> hex digest

The timestamp is APP-GENERATED (UTC, microsecond precision) and inserted
explicitly rather than left to a column DEFAULT: the hash must cover it,
and to cover it the value must exist before the INSERT. One formatter
(format_ts) is used both when writing and when verifying.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_json

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# The closed set of custody event types. Closed ON PURPOSE: a verifier
# that meets an unknown event_type must fail, not shrug — an open
# vocabulary is where "creative" writers smuggle unaudited semantics.
EVENT_TYPES = frozenset(
    {
        "STORED",           # birth; payload MUST carry content_sha256
        "REINFORCED",       # confidence raised (recall hit, corroboration)
        "CONTRADICTED_BY",  # another memory conflicts; payload names it
        "SUPERSEDED_BY",    # a newer memory replaces this one; payload names it
        "QUARANTINED",      # direct action against this memory
        "TAINT_FLAGGED",    # transitive: an actor in this chain was quarantined
        "REHABILITATED",    # audited reversal of QUARANTINED/TAINT_FLAGGED
        "STATE_CHANGED",    # field-state transition (REINFORCED/NEUTRAL/FORGOTTEN)
    }
)

_MAX_ID_LEN = 64
_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:]+$")

_GENESIS_PREFIX = b"MNEME_CUSTODY_GENESIS:"

# The canonical timestamp form that format_ts() emits: UTC, microsecond
# precision, explicit +00:00 offset. Verification re-asserts this shape so
# that (a) a lexicographic comparison of two created_at strings equals a
# chronological one — true only for a fixed-width UTC format, which is why
# a rogue offset like +05:00 is refused — and (b) the discipline enforced
# at WRITE is also enforced at READ, not merely trusted.
_TS_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")


def genesis_hash(memory_id: str) -> str:
    """
    Per-memory genesis. Binding the memory_id into seq 0's prev_hash is
    what makes chain grafting (custody of A presented as custody of B)
    structurally impossible rather than merely detectable.
    """
    _require_id(memory_id, "memory_id")
    return hashlib.sha256(_GENESIS_PREFIX + memory_id.encode("utf-8")).hexdigest()


def format_ts(ts: datetime) -> str:
    """
    The single canonical timestamp formatter. UTC, microsecond precision,
    ISO 8601 with explicit offset. Used when writing AND when verifying,
    so a round-trip through the database cannot introduce drift.
    """
    if ts.tzinfo is None:
        raise ValueError("Naive datetime refused — custody timestamps are UTC-aware.")
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


def now_ts() -> str:
    return format_ts(datetime.now(timezone.utc))


def content_sha256(content: str) -> str:
    """Content identity. UTF-8 bytes, nothing clever."""
    if not isinstance(content, str):
        raise TypeError("Memory content must be str.")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _require_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string.")
    if len(value) > _MAX_ID_LEN:
        raise ValueError(f"{field} exceeds {_MAX_ID_LEN} chars.")
    if not _ID_PATTERN.match(value):
        raise ValueError(
            f"{field} contains characters outside [a-zA-Z0-9_-.:]. "
            "Identifiers participate in genesis hashes and leaf "
            "derivations; a permissive charset is an ambiguity budget "
            "we refuse to spend."
        )


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def compute_entry_hash(
    *,
    prev_hash: str,
    memory_id: str,
    seq: int,
    event_type: str,
    actor_id: str,
    reason: str,
    created_at: str,
    payload: dict[str, Any],
) -> tuple[str, str]:
    """
    Returns (entry_hash, canonical_payload_json).

    The canonical serialization is returned so the caller stores EXACTLY
    the bytes that were hashed — stored bytes and hashed bytes cannot
    drift (same discipline as STIGMERGY's canonical_json contract).
    """
    envelope = {
        "memory_id": memory_id,
        "seq": seq,
        "event_type": event_type,
        "actor_id": actor_id,
        "reason": reason,
        "created_at": created_at,
        "payload": payload,
    }
    canonical = canonical_json(envelope)
    entry_hash = hashlib.sha256(
        prev_hash.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()
    # Store only the payload's canonical form; the envelope fields live
    # in their own columns. Serialize payload separately so the stored
    # payload_json is byte-identical to what the verifier will re-embed.
    return entry_hash, canonical_json(payload)


# ---------------------------------------------------------------------------
# Append (caller owns the transaction)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CustodyEntry:
    memory_id: str
    seq: int
    event_type: str
    actor_id: str
    reason: str
    created_at: str
    payload_json: str
    prev_hash: str
    entry_hash: str


def append_event(
    cur,
    *,
    memory_id: str,
    event_type: str,
    actor_id: str,
    reason: str,
    payload: dict[str, Any],
    created_at: str | None = None,
) -> CustodyEntry:
    """
    Append one custody event for memory_id. NEVER commits — the caller's
    transaction also carries the state change this event describes
    (Invariant M2 is true by construction, not by care).

    Enforcement here, with our words, before SQL can object with its own:
      - event_type must be in the closed vocabulary;
      - reason must be non-empty (an unreasoned event cannot exist);
      - STORED must be seq 0 and must carry content_sha256;
      - any non-STORED event on a chain with no head is refused
        (custody begins at birth, not at first incident).
    """
    _require_id(memory_id, "memory_id")
    _require_id(actor_id, "actor_id")
    if event_type not in EVENT_TYPES:
        raise ValueError(
            f"Unknown custody event_type {event_type!r}. The vocabulary is "
            "closed; extending it is a protocol change, not a call-site choice."
        )
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be a non-empty string — unreasoned custody events cannot exist.")

    cur.execute(
        "SELECT seq, entry_hash FROM custody_chain WHERE memory_id = ? "
        "ORDER BY seq DESC LIMIT 1",
        (memory_id,),
    )
    row = cur.fetchone()

    if row is None:
        if event_type != "STORED":
            raise ValueError(
                f"First custody event for {memory_id} must be STORED, got "
                f"{event_type}. Custody begins at birth."
            )
        seq = 0
        prev_hash = genesis_hash(memory_id)
    else:
        if event_type == "STORED":
            raise ValueError(
                f"{memory_id} already has a custody chain; STORED is a birth "
                "event and a memory is born once. Supersession is the path "
                "for new content (Invariant M1)."
            )
        seq = int(row[0]) + 1
        prev_hash = str(row[1])

    if event_type == "STORED":
        csha = payload.get("content_sha256")
        if not (isinstance(csha, str) and re.fullmatch(r"[0-9a-f]{64}", csha)):
            raise ValueError(
                "STORED payload must carry content_sha256 (64 lowercase hex). "
                "A birth event that does not seal the content seals nothing."
            )

    ts = created_at if created_at is not None else now_ts()
    entry_hash, payload_canon = compute_entry_hash(
        prev_hash=prev_hash,
        memory_id=memory_id,
        seq=seq,
        event_type=event_type,
        actor_id=actor_id,
        reason=reason,
        created_at=ts,
        payload=payload,
    )

    cur.execute(
        "INSERT INTO custody_chain "
        "(memory_id, seq, event_type, actor_id, reason, created_at, "
        " payload_json, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (memory_id, seq, event_type, actor_id, reason, ts,
         payload_canon, prev_hash, entry_hash),
    )
    return CustodyEntry(
        memory_id=memory_id, seq=seq, event_type=event_type,
        actor_id=actor_id, reason=reason, created_at=ts,
        payload_json=payload_canon, prev_hash=prev_hash, entry_hash=entry_hash,
    )


# ---------------------------------------------------------------------------
# Verification (pure over rows; the offline verifier reuses this)
# ---------------------------------------------------------------------------

def verify_custody_rows(memory_id: str, rows: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """
    Verify a full custody chain given its rows in ASCENDING seq order.
    Pure — no cursor — so the 0-dependency offline verifier and the
    online API share one implementation and cannot disagree.

    Checks, in order of what breaks first when someone lies:
      1. non-empty; seq dense from 0; first event STORED, STORED only at 0
      2. genesis binding: rows[0].prev_hash == genesis_hash(memory_id)
      3. linkage: rows[i].prev_hash == rows[i-1].entry_hash
      4. recomputation: every entry_hash re-derives from its fields
      5. vocabulary: every event_type is known
      6. payload is valid JSON whose canonical form matches stored bytes
      7. created_at is canonical UTC form AND non-decreasing along seq —
         a chain cannot run backwards in time. Integrity and insertion
         order are not enough: a hash-valid chain whose seq-1 event is
         timestamped before its seq-0 birth is a history that cannot have
         happened, and evidence that cannot have happened is not evidence.
    """
    import json as _json

    errors: list[str] = []
    if not rows:
        return False, [f"{memory_id}: empty custody chain — a memory without a birth event."]

    expected_prev = genesis_hash(memory_id)
    prev_ts: str | None = None
    for i, r in enumerate(rows):
        where = f"{memory_id} seq {r.get('seq')}"
        if r.get("seq") != i:
            errors.append(f"{where}: seq not dense (expected {i}).")
            return False, errors
        et = r.get("event_type")
        if et not in EVENT_TYPES:
            errors.append(f"{where}: unknown event_type {et!r}.")
            return False, errors
        if i == 0 and et != "STORED":
            errors.append(f"{where}: chain does not begin with STORED.")
            return False, errors
        if i > 0 and et == "STORED":
            errors.append(f"{where}: STORED after birth — duplicated genesis semantics.")
            return False, errors
        if r.get("prev_hash") != expected_prev:
            errors.append(f"{where}: prev_hash does not link (chain broken or grafted).")
            return False, errors

        try:
            payload = _json.loads(r["payload_json"])
        except Exception:
            errors.append(f"{where}: payload_json is not valid JSON.")
            return False, errors
        if canonical_json(payload) != r["payload_json"]:
            errors.append(
                f"{where}: stored payload_json is not in canonical form — "
                "stored bytes and hashed bytes have drifted."
            )
            return False, errors

        recomputed, _ = compute_entry_hash(
            prev_hash=r["prev_hash"],
            memory_id=memory_id,
            seq=r["seq"],
            event_type=et,
            actor_id=r["actor_id"],
            reason=r["reason"],
            created_at=r["created_at"],
            payload=payload,
        )
        if recomputed != r["entry_hash"]:
            errors.append(f"{where}: entry_hash does not recompute — content tampered.")
            return False, errors

        ts = r["created_at"]
        if not isinstance(ts, str) or not _TS_PATTERN.match(ts):
            errors.append(f"{where}: created_at {ts!r} is not canonical UTC "
                          "microsecond ISO 8601 (…+00:00) — a rogue offset "
                          "would make timestamp ordering a lie.")
            return False, errors
        if prev_ts is not None and ts < prev_ts:
            errors.append(f"{where}: created_at {ts} precedes the previous "
                          f"event's {prev_ts} — a custody chain cannot run "
                          "backwards in time.")
            return False, errors
        prev_ts = ts
        expected_prev = r["entry_hash"]

    return True, []


def verify_custody_chain(cur, memory_id: str) -> tuple[bool, list[str]]:
    """Load and verify one memory's full custody chain."""
    cur.execute(
        "SELECT memory_id, seq, event_type, actor_id, reason, created_at, "
        "payload_json, prev_hash, entry_hash FROM custody_chain "
        "WHERE memory_id = ? ORDER BY seq ASC",
        (memory_id,),
    )
    cols = ["memory_id", "seq", "event_type", "actor_id", "reason",
            "created_at", "payload_json", "prev_hash", "entry_hash"]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    return verify_custody_rows(memory_id, rows)
