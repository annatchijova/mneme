"""
MNEME — Actor quarantine and deterministic taint propagation.

The scenario this module exists for: you discover that a data source
(an ingestion pipeline, a scraping agent, a compromised colleague
account) was feeding poisoned content into your agent's memory. The
question is never "delete its memories" — under Invariant M4 nothing is
deleted, and deletion would also destroy the evidence. The question is:

    "Show me EVERYTHING this actor touched, flag all of it so recall
     stops serving it, seal the flagging itself so nobody can later
     dispute what was flagged — and make the whole operation
     reproducible from the audit trail alone."

Definition of "touched" (deliberately broad, documented, testable):
a memory is tainted by actor X if any event in its custody chain names
X as actor_id — EXCEPT CONTRADICTED_BY. Not just STORED — a poisoned
source that REINFORCED a legitimate memory inflated its confidence,
and that inflation is part of the incident. Analysts can REHABILITATE
false positives; the rehabilitation is itself an audited custody
event. Over-flagging with an audited reversal path is recoverable;
under-flagging is not.

The CONTRADICTED_BY carve-out is an explicit architecture decision,
not a softening. When X stores a memory that contradicts memory V, the
contradiction event lands on V's chain with X as its author — the one
event type through which an actor writes its identity onto an
ARBITRARY victim's chain. Counting it as "touched" hands an attacker a
lever: contradict every truth you want suppressed, and the day you are
quarantined, the sweep silences your victims for you — a validated
truth silenced by an unverified claim, the exact outcome the rescue
rule exists to refuse. Taint tracks INFLUENCE (events that created a
memory or raised its standing); being attacked by X is not influence
by X. The attacker's own contradicting memory is still flagged through
its STORED event, and the victim's chain still carries the
CONTRADICTED_BY evidence for any auditor to see.

Determinism: the flagged set is derived from the custody_chain table by
one SQL query with a total ORDER BY; the sweep seals
sha256(canonical_json({"memory_ids": sorted_ids})) so two replays of the
same database state produce byte-identical sweep evidence.

Scoping note (KNOWN_LIMITATIONS candidate): taint here is DIRECT
(actor appears in the chain). TRANSITIVE taint — memory A tainted, and
A's RESONANT links inflated B via STDP — is real but unbounded; Phase 1
surfaces the one-hop resonant neighbourhood of flagged memories as a
REPORT (advisory), not as automatic flags. Automatic transitive
flagging without a fixpoint bound is how a quarantine becomes a
self-inflicted denial of service on your own memory.

As everywhere: modules take a live cursor and NEVER commit (M2).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from . import custody


@dataclass(frozen=True)
class TaintSweep:
    sweep_id: str
    quarantined_actor: str
    initiated_by: str
    reason: str
    created_at: str
    flagged_memory_ids: tuple[str, ...]
    flagged_ids_sha256: str
    advisory_resonant_neighbours: tuple[str, ...]


def _seal_ids(memory_ids: list[str]) -> str:
    return hashlib.sha256(
        canonical_json({"memory_ids": memory_ids}).encode("utf-8")
    ).hexdigest()


def quarantine_actor(
    cur,
    *,
    actor_id: str,
    initiated_by: str,
    reason: str,
    created_at: str | None = None,
) -> TaintSweep:
    """
    Quarantine an actor and taint-flag every memory whose custody chain
    it appears in. One logical operation, one transaction (the caller's):

      1. actors.status -> QUARANTINED (idempotence: re-quarantining an
         already-quarantined actor is refused with our words — a second
         sweep for the same incident would double-write custody events
         and split the evidence across two sweep ids).
      2. SELECT DISTINCT memory_id FROM custody_chain WHERE actor_id = X
         AND event_type != 'CONTRADICTED_BY' ORDER BY memory_id — the
         deterministic flagged set (see the module header for why being
         contradicted by X is not being touched by X).
      3. For each: custody event TAINT_FLAGGED + custody_status update
         (only if currently CLEAN; QUARANTINED/SUPERSEDED memories keep
         their stronger status, but the custody event is still written —
         the chain records that the sweep saw them).
      4. taint_sweeps row sealing the sorted id list.
      5. Advisory: one-hop RESONANT neighbours of the flagged set that
         are NOT themselves flagged — reported, not flagged (see header).
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be non-empty — an unreasoned quarantine cannot exist.")

    cur.execute("SELECT status FROM actors WHERE actor_id = ?", (actor_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown actor {actor_id!r} — quarantine targets a registered identity.")
    if row[0] == "QUARANTINED":
        raise ValueError(
            f"Actor {actor_id!r} is already QUARANTINED. A second sweep for "
            "the same incident would split the evidence; rehabilitate first "
            "if this is a new incident against a restored actor."
        )
    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (initiated_by,))
    if cur.fetchone() is None:
        raise ValueError(f"Unknown initiator {initiated_by!r}.")

    ts = created_at if created_at is not None else custody.now_ts()

    cur.execute(
        "UPDATE actors SET status = 'QUARANTINED' WHERE actor_id = ?", (actor_id,)
    )

    cur.execute(
        "SELECT DISTINCT memory_id FROM custody_chain WHERE actor_id = ? "
        "AND event_type != 'CONTRADICTED_BY' ORDER BY memory_id ASC",
        (actor_id,),
    )
    flagged = [r[0] for r in cur.fetchall()]

    sweep_id = f"sweep-{uuid.uuid4().hex}"
    payload_common: dict[str, Any] = {
        "sweep_id": sweep_id,
        "quarantined_actor": actor_id,
    }

    for mid in flagged:
        custody.append_event(
            cur,
            memory_id=mid,
            event_type="TAINT_FLAGGED",
            actor_id=initiated_by,
            reason=reason,
            payload=dict(payload_common),
            created_at=ts,
        )
        cur.execute(
            "UPDATE memories SET custody_status = 'TAINT_FLAGGED' "
            "WHERE memory_id = ? AND custody_status = 'CLEAN'",
            (mid,),
        )

    seal = _seal_ids(flagged)
    cur.execute(
        "INSERT INTO taint_sweeps (sweep_id, quarantined_actor, initiated_by, "
        "reason, created_at, flagged_count, flagged_ids_sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (sweep_id, actor_id, initiated_by, reason, ts, len(flagged), seal),
    )

    # Advisory one-hop resonant neighbourhood (reported, never auto-flagged).
    neighbours: list[str] = []
    if flagged:
        placeholders = ",".join("?" for _ in flagged)
        cur.execute(
            f"SELECT DISTINCT to_id FROM cell_links "
            f"WHERE link_type = 'RESONANT' AND from_id IN ({placeholders}) "
            f"AND to_id NOT IN ({placeholders}) ORDER BY to_id ASC",
            flagged + flagged,
        )
        neighbours = [r[0] for r in cur.fetchall()]

    return TaintSweep(
        sweep_id=sweep_id,
        quarantined_actor=actor_id,
        initiated_by=initiated_by,
        reason=reason,
        created_at=ts,
        flagged_memory_ids=tuple(flagged),
        flagged_ids_sha256=seal,
        advisory_resonant_neighbours=tuple(neighbours),
    )


def quarantine_memory(
    cur,
    *,
    memory_id: str,
    actor_id: str,
    reason: str,
    created_at: str | None = None,
) -> None:
    """
    Direct quarantine of ONE memory: the analyst has evidence against
    this memory itself (not merely against an actor in its chain).
    QUARANTINED custody event + status update, one transaction, the
    caller's.

    Allowed from any status except QUARANTINED itself: upgrading a
    TAINT_FLAGGED memory records that suspicion became direct evidence,
    and quarantining a SUPERSEDED memory records incrimination the
    supersession must not bury. Re-quarantining is refused — the second
    incident's evidence belongs in the first event's chain succession,
    not in a duplicate status write.

    There is deliberately NO reversal here: rehabilitate_memory()
    reverses TAINT_FLAGGED only. Undoing a direct quarantine is a
    stronger claim with no designed review path yet — named in
    KNOWN_LIMITATIONS, arriving with its own invariant or not at all.
    """
    cur.execute("SELECT custody_status FROM memories WHERE memory_id = ?",
                (memory_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown memory {memory_id!r}.")
    if row[0] == "QUARANTINED":
        raise ValueError(
            f"{memory_id} is already QUARANTINED — a duplicate quarantine "
            "would add a status write with no new evidence."
        )
    ts = created_at if created_at is not None else custody.now_ts()
    custody.append_event(
        cur, memory_id=memory_id, event_type="QUARANTINED",
        actor_id=actor_id, reason=reason, payload={}, created_at=ts,
    )
    cur.execute(
        "UPDATE memories SET custody_status = 'QUARANTINED' WHERE memory_id = ?",
        (memory_id,),
    )


def rehabilitate_memory(
    cur,
    *,
    memory_id: str,
    actor_id: str,
    reason: str,
    created_at: str | None = None,
) -> None:
    """
    Audited reversal of TAINT_FLAGGED for one memory (analyst reviewed a
    false positive). QUARANTINED memories are NOT rehabilitated here —
    direct quarantine is a stronger claim requiring its own review path;
    conflating the two reversals would let a bulk false-positive cleanup
    silently un-quarantine directly-incriminated memories.

    Security audit Round 2, H3: reversing a taint flag is exactly as
    authority-bearing as raising one, so it is held to the same bar as
    quarantine_actor()'s "unknown initiator" check — actor_id must name a
    registered, non-QUARANTINED actor. Without this, the actor a sweep
    just quarantined could rehabilitate the very memories that sweep
    flagged, reversing its own containment.
    """
    cur.execute("SELECT status FROM actors WHERE actor_id = ?", (actor_id,))
    actor_row = cur.fetchone()
    if actor_row is None:
        raise ValueError(
            f"Unknown actor {actor_id!r} — rehabilitation requires a "
            "registered identity, same as quarantine."
        )
    if actor_row[0] == "QUARANTINED":
        raise ValueError(
            f"Actor {actor_id!r} is QUARANTINED and cannot rehabilitate "
            "memories — an actor under investigation is not its own reviewer."
        )

    cur.execute(
        "SELECT custody_status FROM memories WHERE memory_id = ?", (memory_id,)
    )
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown memory {memory_id!r}.")
    if row[0] != "TAINT_FLAGGED":
        raise ValueError(
            f"{memory_id} has custody_status {row[0]!r}; rehabilitate_memory "
            "reverses TAINT_FLAGGED only."
        )
    ts = created_at if created_at is not None else custody.now_ts()
    custody.append_event(
        cur,
        memory_id=memory_id,
        event_type="REHABILITATED",
        actor_id=actor_id,
        reason=reason,
        payload={"from_status": "TAINT_FLAGGED"},
        created_at=ts,
    )
    cur.execute(
        "UPDATE memories SET custody_status = 'CLEAN' WHERE memory_id = ?",
        (memory_id,),
    )


def verify_sweep(cur, sweep_id: str) -> tuple[bool, list[str]]:
    """
    Re-derive a sweep's flagged set from custody evidence and check it
    against the sealed hash. The claim "we flagged exactly these" becomes
    checkable: the set of memories carrying a TAINT_FLAGGED event with
    this sweep_id in its payload must hash to flagged_ids_sha256.
    """
    import json as _json

    cur.execute(
        "SELECT flagged_count, flagged_ids_sha256 FROM taint_sweeps "
        "WHERE sweep_id = ?",
        (sweep_id,),
    )
    row = cur.fetchone()
    if row is None:
        return False, [f"Unknown sweep {sweep_id!r}."]
    count, seal = int(row[0]), str(row[1])

    cur.execute(
        "SELECT memory_id, payload_json FROM custody_chain "
        "WHERE event_type = 'TAINT_FLAGGED' ORDER BY memory_id ASC",
    )
    ids = []
    for mid, pj in cur.fetchall():
        try:
            payload = _json.loads(pj)
        except Exception:
            return False, [f"{mid}: TAINT_FLAGGED payload is not valid JSON."]
        if payload.get("sweep_id") == sweep_id:
            ids.append(mid)

    errors: list[str] = []
    if len(ids) != count:
        errors.append(
            f"Sweep {sweep_id}: {len(ids)} TAINT_FLAGGED events found, "
            f"row claims {count}."
        )
    if _seal_ids(sorted(ids)) != seal:
        errors.append(f"Sweep {sweep_id}: flagged set does not hash to the seal.")
    return (not errors), errors
