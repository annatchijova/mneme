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

SCOPE, AND THE BOUND THAT MAKES IT SAFE. The sweep flags DIRECT taint
only: the actor appears in the chain. TRANSITIVE taint — memory A is
tainted and A's RESONANT links inflated B — is real, and automatic
propagation of it without a bound is how a quarantine becomes a
self-inflicted denial of service on your own memory, because resonance
graphs are connected in practice.

The answer is not to propagate less carelessly; it is to stop equating
contact with contamination. `influence_exposure()` at the foot of this
module spends an exact rational INFLUENCE BUDGET outward from the
tainted set and grades what it reaches: DIRECT_TAINT (evidence names
it), INFLUENCE_EXPOSED (a resonant path carries at least the floor of
influence to it, reported with its exact budget), CLEAN. It terminates
by construction rather than by a visited-set trick, it writes nothing,
and INFLUENCE_EXPOSED is deliberately NOT a custody status. The sweep
still flags only what it can demonstrate; exposure tells an analyst
where to look.

As everywhere: modules take a live cursor and NEVER commit (M2).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .canonical import canonical_json
from . import authority, custody, protocol


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
    grant_id: str | None = None,
) -> TaintSweep:
    """
    Quarantine an actor and taint-flag every memory whose custody chain
    it appears in. One logical operation, one transaction (the caller's).

    AUTHORITY (Round 2, R2-01 and R2-02 together): the initiator must
    hold QUARANTINE_ACTOR, and the quarantine now has TWO halves that
    land in the same transaction —

      retrospective  every memory the actor touched is TAINT_FLAGGED
                     (this was all quarantine ever meant);
      prospective    an ACTOR_QUARANTINED event on the actor's authority
                     chain, from which instant its effective capability
                     set is empty (Invariant A5). The actor cannot store
                     a fresh CLEAN memory, cannot reinforce a clean one,
                     cannot rehabilitate its own evidence.

    Before this, containment was retrospective only: the sweep flagged
    history while the compromised actor kept writing, and a second sweep
    was refused as a duplicate. Flagging the past while the present stays
    open is not containment.

    Step by step:

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
            "the same incident would split the evidence; reinstate the actor "
            "first (authority.reinstate_actor, an audited event) if this is a "
            "new incident against a restored actor."
        )
    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (initiated_by,))
    if cur.fetchone() is None:
        raise ValueError(f"Unknown initiator {initiated_by!r}.")

    ts = created_at if created_at is not None else custody.now_ts()
    sweep_grant = authority.gate(
        cur, actor_id=initiated_by, capability="QUARANTINE_ACTOR", at_ts=ts,
        grant_id=grant_id,
    )
    if authority.ledger_exists(cur):
        # The prospective half. Appended BEFORE the flagging loop so that a
        # failure anywhere below takes the write barrier down with it —
        # a field where the barrier committed but the sweep did not would
        # claim a containment it never performed.
        authority.quarantine_actor_authority(
            cur, subject_id=actor_id, issuer_id=initiated_by, reason=reason,
            created_at=ts,
        )

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
    if sweep_grant is not None:
        payload_common["grant_id"] = sweep_grant

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
    grant_id: str | None = None,
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

    AUTHORITY: QUARANTINE_MEMORY, a capability distinct from
    QUARANTINE_ACTOR on purpose. Incriminating one memory and sweeping an
    entire data source are different-sized claims, and an authority model
    that cannot tell them apart is a role system wearing capability
    vocabulary.
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
    qgrant = authority.gate(cur, actor_id=actor_id,
                            capability="QUARANTINE_MEMORY", at_ts=ts,
                            grant_id=grant_id)
    custody.append_event(
        cur, memory_id=memory_id, event_type="QUARANTINED",
        actor_id=actor_id, reason=reason,
        payload={} if qgrant is None else {"grant_id": qgrant},
        created_at=ts,
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
    grant_id: str | None = None,
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

    Round 2, R2-02, is the deeper half of the same finding and the reason
    REHABILITATE is its own capability: the status check above stops the
    actor a sweep JUST quarantined, and stops nobody else. Any registered
    caller could still nominate itself the reviewer by choosing a string.
    Now the reviewer must hold a grant that someone holding both GRANT
    and REHABILITATE issued, on the record, before this instant — and the
    grant travels in the evidence bundle, where B7 re-derives it.
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
    rgrant = authority.gate(cur, actor_id=actor_id, capability="REHABILITATE",
                            at_ts=ts, grant_id=grant_id)
    rpayload: dict[str, Any] = {"from_status": "TAINT_FLAGGED"}
    if rgrant is not None:
        rpayload["grant_id"] = rgrant
    custody.append_event(
        cur,
        memory_id=memory_id,
        event_type="REHABILITATED",
        actor_id=actor_id,
        reason=reason,
        payload=rpayload,
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


# ---------------------------------------------------------------------------
# Influence budget — the principled bound KNOWN_LIMITATIONS asked for
# ---------------------------------------------------------------------------
#
# The limitation this answers, in its own words: transitive taint is real
# but unbounded, resonance graphs are connected in practice, and automatic
# propagation without a fixpoint bound turns one quarantine into a
# self-inflicted denial of service on the whole field. The note proposed
# hop-limit plus decay threshold. An influence BUDGET is the same idea made
# exact, and it is stronger in one specific way: the bound is not a
# parameter someone tuned until the output looked reasonable, it is a
# consequence of the arithmetic.
#
# THE RULE. Every directly tainted memory starts with influence 1. A
# RESONANT edge conveys INFLUENCE_TRANSFER of whatever reaches its source.
# A memory's exposure is the MAXIMUM over all paths reaching it — the
# strongest line of suspicion, not a sum, because summing lets a
# well-connected memory accumulate past 1 and turns "many weak contacts"
# into a number that looks like proof.
#
# TERMINATION IS STRUCTURAL, not a visited-set trick. Influence along any
# path is strictly decreasing by a factor of 1/2 per edge, and anything
# below EXPOSURE_FLOOR is dropped, so no path longer than
# MAX_INFLUENCE_DEPTH can contribute. Cycles are harmless: a second visit
# to a node necessarily arrives with strictly less influence and is
# discarded. The algorithm cannot fail to halt, for any graph.
#
# INHIBITORY EDGES CONVEY NOTHING. Exactly the CONTRADICTED_BY carve-out
# in this module's header, applied to the graph: being disagreed with by a
# poisoned memory is not being influenced by it. Counting inhibition as
# influence would hand an attacker the same lever — contradict everything
# you want suspected, then get yourself quarantined.
#
# THE GRAPH IS READ WITHOUT THE CUSTODY GATE, deliberately. Recall refuses
# to traverse a non-CLEAN node because it must not let a tainted memory
# perturb what is served TODAY. Exposure asks a historical question —
# what did this memory influence while it was trusted — and gating that
# traversal would hide precisely the paths an incident is about.

INFLUENCE_TRANSFER = Fraction(1, 2)   # a RESONANT edge conveys half
EXPOSURE_FLOOR = Fraction(1, 64)      # below this, suspicion is noise
MAX_INFLUENCE_DEPTH = 6               # = floor(log2(1/EXPOSURE_FLOOR)); derived,
                                      #   never configured independently

EXPOSURE_LEVELS = ("DIRECT_TAINT", "INFLUENCE_EXPOSED", "CLEAN")


@dataclass(frozen=True)
class ExposureReport:
    """
    Three levels, and the whole value is in refusing to collapse them.

      DIRECT_TAINT       evidence names this memory: a sweep flagged it or
                         an analyst quarantined it.
      INFLUENCE_EXPOSED  a RESONANT path from a tainted memory carries at
                         least EXPOSURE_FLOOR of influence to it. Reported
                         with its exact budget, so "how exposed" is a
                         rational number rather than an adjective.
      CLEAN              neither.

    INFLUENCE_EXPOSED is NOT a custody status and this report writes
    nothing. Demonstrated contamination and indirect contact are different
    findings, and a system that quarantines on contact is a system whose
    incident response is indistinguishable from the incident.
    """
    taint_protocol: str
    sources: tuple[str, ...]
    direct_taint: tuple[str, ...]
    exposed: tuple[tuple[str, str], ...]     # (memory_id, exact "n/d" budget)
    clean: tuple[str, ...]
    transfer: str
    floor: str
    max_depth: int
    exposure_sha256: str

    def level(self, memory_id: str) -> str:
        if memory_id in self.direct_taint:
            return "DIRECT_TAINT"
        if any(m == memory_id for m, _ in self.exposed):
            return "INFLUENCE_EXPOSED"
        return "CLEAN"


def influence_exposure(cur, *, sources: list[str] | None = None) -> ExposureReport:
    """
    Spend an exact influence budget outward from the tainted set and
    report who it reaches, graded.

    sources=None uses the field's own evidence: every memory currently
    TAINT_FLAGGED or QUARANTINED. Passing a set explicitly answers the
    hypothetical — "if THESE were poisoned, who is exposed" — which is
    the question worth asking before a sweep rather than after.

    Deterministic and sealed: sources sorted, edges ordered, budgets
    exact rationals. Two runs against the same state produce the same
    digest, so an exposure claim is recomputable rather than screenshot.
    """
    if sources is None:
        cur.execute("SELECT memory_id FROM memories WHERE custody_status IN "
                    "('TAINT_FLAGGED','QUARANTINED') ORDER BY memory_id ASC")
        direct = [r[0] for r in cur.fetchall()]
    else:
        direct = sorted(set(sources))
        cur.execute("SELECT memory_id FROM memories")
        known = {r[0] for r in cur.fetchall()}
        unknown = [m for m in direct if m not in known]
        if unknown:
            raise ValueError(f"Unknown memories {unknown} — exposure is about "
                             "THIS field or it is fiction.")

    cur.execute("SELECT from_id, to_id FROM cell_links WHERE link_type = "
                "'RESONANT' ORDER BY from_id ASC, to_id ASC")
    out_edges: dict[str, list[str]] = {}
    for f, t in cur.fetchall():
        out_edges.setdefault(f, []).append(t)

    best: dict[str, Fraction] = {}
    frontier: dict[str, Fraction] = {m: Fraction(1) for m in direct}
    for _ in range(MAX_INFLUENCE_DEPTH):
        nxt: dict[str, Fraction] = {}
        for src in sorted(frontier):
            carried = frontier[src] * INFLUENCE_TRANSFER
            if carried < EXPOSURE_FLOOR:
                continue
            for tgt in out_edges.get(src, []):
                if tgt in direct:
                    continue          # already the strongest claim there is
                if carried > best.get(tgt, Fraction(0)):
                    best[tgt] = carried
                    nxt[tgt] = max(carried, nxt.get(tgt, Fraction(0)))
        if not nxt:
            break
        frontier = nxt

    cur.execute("SELECT memory_id FROM memories ORDER BY memory_id ASC")
    all_ids = [r[0] for r in cur.fetchall()]
    exposed = tuple((m, f"{best[m].numerator}/{best[m].denominator}")
                    for m in sorted(best))
    clean = tuple(m for m in all_ids if m not in best and m not in direct)

    body = {
        "taint_protocol": protocol.TAINT_PROTOCOL,
        "sources": list(direct),
        "direct_taint": list(direct),
        "exposed": [list(p) for p in exposed],
        "clean": list(clean),
        "transfer": f"{INFLUENCE_TRANSFER.numerator}/{INFLUENCE_TRANSFER.denominator}",
        "floor": f"{EXPOSURE_FLOOR.numerator}/{EXPOSURE_FLOOR.denominator}",
        "max_depth": MAX_INFLUENCE_DEPTH,
    }
    return ExposureReport(
        taint_protocol=protocol.TAINT_PROTOCOL,
        sources=tuple(direct), direct_taint=tuple(direct), exposed=exposed,
        clean=clean,
        transfer=body["transfer"], floor=body["floor"],
        max_depth=MAX_INFLUENCE_DEPTH,
        exposure_sha256=hashlib.sha256(
            canonical_json(body).encode("utf-8")).hexdigest(),
    )
