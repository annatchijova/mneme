"""
MNEME — Causal closure: recall → decision → blast radius.

The gap this module closes was named in KNOWN_LIMITATIONS before it was
closed: a recall receipt proves what the agent was SHOWN, and nothing
proves what the agent DID with it. So MNEME could answer

    "why did the agent remember X?"

and could not answer the question an incident actually asks:

    "which DECISIONS were causally contaminated by X?"

A receipt is evidence about a read. A DECISION RECORD is evidence about
an act, and it is the agent's own explicit, authorized commitment:

    receipt_sha256    what the recall showed it (a persisted receipt,
                      itself replayable — receipt_protocol 2.0.0 records
                      the question as well as the answer)
    decision_sha256   what it produced, BY HASH. MNEME never sees the
                      artifact and will not pretend to: it commits to a
                      digest the agent supplies, so "this decision" is a
                      fixed object that cannot be quietly re-written
                      later, while its content stays outside the field.
    policy_version    under which rules. Two decisions from one receipt
                      under different policies are two different facts.
    used_memory_ids   which of the served memories the decision actually
                      consumed — a SUBSET of the receipt's served list,
                      checked at write and re-checked at verification.
                      "A receipt that references a memory it never
                      served" is precisely the lie this refuses.

BILATERAL, like contradiction and lineage. Each used memory's custody
chain gains a DECISION_USED_MEMORY event naming the decision, and the
decision names the memory back. Neither side can hide the link alone:
delete the decision row and the memory chains still accuse it; strip the
custody events and the decision's claim has no corroboration. Bundle
check B8 demands both directions.

WHY THIS IS NOT A RECALL SIDE EFFECT. Recall stays read-only (Invariant
M2's intent): serving is not a state transition, and writing a decision
event on every recall would convert the hottest read path into a write
path AND would record a decision that may never have been made. Using a
memory in a decision is a separate act, by a separate capability
(DECIDE), at a separate moment.

────────────────────────────────────────────────────────────────────────
BLAST RADIUS

`impact(cur, memory_id)` reconstructs, from evidence alone, everything
that depended on one memory — and grades it, because the alternative is
the failure mode KNOWN_LIMITATIONS already names: indiscriminate
transitive taint turns a connected graph into a self-inflicted denial of
service. Three levels, and the distinction between them is the point:

  DIRECT     Evidence says this memory was served or used. Persisted
             receipts whose served list contains it; decisions whose
             used_memory_ids contain it. Not inference — rows.

  DERIVED    Evidence says this could not be what it is without that
             memory: supersession successors (transitively), and
             memories whose STORED payload names a decision that is
             itself DIRECT or DERIVED (`derived_from_decision`). The
             agent declares that link when it stores; MNEME does not
             guess it.

  POSSIBLE   Contact, not contamination. Memories co-served in the same
             recall as this one, and its RESONANT neighbours. These
             ranked alongside it or could have been amplified by it. The
             level exists so an analyst can SEE the perimeter without the
             system pretending contact is proof — POSSIBLE is reported,
             never acted on, and never a custody status.

The report is deterministic (every set sorted, every traversal ordered)
and sealed: two runs against the same state produce byte-identical
evidence, so "this was the blast radius" is a claim someone else can
recompute rather than a screenshot.

As everywhere: every function takes a live cursor and NEVER commits.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from . import authority, custody, field, protocol


# ---------------------------------------------------------------------------
# Decision records
# ---------------------------------------------------------------------------

DECISION_COLS = ["decision_id", "receipt_sha256", "decision_sha256",
                 "policy_version", "actor_id", "reason", "used_json",
                 "created_at", "record_sha256"]


def decision_hash(artifact: str) -> str:
    """
    Hash a decision artifact (the answer, the action plan, the tool call
    — whatever the agent treats as "the decision"). Offered as a
    convenience so the digest is computed one way; the field never stores
    the artifact and never needs to.
    """
    if not isinstance(artifact, str):
        raise TypeError("Decision artifact must be str; hash bytes yourself otherwise.")
    return hashlib.sha256(artifact.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DecisionRecord:
    decision_id: str
    receipt_sha256: str
    decision_sha256: str
    policy_version: str
    actor_id: str
    reason: str
    used_memory_ids: tuple[str, ...]
    created_at: str
    record_sha256: str


def decision_body(*, decision_id: str, receipt_sha256: str,
                  decision_sha256: str, policy_version: str, actor_id: str,
                  reason: str, used_memory_ids: list[str],
                  created_at: str) -> dict[str, Any]:
    """
    The exact bytes a decision record's seal covers. One function, used
    when sealing and when verifying, in both implementations.

    used_memory_ids is sorted here, not as the caller passed it: rank
    order is the receipt's job and citation order carries no fact the
    receipt does not already hold, so leaving it free would admit two
    representations of one claim.
    """
    return {
        "decision_id": decision_id,
        "receipt_sha256": receipt_sha256,
        "decision_sha256": decision_sha256,
        "policy_version": policy_version,
        "actor_id": actor_id,
        "reason": reason,
        "used_memory_ids": sorted(used_memory_ids),
        "created_at": created_at,
    }


def _seal_decision(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def record_decision(
    cur,
    *,
    receipt: field.RecallReceipt | str,
    used_memory_ids: list[str],
    decision_sha256: str,
    policy_version: str,
    actor_id: str,
    reason: str,
    decision_id: str | None = None,
    created_at: str | None = None,
    grant_id: str | None = None,
) -> DecisionRecord:
    """
    Commit "this decision used these memories, from this recall, under
    this policy". Requires DECIDE.

    The receipt must ALREADY be persisted. A decision citing a receipt
    nobody kept is an unfalsifiable claim about a read that left no
    trace, and admitting one would make every later blast-radius answer
    depend on a number the field cannot check.

    used_memory_ids must be a non-empty subset of the receipt's served
    list. Empty would record a decision that consumed nothing, which is
    not a causal link; a superset would be the decision claiming a memory
    the recall never handed it.

    Writes, in the caller's transaction: the decisions row, plus one
    DECISION_USED_MEMORY custody event per used memory. Both halves or
    neither.
    """
    rsha = receipt.receipt_sha256 if isinstance(receipt, field.RecallReceipt) else receipt
    if not (isinstance(rsha, str) and len(rsha) == 64):
        raise ValueError("receipt must be a RecallReceipt or a 64-hex digest.")
    if not (isinstance(decision_sha256, str) and len(decision_sha256) == 64):
        raise ValueError(
            "decision_sha256 must be a 64-hex digest of the decision artifact "
            "(causality.decision_hash computes one). MNEME commits to the "
            "hash; it never sees the artifact.")
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise ValueError(
            "policy_version must be non-empty — a decision whose rules are "
            "unnamed cannot be compared with any other decision.")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be non-empty — an unreasoned decision "
                         "cannot exist, same as an unreasoned custody event.")

    rows = field.load_receipt_rows(cur, [rsha])
    if not rows:
        raise ValueError(
            f"Receipt {rsha[:16]}… is not persisted. A decision may only cite "
            "a receipt the field kept (field.persist_receipt) — otherwise the "
            "causal claim rests on a read that left no evidence.")
    if json.loads(rows[0]["custody_override_json"])["override"]:
        raise ValueError(
            f"Receipt {rsha[:16]}… is COUNTERFACTUAL — it was taken against a "
            "hypothetical custody state. No agent ever decided from a world "
            "that did not exist, and a decision citing one would launder a "
            "simulation into the causal record.")
    served = json.loads(rows[0]["served_json"])["served"]
    used = sorted(set(used_memory_ids))
    if not used:
        raise ValueError("A decision that used no memory records no causal "
                         "link; refusing to store one.")
    not_served = [m for m in used if m not in served]
    if not_served:
        raise ValueError(
            f"Decision claims it used {not_served}, which the cited recall "
            "never served. A receipt that references a memory it did not "
            "serve is the lie this check exists for.")

    ts = created_at if created_at is not None else custody.now_ts()
    did = decision_id if decision_id is not None else f"decision-{uuid.uuid4().hex[:16]}"
    custody.require_id(did, "decision_id")
    decide_grant = authority.gate(cur, actor_id=actor_id, capability="DECIDE",
                                  at_ts=ts, grant_id=grant_id)

    body = decision_body(
        decision_id=did, receipt_sha256=rsha, decision_sha256=decision_sha256,
        policy_version=policy_version, actor_id=actor_id, reason=reason,
        used_memory_ids=used, created_at=ts)
    seal = _seal_decision(body)

    cur.execute(
        "INSERT INTO decisions (decision_id, receipt_sha256, decision_sha256, "
        "policy_version, actor_id, reason, used_json, created_at, record_sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (did, rsha, decision_sha256, policy_version, actor_id, reason,
         canonical_json({"used": used}), ts, seal),
    )
    for mid in used:
        payload: dict[str, Any] = {
            "decision_id": did,
            "receipt_sha256": rsha,
            "decision_sha256": decision_sha256,
            "policy_version": policy_version,
        }
        if decide_grant is not None:
            payload["grant_id"] = decide_grant
        custody.append_event(
            cur, memory_id=mid, event_type="DECISION_USED_MEMORY",
            actor_id=actor_id, reason=reason, payload=payload, created_at=ts,
        )
    return DecisionRecord(
        decision_id=did, receipt_sha256=rsha, decision_sha256=decision_sha256,
        policy_version=policy_version, actor_id=actor_id, reason=reason,
        used_memory_ids=tuple(used), created_at=ts, record_sha256=seal,
    )


def load_decision_rows(cur, decision_ids: list[str] | None = None) -> list[dict[str, Any]]:
    sql = "SELECT " + ", ".join(DECISION_COLS) + " FROM decisions "
    params: tuple = ()
    if decision_ids is not None:
        if not decision_ids:
            return []
        sql += "WHERE decision_id IN (%s) " % ",".join("?" for _ in decision_ids)
        params = tuple(decision_ids)
    sql += "ORDER BY decision_id ASC"
    cur.execute(sql, params)
    return [dict(zip(DECISION_COLS, r)) for r in cur.fetchall()]


def verify_decisions(cur) -> tuple[bool, list[str]]:
    """
    Re-derive every decision's seal from its own columns, re-check the
    subset claim against its receipt, and re-check bilaterality against
    the custody chains. The online twin of bundle check B8.
    """
    errors: list[str] = []
    for row in load_decision_rows(cur):
        did = row["decision_id"]
        try:
            used = json.loads(row["used_json"])["used"]
        except Exception:
            errors.append(f"decision {did}: used_json is not valid JSON.")
            continue
        body = decision_body(
            decision_id=did, receipt_sha256=row["receipt_sha256"],
            decision_sha256=row["decision_sha256"],
            policy_version=row["policy_version"], actor_id=row["actor_id"],
            reason=row["reason"], used_memory_ids=used,
            created_at=row["created_at"])
        if _seal_decision(body) != row["record_sha256"]:
            errors.append(f"decision {did}: does not recompute from its "
                          "columns — decision evidence edited.")
            continue
        rrows = field.load_receipt_rows(cur, [row["receipt_sha256"]])
        if not rrows:
            errors.append(f"decision {did}: cites a receipt that is not persisted.")
            continue
        served = json.loads(rrows[0]["served_json"])["served"]
        missing = [m for m in used if m not in served]
        if missing:
            errors.append(f"decision {did}: claims memories {missing} its "
                          "cited recall never served.")
        for mid in used:
            cur.execute(
                "SELECT payload_json FROM custody_chain WHERE memory_id = ? "
                "AND event_type = 'DECISION_USED_MEMORY'", (mid,))
            if not any(json.loads(pj).get("decision_id") == did
                       for (pj,) in cur.fetchall()):
                errors.append(
                    f"decision {did}: names {mid} but {mid}'s custody chain "
                    "has no DECISION_USED_MEMORY naming it back — a causal "
                    "claim only one side makes.")
    return (not errors), errors


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ImpactReport:
    """
    What depended on one memory, graded by what the evidence supports.
    `edges` is the causal DAG itself: (level, kind, source, target)
    tuples, sorted, so the report can be drawn as well as counted.
    """
    memory_id: str
    direct_receipts: tuple[str, ...]
    direct_decisions: tuple[str, ...]
    derived_memories: tuple[str, ...]
    derived_decisions: tuple[str, ...]
    possible_memories: tuple[str, ...]
    edges: tuple[tuple[str, str, str, str], ...]
    impact_sha256: str


def _impact_body(r: dict[str, Any]) -> str:
    return canonical_json(r)


def impact(cur, memory_id: str) -> ImpactReport:
    """
    Reconstruct the blast radius of one memory from evidence alone.

    Deliberately does NOT quarantine anything. Discovering that a memory
    was poisoned and discovering what depended on it are two findings;
    acting on the second is an analyst's decision with its own authority
    and its own audited events. A function that both measures and
    contains would make the measurement impossible to trust.
    """
    cur.execute("SELECT 1 FROM memories WHERE memory_id = ?", (memory_id,))
    if cur.fetchone() is None:
        raise ValueError(f"Unknown memory {memory_id!r} — impact does not "
                         "invent a subject.")

    edges: set[tuple[str, str, str, str]] = set()

    # --- DIRECT: persisted recalls that served it, decisions that used it.
    direct_receipts: list[str] = []
    for row in field.load_receipt_rows(cur):
        try:
            served = json.loads(row["served_json"])["served"]
        except Exception:
            continue
        if memory_id in served:
            direct_receipts.append(row["receipt_sha256"])
            edges.add(("DIRECT", "SERVED_BY", memory_id, row["receipt_sha256"]))

    direct_decisions: list[str] = []
    for row in load_decision_rows(cur):
        try:
            used = json.loads(row["used_json"])["used"]
        except Exception:
            continue
        if memory_id in used:
            direct_decisions.append(row["decision_id"])
            edges.add(("DIRECT", "USED_BY", memory_id, row["decision_id"]))

    # --- DERIVED: a fixpoint over lineage and declared decision descent.
    #
    # Iterated to a fixpoint rather than walked recursively, and it
    # terminates by construction: the two relations it follows only ever
    # point from an older record to a strictly newer one (a memory to its
    # successor; a decision to a memory stored after it), so no cycle can
    # exist, and each pass either adds at least one element to a set
    # bounded by the field or stops.
    derived_memories: set[str] = set()
    derived_decisions: set[str] = set(direct_decisions)

    all_decisions = load_decision_rows(cur)
    cur.execute("SELECT memory_id, superseded_by FROM memories "
                "WHERE superseded_by IS NOT NULL ORDER BY memory_id ASC")
    successor_of = dict(cur.fetchall())
    cur.execute("SELECT memory_id, payload_json FROM custody_chain "
                "WHERE seq = 0 ORDER BY memory_id ASC")
    declared_descent: list[tuple[str, str]] = []
    for mid, pj in cur.fetchall():
        dfd = json.loads(pj).get("derived_from_decision")
        if isinstance(dfd, str):
            declared_descent.append((mid, dfd))

    changed = True
    while changed:
        changed = False
        reached = derived_memories | {memory_id}

        for src in sorted(reached):
            succ = successor_of.get(src)
            if succ is not None:
                edges.add(("DERIVED", "SUPERSEDED_BY", src, succ))
                if succ != memory_id and succ not in derived_memories:
                    derived_memories.add(succ)
                    changed = True

        for row in all_decisions:
            used = set(json.loads(row["used_json"])["used"])
            hit = sorted(used & derived_memories)
            if hit:
                for u in hit:
                    edges.add(("DERIVED", "USED_BY", u, row["decision_id"]))
                if row["decision_id"] not in derived_decisions:
                    derived_decisions.add(row["decision_id"])
                    changed = True

        for mid, dfd in declared_descent:
            if dfd in derived_decisions:
                edges.add(("DERIVED", "DERIVED_FROM_DECISION", dfd, mid))
                if mid != memory_id and mid not in derived_memories:
                    derived_memories.add(mid)
                    changed = True

    # --- POSSIBLE: contact, not contamination. Reported, never acted on.
    possible: set[str] = set()
    for rsha in direct_receipts:
        row = field.load_receipt_rows(cur, [rsha])[0]
        for other in json.loads(row["served_json"])["served"]:
            if other != memory_id:
                possible.add(other)
                edges.add(("POSSIBLE", "CO_SERVED", memory_id, other))
    cur.execute("SELECT to_id FROM cell_links WHERE from_id = ? AND "
                "link_type = 'RESONANT' ORDER BY to_id ASC", (memory_id,))
    for (other,) in cur.fetchall():
        if other != memory_id:
            possible.add(other)
            edges.add(("POSSIBLE", "RESONANT_NEIGHBOUR", memory_id, other))
    possible -= derived_memories
    possible.discard(memory_id)

    body = {
        "memory_id": memory_id,
        "taint_protocol": protocol.TAINT_PROTOCOL,
        "direct_receipts": sorted(direct_receipts),
        "direct_decisions": sorted(direct_decisions),
        "derived_memories": sorted(derived_memories),
        "derived_decisions": sorted(derived_decisions),
        "possible_memories": sorted(possible),
        "edges": sorted([list(e) for e in edges]),
    }
    return ImpactReport(
        memory_id=memory_id,
        direct_receipts=tuple(sorted(direct_receipts)),
        direct_decisions=tuple(sorted(direct_decisions)),
        derived_memories=tuple(sorted(derived_memories)),
        derived_decisions=tuple(sorted(derived_decisions)),
        possible_memories=tuple(sorted(possible)),
        edges=tuple(sorted(edges)),
        impact_sha256=hashlib.sha256(_impact_body(body).encode("utf-8")).hexdigest(),
    )
