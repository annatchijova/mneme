"""
MNEME — Epistemic claims: the proposition, separated from the document.

Until now a memory was doing two jobs that are not the same job. It was
the CONTAINER (this text was stored, by this actor, at this time, with
this chain) and it was the EPISTEMIC UNIT (this is what the field
believes). raven's contradiction rule made the conflation visible: two
memories with the same topic and different `claim` strings got
bidirectional INHIBITORY links, which works exactly as long as every
proposition lives in exactly one document and every document asserts
exactly one proposition. Neither is true of anything real.

A claim is a proposition. It has its own id, its own per-claim hash
chain, its own state, and its own provenance — and none of those are the
memory's. The separation buys four sentences that used to be one:

    "this text was stored"          a memory, with a custody chain
    "this actor asserts P"          a claim, with a claim chain
    "these two artifacts support P" evidence links, each one an event
    "MNEME holds P"                 a DERIVED standing, computed from
                                    the above, never a stored number

PROVENANCE IS INDEPENDENT OF CONFIDENCE, and that is the point of the
fourth line. A claim's provenance is its chain: who asserted it, when,
under what grant, what evidence was linked and by whom. Its standing is
recomputed from evidence every time it is asked for. Nothing stores "how
sure we are", because a stored confidence is a number whose derivation
has been thrown away — and a number whose derivation is gone is exactly
what an audit cannot use.

WHY EVIDENCE LINKS LIVE ON THE CLAIM'S CHAIN AND NOT THE MEMORY'S.
Contradiction, lineage and decisions are all bilateral in MNEME, so the
asymmetry here is deliberate and worth defending. A claim is ABOUT
memories; memories are not about claims. If every memory's chain had to
record every claim that ever cited it, a document's history would grow
with other people's epistemics forever — the container would once again
be carrying the epistemic unit's weight, which is the conflation this
module exists to undo. The link is still tamper-evident: it is an event
inside a hash chain, and a bundle that omits a cited memory must DECLARE
the omission (B9), never imply it.

N-ARY CONTRADICTION. `A contradicts B` is too poor for most real
conflicts. A claim SET is a constraint over many hypotheses:

    AT_MOST_ONE   at most one member may hold   (the date is one of these)
    EXACTLY_ONE   exactly one member must hold  (…and we know it is one)
    INCOMPATIBLE  they cannot ALL hold together (weaker, and often the
                  only thing actually known)

Resolution is then an operation on the SET rather than on an arbitrary
pair: `resolve_set` validates and refutes members in one audited
transaction, and REFUSES to commit a resolution that leaves the
constraint still violated. Rescuing a validated truth stops being a
special case of link surgery and becomes what it always was — deciding
between hypotheses, on the record.

Invariants (C for Claims):
  C1  A claim's statement is immutable. Revision is supersession, an
      event, never an edit — the same rule M1 holds memories to.
  C2  Claim chains are per-claim, append-only, genesis bound to claim_id,
      seq dense from 0.
  C3  A claim's STANDING is derived from evidence and never stored.
  C4  Claim-to-claim relations are bilateral: both chains record them, or
      the relation does not exist.
  C5  A resolution must leave its set satisfied, checked in the same
      transaction that writes it.

As everywhere: every function takes a live cursor and NEVER commits.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from . import authority, custody

_CLAIM_GENESIS_PREFIX = b"MNEME_CLAIM_GENESIS:"

CLAIM_EVENT_TYPES = frozenset({
    "CLAIM_ASSERTED",    # seq 0; payload carries statement_sha256
    "EVIDENCE_LINKED",   # a memory supports or contradicts this claim
    "RELATED_TO",        # a claim-to-claim relation, one direction of two
    "SET_MEMBERSHIP",    # this claim joined a mutually-constrained set
    "CLAIM_VALIDATED",   # adjudicated: it holds
    "CLAIM_REFUTED",     # adjudicated: it does not
    "CLAIM_WITHDRAWN",   # the asserter took it back
    "CLAIM_SUPERSEDED",  # a successor claim replaces it
})

STANCES = ("SUPPORTS", "CONTRADICTS")
RELATIONS = ("SUPPORTS", "CONTRADICTS", "SUPERSEDES", "DERIVED_FROM")
CONSTRAINTS = ("AT_MOST_ONE", "EXACTLY_ONE", "INCOMPATIBLE")
CLAIM_STATES = ("ASSERTED", "VALIDATED", "REFUTED", "WITHDRAWN", "SUPERSEDED")

# Which capability each claim event requires of its actor. Asserting a
# proposition is not storing a document and adjudicating between
# hypotheses is neither — which is the whole reason these are separate
# capabilities rather than a reused STORE.
CLAIM_EVENT_CAPABILITY: dict[str, str] = {
    "CLAIM_ASSERTED": "ASSERT",
    "EVIDENCE_LINKED": "ASSERT",
    "RELATED_TO": "ASSERT",
    "SET_MEMBERSHIP": "ASSERT",
    "CLAIM_VALIDATED": "ADJUDICATE",
    "CLAIM_REFUTED": "ADJUDICATE",
    "CLAIM_WITHDRAWN": "ASSERT",
    "CLAIM_SUPERSEDED": "ASSERT",
}

CLAIM_COLS = ["claim_id", "seq", "event_type", "actor_id", "reason",
              "created_at", "payload_json", "prev_hash", "entry_hash"]


def claim_genesis_hash(claim_id: str) -> str:
    custody.require_id(claim_id, "claim_id")
    return hashlib.sha256(
        _CLAIM_GENESIS_PREFIX + claim_id.encode("utf-8")).hexdigest()


def statement_sha256(statement: str) -> str:
    if not isinstance(statement, str) or not statement.strip():
        raise ValueError("A claim's statement must be non-empty — a "
                         "proposition nobody stated is not a proposition.")
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def compute_claim_hash(*, prev_hash: str, claim_id: str, seq: int,
                       event_type: str, actor_id: str, reason: str,
                       created_at: str,
                       payload: dict[str, Any]) -> tuple[str, str]:
    envelope = {
        "claim_id": claim_id, "seq": seq, "event_type": event_type,
        "actor_id": actor_id, "reason": reason, "created_at": created_at,
        "payload": payload,
    }
    canonical = canonical_json(envelope)
    return (hashlib.sha256(prev_hash.encode("ascii")
                           + canonical.encode("utf-8")).hexdigest(),
            canonical_json(payload))


def append_claim_event(cur, *, claim_id: str, event_type: str, actor_id: str,
                       reason: str, payload: dict[str, Any],
                       created_at: str | None = None) -> None:
    custody.require_id(claim_id, "claim_id")
    custody.require_id(actor_id, "actor_id")
    if event_type not in CLAIM_EVENT_TYPES:
        raise ValueError(
            f"Unknown claim event_type {event_type!r}. The vocabulary is "
            "closed; extending it is a protocol change.")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be non-empty — an unreasoned epistemic "
                         "act cannot exist, same as an unreasoned custody event.")
    cur.execute("SELECT seq, entry_hash FROM claim_chain WHERE claim_id = ? "
                "ORDER BY seq DESC LIMIT 1", (claim_id,))
    row = cur.fetchone()
    if row is None:
        if event_type != "CLAIM_ASSERTED":
            raise ValueError(
                f"First claim event for {claim_id} must be CLAIM_ASSERTED, "
                f"got {event_type}. A proposition's history begins when "
                "someone asserts it.")
        seq, prev_hash = 0, claim_genesis_hash(claim_id)
    else:
        if event_type == "CLAIM_ASSERTED":
            raise ValueError(
                f"{claim_id} already has a chain; a claim is asserted once. "
                "Revision is supersession (Invariant C1).")
        seq, prev_hash = int(row[0]) + 1, str(row[1])
    ts = created_at if created_at is not None else custody.now_ts()
    entry_hash, payload_canon = compute_claim_hash(
        prev_hash=prev_hash, claim_id=claim_id, seq=seq, event_type=event_type,
        actor_id=actor_id, reason=reason, created_at=ts, payload=payload)
    cur.execute(
        "INSERT INTO claim_chain (claim_id, seq, event_type, actor_id, reason, "
        "created_at, payload_json, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (claim_id, seq, event_type, actor_id, reason, ts, payload_canon,
         prev_hash, entry_hash))


# ---------------------------------------------------------------------------
# Verification + replay (pure; the offline verifier transcribes both)
# ---------------------------------------------------------------------------

def verify_claim_rows(claim_id: str,
                      rows: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Structure: genesis binding, dense seq, linkage, recomputation,
    closed vocabulary, canonical payload bytes, canonical monotone UTC."""
    errors: list[str] = []
    if not rows:
        return False, [f"{claim_id}: empty claim chain — a proposition nobody "
                       "asserted."]
    expected_prev = claim_genesis_hash(claim_id)
    prev_ts: str | None = None
    for i, r in enumerate(rows):
        where = f"{claim_id} claim seq {r.get('seq')}"
        if r.get("seq") != i:
            return False, errors + [f"{where}: seq not dense (expected {i})."]
        et = r.get("event_type")
        if et not in CLAIM_EVENT_TYPES:
            return False, errors + [f"{where}: unknown event_type {et!r}."]
        if i == 0 and et != "CLAIM_ASSERTED":
            return False, errors + [f"{where}: chain does not begin with "
                                    "CLAIM_ASSERTED."]
        if i > 0 and et == "CLAIM_ASSERTED":
            return False, errors + [f"{where}: CLAIM_ASSERTED after birth."]
        if r.get("prev_hash") != expected_prev:
            return False, errors + [f"{where}: prev_hash does not link "
                                    "(chain broken or grafted)."]
        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            return False, errors + [f"{where}: payload_json is not valid JSON."]
        if canonical_json(payload) != r["payload_json"]:
            return False, errors + [f"{where}: payload_json is not canonical."]
        recomputed, _ = compute_claim_hash(
            prev_hash=r["prev_hash"], claim_id=claim_id, seq=r["seq"],
            event_type=et, actor_id=r["actor_id"], reason=r["reason"],
            created_at=r["created_at"], payload=payload)
        if recomputed != r["entry_hash"]:
            return False, errors + [f"{where}: entry_hash does not recompute "
                                    "— claim evidence tampered."]
        ts = r["created_at"]
        if not isinstance(ts, str) or not custody._TS_PATTERN.match(ts):
            return False, errors + [f"{where}: created_at {ts!r} is not "
                                    "canonical UTC microsecond ISO 8601."]
        if prev_ts is not None and ts < prev_ts:
            return False, errors + [f"{where}: created_at {ts} precedes the "
                                    "previous event — a claim's history "
                                    "cannot run backwards."]
        prev_ts = ts
        expected_prev = r["entry_hash"]
    return True, []


@dataclass
class ClaimState:
    claim_id: str
    statement_sha256: str = ""
    topic: str | None = None
    asserted_by: str = ""
    asserted_at: str = ""
    state: str = "ASSERTED"
    supports: tuple = ()
    contradicts: tuple = ()
    relations: tuple = ()
    sets: tuple = ()


def replay_claim(claim_id: str,
                 rows: list[dict[str, Any]]) -> tuple[ClaimState, list[str]]:
    """
    The claim state machine — the single normative statement
    (claim_protocol), transcribed verbatim by the standalone verifier:

      state: starts ASSERTED at CLAIM_ASSERTED.
          CLAIM_VALIDATED   -> VALIDATED, valid only from ASSERTED
          CLAIM_REFUTED     -> REFUTED, valid from ASSERTED or VALIDATED
                               (new evidence may overturn an adjudication;
                               that is what an adjudication is FOR)
          CLAIM_WITHDRAWN   -> WITHDRAWN, valid only from ASSERTED. An
                               adjudicated claim cannot be withdrawn:
                               taking back a proposition someone ruled on
                               would erase the ruling, not the claim.
          CLAIM_SUPERSEDED  -> SUPERSEDED, valid from ASSERTED or VALIDATED
      EVIDENCE_LINKED, RELATED_TO and SET_MEMBERSHIP change no state. They
      accumulate the material a STANDING is computed from, and a claim
      whose state moved merely because evidence arrived would be storing
      the conclusion instead of deriving it (Invariant C3).
    """
    st = ClaimState(claim_id=claim_id)
    errors: list[str] = []
    supports: list[str] = []
    contradicts: list[str] = []
    relations: list[tuple[str, str, str]] = []
    sets: list[str] = []
    for r in rows:
        et, payload = r["event_type"], json.loads(r["payload_json"])
        where = f"{claim_id} claim seq {r['seq']}"
        if et == "CLAIM_ASSERTED":
            sha = payload.get("statement_sha256")
            if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
                errors.append(f"{where}: CLAIM_ASSERTED without a statement "
                              "hash — an assertion that seals nothing.")
            st.statement_sha256 = sha or ""
            st.topic = payload.get("topic")
            st.asserted_by = r["actor_id"]
            st.asserted_at = r["created_at"]
        elif et == "EVIDENCE_LINKED":
            mid, stance = payload.get("memory_id"), payload.get("stance")
            if not isinstance(mid, str) or stance not in STANCES:
                errors.append(f"{where}: EVIDENCE_LINKED without a memory and "
                              f"a stance in {list(STANCES)}.")
            elif stance == "SUPPORTS":
                supports.append(mid)
            else:
                contradicts.append(mid)
        elif et == "RELATED_TO":
            other, rel = payload.get("other_claim_id"), payload.get("relation")
            direction = payload.get("direction")
            if not isinstance(other, str) or rel not in RELATIONS \
                    or direction not in ("OUT", "IN"):
                errors.append(f"{where}: RELATED_TO without a claim, a "
                              f"relation in {list(RELATIONS)} and a direction.")
            else:
                relations.append((rel, direction, other))
        elif et == "SET_MEMBERSHIP":
            sid = payload.get("set_id")
            if not isinstance(sid, str):
                errors.append(f"{where}: SET_MEMBERSHIP without a set_id.")
            else:
                sets.append(sid)
        elif et == "CLAIM_VALIDATED":
            if st.state != "ASSERTED":
                errors.append(f"{where}: CLAIM_VALIDATED from {st.state}, "
                              "valid only from ASSERTED.")
            st.state = "VALIDATED"
        elif et == "CLAIM_REFUTED":
            if st.state not in ("ASSERTED", "VALIDATED"):
                errors.append(f"{where}: CLAIM_REFUTED from {st.state}.")
            st.state = "REFUTED"
        elif et == "CLAIM_WITHDRAWN":
            if st.state != "ASSERTED":
                errors.append(f"{where}: CLAIM_WITHDRAWN from {st.state} — an "
                              "adjudicated claim cannot be taken back; that "
                              "would erase the ruling, not the claim.")
            st.state = "WITHDRAWN"
        elif et == "CLAIM_SUPERSEDED":
            if st.state not in ("ASSERTED", "VALIDATED"):
                errors.append(f"{where}: CLAIM_SUPERSEDED from {st.state}.")
            st.state = "SUPERSEDED"
    st.supports = tuple(sorted(set(supports)))
    st.contradicts = tuple(sorted(set(contradicts)))
    st.relations = tuple(sorted(set(relations)))
    st.sets = tuple(sorted(set(sets)))
    return st, errors


def load_claim_rows(cur, claim_id: str) -> list[dict[str, Any]]:
    cur.execute("SELECT " + ", ".join(CLAIM_COLS) + " FROM claim_chain "
                "WHERE claim_id = ? ORDER BY seq ASC", (claim_id,))
    return [dict(zip(CLAIM_COLS, r)) for r in cur.fetchall()]


def load_claim_state(cur, claim_id: str) -> ClaimState:
    rows = load_claim_rows(cur, claim_id)
    ok, errors = verify_claim_rows(claim_id, rows)
    if not ok:
        raise ValueError(f"Claim chain for {claim_id!r} does not verify: {errors[0]}")
    st, rerrors = replay_claim(claim_id, rows)
    if rerrors:
        raise ValueError(f"Claim chain for {claim_id!r} does not replay: {rerrors[0]}")
    return st


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

def assert_claim(cur, *, statement: str, actor_id: str, reason: str,
                 claim_id: str | None = None, topic: str | None = None,
                 created_at: str | None = None,
                 grant_id: str | None = None) -> str:
    """Assert a proposition. Requires ASSERT."""
    cid = claim_id if claim_id is not None else f"claim-{uuid.uuid4().hex[:16]}"
    custody.require_id(cid, "claim_id")
    sha = statement_sha256(statement)
    ts = created_at if created_at is not None else custody.now_ts()
    gid = authority.gate(cur, actor_id=actor_id, capability="ASSERT",
                         at_ts=ts, grant_id=grant_id)
    cur.execute("SELECT 1 FROM claims WHERE claim_id = ?", (cid,))
    if cur.fetchone() is not None:
        raise ValueError(f"Claim {cid!r} already exists.")
    cur.execute(
        "INSERT INTO claims (claim_id, statement, statement_sha256, topic, "
        "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (cid, statement, sha, topic, actor_id, ts))
    payload: dict[str, Any] = {"statement_sha256": sha}
    if topic is not None:
        payload["topic"] = topic
    if gid is not None:
        payload["grant_id"] = gid
    append_claim_event(cur, claim_id=cid, event_type="CLAIM_ASSERTED",
                       actor_id=actor_id, reason=reason, payload=payload,
                       created_at=ts)
    return cid


def link_evidence(cur, *, claim_id: str, memory_id: str, stance: str,
                  actor_id: str, reason: str, created_at: str | None = None,
                  grant_id: str | None = None) -> None:
    """
    Record that a memory supports or contradicts a claim. Requires ASSERT.

    The memory must exist. Its custody_status is NOT checked here: linking
    a tainted memory as evidence is a legitimate, and often necessary,
    epistemic act — "this claim rests on material we later quarantined" is
    precisely what an incident review needs to be able to say. What the
    gate does instead is refuse to COUNT it: standing() reads only CLEAN
    evidence, and reports the rest separately.
    """
    if stance not in STANCES:
        raise ValueError(f"stance must be one of {list(STANCES)}.")
    cur.execute("SELECT 1 FROM memories WHERE memory_id = ?", (memory_id,))
    if cur.fetchone() is None:
        raise ValueError(f"Unknown memory {memory_id!r} — evidence is a "
                         "pointer at something the field actually holds.")
    st = load_claim_state(cur, claim_id)
    if st.state in ("REFUTED", "WITHDRAWN", "SUPERSEDED"):
        raise ValueError(
            f"{claim_id} is {st.state}; refusing to attach evidence to a claim "
            "that is no longer live. Assert a successor and link it there — "
            "the history of what was believed stays readable either way.")
    ts = created_at if created_at is not None else custody.now_ts()
    gid = authority.gate(cur, actor_id=actor_id, capability="ASSERT",
                         at_ts=ts, grant_id=grant_id)
    payload: dict[str, Any] = {"memory_id": memory_id, "stance": stance}
    if gid is not None:
        payload["grant_id"] = gid
    append_claim_event(cur, claim_id=claim_id, event_type="EVIDENCE_LINKED",
                       actor_id=actor_id, reason=reason, payload=payload,
                       created_at=ts)


def relate(cur, *, from_claim: str, to_claim: str, relation: str,
           actor_id: str, reason: str, created_at: str | None = None,
           grant_id: str | None = None) -> None:
    """
    Relate two claims. BILATERAL (Invariant C4): the event lands on both
    chains, one marked OUT and one IN, so neither party's export can hide
    a relationship the other records.
    """
    if relation not in RELATIONS:
        raise ValueError(f"relation must be one of {list(RELATIONS)}.")
    if from_claim == to_claim:
        raise ValueError("A claim cannot relate to itself.")
    load_claim_state(cur, from_claim)
    load_claim_state(cur, to_claim)
    ts = created_at if created_at is not None else custody.now_ts()
    gid = authority.gate(cur, actor_id=actor_id, capability="ASSERT",
                         at_ts=ts, grant_id=grant_id)
    for cid, other, direction in ((from_claim, to_claim, "OUT"),
                                  (to_claim, from_claim, "IN")):
        payload: dict[str, Any] = {"other_claim_id": other,
                                   "relation": relation,
                                   "direction": direction}
        if gid is not None:
            payload["grant_id"] = gid
        append_claim_event(cur, claim_id=cid, event_type="RELATED_TO",
                           actor_id=actor_id, reason=reason, payload=payload,
                           created_at=ts)


# ---------------------------------------------------------------------------
# Claim sets — n-ary contradiction
# ---------------------------------------------------------------------------

SET_COLS = ["set_id", "constraint_type", "topic", "reason", "created_by",
            "created_at", "members_json", "members_sha256"]


def _seal_members(members: list[str]) -> str:
    return hashlib.sha256(
        canonical_json({"members": sorted(members)}).encode("utf-8")).hexdigest()


def declare_set(cur, *, members: list[str], constraint_type: str,
                actor_id: str, reason: str, set_id: str | None = None,
                topic: str | None = None, created_at: str | None = None,
                grant_id: str | None = None) -> str:
    """
    Declare that a group of claims is mutually constrained. Requires
    ASSERT, and writes a SET_MEMBERSHIP event on every member's chain so
    the membership is re-derivable from evidence rather than trusted to
    one row (the same lesson taint_protocol 2.0.0 learned about sweeps).
    """
    if constraint_type not in CONSTRAINTS:
        raise ValueError(f"constraint_type must be one of {list(CONSTRAINTS)}.")
    ms = sorted(set(members))
    if len(ms) < 2:
        raise ValueError(
            "A constraint over fewer than two claims constrains nothing. "
            "If the point is that one claim is false, refute it.")
    for cid in ms:
        load_claim_state(cur, cid)
    sid = set_id if set_id is not None else f"claimset-{uuid.uuid4().hex[:16]}"
    custody.require_id(sid, "set_id")
    ts = created_at if created_at is not None else custody.now_ts()
    gid = authority.gate(cur, actor_id=actor_id, capability="ASSERT",
                         at_ts=ts, grant_id=grant_id)
    cur.execute(
        "INSERT INTO claim_sets (set_id, constraint_type, topic, reason, "
        "created_by, created_at, members_json, members_sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sid, constraint_type, topic, reason, actor_id, ts,
         canonical_json({"members": ms}), _seal_members(ms)))
    for cid in ms:
        payload: dict[str, Any] = {"set_id": sid,
                                   "constraint_type": constraint_type}
        if gid is not None:
            payload["grant_id"] = gid
        append_claim_event(cur, claim_id=cid, event_type="SET_MEMBERSHIP",
                           actor_id=actor_id, reason=reason, payload=payload,
                           created_at=ts)
    return sid


def load_set_rows(cur, set_ids: list[str] | None = None) -> list[dict[str, Any]]:
    sql = "SELECT " + ", ".join(SET_COLS) + " FROM claim_sets "
    params: tuple = ()
    if set_ids is not None:
        if not set_ids:
            return []
        sql += "WHERE set_id IN (%s) " % ",".join("?" for _ in set_ids)
        params = tuple(set_ids)
    sql += "ORDER BY set_id ASC"
    cur.execute(sql, params)
    return [dict(zip(SET_COLS, r)) for r in cur.fetchall()]


def evaluate_constraint(constraint_type: str,
                        states: dict[str, str]) -> tuple[str, str]:
    """
    Evaluate one constraint over its members' replayed states. Pure, so
    both verifiers and the online path share one definition of what a
    violation IS. Returns (status, explanation).

    "Holds" means VALIDATED — adjudicated to hold. ASSERTED is under
    consideration, not believed, which is why a set with open hypotheses
    is UNDETERMINED rather than satisfied by default. A system that read
    "nobody has objected yet" as "true" would be manufacturing agreement.
    """
    held = sorted(c for c, s in states.items() if s == "VALIDATED")
    open_ = sorted(c for c, s in states.items() if s == "ASSERTED")
    n = len(states)
    if constraint_type == "AT_MOST_ONE":
        if len(held) > 1:
            return "VIOLATED", f"{len(held)} members hold simultaneously: {held}"
        return ("SATISFIED" if not open_ else "UNDETERMINED",
                f"{len(held)} holding, {len(open_)} still open")
    if constraint_type == "EXACTLY_ONE":
        if len(held) > 1:
            return "VIOLATED", f"{len(held)} members hold simultaneously: {held}"
        if len(held) == 1:
            return ("SATISFIED" if not open_ else "UNDETERMINED",
                    f"{held[0]} holds, {len(open_)} still open")
        if not open_:
            return "VIOLATED", "no member holds, and none is still open"
        return "UNDETERMINED", f"no member holds yet, {len(open_)} still open"
    # INCOMPATIBLE: the weakest and often the only thing actually known.
    if len(held) == n:
        return "VIOLATED", "every member holds, and they cannot all hold"
    return ("SATISFIED" if not open_ else "UNDETERMINED",
            f"{len(held)} of {n} holding, {len(open_)} still open")


@dataclass(frozen=True)
class SetEvaluation:
    set_id: str
    constraint_type: str
    members: tuple[str, ...]
    member_states: tuple[tuple[str, str], ...]
    status: str
    explanation: str
    members_sha256: str


def evaluate_set(cur, set_id: str) -> SetEvaluation:
    rows = load_set_rows(cur, [set_id])
    if not rows:
        raise ValueError(f"Unknown claim set {set_id!r}.")
    row = rows[0]
    members = json.loads(row["members_json"])["members"]
    states = {c: load_claim_state(cur, c).state for c in members}
    status, explanation = evaluate_constraint(row["constraint_type"], states)
    return SetEvaluation(
        set_id=set_id, constraint_type=row["constraint_type"],
        members=tuple(members),
        member_states=tuple(sorted(states.items())),
        status=status, explanation=explanation,
        members_sha256=row["members_sha256"])


def resolve_set(cur, *, set_id: str, validate: list[str], refute: list[str],
                actor_id: str, reason: str, created_at: str | None = None,
                grant_id: str | None = None) -> SetEvaluation:
    """
    Decide between hypotheses, as one audited transaction over the SET.
    Requires ADJUDICATE.

    Invariant C5: the resolution must LEAVE THE CONSTRAINT SATISFIED, and
    that is checked after the writes, in the same transaction. A partial
    resolution that still violates its own constraint is refused — the
    caller sees why, and the field never records an adjudication that
    settled nothing.

    Rescuing a validated truth used to be surgery on an arbitrary
    INHIBITORY pair. Here it is what it always was: choosing among the
    hypotheses, on the record, with the constraint as the check.
    """
    ev = evaluate_set(cur, set_id)
    members = set(ev.members)
    stray = sorted((set(validate) | set(refute)) - members)
    if stray:
        raise ValueError(f"{stray} are not members of {set_id} — a resolution "
                         "decides the set it names.")
    both = sorted(set(validate) & set(refute))
    if both:
        raise ValueError(f"{both} appear in both validate and refute.")
    ts = created_at if created_at is not None else custody.now_ts()
    gid = authority.gate(cur, actor_id=actor_id, capability="ADJUDICATE",
                         at_ts=ts, grant_id=grant_id)
    payload_common: dict[str, Any] = {"set_id": set_id}
    if gid is not None:
        payload_common["grant_id"] = gid
    for cid in sorted(validate):
        append_claim_event(cur, claim_id=cid, event_type="CLAIM_VALIDATED",
                           actor_id=actor_id, reason=reason,
                           payload=dict(payload_common), created_at=ts)
    for cid in sorted(refute):
        append_claim_event(cur, claim_id=cid, event_type="CLAIM_REFUTED",
                           actor_id=actor_id, reason=reason,
                           payload=dict(payload_common), created_at=ts)
    after = evaluate_set(cur, set_id)
    if after.status == "VIOLATED":
        raise ValueError(
            f"This resolution leaves {set_id} VIOLATED ({after.explanation}). "
            "Refusing to record an adjudication that settles nothing "
            "(Invariant C5).")
    return after


# ---------------------------------------------------------------------------
# Standing — derived, never stored (C3)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClaimStanding:
    claim_id: str
    statement: str
    state: str
    asserted_by: str
    asserted_at: str
    supporting: tuple[str, ...]          # CLEAN memories only
    contradicting: tuple[str, ...]       # CLEAN memories only
    withheld_evidence: tuple[tuple[str, str], ...]   # (memory_id, status)
    relations: tuple[tuple[str, str, str], ...]
    set_evaluations: tuple[SetEvaluation, ...]
    standing_sha256: str


def standing(cur, claim_id: str) -> ClaimStanding:
    """
    Recompute what the field can say about a proposition, from evidence,
    every time it is asked. Nothing here is stored (Invariant C3): a
    persisted confidence is a number whose derivation has been thrown
    away, and a number whose derivation is gone is what an audit cannot
    use.

    Evidence whose memory is not CLEAN is EXCLUDED from the counts and
    REPORTED separately. The custody gate that keeps a quarantined memory
    out of recall keeps it out of the epistemic tally too — otherwise a
    claim could keep standing on material the field has already refused
    to serve, which is the poisoned-RAG failure one level up.
    """
    st = load_claim_state(cur, claim_id)
    cur.execute("SELECT statement FROM claims WHERE claim_id = ?", (claim_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown claim {claim_id!r}.")
    statement = row[0]
    if statement_sha256(statement) != st.statement_sha256:
        raise ValueError(
            f"{claim_id}: the stored statement does not hash to the one its "
            "assertion sealed — the proposition was edited (Invariant C1).")

    def partition(ids: tuple[str, ...]) -> tuple[list[str], list[tuple[str, str]]]:
        clean, withheld = [], []
        for mid in ids:
            cur.execute("SELECT custody_status FROM memories WHERE memory_id = ?",
                        (mid,))
            r = cur.fetchone()
            status = r[0] if r else "MISSING"
            (clean if status == "CLEAN" else withheld).append(
                mid if status == "CLEAN" else (mid, status))
        return clean, withheld

    sup, sup_w = partition(st.supports)
    con, con_w = partition(st.contradicts)
    evaluations = tuple(evaluate_set(cur, sid) for sid in st.sets)
    body = {
        "claim_id": claim_id,
        "statement_sha256": st.statement_sha256,
        "state": st.state,
        "supporting": sorted(sup),
        "contradicting": sorted(con),
        "withheld_evidence": sorted([list(x) for x in sup_w + con_w]),
        "relations": sorted([list(r) for r in st.relations]),
        "sets": sorted([[e.set_id, e.status] for e in evaluations]),
    }
    return ClaimStanding(
        claim_id=claim_id, statement=statement, state=st.state,
        asserted_by=st.asserted_by, asserted_at=st.asserted_at,
        supporting=tuple(sorted(sup)), contradicting=tuple(sorted(con)),
        withheld_evidence=tuple(sorted(sup_w + con_w)),
        relations=st.relations, set_evaluations=evaluations,
        standing_sha256=hashlib.sha256(
            canonical_json(body).encode("utf-8")).hexdigest())
