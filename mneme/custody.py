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
from typing import Any

from decimal import Decimal
from fractions import Fraction

from . import chain as _chain

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# The closed set of custody event types. Closed ON PURPOSE: a verifier
# that meets an unknown event_type must fail, not shrug — an open
# vocabulary is where "creative" writers smuggle unaudited semantics.
#
# VERSIONED, because closing a vocabulary and then quietly widening it is
# the same lie in slow motion. Each custody_protocol version names exactly
# the words that existed under it, so a bundle sealed under 1.0.0 cannot
# acquire 1.1.0's vocabulary by being read with a newer verifier — and a
# bundle that declares 1.0.0 while carrying a 1.1.0 event is caught.
_V1_EVENT_TYPES = frozenset(
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

EVENT_TYPES_BY_PROTOCOL = {
    "1.0.0": _V1_EVENT_TYPES,
    # 1.1.0 adds ONE word, and it changes no state: DECISION_USED_MEMORY is
    # the agent's explicit act of recording that a decision consumed this
    # memory. Replay treats it as a no-op (it moves no status, no field
    # state, no confidence), which is why the addition is MINOR: every
    # 1.0.0 check still holds, on the same events, with the same outcomes.
    "1.1.0": _V1_EVENT_TYPES | {"DECISION_USED_MEMORY"},
}

# What THIS build writes.
EVENT_TYPES = EVENT_TYPES_BY_PROTOCOL["1.1.0"]

# ---------------------------------------------------------------------------
# The chain shape, declared
# ---------------------------------------------------------------------------

# Custody's instance of the shared chain core (mneme/chain.py). The core
# owns the SHAPE — genesis binding, the hashed envelope, dense seq, the
# birth-event rule, structural verification. This spec owns everything the
# core cannot assume: which table, which prefix, which words custody uses
# when it refuses. Replay — what the events MEAN — stays below, in this
# module, because that is where the three chains stop being the same thing.
SPEC = _chain.ChainSpec(
    kind="custody",
    table="custody_chain",
    genesis_prefix=b"MNEME_CUSTODY_GENESIS:",
    subject_key="memory_id",
    actor_key="actor_id",
    birth_event="STORED",
    event_types=EVENT_TYPES,
    where_fmt="{subject} seq {seq}",
    empty_chain="{subject}: empty custody chain — a memory without a birth event.",
    birth_required=("First custody event for {subject} must be STORED, got "
                    "{event}. Custody begins at birth."),
    birth_repeated=("{subject} already has a custody chain; STORED is a birth "
                    "event and a memory is born once. Supersession is the "
                    "path for new content (Invariant M1)."),
    unknown_event=("Unknown custody event_type {event!r}. The vocabulary is "
                   "closed; extending it is a protocol change, not a "
                   "call-site choice."),
    unreasoned=("reason must be a non-empty string — unreasoned custody "
                "events cannot exist."),
    tampered="content tampered",
    rogue_offset="timestamp ordering",
    birth_payload_check=lambda payload: _require_birth_seal(payload),
)


def _require_birth_seal(payload: dict[str, Any]) -> None:
    """
    Custody's own birth rule, run by the core at seq 0 and nowhere else.
    A STORED event must seal the content; no other chain has an equivalent
    (authority's birth registers an identity, claims' seals a statement),
    which is exactly why this lives here and not in chain.py.
    """
    csha = payload.get("content_sha256")
    if not (isinstance(csha, str) and re.fullmatch(r"[0-9a-f]{64}", csha)):
        raise ValueError(
            "STORED payload must carry content_sha256 (64 lowercase hex). "
            "A birth event that does not seal the content seals nothing."
        )

# Re-exported so call sites and the rest of the package keep importing the
# identifier rule, the timestamp formatter and the canonical timestamp
# pattern from custody, where they have always lived. There is now ONE
# implementation of each, in chain.py: one identifier rule for the whole
# protocol, or three chains can disagree about what an identifier even is.
_MAX_ID_LEN = _chain._MAX_ID_LEN
_ID_PATTERN = _chain._ID_PATTERN
_TS_PATTERN = _chain.TS_PATTERN
_GENESIS_PREFIX = SPEC.genesis_prefix
require_id = _require_id = _chain.require_id
format_ts = _chain.format_ts
now_ts = _chain.now_ts


def genesis_hash(memory_id: str) -> str:
    """
    Per-memory genesis. Binding the memory_id into seq 0's prev_hash is
    what makes chain grafting (custody of A presented as custody of B)
    structurally impossible rather than merely detectable.
    """
    return _chain.genesis_hash(SPEC, memory_id)


def content_sha256(content: str) -> str:
    """Content identity. UTF-8 bytes, nothing clever."""
    if not isinstance(content, str):
        raise TypeError("Memory content must be str.")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


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

    The envelope and the hash formula live in chain.compute_hash; this is
    custody's name for them, kept because the formula is documented in
    this module's header and referenced by name across the project.
    """
    return _chain.compute_hash(
        SPEC, prev_hash=prev_hash, subject_id=memory_id, seq=seq,
        event_type=event_type, actor_id=actor_id, reason=reason,
        created_at=created_at, payload=payload)


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

    The shared core enforces what every chain enforces: closed vocabulary,
    non-empty reason, STORED at seq 0 and only there, and no non-birth
    event on a chain with no head — custody begins at birth, not at first
    incident.

    Custody's own birth rule — a STORED event must seal the content —
    travels with SPEC as birth_payload_check, so the core runs it at the
    one moment it applies. See _require_birth_seal.
    """
    seq, prev_hash, entry_hash, payload_canon, ts = _chain.append(
        cur, SPEC, subject_id=memory_id, event_type=event_type,
        actor_id=actor_id, reason=reason, payload=payload,
        created_at=created_at)

    return CustodyEntry(
        memory_id=memory_id, seq=seq, event_type=event_type,
        actor_id=actor_id, reason=reason, created_at=ts,
        payload_json=payload_canon, prev_hash=prev_hash, entry_hash=entry_hash,
    )


# ---------------------------------------------------------------------------
# Verification (pure over rows; the offline verifier reuses this)
# ---------------------------------------------------------------------------

# Where a memory's confidence begins, before any REINFORCED event.
INITIAL_CONFIDENCE = "0.5000000000"

# The confidence at which NEUTRAL becomes REINFORCED. It lives here rather
# than in field.py because replay_protocol 1.1.0 CHECKS it: a promotion is
# no longer merely recorded, it must be arithmetically due. A semantic
# mutant that turns the comparison from >= into > is caught by this and by
# nothing else, which is exactly how the mutation suite found it.
PROMOTION_THRESHOLD = Fraction(3, 4)


def replay_state(chain: list[dict[str, Any]],
                 replay_protocol: str = "1.1.0") -> tuple[str, str, str, list[str]]:
    """
    Replay a verified chain's events through the normative state machine.
    Returns (custody_status, field_state, confidence, errors). Pure; the
    standalone verifier transcribes this function, and bundle check B4
    compares its output against what a bundle DECLARES.

    THE NORMATIVE STATEMENT, written down once, here (replay_protocol):

      custody_status: starts CLEAN at STORED.
          QUARANTINED      -> QUARANTINED
          SUPERSEDED_BY    -> SUPERSEDED
          TAINT_FLAGGED    -> TAINT_FLAGGED only if currently CLEAN
                              (stronger statuses are retained; the event
                              still exists — the chain records that the
                              sweep saw the memory)
          REHABILITATED    -> CLEAN, valid only from TAINT_FLAGGED
      field_state: starts NEUTRAL; STATE_CHANGED applies payload["to"] and
          its payload["from"] must equal the current state.
      confidence: starts 0.5000000000; each REINFORCED must declare
          confidence_before equal to current, and sets confidence_after.
      Every other event type changes nothing: CONTRADICTED_BY records a
      fact about a relationship, and DECISION_USED_MEMORY records a fact
      about a decision. Neither is a state transition, and a replay that
      moved state on them would be inventing history.

    replay_protocol 1.1.0 adds ONE rule, and the mutation suite is why:

      PROMOTION IS ARITHMETICALLY DUE. A STATE_CHANGED from NEUTRAL to
      REINFORCED is valid only when the replayed confidence has reached
      PROMOTION_THRESHOLD, and a REINFORCED that carries confidence to or
      past the threshold while NEUTRAL must be followed by that
      promotion. Under 1.0.0 the replay only checked that a declared
      state was DERIVABLE from the events, which a writer that quietly
      changed >= to > satisfied perfectly — it simply emitted fewer
      events, and every one of them was consistent. That mutant survived
      every check MNEME had. Now it does not.

      1.0.0 is still implemented and still supported: a bundle sealed
      under it is checked under it, promotion rule and all, because
      applying a rule its sealer never agreed to is the retroactive
      semantics this project refuses.
    """
    import json
    errors: list[str] = []
    check_promotion = replay_protocol != "1.0.0"
    status, fstate, conf = "CLEAN", "NEUTRAL", INITIAL_CONFIDENCE
    promotion_due = False
    for r in chain:
        et = r["event_type"]
        where = f"{r['memory_id']} seq {r['seq']}"
        payload = json.loads(r["payload_json"])
        if et == "QUARANTINED":
            status = "QUARANTINED"
        elif et == "SUPERSEDED_BY":
            status = "SUPERSEDED"
        elif et == "TAINT_FLAGGED":
            if status == "CLEAN":
                status = "TAINT_FLAGGED"
        elif et == "REHABILITATED":
            if status != "TAINT_FLAGGED":
                errors.append(f"{where}: REHABILITATED from {status}, "
                              "valid only from TAINT_FLAGGED.")
            status = "CLEAN"
        elif et == "STATE_CHANGED":
            if check_promotion and payload.get("to") == "REINFORCED" \
                    and payload.get("from") == "NEUTRAL" \
                    and Fraction(Decimal(conf)) < PROMOTION_THRESHOLD:
                errors.append(
                    f"{where}: promotion to REINFORCED at confidence {conf}, "
                    f"below the threshold "
                    f"{PROMOTION_THRESHOLD.numerator}/"
                    f"{PROMOTION_THRESHOLD.denominator} — a promotion that was "
                    "not arithmetically due.")
            promotion_due = False
            if payload.get("from") != fstate:
                errors.append(f"{where}: STATE_CHANGED claims from="
                              f"{payload.get('from')!r} but replay says {fstate!r}.")
            to = payload.get("to")
            if to not in ("REINFORCED", "NEUTRAL", "FORGOTTEN"):
                errors.append(f"{where}: STATE_CHANGED to unknown state {to!r}.")
            else:
                fstate = to
        elif et == "REINFORCED":
            before = payload.get("confidence_before")
            after = payload.get("confidence_after")
            if before != conf:
                errors.append(f"{where}: REINFORCED claims before={before!r} "
                              f"but replay says {conf!r}.")
            if not isinstance(after, str):
                errors.append(f"{where}: REINFORCED without confidence_after.")
            else:
                conf = after
                if check_promotion and fstate == "NEUTRAL" \
                        and Fraction(Decimal(conf)) >= PROMOTION_THRESHOLD:
                    promotion_due = True
    if check_promotion and promotion_due:
        errors.append(
            f"{chain[-1]['memory_id']}: confidence reached {conf}, at or past "
            f"the promotion threshold "
            f"{PROMOTION_THRESHOLD.numerator}/{PROMOTION_THRESHOLD.denominator}, "
            "with no STATE_CHANGED to REINFORCED — a promotion that was due "
            "and never recorded.")
    return status, fstate, conf, errors

def verify_custody_rows(memory_id: str, rows: list[dict[str, Any]],
                        event_types: frozenset[str] | None = None) -> tuple[bool, list[str]]:
    """
    Verify a full custody chain given its rows in ASCENDING seq order.
    Pure — no cursor — so the 0-dependency offline verifier and the
    online API share one implementation and cannot disagree.

    The checks live in chain.verify_rows, against custody's SPEC:

      1. non-empty; seq dense from 0; first event STORED, STORED only at 0
      2. genesis binding: rows[0].prev_hash == genesis_hash(memory_id)
      3. linkage: rows[i].prev_hash == rows[i-1].entry_hash
      4. recomputation: every entry_hash re-derives from its fields
      5. vocabulary: every event_type belongs to the custody_protocol
         version being verified (the caller passes it; the default is what
         this build writes)
      6. payload is valid JSON whose canonical form matches stored bytes
      7. created_at is canonical UTC form AND non-decreasing along seq —
         a chain cannot run backwards in time. Integrity and insertion
         order are not enough: a hash-valid chain whose seq-1 event is
         timestamped before its seq-0 birth is a history that cannot have
         happened, and evidence that cannot have happened is not evidence.

    What this does NOT check is what the events MEAN. That is
    replay_state(), above, and replay is where custody stops being a
    generic chain and starts being a chain of custody.
    """
    return _chain.verify_rows(SPEC, memory_id, rows, event_types)


def verify_custody_chain(cur, memory_id: str) -> tuple[bool, list[str]]:
    """Load and verify one memory's full custody chain."""
    return verify_custody_rows(memory_id, _chain.load_rows(cur, SPEC, memory_id))
