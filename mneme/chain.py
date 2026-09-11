"""
MNEME — The chain core. One implementation of the shape all three
tamper-evident chains share.

MNEME hash-chains three different things — memories (custody.py), actors
(authority.py) and propositions (claims.py) — and each one arrived by
copying the last. That was the right way to discover the pattern and the
wrong way to keep it: the genesis derivation, the envelope, the append
rules and the structural verification were three near-identical
implementations, and a rule fixed in one could quietly fail to reach the
others.

WHAT IS SHARED, and therefore lives here:

    genesis binding      prev_hash of seq 0 is sha256(PREFIX || subject),
                         so a chain for one subject cannot be presented
                         as another's
    the envelope         sha256(prev_hash || canonical_json({subject,
                         seq, event_type, actor, reason, created_at,
                         payload}))
    append rules         dense seq from 0, the birth event exactly once
                         and only at 0, a closed vocabulary, a non-empty
                         reason, and the caller's transaction
    verification         genesis, density, linkage, recomputation,
                         canonical payload bytes, canonical UTC
                         timestamps that never run backwards

WHAT IS NOT SHARED, and therefore stays in its own module: what the
events MEAN. Replay, state machines, capability maps, birth-payload
rules — custody's content seal, authority's root grant, claims' statement
hash — are the parts that differ, and folding them in here would trade a
real duplication for a false abstraction.

THE WORDING TRAVELS WITH THE SPEC. This project refuses things with its
own words, and the refusals are load-bearing: tests assert on them and
operators read them. So the messages are part of each ChainSpec rather
than generic text, and a custody chain still refuses in custody's voice.

WHY THIS IS NOT THE DUPLICATION verify_offline.py KEEPS. That file
transcribes this logic a fourth time, on purpose, so an auditor can read
one short file and install nothing. The duplication there buys a
property. The duplication here bought nothing — it was three copies
inside one import graph, all read by the same people, changed in the
same commits.

An honest note on what removing it does and does not buy: no divergence
bug was ever found between these three. The defects this session
surfaced (R3-08 and its repeat one layer up) were between a WRITER and a
VERIFIER, and between the two verifiers — duplication this refactor does
not touch. So this is prophylaxis against a failure that has not
happened yet, not a fix for one that did. It is gated by
tests/test_protocol_vectors.py, which pins the bytes so the change is
provably byte-neutral rather than merely believed to be.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .canonical import canonical_json

_MAX_ID_LEN = 64
_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:]+$")

# The canonical timestamp form that format_ts() emits: UTC, microsecond
# precision, explicit +00:00 offset. Verification re-asserts this shape so
# that (a) a lexicographic comparison of two created_at strings equals a
# chronological one — true only for a fixed-width UTC format, which is why
# a rogue offset like +05:00 is refused — and (b) the discipline enforced
# at WRITE is also enforced at READ, not merely trusted.
TS_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")


def require_id(value: str, field: str) -> None:
    """
    One identifier rule for the whole protocol. Identifiers participate in
    genesis hashes and leaf derivations; a permissive charset is an
    ambiguity budget we refuse to spend, and three different rules would
    let three chains disagree about what an identifier even is.
    """
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


@dataclass(frozen=True)
class ChainSpec:
    """
    Everything one chain kind needs that the core cannot assume.

    The message fields exist because a refusal in this project is a
    sentence someone reads, not an error code. `{subject}`, `{event}` and
    `{where}` are the only placeholders.
    """
    kind: str                    # "custody" / "authority" / "claim"
    table: str                   # SQL table name
    genesis_prefix: bytes
    subject_key: str             # envelope + column key for the subject
    actor_key: str               # envelope + column key for the writer
    birth_event: str
    event_types: frozenset[str]
    where_fmt: str               # e.g. "{subject} authority seq {seq}"
    empty_chain: str
    birth_required: str
    birth_repeated: str
    unknown_event: str
    unreasoned: str
    # The two refusals whose NOUN carries information an operator needs:
    # what exactly was tampered with, and what exactly a rogue timestamp
    # offset would make into a lie. The other verification messages are
    # derived from `kind` and `birth_event` because their wording was
    # incidental, not chosen — three near-copies drifting apart by
    # transcription rather than by intent.
    tampered: str
    rogue_offset: str

    # The one per-chain rule the core must run rather than describe: what
    # a BIRTH payload has to carry. Custody's birth seals a content hash,
    # claims' seals a statement hash, authority's registers an identity and
    # seals nothing. The core knows only WHEN a birth happens; the module
    # knows what one has to contain. Called with the payload, only on the
    # event that actually lands at seq 0, so a second birth is still
    # refused as a second birth and not as a malformed one.
    birth_payload_check: Callable[[dict[str, Any]], None] | None = None

    @property
    def columns(self) -> list[str]:
        return [self.subject_key, "seq", "event_type", self.actor_key,
                "reason", "created_at", "payload_json", "prev_hash",
                "entry_hash"]

    def where(self, subject_id: str, seq: Any) -> str:
        return self.where_fmt.format(subject=subject_id, seq=seq)


def genesis_hash(spec: ChainSpec, subject_id: str) -> str:
    """
    Per-subject genesis. Binding the subject id into seq 0's prev_hash is
    what makes chain grafting (the history of A presented as the history
    of B) structurally impossible rather than merely detectable.
    """
    require_id(subject_id, spec.subject_key)
    return hashlib.sha256(
        spec.genesis_prefix + subject_id.encode("utf-8")).hexdigest()


def compute_hash(spec: ChainSpec, *, prev_hash: str, subject_id: str, seq: int,
                 event_type: str, actor_id: str, reason: str, created_at: str,
                 payload: dict[str, Any]) -> tuple[str, str]:
    """
    Returns (entry_hash, canonical_payload_json).

    The canonical serialization is returned so the caller stores EXACTLY
    the bytes that were hashed — stored bytes and hashed bytes cannot
    drift. The payload is serialized separately from the envelope so the
    stored payload_json is byte-identical to what a verifier re-embeds.
    """
    envelope = {
        spec.subject_key: subject_id,
        "seq": seq,
        "event_type": event_type,
        spec.actor_key: actor_id,
        "reason": reason,
        "created_at": created_at,
        "payload": payload,
    }
    canonical = canonical_json(envelope)
    entry_hash = hashlib.sha256(
        prev_hash.encode("ascii") + canonical.encode("utf-8")).hexdigest()
    return entry_hash, canonical_json(payload)


def append(cur, spec: ChainSpec, *, subject_id: str, event_type: str,
           actor_id: str, reason: str, payload: dict[str, Any],
           created_at: str | None = None) -> tuple[int, str, str, str, str]:
    """
    Append one event. NEVER commits — the caller's transaction also carries
    whatever state change this event describes.

    Returns (seq, prev_hash, entry_hash, payload_json, created_at).

    Enforcement here, with the spec's words, before SQL can object with
    its own: closed vocabulary, non-empty reason, the birth event exactly
    once and only at seq 0, and no non-birth event on a chain that has no
    head — a history begins at birth, not at the first incident.
    """
    require_id(subject_id, spec.subject_key)
    require_id(actor_id, spec.actor_key)
    if event_type not in spec.event_types:
        raise ValueError(spec.unknown_event.format(event=event_type))
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(spec.unreasoned)

    cur.execute(
        f"SELECT seq, entry_hash FROM {spec.table} "
        f"WHERE {spec.subject_key} = ? ORDER BY seq DESC LIMIT 1",
        (subject_id,),
    )
    row = cur.fetchone()
    if row is None:
        if event_type != spec.birth_event:
            raise ValueError(spec.birth_required.format(
                subject=subject_id, event=event_type))
        if spec.birth_payload_check is not None:
            spec.birth_payload_check(payload)
        seq, prev_hash = 0, genesis_hash(spec, subject_id)
    else:
        if event_type == spec.birth_event:
            raise ValueError(spec.birth_repeated.format(subject=subject_id))
        seq, prev_hash = int(row[0]) + 1, str(row[1])

    ts = created_at if created_at is not None else now_ts()
    entry_hash, payload_canon = compute_hash(
        spec, prev_hash=prev_hash, subject_id=subject_id, seq=seq,
        event_type=event_type, actor_id=actor_id, reason=reason,
        created_at=ts, payload=payload)

    cols = ", ".join(spec.columns)
    cur.execute(
        f"INSERT INTO {spec.table} ({cols}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (subject_id, seq, event_type, actor_id, reason, ts,
         payload_canon, prev_hash, entry_hash),
    )
    return seq, prev_hash, entry_hash, payload_canon, ts


def verify_rows(spec: ChainSpec, subject_id: str, rows: list[dict[str, Any]],
                event_types: frozenset[str] | None = None
                ) -> tuple[bool, list[str]]:
    """
    Verify a full chain given its rows in ASCENDING seq order. Pure — no
    cursor — so a zero-dependency offline verifier and the online API can
    share one statement of what "structurally sound" means.

    Checks, in the order things break when someone lies:
      1. non-empty; seq dense from 0; the birth event first and only first
      2. genesis binding: rows[0].prev_hash == genesis_hash(subject)
      3. linkage: rows[i].prev_hash == rows[i-1].entry_hash
      4. recomputation: every entry_hash re-derives from its own fields
      5. vocabulary: every event_type belongs to the version being verified
      6. payload is valid JSON whose canonical form matches stored bytes
      7. created_at is canonical UTC AND non-decreasing along seq — a
         hash-valid chain that runs backwards is a history that cannot
         have happened, and evidence that cannot have happened is not
         evidence.

    What it does NOT check is what the events MEAN. That is replay, and
    replay is where the three chains stop being the same thing.
    """
    vocabulary = event_types if event_types is not None else spec.event_types
    errors: list[str] = []
    if not rows:
        return False, [spec.empty_chain.format(subject=subject_id)]

    expected_prev = genesis_hash(spec, subject_id)
    prev_ts: str | None = None
    for i, r in enumerate(rows):
        where = spec.where(subject_id, r.get("seq"))
        if r.get("seq") != i:
            errors.append(f"{where}: seq not dense (expected {i}).")
            return False, errors
        et = r.get("event_type")
        if et not in vocabulary:
            errors.append(f"{where}: event_type {et!r} is not in the "
                          f"{spec.kind} vocabulary being verified.")
            return False, errors
        if i == 0 and et != spec.birth_event:
            errors.append(f"{where}: chain does not begin with "
                          f"{spec.birth_event}.")
            return False, errors
        if i > 0 and et == spec.birth_event:
            errors.append(f"{where}: {spec.birth_event} after birth — "
                          "duplicated genesis semantics.")
            return False, errors
        if r.get("prev_hash") != expected_prev:
            errors.append(f"{where}: prev_hash does not link (chain broken "
                          "or grafted).")
            return False, errors

        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            errors.append(f"{where}: payload_json is not valid JSON.")
            return False, errors
        if canonical_json(payload) != r["payload_json"]:
            errors.append(
                f"{where}: stored payload_json is not in canonical form — "
                "stored bytes and hashed bytes have drifted.")
            return False, errors

        recomputed, _ = compute_hash(
            spec, prev_hash=r["prev_hash"], subject_id=subject_id,
            seq=r["seq"], event_type=et, actor_id=r[spec.actor_key],
            reason=r["reason"], created_at=r["created_at"], payload=payload)
        if recomputed != r["entry_hash"]:
            errors.append(f"{where}: entry_hash does not recompute — "
                          f"{spec.tampered}.")
            return False, errors

        ts = r["created_at"]
        if not isinstance(ts, str) or not TS_PATTERN.match(ts):
            errors.append(f"{where}: created_at {ts!r} is not canonical UTC "
                          "microsecond ISO 8601 (…+00:00) — a rogue offset "
                          f"would make {spec.rogue_offset} a lie.")
            return False, errors
        if prev_ts is not None and ts < prev_ts:
            errors.append(f"{where}: created_at {ts} precedes the previous "
                          f"event's {prev_ts} — a {spec.kind} chain cannot "
                          "run backwards in time.")
            return False, errors
        prev_ts = ts
        expected_prev = r["entry_hash"]

    return True, []


def load_rows(cur, spec: ChainSpec, subject_id: str) -> list[dict[str, Any]]:
    cols = ", ".join(spec.columns)
    cur.execute(f"SELECT {cols} FROM {spec.table} WHERE {spec.subject_key} = ? "
                "ORDER BY seq ASC", (subject_id,))
    return [dict(zip(spec.columns, r)) for r in cur.fetchall()]
