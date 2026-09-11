"""
MNEME — Adaptive memory field with custody-gated recall and EXACT ranking.

The field mechanics are raven-memory's (ternary states, RESONANT /
INHIBITORY links, BFS hop expansion, the REINFORCED-rescue rule), with
two upgrades that raven could not make and MNEME exists to make:

1.  THE CUSTODY GATE. Recall never serves a memory whose custody_status
    is not CLEAN. QUARANTINED, TAINT_FLAGGED and SUPERSEDED memories
    remain in the field (Invariant M4 — nothing is deleted, evidence is
    preserved) but are invisible to the agent. Every exclusion is
    counted in the recall receipt, so "what was withheld and why" is a
    number, not a mystery.

2.  EXACT RANKING. raven ranks with float cosine + exp() decay and buys
    determinism by pinning BLAS to one thread. MNEME removes the
    problem instead of managing it:

        score(m) = sim(q, m) · (state_boost · decay^hop + resonant_boost)
        sim(q,m) = dot(q,m) / sqrt(|q|²·|m|²)

    Every factor except the square root is a Fraction. Ranking does not
    need the square root: for non-negative t_i = dot_i · M_i (with
    M_i = state·decay^hop + boost, exact), the order of t_i / sqrt(n_i)
    is the order of t_i² / n_i — an exact Fraction. Negative t carries
    no ranking information the agent should act on (raven clamps to 0;
    we do too, exactly). Ties break on memory_id ascending. Result:
    same database state + same query ⇒ byte-identical ranking on any
    machine, no BLAS, no float, no seed.

    exp(-λ·hop) is replaced by DECAY_BASE^hop with DECAY_BASE = 43/50
    (= 0.86; e^-0.15 ≈ 0.8607). The half-life story is unchanged; the
    arithmetic becomes exact.

FLOAT BOUNDARY, stated once: embeddings arrive from models as floats.
That is a MEASUREMENT, not a decision — the one sanctioned float
ingestion. quantize_embedding() converts them to canonical-scale
Decimals immediately at the boundary; from that point on the vector is
exact and its stored JSON bytes are the bytes any hash would cover.
Scores REPORTED to humans go the other way: exact Fraction → Decimal
via integer sqrt (math.isqrt — deterministic), quantized at scale 10.

As everywhere: every function takes a live cursor and NEVER commits.
State transitions write custody events in the caller's transaction (M2).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from decimal import Decimal
from fractions import Fraction
from typing import Any, Iterable

from .canonical import CANONICAL_SCALE, canonical_json, quantize
from . import authority, custody, protocol

# ---------------------------------------------------------------------------
# Exact constants (raven's, made rational)
# ---------------------------------------------------------------------------

STATE_BOOST = {
    "REINFORCED": Fraction(3, 2),   # raven: ×1.5
    "NEUTRAL": Fraction(1, 1),      # raven: ×1.0
    "FORGOTTEN": Fraction(0, 1),    # raven: ×0.0 (filtered before scoring)
}
DECAY_BASE = Fraction(43, 50)       # ≈ e^-0.15 per hop, exactly 0.86
RESONANT_BOOST_STEP = Fraction(1, 2)  # raven: +0.5 per resonant in-edge
DEFAULT_HOPS = 2
MAX_HOP_SEARCH = 10                 # raven's named BFS ceiling

REINFORCEMENT_ALPHA = Fraction(1, 4)      # c' = c + α(1−c) — STIGMERGY's closed form
PROMOTION_THRESHOLD = Fraction(3, 4)      # confidence ≥ 3/4 ⇒ field_state REINFORCED

_SCALE_INT = 10 ** CANONICAL_SCALE


# ---------------------------------------------------------------------------
# Embedding boundary
# ---------------------------------------------------------------------------

def quantize_embedding(values: Iterable[float | int | str | Decimal | Fraction]) -> list[Decimal]:
    """
    The one sanctioned float crossing. Model output (floats) becomes a
    list of canonical-scale Decimals, exactly once, at the boundary.
    Strings are accepted (round-trip from storage), floats are converted
    via Fraction(float) — exact binary value, then explicit quantization.
    """
    out: list[Decimal] = []
    for i, v in enumerate(values):
        if isinstance(v, bool):
            raise TypeError(f"embedding[{i}]: bool is not a component.")
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ValueError(f"embedding[{i}]: non-finite component.")
            out.append(quantize(Fraction(v), field=f"embedding[{i}]"))
        elif isinstance(v, str):
            out.append(quantize(Fraction(Decimal(v)), field=f"embedding[{i}]"))
        else:
            out.append(quantize(v if isinstance(v, (Fraction, int)) else Fraction(v),
                                field=f"embedding[{i}]"))
    if not out:
        raise ValueError("Empty embedding refused.")
    return out


def embedding_to_json(emb: list[Decimal]) -> str:
    """Canonical storage form: JSON array of fixed-point strings."""
    return canonical_json({"v": emb})


def embedding_from_json(s: str) -> list[Fraction]:
    data = json.loads(s)
    return [Fraction(Decimal(x)) for x in data["v"]]


def _dot(a: list[Fraction], b: list[Fraction]) -> Fraction:
    if len(a) != len(b):
        raise ValueError(f"Dimension mismatch: {len(a)} vs {len(b)}.")
    return sum((x * y for x, y in zip(a, b)), Fraction(0))


def _sqrt_fraction(f: Fraction) -> Fraction:
    """
    Deterministic rational approximation of sqrt for REPORTING only
    (never for ranking): floor(isqrt(p·s²·q) / q) / s at scale s=10^10.
    math.isqrt is exact integer arithmetic — identical on every platform.
    """
    if f < 0:
        raise ValueError("sqrt of negative refused.")
    p, q = f.numerator, f.denominator
    return Fraction(math.isqrt(p * _SCALE_INT * _SCALE_INT * q), q * _SCALE_INT)


# ---------------------------------------------------------------------------
# Store / contradict / reinforce (state changes ⇒ custody events)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StoredMemory:
    memory_id: str
    content_sha256: str
    inhibitory_links: tuple[str, ...]   # contradictions detected at birth


def store(
    cur,
    *,
    memory_id: str,
    content: str,
    embedding: list[Decimal],
    embedding_model: str,
    actor_id: str,
    reason: str,
    topic: str | None = None,
    claim: str | None = None,
    supersedes: str | None = None,
    derived_from_decision: str | None = None,
    created_at: str | None = None,
    grant_id: str | None = None,
) -> StoredMemory:
    """
    Insert a memory + its STORED custody event + auto-detected
    contradiction links, all in the caller's transaction.

    AUTHORITY (Invariant A1): the actor must hold STORE at this instant —
    or SUPERSEDE, when `supersedes` names a predecessor, because retiring
    an existing memory is a strictly stronger act than adding one. The
    grant that authorized it is sealed into the STORED payload, so the
    event carries its own authority proof and B7 can re-check it offline
    against the actor's authority chain. In a field with no authority
    ledger the write proceeds and seals no grant_id — unauthorized by
    declaration, never by omission (see authority.gate).

    Contradiction rule (raven's, verbatim in spirit): same topic,
    different claim ⇒ bidirectional INHIBITORY links, PLUS — the MNEME
    addition — a CONTRADICTED_BY custody event on BOTH chains. A
    contradiction is a fact about both parties' history; recording it
    on one chain only would let the other party's export hide it.

    `supersedes` names a predecessor in the STORED payload. Callers do
    not pass it directly — supersede() is the path, and it writes the
    matching SUPERSEDED_BY event on the predecessor's chain in the same
    transaction. A STORED payload claiming supersession that the named
    predecessor's chain does not corroborate fails bundle check B4:
    lineage is a bilateral fact, like contradiction.
    """
    ts = created_at if created_at is not None else custody.now_ts()
    birth_capability = "SUPERSEDE" if supersedes is not None else "STORE"
    birth_grant = authority.gate(
        cur, actor_id=actor_id, capability=birth_capability, at_ts=ts,
        grant_id=grant_id,
    )
    csha = custody.content_sha256(content)
    emb_json = embedding_to_json(embedding)

    cur.execute(
        "INSERT INTO memories (memory_id, content, content_sha256, "
        "embedding_json, embedding_model, topic, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (memory_id, content, csha, emb_json, embedding_model, topic, actor_id, ts),
    )
    payload: dict[str, Any] = {"content_sha256": csha, "embedding_model": embedding_model}
    if topic is not None:
        payload["topic"] = topic
    if claim is not None:
        payload["claim"] = claim
    if supersedes is not None:
        payload["supersedes"] = supersedes
    if derived_from_decision is not None:
        # The agent's declared causal parent: "I stored this BECAUSE of
        # that decision". Blast-radius reconstruction follows this edge
        # instead of guessing one, which is the difference between a
        # DERIVED level that means something and a heuristic.
        payload["derived_from_decision"] = derived_from_decision
    if birth_grant is not None:
        payload["grant_id"] = birth_grant
    custody.append_event(
        cur, memory_id=memory_id, event_type="STORED", actor_id=actor_id,
        reason=reason, payload=payload, created_at=ts,
    )

    contradicted: list[str] = []
    if topic and claim:
        # Claims live in the STORED payload of each chain — the custody
        # chain is the source of truth, not a mutable metadata column.
        cur.execute(
            "SELECT c.memory_id, c.payload_json FROM custody_chain c "
            "JOIN memories m ON m.memory_id = c.memory_id "
            "WHERE c.seq = 0 AND m.topic = ? AND c.memory_id != ? "
            "ORDER BY c.memory_id ASC",
            (topic, memory_id),
        )
        for other_id, pj in cur.fetchall():
            other_claim = json.loads(pj).get("claim")
            if other_claim and other_claim != claim:
                contradicted.append(other_id)

    # A contradiction event lands on a THIRD PARTY's chain, so it is
    # authorized separately and always against STORE — superseding a claim
    # is disagreeing with it, and disagreeing on someone else's chain is
    # the act of a writer, not of a retirer. An actor that may supersede
    # but may not store therefore cannot supersede INTO a contradiction;
    # the refusal is loud and its reason is this sentence.
    contradiction_grant = None
    if contradicted:
        contradiction_grant = authority.gate(
            cur, actor_id=actor_id, capability="STORE", at_ts=ts,
            grant_id=grant_id if birth_capability == "STORE" else None,
        )

    for other_id in contradicted:
        for a, b in ((memory_id, other_id), (other_id, memory_id)):
            cur.execute(
                "INSERT OR IGNORE INTO cell_links "
                "(from_id, to_id, link_type, auto, created_at) "
                "VALUES (?, ?, 'INHIBITORY', 1, ?)",
                (a, b, ts),
            )
            cpayload: dict[str, Any] = {"other_memory_id": b, "topic": topic}
            if contradiction_grant is not None:
                cpayload["grant_id"] = contradiction_grant
            custody.append_event(
                cur, memory_id=a, event_type="CONTRADICTED_BY", actor_id=actor_id,
                reason=f"auto contradiction on topic {topic!r}",
                payload=cpayload,
                created_at=ts,
            )

    return StoredMemory(memory_id=memory_id, content_sha256=csha,
                        inhibitory_links=tuple(contradicted))


def supersede(
    cur,
    *,
    old_memory_id: str,
    memory_id: str,
    content: str,
    embedding: list[Decimal],
    embedding_model: str,
    actor_id: str,
    reason: str,
    topic: str | None = None,
    claim: str | None = None,
    created_at: str | None = None,
    grant_id: str | None = None,
) -> StoredMemory:
    """
    The M1 path for new content: content is immutable, so an "update"
    is a NEW memory plus evidence on both chains, in one transaction —
      - the successor's STORED payload names its predecessor
        ("supersedes"), and
      - the predecessor's chain gains SUPERSEDED_BY naming the
        successor, its custody_status becomes SUPERSEDED (invisible to
        recall, preserved as evidence — M4), and memories.superseded_by
        points forward.

    Refused for a non-CLEAN predecessor: a SUPERSEDED memory already
    has a successor (two would fork the lineage), and a TAINT_FLAGGED /
    QUARANTINED memory is incident evidence — correcting the record is
    rehabilitation's job or a fresh store, not a supersession that
    would overwrite the incident's most-recent-status.

    If the successor shares the predecessor's topic with a different
    claim, the automatic contradiction rule fires as usual and both
    chains also record CONTRADICTED_BY — truthful, kept: superseding a
    claim IS disagreeing with it.

    AUTHORITY: SUPERSEDE, resolved once and sealed into both halves of
    the lineage, so an auditor reading either chain finds the same grant
    behind the same act. A contradiction fired by the successor is
    authorized separately against STORE (see store()).
    """
    cur.execute("SELECT custody_status FROM memories WHERE memory_id = ?",
                (old_memory_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown memory {old_memory_id!r} — nothing to supersede.")
    if row[0] != "CLEAN":
        raise ValueError(
            f"{old_memory_id} has custody_status {row[0]!r}; only a CLEAN "
            "memory can be superseded (a second successor would fork the "
            "lineage; tainted memories are incident evidence)."
        )
    ts = created_at if created_at is not None else custody.now_ts()
    # Both halves of the lineage are one act, so both are authorized by one
    # grant, resolved once here and sealed into both events. Resolving it
    # before store() also means an unauthorized supersession never creates
    # the successor at all.
    lineage_grant = authority.gate(
        cur, actor_id=actor_id, capability="SUPERSEDE", at_ts=ts,
        grant_id=grant_id,
    )

    stored = store(
        cur, memory_id=memory_id, content=content, embedding=embedding,
        embedding_model=embedding_model, actor_id=actor_id, reason=reason,
        topic=topic, claim=claim, supersedes=old_memory_id, created_at=ts,
        grant_id=lineage_grant,
    )
    retire_payload: dict[str, Any] = {"successor_memory_id": memory_id}
    if lineage_grant is not None:
        retire_payload["grant_id"] = lineage_grant
    custody.append_event(
        cur, memory_id=old_memory_id, event_type="SUPERSEDED_BY",
        actor_id=actor_id, reason=reason,
        payload=retire_payload, created_at=ts,
    )
    # Security audit Round 2, H4: the CLEAN check above is a single read;
    # a concurrent supersede() on the same old_memory_id can pass that
    # same read before either writer commits, and both would otherwise
    # append their own SUPERSEDED_BY event — forking the lineage this
    # function's docstring claims cannot fork. The guard here re-asserts
    # CLEAN at the moment of the write, atomically with the write itself;
    # a rowcount of 0 means a concurrent writer got there first, and the
    # whole transaction (including the successor's STORED and this
    # SUPERSEDED_BY event, still uncommitted) rolls back with the caller's
    # rollback — nothing is left half-applied.
    cur.execute(
        "UPDATE memories SET custody_status = 'SUPERSEDED', superseded_by = ? "
        "WHERE memory_id = ? AND custody_status = 'CLEAN'",
        (memory_id, old_memory_id),
    )
    if cur.rowcount != 1:
        raise ValueError(
            f"{old_memory_id} custody_status changed after the initial CLEAN "
            "check — a concurrent writer raced this supersession. Refusing "
            "to fork the lineage."
        )
    return stored


def reinforce(cur, *, memory_id: str, actor_id: str, reason: str,
              created_at: str | None = None,
              grant_id: str | None = None) -> tuple[Decimal, str]:
    """
    STIGMERGY's closed form c' = c + α(1−c), exact, plus custody event.
    Returns (new_confidence, field_state). Promotion to REINFORCED at
    the exact threshold writes its own STATE_CHANGED event — one state
    transition, one event, always.

    AUTHORITY: REINFORCE, and the promotion event it may trigger is
    sealed under the same grant — one act, one authorization. Round 2's
    R2-01 lived exactly here: a quarantined actor could keep inflating a
    clean memory's confidence. It no longer can, and the refusal happens
    in this transaction rather than in a later sweep.
    """
    cur.execute(
        "SELECT confidence, field_state, custody_status FROM memories "
        "WHERE memory_id = ?", (memory_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Unknown memory {memory_id!r}.")
    conf_txt, state, status = row
    if status != "CLEAN":
        raise ValueError(
            f"{memory_id} has custody_status {status!r}; reinforcing a "
            "non-CLEAN memory would launder taint into confidence."
        )
    ts = created_at if created_at is not None else custody.now_ts()
    reinforce_grant = authority.gate(
        cur, actor_id=actor_id, capability="REINFORCE", at_ts=ts,
        grant_id=grant_id,
    )

    c = Fraction(Decimal(conf_txt))
    c_new = c + REINFORCEMENT_ALPHA * (1 - c)
    conf_q = quantize(c_new, field="confidence")

    rpayload: dict[str, Any] = {"confidence_before": quantize(c),
                                "confidence_after": conf_q}
    if reinforce_grant is not None:
        rpayload["grant_id"] = reinforce_grant
    custody.append_event(
        cur, memory_id=memory_id, event_type="REINFORCED", actor_id=actor_id,
        reason=reason, payload=rpayload, created_at=ts,
    )
    cur.execute("UPDATE memories SET confidence = ? WHERE memory_id = ?",
                (format(conf_q, "f"), memory_id))

    new_state = state
    if state == "NEUTRAL" and c_new >= PROMOTION_THRESHOLD:
        new_state = "REINFORCED"
        spayload: dict[str, Any] = {"from": "NEUTRAL", "to": "REINFORCED"}
        if reinforce_grant is not None:
            spayload["grant_id"] = reinforce_grant
        custody.append_event(
            cur, memory_id=memory_id, event_type="STATE_CHANGED", actor_id=actor_id,
            reason=f"confidence crossed promotion threshold "
                   f"{PROMOTION_THRESHOLD.numerator}/{PROMOTION_THRESHOLD.denominator}",
            payload=spayload,
            created_at=ts,
        )
        cur.execute("UPDATE memories SET field_state = 'REINFORCED' "
                    "WHERE memory_id = ?", (memory_id,))
    return conf_q, new_state


# ---------------------------------------------------------------------------
# Recall (read-only over memories; gated by custody_status)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecallHit:
    memory_id: str
    content: str
    score: Decimal          # reported value (isqrt approximation, scale 10)
    hop_distance: int       # -1 = not graph-reachable from seed
    field_state: str
    inhibition_rescued: bool


@dataclass(frozen=True)
class RecallReceipt:
    """
    What recall DID, sealed into one deterministic digest. This is the
    object a CRONOS-style tracer records: served ids in order, plus the
    counts of everything withheld and why. 'Why does the agent remember
    this' starts with 'here is the receipt of the recall that served it.'

    receipt_protocol 2.0.0 — a MAJOR bump, and worth stating why, since
    MINOR would have been the comfortable choice. The 1.0.0 body recorded
    what a recall RETURNED but not what it was ASKED: no top_k, no hops,
    no ranking semantics. A receipt that cannot say which question it
    answered cannot be replayed, and a receipt that cannot be replayed
    cannot anchor a counterfactual ("would this decision have differed
    without the poisoned memory?"). Adding those three fields changes the
    digest body, so a 1.0.0 receipt does not recompute under 1.0.0 rules
    — that is a different protocol, not an extension of one, and calling
    it MINOR would have been the first lie this file tells.
    """
    query_sha256: str
    seed_memory_id: str | None
    served: tuple[str, ...]
    excluded_custody: int      # TAINT_FLAGGED / QUARANTINED / SUPERSEDED
    excluded_forgotten: int
    excluded_inhibited: int
    top_k: int
    hops: int
    ranking_protocol: str
    # The WORLD this recall was taken in. Empty for a real recall against
    # the field's actual custody state; non-empty for a counterfactual —
    # a recall run against a hypothetical custody state, e.g. "as if the
    # poisoned memory had never been contained". It is inside the digest
    # on purpose: a counterfactual receipt must be structurally impossible
    # to launder into evidence about the actual field.
    custody_override: tuple[tuple[str, str], ...]
    receipt_sha256: str


def receipt_body(r: RecallReceipt) -> dict[str, Any]:
    """
    The exact bytes a receipt's digest covers. One function, used when
    sealing, when persisting, and when verifying, so the three cannot
    drift — the same discipline compute_entry_hash holds custody to.
    """
    return {
        "query_sha256": r.query_sha256,
        "seed_memory_id": r.seed_memory_id,
        "served": list(r.served),
        "excluded_custody": r.excluded_custody,
        "excluded_forgotten": r.excluded_forgotten,
        "excluded_inhibited": r.excluded_inhibited,
        "top_k": r.top_k,
        "hops": r.hops,
        "ranking_protocol": r.ranking_protocol,
        "custody_override": [list(p) for p in r.custody_override],
    }


def _receipt(query_sha: str, seed: str | None, served: list[str],
             exc_c: int, exc_f: int, exc_i: int,
             top_k: int, hops: int,
             override: dict[str, str] | None = None) -> RecallReceipt:
    import hashlib
    r = RecallReceipt(query_sha256=query_sha, seed_memory_id=seed,
                      served=tuple(served), excluded_custody=exc_c,
                      excluded_forgotten=exc_f, excluded_inhibited=exc_i,
                      top_k=top_k, hops=hops,
                      ranking_protocol=protocol.RANKING_PROTOCOL,
                      custody_override=tuple(
                          (k, override[k]) for k in sorted(override or {})),
                      receipt_sha256="")
    digest = hashlib.sha256(
        canonical_json(receipt_body(r)).encode("utf-8")).hexdigest()
    return replace(r, receipt_sha256=digest)


def persist_receipt(cur, receipt: RecallReceipt, *,
                    persisted_at: str | None = None) -> None:
    """
    The caller's explicit act of keeping a recall receipt. Recall
    itself stays read-only — forcing a write into every recall would
    quietly convert the hottest read path into a write path — so
    persistence is a separate, deliberate call, made in the caller's
    transaction like every other write.

    The digest is recomputed here before insert: this table can never
    hold a receipt that does not recompute from its own fields.
    Persisting the same receipt twice is a no-op (same evidence, same
    digest, one row).
    """
    import hashlib
    digest = hashlib.sha256(
        canonical_json(receipt_body(receipt)).encode("utf-8")).hexdigest()
    if digest != receipt.receipt_sha256:
        raise ValueError(
            "Receipt digest does not recompute from its fields — refusing "
            "to persist a receipt that is already a lie."
        )
    cur.execute("SELECT 1 FROM recall_receipts WHERE receipt_sha256 = ?",
                (digest,))
    if cur.fetchone() is not None:
        return
    ts = persisted_at if persisted_at is not None else custody.now_ts()
    cur.execute(
        "INSERT INTO recall_receipts (receipt_sha256, query_sha256, "
        "seed_memory_id, served_json, excluded_custody, excluded_forgotten, "
        "excluded_inhibited, top_k, hops, ranking_protocol, "
        "custody_override_json, persisted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (digest, receipt.query_sha256, receipt.seed_memory_id,
         canonical_json({"served": list(receipt.served)}),
         receipt.excluded_custody, receipt.excluded_forgotten,
         receipt.excluded_inhibited, receipt.top_k, receipt.hops,
         receipt.ranking_protocol,
         canonical_json({"override": [list(p) for p in receipt.custody_override]}),
         ts),
    )


def verify_receipts(cur) -> tuple[bool, list[str]]:
    """
    Recompute every persisted receipt's digest from its own columns.
    A row whose primary key does not re-derive has been edited — the
    same state-is-derivable-from-evidence discipline as bundle check
    B4, applied to recall evidence.
    """
    errors: list[str] = []
    for row in load_receipt_rows(cur):
        digest = row["receipt_sha256"]
        try:
            served = json.loads(row["served_json"])["served"]
        except Exception:
            errors.append(f"receipt {digest}: served_json is not valid JSON.")
            continue
        if receipt_digest_from_row(row, served) != digest:
            errors.append(f"receipt {digest}: does not recompute from its "
                          "columns — receipt evidence edited.")
    return (not errors), errors


RECEIPT_COLS = ["receipt_sha256", "query_sha256", "seed_memory_id",
                "served_json", "excluded_custody", "excluded_forgotten",
                "excluded_inhibited", "top_k", "hops", "ranking_protocol",
                "custody_override_json", "persisted_at"]


def load_receipt_rows(cur, receipt_sha256s: list[str] | None = None) -> list[dict[str, Any]]:
    sql = ("SELECT " + ", ".join(RECEIPT_COLS) + " FROM recall_receipts ")
    params: tuple = ()
    if receipt_sha256s is not None:
        if not receipt_sha256s:
            return []
        sql += "WHERE receipt_sha256 IN (%s) " % ",".join(
            "?" for _ in receipt_sha256s)
        params = tuple(receipt_sha256s)
    sql += "ORDER BY receipt_sha256 ASC"
    cur.execute(sql, params)
    return [dict(zip(RECEIPT_COLS, r)) for r in cur.fetchall()]


def receipt_digest_from_row(row: dict[str, Any], served: list[str]) -> str:
    """
    Re-derive a persisted receipt's digest from its own columns. Shared by
    verify_receipts() and by bundle check B8, and transcribed by the
    offline verifier — one statement of what a receipt digest covers.
    """
    import hashlib
    body = {
        "query_sha256": row["query_sha256"],
        "seed_memory_id": row["seed_memory_id"],
        "served": served,
        "excluded_custody": int(row["excluded_custody"]),
        "excluded_forgotten": int(row["excluded_forgotten"]),
        "excluded_inhibited": int(row["excluded_inhibited"]),
        "top_k": int(row["top_k"]),
        "hops": int(row["hops"]),
        "ranking_protocol": row["ranking_protocol"],
        "custody_override": json.loads(row["custody_override_json"])["override"],
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


CUSTODY_STATUSES = frozenset({"CLEAN", "TAINT_FLAGGED", "QUARANTINED",
                              "SUPERSEDED"})


def recall(
    cur,
    *,
    query_embedding: list[Decimal],
    top_k: int = 5,
    hops: int = DEFAULT_HOPS,
    custody_override: dict[str, str] | None = None,
) -> tuple[list[RecallHit], RecallReceipt]:
    """
    Custody-gated, exactly-ranked recall.

      1. Load servable candidates: custody_status = 'CLEAN' only. The
         gate is a WHERE clause, not a post-filter — a tainted memory
         cannot even become the BFS seed, AND cannot be traversed as a
         BFS intermediary: links are followed only between CLEAN
         endpoints, so a non-CLEAN memory exerts zero influence on the
         ranking of the memories that ARE served.
      2. Field-state filter: FORGOTTEN never scores (counted).
      3. Seed = exact-similarity argmax (squared comparison, sign-aware,
         memory_id tiebreak).
      4. BFS over cell_links from the seed: INHIBITORY silences targets,
         RESONANT accumulates +1/2 boost per in-edge and extends the
         frontier. raven's rescue rule holds: a REINFORCED memory cannot
         be silenced by inhibition ("a validated truth cannot be
         silenced by an unverified claim").
      5. score = sim · (state_boost · DECAY_BASE^hop + resonant_boost),
         ranked by the exact Fraction t²/n (see module header), clamped
         at 0, ties on memory_id ascending.

    Read-only by design: recall does not write custody events (serving
    is not a state transition). Reinforcement driven by recall results
    is the caller's explicit, audited act via reinforce().

    custody_override runs the SAME recall against a HYPOTHETICAL custody
    state: {memory_id: status}. It is the primitive the counterfactual
    analysis is built on — "what would this query have returned in a
    world where the poisoned memory had never been contained" — and it
    works in both directions, since a memory can be forced CLEAN as
    easily as forced QUARANTINED.

    Two disciplines make this safe rather than a hole:
      - it changes nothing. No write, no status column touched; the
        override lives only in this call's arithmetic.
      - the receipt SAYS SO. The override is inside the receipt digest,
        so a counterfactual receipt is structurally distinguishable from
        a real one and cannot be laundered into evidence about the actual
        field — and record_decision refuses to let a decision cite one,
        because no agent ever decided from a world that did not exist.

    ranking_protocol stays 1.0.0: with an empty override the behaviour is
    byte-identical, and with a non-empty one the SCORING rules are
    untouched — only which memories the (unchanged) gate admits.
    """
    override = dict(custody_override or {})
    for mid, status in override.items():
        if status not in CUSTODY_STATUSES:
            raise ValueError(
                f"custody_override[{mid!r}] = {status!r} is not a custody "
                f"status. A hypothetical world must still be a possible one.")
    q = [Fraction(x) for x in query_embedding]
    nq = _dot(q, q)
    if nq == 0:
        raise ValueError("Zero query vector refused — cosine is undefined.")
    import hashlib
    query_sha = hashlib.sha256(
        embedding_to_json(list(query_embedding)).encode("utf-8")
    ).hexdigest()

    # The gate, computed once from (actual status, overridden status). Read
    # every memory rather than filtering in SQL, because the override can
    # move a memory in EITHER direction and a WHERE clause can only ever
    # narrow.
    cur.execute(
        "SELECT memory_id, content, embedding_json, field_state, custody_status "
        "FROM memories ORDER BY memory_id ASC",
    )
    all_rows = cur.fetchall()
    unknown = sorted(set(override) - {r[0] for r in all_rows})
    if unknown:
        raise ValueError(
            f"custody_override names memories this field does not have: "
            f"{unknown}. A counterfactual is about THIS field or it is fiction.")
    rows = []
    excluded_custody = 0
    servable_ids: set[str] = set()
    for mid, content, ej, state, status in all_rows:
        if override.get(mid, status) == "CLEAN":
            rows.append((mid, content, ej, state))
            servable_ids.add(mid)
        else:
            excluded_custody += 1

    candidates = []       # (memory_id, content, vec, norm², dot, state)
    excluded_forgotten = 0
    for mid, content, ej, state in rows:
        if state == "FORGOTTEN":
            excluded_forgotten += 1
            continue
        vec = embedding_from_json(ej)
        nv = _dot(vec, vec)
        if nv == 0:
            continue
        candidates.append((mid, content, vec, nv, _dot(q, vec), state))

    if not candidates:
        return [], _receipt(query_sha, None, [], excluded_custody,
                            excluded_forgotten, 0, top_k, hops, override)

    # --- Seed: exact argmax of dot/sqrt(nv) — sign-aware squared compare.
    def sim_key(c):
        _, _, _, nv, d, _ = c
        if d <= 0:
            return (0, Fraction(0))
        return (1, d * d / nv)
    # Argmax with deterministic tiebreak (memory_id ASC on equal keys):
    best = None
    best_key = None
    for c in candidates:
        k = sim_key(c)
        if best is None or k > best_key or (k == best_key and c[0] < best[0]):
            best, best_key = c, k
    seed_id = best[0]

    # --- BFS from seed over links.
    # The custody gate extends to the GRAPH, not only to serving: a
    # non-CLEAN memory is invisible to the agent as a result AND as an
    # influence. A link is traversable only if BOTH endpoints are CLEAN,
    # so a quarantined / tainted / superseded node can neither inhibit
    # nor resonate a served memory. Gating serving alone (the WHERE
    # clause) left the ranking of clean memories perturbable by a
    # quarantined node sitting on a resonant path — confirmed by
    # induction and refused here. Gate on custody_status only: FORGOTTEN
    # is a weak field_state, not an untrusted one, so its links stay.
    cur.execute("SELECT from_id, to_id, link_type FROM cell_links "
                "ORDER BY from_id ASC, to_id ASC")
    links: dict[str, list[tuple[str, str]]] = {}
    for f, t, lt in cur.fetchall():
        if f in servable_ids and t in servable_ids:
            links.setdefault(f, []).append((t, lt))

    hop_of: dict[str, int] = {}
    inhibited: set[str] = set()
    resonant_boost: dict[str, Fraction] = {}
    frontier = {seed_id}
    for depth in range(min(hops, MAX_HOP_SEARCH) + 1):
        next_frontier: set[str] = set()
        for mid in sorted(frontier):
            if mid in inhibited or mid in hop_of:
                continue
            hop_of[mid] = depth
            for target, lt in links.get(mid, []):
                if lt == "INHIBITORY":
                    inhibited.add(target)
                elif lt == "RESONANT":
                    next_frontier.add(target)
                    resonant_boost[target] = resonant_boost.get(
                        target, Fraction(0)) + RESONANT_BOOST_STEP
                else:
                    next_frontier.add(target)
        frontier = next_frontier - set(hop_of) - inhibited

    # --- Score (exact) with inhibition + rescue.
    scored = []
    excluded_inhibited = 0
    for mid, content, vec, nv, d, state in candidates:
        rescued = False
        if mid in inhibited and mid != seed_id:
            if state == "REINFORCED":
                rescued = True   # raven's rescue rule
            else:
                excluded_inhibited += 1
                continue
        hop = hop_of.get(mid, -1)
        decay = DECAY_BASE ** hop if hop >= 0 else Fraction(1)
        m = STATE_BOOST[state] * decay + resonant_boost.get(mid, Fraction(0))
        t = d * m
        rank = Fraction(0) if t <= 0 else t * t / nv     # exact ranking key
        scored.append((rank, mid, content, t, nv, hop, state, rescued))

    scored.sort(key=lambda s: (-s[0], s[1]))
    top = scored[:top_k]

    hits: list[RecallHit] = []
    for rank, mid, content, t, nv, hop, state, rescued in top:
        if t <= 0:
            display = quantize(0)
        else:
            display = quantize(t / _sqrt_fraction(nv * nq), field="score")
        hits.append(RecallHit(memory_id=mid, content=content, score=display,
                              hop_distance=hop, field_state=state,
                              inhibition_rescued=rescued))

    receipt = _receipt(query_sha, seed_id, [h.memory_id for h in hits],
                       excluded_custody, excluded_forgotten, excluded_inhibited,
                       top_k, hops, override)
    return hits, receipt
