"""
MNEME — Counterfactual contamination analysis. Non-interference, measured.

Containment normally ends with a sentence that sounds like a result and
is not one:

    "We found the poisoned memory and excluded it."

That says what was done. It does not say what it DID. The question an
incident review actually needs answered is the counterfactual one:

    Given this sealed state, does removing the tainted memories change
    the agent's behaviour — and if so, in exactly which outputs?

This module answers it as an arithmetic fact rather than a reassurance.
Two worlds over one field:

    W   the field under one hypothetical custody state
    W'  the field under another

    recall(W, q)  -> R
    recall(W', q) -> R'

and the exact, reproducible delta between them:

    removed_from_serving           in R, gone from R'
    entered_top_k                  in R', absent from R
    rank_changed                   in both, at different positions
    score_changed                  in both, at the same position,
                                   different exact score
    claim_outcome_changed          a topic whose winning claim flips
    decision_dependency_changed    recorded decisions whose evidence base
                                   the change removes

The first five are QUERY-SCOPED: they are about what this query returned.
The sixth is FIELD-WIDE — decisions whose evidence base moves, most of
which came from other queries entirely — and it is deliberately NOT
folded into the interference verdict. Merging them was the first version
of this code, and it made the finding the module exists for unreachable:
any memory that had ever informed a decision would have reported
interference on every query forever, including queries it could not
possibly touch. The two scopes are reported side by side, and the seal
covers both.

If the query-scoped delta is empty, the statement MNEME can make is
strong and unusual: *for this query, under this sealed state, the
tainted memories exerted no observable influence.* NON-INTERFERENCE,
proven for that query — not asserted, and not extrapolated to other
queries, which is the boundary this module is most careful about.

WHY THIS IS EXACT AND NOT A SAMPLE. Ranking is exact rational arithmetic
with a total tiebreak (ranking_protocol 1.0.0), so recall is a pure
function of (state, query, top_k, hops). Two worlds differing only in
custody status therefore differ in exactly the ways this delta lists,
every time, on any machine. A float ranking would have made the same
comparison a matter of opinion near ties — which is the practical reason
the exactness discipline was worth its cost.

WHAT IT DOES NOT PROVE, stated plainly because the value of the claim
depends on the boundary:
  - It is per QUERY. "No interference on q" is not "no interference".
    The honest generalization is over a stated query set, and the delta
    seals the query it examined.
  - It compares RECALL outputs, not the agent's reasoning. If two
    different served sets would have produced the same decision anyway,
    that is a fact about the policy, not about MNEME.
  - decision_dependency_changed names decisions whose INPUT changes. It
    does not re-run them; MNEME never sees a decision's content, only
    its hash.

As everywhere: takes a live cursor, NEVER commits, and changes nothing.
The whole point is a measurement that could not have perturbed its own
subject.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from . import causality, field, protocol


@dataclass(frozen=True)
class CounterfactualDelta:
    """
    The exact observable difference between two worlds, for one query.
    Every tuple is sorted; the seal covers all of it, so "this was the
    effect" is a claim anyone can recompute rather than a screenshot.
    """
    query_sha256: str
    top_k: int
    hops: int
    world_a_override: tuple[tuple[str, str], ...]
    world_b_override: tuple[tuple[str, str], ...]
    served_a: tuple[str, ...]
    served_b: tuple[str, ...]
    receipt_a_sha256: str
    receipt_b_sha256: str
    removed_from_serving: tuple[str, ...]
    entered_top_k: tuple[str, ...]
    rank_changed: tuple[tuple[str, int, int], ...]
    score_changed: tuple[tuple[str, str, str], ...]
    claim_outcome_changed: tuple[tuple[str, str, str], ...]
    decision_dependency_changed: tuple[str, ...]
    interference: bool
    delta_sha256: str

    def summary(self) -> str:
        """
        Two scopes, never merged. `interference` is about THIS QUERY's
        recall outputs. decision_dependency_changed is a FIELD-WIDE fact:
        recorded decisions whose input the change moves, most of which
        came from other queries entirely.

        Merging them was the first version of this code, and it made the
        finding the module exists for unreachable: any memory that had
        ever informed a decision would report interference on every
        query forever, including queries it could not possibly affect.
        So the flag stays query-scoped and the field-wide fact is said
        out loud beside it — never folded into it, and never dropped.
        """
        tail = ""
        if self.decision_dependency_changed:
            tail = (f" Separately, and not about this query: "
                    f"{len(self.decision_dependency_changed)} recorded "
                    "decision(s) had their evidence base moved by this change.")
        if not self.interference:
            return ("NON-INTERFERENCE: for this query, under this state, the "
                    "difference between the two worlds changed nothing "
                    "observable." + tail)
        parts = []
        for label, seq in (("removed", self.removed_from_serving),
                           ("entered", self.entered_top_k),
                           ("reranked", self.rank_changed),
                           ("rescored", self.score_changed),
                           ("claims flipped", self.claim_outcome_changed)):
            if seq:
                parts.append(f"{label}={len(seq)}")
        return "INTERFERENCE: " + ", ".join(parts) + tail


def _claim_outcomes(cur, served: list[str]) -> dict[str, str]:
    """
    Which claim currently WINS each topic, among the memories a recall
    served, in rank order.

    Claims live in the STORED payload — the custody chain is the source
    of truth, not a mutable column (the same rule store() follows when it
    detects contradictions). The winner is the highest-ranked served
    memory carrying a claim for that topic, so this reads the field's
    epistemic output rather than its contents: what the agent would have
    concluded, not what it holds.
    """
    out: dict[str, str] = {}
    for mid in served:
        cur.execute("SELECT payload_json FROM custody_chain "
                    "WHERE memory_id = ? AND seq = 0", (mid,))
        row = cur.fetchone()
        if row is None:
            continue
        p = json.loads(row[0])
        topic, claim = p.get("topic"), p.get("claim")
        if isinstance(topic, str) and isinstance(claim, str):
            out.setdefault(topic, claim)
    return out


def compare_worlds(
    cur,
    *,
    query_embedding: list[Any],
    world_a: dict[str, str] | None = None,
    world_b: dict[str, str] | None = None,
    top_k: int = 5,
    hops: int = field.DEFAULT_HOPS,
) -> CounterfactualDelta:
    """
    The primitive: run one query against two hypothetical custody states
    and seal the exact difference.

    Neither world is privileged. `containment_effect` and
    `exclusion_effect` below are the two directions people actually ask
    for, expressed in terms of this.
    """
    hits_a, receipt_a = field.recall(
        cur, query_embedding=query_embedding, top_k=top_k, hops=hops,
        custody_override=world_a)
    hits_b, receipt_b = field.recall(
        cur, query_embedding=query_embedding, top_k=top_k, hops=hops,
        custody_override=world_b)

    rank_a = {h.memory_id: i for i, h in enumerate(hits_a)}
    rank_b = {h.memory_id: i for i, h in enumerate(hits_b)}
    score_a = {h.memory_id: format(h.score, "f") for h in hits_a}
    score_b = {h.memory_id: format(h.score, "f") for h in hits_b}

    removed = tuple(sorted(set(rank_a) - set(rank_b)))
    entered = tuple(sorted(set(rank_b) - set(rank_a)))
    both = sorted(set(rank_a) & set(rank_b))
    rank_changed = tuple(
        (m, rank_a[m], rank_b[m]) for m in both if rank_a[m] != rank_b[m])
    # Reported separately from rank_changed: a memory can keep its
    # position while its score moves, which means its margin over the next
    # result changed even though the ordering survived. Collapsing the two
    # would hide exactly the near-miss cases an analyst wants to see.
    score_changed = tuple(
        (m, score_a[m], score_b[m])
        for m in both if rank_a[m] == rank_b[m] and score_a[m] != score_b[m])

    claims_a = _claim_outcomes(cur, list(receipt_a.served))
    claims_b = _claim_outcomes(cur, list(receipt_b.served))
    claim_changed = tuple(sorted(
        (t, claims_a.get(t, ""), claims_b.get(t, ""))
        for t in set(claims_a) | set(claims_b)
        if claims_a.get(t) != claims_b.get(t)))

    # Decisions whose evidence base the change moves. Computed from the
    # SERVABLE sets rather than from the top-k results: a decision made
    # from an earlier recall may have used a memory that never appears in
    # THIS query's top_k, and it is still a decision whose input the
    # change removes (or restores). The symmetric difference is the
    # honest set — a memory that becomes servable matters as much as one
    # that stops.
    #
    # This names decisions whose INPUT differs, never decisions whose
    # OUTCOME is known to differ. MNEME holds a decision's hash, never
    # its reasoning, and will not pretend to have re-run it.
    moved = _servable(cur, world_a) ^ _servable(cur, world_b)
    affected = []
    for d in causality.load_decision_rows(cur):
        used = set(json.loads(d["used_json"])["used"])
        if used & moved:
            affected.append(d["decision_id"])
    decision_dependency_changed = tuple(sorted(set(affected)))

    body = {
        "query_sha256": receipt_a.query_sha256,
        "top_k": top_k,
        "hops": hops,
        "ranking_protocol": protocol.RANKING_PROTOCOL,
        "world_a_override": [list(p) for p in receipt_a.custody_override],
        "world_b_override": [list(p) for p in receipt_b.custody_override],
        "served_a": list(receipt_a.served),
        "served_b": list(receipt_b.served),
        "receipt_a_sha256": receipt_a.receipt_sha256,
        "receipt_b_sha256": receipt_b.receipt_sha256,
        "removed_from_serving": list(removed),
        "entered_top_k": list(entered),
        "rank_changed": [list(x) for x in rank_changed],
        "score_changed": [list(x) for x in score_changed],
        "claim_outcome_changed": [list(x) for x in claim_changed],
        "decision_dependency_changed": list(decision_dependency_changed),
    }
    # Query-scoped on purpose — see summary() for why merging the
    # field-wide decision fact into this flag made non-interference
    # unreachable. The seal covers both, so nothing is lost.
    interference = bool(removed or entered or rank_changed or score_changed
                        or claim_changed)
    body["interference"] = interference
    return CounterfactualDelta(
        query_sha256=receipt_a.query_sha256, top_k=top_k, hops=hops,
        world_a_override=receipt_a.custody_override,
        world_b_override=receipt_b.custody_override,
        served_a=receipt_a.served, served_b=receipt_b.served,
        receipt_a_sha256=receipt_a.receipt_sha256,
        receipt_b_sha256=receipt_b.receipt_sha256,
        removed_from_serving=removed, entered_top_k=entered,
        rank_changed=rank_changed, score_changed=score_changed,
        claim_outcome_changed=claim_changed,
        decision_dependency_changed=decision_dependency_changed,
        interference=interference,
        delta_sha256=hashlib.sha256(
            canonical_json(body).encode("utf-8")).hexdigest(),
    )


def _servable(cur, override: dict[str, str] | None) -> set[str]:
    """The memories recall could serve in the world this override names."""
    cur.execute("SELECT memory_id, custody_status FROM memories")
    ov = override or {}
    return {mid for mid, status in cur.fetchall()
            if ov.get(mid, status) == "CLEAN"}


def _actual_status(cur, memory_id: str) -> str | None:
    cur.execute("SELECT custody_status FROM memories WHERE memory_id = ?",
                (memory_id,))
    row = cur.fetchone()
    return row[0] if row else None


def containment_effect(
    cur, *, query_embedding: list[Any], contained: list[str],
    top_k: int = 5, hops: int = field.DEFAULT_HOPS,
) -> CounterfactualDelta:
    """
    "What did the poison actually DO?"

    W  — the world where the contained memories were never contained
         (each forced CLEAN)
    W' — the field as it stands

    The delta is the exact observable causal effect of the contamination
    on this query. An empty delta is the finding people least expect and
    most need: the poison was there, it was excluded, and it had changed
    nothing — the incident's damage, measured at zero rather than assumed
    at unknown.
    """
    _require_known(cur, contained)
    return compare_worlds(
        cur, query_embedding=query_embedding,
        world_a={m: "CLEAN" for m in sorted(set(contained))},
        world_b=None, top_k=top_k, hops=hops)


def exclusion_effect(
    cur, *, query_embedding: list[Any], excluded: list[str],
    top_k: int = 5, hops: int = field.DEFAULT_HOPS,
) -> CounterfactualDelta:
    """
    "If we removed these, what would change?"

    W  — the field as it stands
    W' — the same field with the named memories quarantined

    Run BEFORE containment, this turns a proposed quarantine into a
    forecast with a seal: exactly which outputs it will move, and which
    it will not. An analyst can then contain knowing the blast radius of
    the containment itself — which is the question the taint-sweep DoS
    warning in KNOWN_LIMITATIONS is really about.
    """
    _require_known(cur, excluded)
    return compare_worlds(
        cur, query_embedding=query_embedding, world_a=None,
        world_b={m: "QUARANTINED" for m in sorted(set(excluded))},
        top_k=top_k, hops=hops)


def _require_known(cur, memory_ids: list[str]) -> None:
    if not memory_ids:
        raise ValueError(
            "A counterfactual over an empty set compares a world with "
            "itself; refusing to seal a delta that says nothing.")
    for mid in memory_ids:
        if _actual_status(cur, mid) is None:
            raise ValueError(f"Unknown memory {mid!r} — a counterfactual is "
                             "about THIS field or it is fiction.")
