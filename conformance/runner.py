"""
MNEME — the conformance vector interpreter.

One function, `run`, that takes the operation list from a conformance
file and executes it against a fresh field. Shared by the generator
(which writes the vectors) and by tests/test_conformance.py (which
checks the committed file still matches), so the artifact and its gate
cannot execute two different scripts.

WHY THE OPERATIONS ARE HIGH-LEVEL. A conformance file could have listed
literal chain appends with explicit payloads, and it would have been
easier to implement against — and it would have tested only the hashing
layer. But the interesting rules are not in the hashing layer: they are
in what `supersede` has to write on BOTH chains, what `record_decision`
has to write back onto each cited memory, what capability each act
costs. So the operations are the acts, and reproducing the digests
requires having implemented the semantics, which is what conformance
means.

WHAT IS PINNED, so the field is a function of the file and nothing else:
every timestamp, every grant id, every claim, set and decision id. There
is no clock and no random source in this path. An implementation that
needs its own generated ids will not reproduce these digests, and that
is correct: the ids are inside the hashes.

Embeddings travel as canonical fixed-point strings (SPEC.md §1.2), not
as JSON numbers. A conformance file that carried them as floats would be
asking implementations to agree about binary64, which is the thing MNEME
refuses to depend on.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from decimal import Decimal
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import authority, causality, claims, field, trust  # noqa: E402

SCHEMA = os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")


def _emb(values: list[str]) -> list[Decimal]:
    """Canonical fixed-point strings -> exact decimals. No float ever."""
    return [Decimal(v) for v in values]


class World:
    """The field an operation list builds, plus the handles it produces."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        with open(SCHEMA) as f:
            self.conn.executescript(f.read())
        self.cur = self.conn.cursor()
        self.receipt = None
        self.decision = None
        self.set_evaluation = None


def run(operations: list[dict[str, Any]]) -> World:
    w = World()
    for i, op in enumerate(operations):
        try:
            _apply(w, op["op"], op.get("args", {}))
        except Exception as exc:                                # noqa: BLE001
            raise RuntimeError(
                f"operation {i} ({op['op']}) failed: {exc}") from exc
    return w


def _apply(w: World, name: str, a: dict[str, Any]) -> None:
    cur = w.cur

    if name == "bootstrap_root":
        # The root grant's id is INSIDE the root chain's hash, and
        # bootstrap_root generates it (there is no parameter — the root
        # act is deliberately not parameterised by its caller). So it is
        # an input to the reference field whether or not anyone named it,
        # and a conformance file that left it implicit would be asking
        # implementations to reproduce a uuid. It is pinned here as data
        # and installed for the duration of the call.
        #
        # Writing this file is what surfaced that: the first generator run
        # produced a different authority merkle root every time.
        _orig = authority._new_grant_id
        authority._new_grant_id = lambda: a["root_grant_id"]
        try:
            authority.bootstrap_root(cur, actor_id=a["actor_id"],
                                     display_name=a["display_name"],
                                     kind=a["kind"], reason=a["reason"],
                                     created_at=a["at"])
        finally:
            authority._new_grant_id = _orig
    elif name == "register_actor":
        authority.register_actor(cur, actor_id=a["actor_id"],
                                 display_name=a["display_name"],
                                 kind=a["kind"], issuer_id=a["issuer_id"],
                                 reason=a["reason"], created_at=a["at"])
    elif name == "grant":
        authority.grant(cur, subject_id=a["subject_id"],
                        capabilities=a["capabilities"],
                        issuer_id=a["issuer_id"], reason=a["reason"],
                        grant_id=a["grant_id"], created_at=a["at"])
    elif name == "store":
        prov = None
        if "provenance" in a:
            p = a["provenance"]
            prov = field.declare_embedding(
                provider=p["provider"], model=p["model"],
                revision=p["revision"], embedding=_emb(a["embedding"]),
                model_input=p["model_input"],
                preprocessing=p.get("preprocessing", "none"))
        field.store(cur, memory_id=a["memory_id"], content=a["content"],
                    embedding=_emb(a["embedding"]),
                    embedding_model=a["embedding_model"],
                    embedding_provenance=prov, actor_id=a["actor_id"],
                    reason=a["reason"], topic=a.get("topic"),
                    claim=a.get("claim"), created_at=a["at"])
    elif name == "reinforce":
        field.reinforce(cur, memory_id=a["memory_id"], actor_id=a["actor_id"],
                        reason=a["reason"], created_at=a["at"])
    elif name == "supersede":
        field.supersede(cur, old_memory_id=a["old_memory_id"],
                        memory_id=a["memory_id"], content=a["content"],
                        embedding=_emb(a["embedding"]),
                        embedding_model=a["embedding_model"],
                        actor_id=a["actor_id"], reason=a["reason"],
                        created_at=a["at"])
    elif name == "quarantine_memory":
        trust.quarantine_memory(cur, memory_id=a["memory_id"],
                                actor_id=a["actor_id"], reason=a["reason"],
                                created_at=a["at"])
    elif name == "recall":
        _, w.receipt = field.recall(cur, query_embedding=_emb(a["query"]),
                                    top_k=a["top_k"])
    elif name == "persist_receipt":
        field.persist_receipt(w.cur, w.receipt, persisted_at=a["at"])
    elif name == "record_decision":
        w.decision = causality.record_decision(
            cur, receipt=w.receipt, used_memory_ids=a["used_memory_ids"],
            decision_sha256=causality.decision_hash(a["decision_artifact"]),
            policy_version=a["policy_version"], actor_id=a["actor_id"],
            reason=a["reason"], decision_id=a["decision_id"],
            created_at=a["at"])
    elif name == "assert_claim":
        claims.assert_claim(cur, statement=a["statement"],
                            actor_id=a["actor_id"], reason=a["reason"],
                            topic=a.get("topic"), claim_id=a["claim_id"],
                            created_at=a["at"])
    elif name == "link_evidence":
        claims.link_evidence(cur, claim_id=a["claim_id"],
                             memory_id=a["memory_id"], stance=a["stance"],
                             actor_id=a["actor_id"], reason=a["reason"],
                             created_at=a["at"])
    elif name == "relate_claims":
        claims.relate(cur, from_claim=a["from_claim"], to_claim=a["to_claim"],
                      relation=a["relation"], actor_id=a["actor_id"],
                      reason=a["reason"], created_at=a["at"])
    elif name == "declare_set":
        claims.declare_set(cur, members=a["members"],
                           constraint_type=a["constraint_type"],
                           actor_id=a["actor_id"], reason=a["reason"],
                           set_id=a["set_id"], created_at=a["at"])
    elif name == "resolve_set":
        w.set_evaluation = claims.resolve_set(
            cur, set_id=a["set_id"], validate=a["validate"],
            refute=a["refute"], actor_id=a["actor_id"], reason=a["reason"],
            created_at=a["at"])
    elif name == "commit":
        w.conn.commit()
    else:
        raise ValueError(
            f"unknown conformance operation {name!r}. The operation "
            "vocabulary is closed, for the same reason every other "
            "vocabulary in MNEME is closed.")
