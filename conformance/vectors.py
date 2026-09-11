"""
MNEME — the vectors a built field produces, and the operation script
that builds it.

Shared by generate.py and tests/test_conformance.py so the artifact and
its gate compute the same things from the same script.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import (authority, bundle, causality, chain, claims,  # noqa: E402
                   counterfactual, custody, field, protocol, trust)

from runner import World  # noqa: E402  (same directory)

CONFORMANCE_FORMAT = "MNEME_CONFORMANCE_V1"
BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _ts(n: int) -> str:
    return custody.format_ts(BASE + timedelta(seconds=n))


def _v(*vals: float | str) -> list[str]:
    """Embedding literals as canonical fixed-point strings (SPEC.md §1.2)."""
    return [format(Decimal(str(v)).quantize(Decimal("1E-10")), "f")
            for v in vals]


# ---------------------------------------------------------------------------
# The script. Every timestamp and every identifier is explicit: the field
# is a function of this list and nothing else — no clock, no uuid, no
# insertion order that a different storage engine could permute.
# ---------------------------------------------------------------------------

def operations() -> list[dict[str, Any]]:
    t = iter(range(1, 1000))

    def at() -> str:
        return _ts(next(t))

    ops: list[dict[str, Any]] = [
        {"op": "bootstrap_root",
         "args": {"actor_id": "root", "display_name": "Root", "kind": "HUMAN",
                  "reason": "field genesis", "root_grant_id": "grant-0000",
                  "at": at()}},
    ]
    for aid, caps, gid in [
            ("scribe", ["STORE", "REINFORCE", "SUPERSEDE", "ASSERT", "DECIDE"],
             "grant-0001"),
            ("judge", ["ADJUDICATE", "QUARANTINE_MEMORY", "COUNTERFACTUAL"],
             "grant-0002")]:
        ops.append({"op": "register_actor",
                    "args": {"actor_id": aid, "display_name": aid,
                             "kind": "HUMAN", "issuer_id": "root",
                             "reason": "staffing", "at": at()}})
        ops.append({"op": "grant",
                    "args": {"subject_id": aid, "capabilities": caps,
                             "issuer_id": "root", "reason": "duty",
                             "grant_id": gid, "at": at()}})

    ops.append({"op": "store", "args": {
        "memory_id": "m-1", "content": "the gate is required",
        "embedding": _v(1.0, 0.0), "embedding_model": "acme/embed-3",
        "provenance": {"provider": "acme", "model": "embed-3",
                       "revision": "2026-01-01",
                       "model_input": "the gate is required"},
        "actor_id": "scribe", "reason": "runbook", "topic": "policy",
        "claim": "required", "at": at()}})
    ops.append({"op": "store", "args": {
        "memory_id": "m-2", "content": "the gate is optional",
        "embedding": _v(0.9, 0.1), "embedding_model": "acme/embed-3",
        "actor_id": "scribe", "reason": "feed", "topic": "policy",
        "claim": "optional", "at": at()}})
    for _ in range(3):
        ops.append({"op": "reinforce", "args": {
            "memory_id": "m-1", "actor_id": "scribe",
            "reason": "corroborated", "at": at()}})
    ops.append({"op": "supersede", "args": {
        "old_memory_id": "m-2", "memory_id": "m-3",
        "content": "the gate is optional for hotfixes",
        "embedding": _v(0.85, 0.15), "embedding_model": "acme/embed-3",
        "actor_id": "scribe", "reason": "narrowed", "at": at()}})
    ops.append({"op": "quarantine_memory", "args": {
        "memory_id": "m-3", "actor_id": "judge",
        "reason": "poisoned feed", "at": at()}})
    ops.append({"op": "commit", "args": {}})

    ops.append({"op": "recall", "args": {"query": _v(1.0, 0.0), "top_k": 3}})
    ops.append({"op": "persist_receipt", "args": {"at": at()}})
    ops.append({"op": "record_decision", "args": {
        "used_memory_ids": ["m-1"], "decision_artifact": "ship it",
        "policy_version": "deploy@1", "actor_id": "scribe",
        "reason": "answered", "decision_id": "decision-0001", "at": at()}})

    ops.append({"op": "assert_claim", "args": {
        "statement": "The gate is required.", "actor_id": "scribe",
        "reason": "from the runbook", "topic": "policy",
        "claim_id": "claim-0001", "at": at()}})
    ops.append({"op": "assert_claim", "args": {
        "statement": "The gate is optional.", "actor_id": "scribe",
        "reason": "from the feed", "topic": "policy",
        "claim_id": "claim-0002", "at": at()}})
    ops.append({"op": "link_evidence", "args": {
        "claim_id": "claim-0001", "memory_id": "m-1", "stance": "SUPPORTS",
        "actor_id": "scribe", "reason": "states it", "at": at()}})
    ops.append({"op": "relate_claims", "args": {
        "from_claim": "claim-0001", "to_claim": "claim-0002",
        "relation": "CONTRADICTS", "actor_id": "scribe",
        "reason": "one policy", "at": at()}})
    ops.append({"op": "declare_set", "args": {
        "members": ["claim-0001", "claim-0002"],
        "constraint_type": "EXACTLY_ONE", "actor_id": "scribe",
        "reason": "one policy", "set_id": "claimset-0001", "at": at()}})
    ops.append({"op": "resolve_set", "args": {
        "set_id": "claimset-0001", "validate": ["claim-0001"],
        "refute": ["claim-0002"], "actor_id": "judge",
        "reason": "runbook wins", "at": at()}})
    ops.append({"op": "commit", "args": {}})
    return ops


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------

def _head(cur, table: str, key: str, value: str) -> str:
    cur.execute(f"SELECT entry_hash FROM {table} WHERE {key} = ? "
                "ORDER BY seq DESC LIMIT 1", (value,))
    return cur.fetchone()[0]


def compute(w: World) -> list[dict[str, Any]]:
    """
    Every digest the reference field produces, each tagged with the
    protocols it exercises so an implementation can check PARTIAL
    conformance: someone who has built chains but not claims can run the
    genesis and head vectors today rather than nothing until everything
    is done.
    """
    cur = w.cur
    emb = [Decimal(v) for v in _v(1.0, 0.0)]
    out: list[dict[str, Any]] = []

    def vec(name: str, value: str, requires: list[str], note: str = "") -> None:
        entry = {"name": name, "value": value, "requires": requires}
        if note:
            entry["note"] = note
        out.append(entry)

    # Genesis derivations — the cheapest vectors to implement, and the
    # ones that catch a wrong prefix before anything else can.
    vec("genesis.custody.m-1", chain.genesis_hash(custody.SPEC, "m-1"),
        ["custody_protocol"])
    vec("genesis.authority.root",
        chain.genesis_hash(authority.SPEC, "root"), ["authority_protocol"])
    vec("genesis.claim.claim-0001",
        chain.genesis_hash(claims.SPEC, "claim-0001"), ["claim_protocol"])

    # Chain heads — every event's bytes, transitively.
    for mid in ("m-1", "m-2", "m-3"):
        vec(f"head.custody.{mid}", _head(cur, "custody_chain", "memory_id", mid),
            ["custody_protocol"])
    for aid in ("root", "scribe", "judge"):
        vec(f"head.authority.{aid}",
            _head(cur, "authority_chain", "subject_id", aid),
            ["authority_protocol"])
    for cid in ("claim-0001", "claim-0002"):
        vec(f"head.claim.{cid}", _head(cur, "claim_chain", "claim_id", cid),
            ["claim_protocol"])

    # Seals over derived evidence.
    vec("seal.receipt", w.receipt.receipt_sha256,
        ["ranking_protocol", "receipt_protocol"])
    vec("seal.decision", w.decision.record_sha256, ["receipt_protocol"])
    vec("seal.impact.m-1", causality.impact(cur, "m-1").impact_sha256,
        ["receipt_protocol", "custody_protocol"])
    vec("seal.exposure.m-3",
        trust.influence_exposure(cur, sources=["m-3"]).exposure_sha256,
        ["taint_protocol"])
    vec("seal.standing.claim-0001",
        claims.standing(cur, "claim-0001").standing_sha256, ["claim_protocol"])
    vec("seal.counterfactual.exclude-m-1",
        counterfactual.exclusion_effect(
            cur, query_embedding=emb, excluded=["m-1"],
            top_k=3).delta_sha256,
        ["ranking_protocol", "receipt_protocol"])

    # The bundle.
    doc = json.loads(bundle.export_bundle(cur))
    vec("root.heads_merkle", doc["body"]["heads_merkle_root"],
        ["custody_protocol"])
    vec("root.authority_merkle", doc["body"]["authority_merkle_root"],
        ["authority_protocol"])
    body = dict(doc["body"])
    del body["created_at"]
    vec("seal.bundle_body",
        hashlib.sha256(bundle.canonical_json(body).encode("utf-8")).hexdigest(),
        ["custody_protocol", "replay_protocol", "ranking_protocol",
         "taint_protocol", "authority_protocol", "receipt_protocol",
         "claim_protocol"],
        "the export's created_at is removed before sealing: it is the one "
        "wall-clock field, and a vector over it would test the clock")

    # The version table is itself part of the protocol.
    vec("table.protocols",
        hashlib.sha256(bundle.canonical_json(
            dict(protocol.CURRENT_PROTOCOLS)).encode("utf-8")).hexdigest(),
        [], "a change to any declared version changes this digest")

    return out


def document() -> dict[str, Any]:
    import runner
    ops = operations()
    w = runner.run(ops)
    doc = {
        "conformance_format": CONFORMANCE_FORMAT,
        "protocols": dict(protocol.CURRENT_PROTOCOLS),
        "spec": "SPEC.md",
        "operations": ops,
        "vectors": compute(w),
    }
    w.conn.close()
    return doc
