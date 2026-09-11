"""
MNEME — GOLDEN PROTOCOL VECTORS. The bytes, pinned.

Every other suite asks whether MNEME catches a lie. This one asks a
question none of them do: **is the protocol still producing the same
bytes it produced yesterday?**

Nothing did. Hash formulas, genesis derivations, canonical envelopes and
seal bodies were covered only by tests that recompute them the same way
the code does — so any change that altered the bytes CONSISTENTLY, in
both the writer and the verifier, would pass everything. A refactor is
exactly that kind of change, and this file exists because one was about
to happen to the three chain implementations.

WHAT THIS PROVES, stated narrowly because the value depends on the
boundary: that a fixed input still produces these exact digests. It does
NOT prove the digests are correct — a golden vector inherits whatever
was true the day it was generated. Correctness comes from somewhere
else entirely: two independent implementations that must agree
(tests/test_bundle_pure.py's agreement section), and the semantic
mutants. This file only guarantees that the protocol cannot move
silently.

Which is precisely what a protocol needs, and what `protocol.py` would
otherwise be enforcing on paper alone: a MINOR version bump promises
that "everything the old version checked is still checked identically",
and until now nothing held anyone to it.

Determinism is engineered, not hoped for: fixed ids, fixed timestamps, a
counter in place of every uuid. If a vector below changes, either the
protocol changed — in which case the version must move and this file is
the evidence of what moved — or something is wrong.

NEGATIVE CONTROL, because a golden file that cannot go red is furniture.
Two deliberate protocol perturbations were run against these vectors
before they were committed:

    one character added to the custody genesis prefix   ->  6 vectors red
    canonical JSON separators changed to ", "           -> 17 vectors red

The second number is the useful one: seventeen of twenty vectors depend
on canonicalization, so the file has real reach into the protocol rather
than sampling its edges.

A LIMIT THIS FILE HIT IMMEDIATELY, recorded because it is the exact
shape of what golden vectors cannot do. During the chain refactor these
twenty vectors stayed green while mneme/authority.py carried TWO full
implementations of its chain — the extracted one, and the original it
was meant to replace, still in the file, shadowed by definition order.
Byte-identical output, so nothing here could see it. Golden vectors
prove the protocol did not move; they say nothing about whether the code
that moved it is gone. The duplicate-definition scan at the end of this
file is what covers that, and it is here because this file is where a
refactor comes to be checked.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import (authority, bundle, causality, claims, counterfactual,  # noqa: E402
                   custody, field, protocol, trust)

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}  {detail}")


def vector(name: str, actual: str, expected: str) -> None:
    check(name, actual == expected,
          f"\n        expected {expected}\n        actual   {actual}")


BASE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_tick = [0]


def ts() -> str:
    """A clock that advances one second per call, so the field is a
    function of its script and nothing else."""
    _tick[0] += 1
    return custody.format_ts(BASE + timedelta(seconds=_tick[0]))


_ids = [0]


def det_id(prefix: str) -> str:
    _ids[0] += 1
    return f"{prefix}-{_ids[0]:04d}"


# Every uuid in the write paths, replaced by a counter. Done here rather
# than by adding id parameters to the API: the production code should not
# grow a seam that exists only for a test.
authority._new_grant_id = lambda: det_id("grant")


class _DetUUID:
    @staticmethod
    def uuid4():
        class _H:
            hex = f"{_ids[0]:032x}"
        _ids[0] += 1
        return _H()


trust.uuid = _DetUUID
causality.uuid = _DetUUID
claims.uuid = _DetUUID


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


conn = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn.executescript(f.read())
cur = conn.cursor()

# ------------------------------------------------------------- the field
authority.bootstrap_root(cur, actor_id="root", display_name="Root",
                         kind="HUMAN", reason="field genesis", created_at=ts())
for aid, caps in [("scribe", ["STORE", "REINFORCE", "SUPERSEDE", "ASSERT", "DECIDE"]),
                  ("judge", ["ADJUDICATE", "QUARANTINE_MEMORY", "COUNTERFACTUAL"])]:
    authority.register_actor(cur, actor_id=aid, display_name=aid, kind="HUMAN",
                             issuer_id="root", reason="staffing", created_at=ts())
    authority.grant(cur, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty", grant_id=det_id("grant"), created_at=ts())

prov = field.declare_embedding(provider="acme", model="embed-3",
                               revision="2026-01-01", embedding=emb(1.0, 0.0),
                               model_input="the gate is required")
field.store(cur, memory_id="m-1", content="the gate is required",
            embedding=emb(1.0, 0.0), embedding_model="acme/embed-3",
            embedding_provenance=prov, actor_id="scribe", reason="runbook",
            topic="policy", claim="required", created_at=ts())
field.store(cur, memory_id="m-2", content="the gate is optional",
            embedding=emb(0.9, 0.1), embedding_model="acme/embed-3",
            actor_id="scribe", reason="feed", topic="policy", claim="optional",
            created_at=ts())
for _ in range(3):
    field.reinforce(cur, memory_id="m-1", actor_id="scribe",
                    reason="corroborated", created_at=ts())
field.supersede(cur, old_memory_id="m-2", memory_id="m-3",
                content="the gate is optional for hotfixes",
                embedding=emb(0.85, 0.15), embedding_model="acme/embed-3",
                actor_id="scribe", reason="narrowed", created_at=ts())
trust.quarantine_memory(cur, memory_id="m-3", actor_id="judge",
                        reason="poisoned feed", created_at=ts())
conn.commit()

_, receipt = field.recall(cur, query_embedding=emb(1.0, 0.0), top_k=3)
field.persist_receipt(cur, receipt, persisted_at=ts())
decision = causality.record_decision(
    cur, receipt=receipt, used_memory_ids=["m-1"],
    decision_sha256=causality.decision_hash("ship it"),
    policy_version="deploy@1", actor_id="scribe", reason="answered",
    decision_id="decision-0001", created_at=ts())
c1 = claims.assert_claim(cur, statement="The gate is required.",
                         actor_id="scribe", reason="from the runbook",
                         topic="policy", claim_id="claim-0001", created_at=ts())
c2 = claims.assert_claim(cur, statement="The gate is optional.",
                         actor_id="scribe", reason="from the feed",
                         topic="policy", claim_id="claim-0002", created_at=ts())
claims.link_evidence(cur, claim_id=c1, memory_id="m-1", stance="SUPPORTS",
                     actor_id="scribe", reason="states it", created_at=ts())
claims.relate(cur, from_claim=c1, to_claim=c2, relation="CONTRADICTS",
              actor_id="scribe", reason="one policy", created_at=ts())
cset = claims.declare_set(cur, members=[c1, c2], constraint_type="EXACTLY_ONE",
                          actor_id="scribe", reason="one policy",
                          set_id="claimset-0001", created_at=ts())
claims.resolve_set(cur, set_id=cset, validate=[c1], refute=[c2],
                   actor_id="judge", reason="runbook wins", created_at=ts())
conn.commit()


def head(table: str, key: str, value: str) -> str:
    cur.execute(f"SELECT entry_hash FROM {table} WHERE {key} = ? "
                "ORDER BY seq DESC LIMIT 1", (value,))
    return cur.fetchone()[0]


print("[the three chains: genesis derivations]")
vector("custody genesis for m-1", custody.genesis_hash("m-1"),
       "c92384af132847121bdda4dfd4723e93d8b46e98f7562f4be703eb5ffab893b9")
vector("authority genesis for root", authority.authority_genesis_hash("root"),
       "92c99f0abd4f57f2f88735690404b417510975f1501e82109264fc2b53ebc7e4")
vector("claim genesis for claim-0001", claims.claim_genesis_hash("claim-0001"),
       "b816f2c50bb2dd33beea71ce5c868a28cf99c94f55f7983edc3786e0c52e3d2a")

print("\n[chain heads — every event's bytes, transitively]")
vector("custody head m-1", head("custody_chain", "memory_id", "m-1"), "865f02f776affb9a8d3c1502744c4c91a968d42535019239065f7ce6bcea99be")
vector("custody head m-2", head("custody_chain", "memory_id", "m-2"), "ab5d9f7af197baf5df9ab03666158a5f9442dc37deda2c1872b79c87023007d7")
vector("custody head m-3", head("custody_chain", "memory_id", "m-3"), "22aca97b500841efc427738cbcebdaec2824ab474a5904cf106a19d4829fa9af")
vector("authority head root", head("authority_chain", "subject_id", "root"), "3f387d9faf53b86f6c4fde47f70e63a278feb09898842dc5360cdeebd97020c0")
vector("authority head scribe", head("authority_chain", "subject_id", "scribe"), "cff8f09fd7ec8b2ff3da89a71e6297290899156df67fa8dd260747947f0843fc")
vector("claim head claim-0001", head("claim_chain", "claim_id", "claim-0001"), "9d87067f86750985d90c7e62a47d9e54b39967a835d874672526e796ad263fd2")
vector("claim head claim-0002", head("claim_chain", "claim_id", "claim-0002"), "880bcc3a83a6b47a4190377c33a82b5f71b5c68567b62f5b99c5369ae7eab6db")

print("\n[seals over derived evidence]")
vector("recall receipt digest", receipt.receipt_sha256, "32a31b259d122859b16e58e5119266e2f9606def384bfaab8cf271df8497a005")
vector("decision record seal", decision.record_sha256, "56b2fad458c100edb7db61db7f94cce8f5f161c7f013931eb0e2fa38e9ded295")
vector("impact report seal", causality.impact(cur, "m-1").impact_sha256, "e8d61d22c7617f05405ebf4142b20d24a19bee81ef52860e2eae9ee77024ba7e")
vector("influence exposure seal",
       trust.influence_exposure(cur, sources=["m-3"]).exposure_sha256, "c96e1191115f203f2a19540eb31dea6fdec0198bf7007c4db76face075b4766e")
vector("claim standing seal", claims.standing(cur, c1).standing_sha256, "2290c8f93dbea113af95e1ad0eef1c5538f5bfa5b1182d7120e7cd53ed8dba57")
vector("counterfactual delta seal",
       counterfactual.exclusion_effect(cur, query_embedding=emb(1.0, 0.0),
                                       excluded=["m-1"], top_k=3).delta_sha256, "33fdd37852bf5fc7333b6130a9f1a159b24fce176ca5c7541070cd201ea7c935")

print("\n[the bundle]")
doc = json.loads(bundle.export_bundle(cur))
vector("heads Merkle root", doc["body"]["heads_merkle_root"], "2ac9965bf8f5f5a7b7c79e63c4c2de52a1e79fb831122e39674956b7fd497d12")
vector("authority Merkle root", doc["body"]["authority_merkle_root"], "0546cde2ec8dd1d7c9bb1e6a37d3e739d507d8d8fc972a869fe3f8bde168bfdb")
del doc["body"]["created_at"]          # the one wall-clock field
vector("bundle body seal (created_at removed)",
       hashlib.sha256(bundle.canonical_json(doc["body"]).encode("utf-8")).hexdigest(), "24d982df601842b36de80ed17ac5fef0e41cb1678bf95b15e215400d2fa019da")

print("\n[the protocol version table is itself part of the protocol]")
vector("declared protocol versions",
       hashlib.sha256(bundle.canonical_json(
           dict(protocol.CURRENT_PROTOCOLS)).encode("utf-8")).hexdigest(), "7606951289558d3c9e6e0fa34293fe5d01fd51dfb4279084b5385e6048e0c5e9")

print("\n[no module carries two implementations of the same thing]")
# The check the vectors above cannot perform. A refactor that extracts
# shared code and leaves the original behind produces IDENTICAL bytes —
# Python simply uses whichever definition came last — so every digest
# stays green while the duplication the refactor was meant to remove is
# still sitting in the file. This actually happened, to authority.py,
# during the extraction of mneme/chain.py.
for _mod in ("chain", "custody", "authority", "claims", "trust", "field",
             "bundle", "causality", "counterfactual", "protocol"):
    _tree = ast.parse(open(os.path.join(
        os.path.dirname(__file__), "..", "mneme", f"{_mod}.py")).read())
    _names = [n.name for n in _tree.body
              if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    _dupes = sorted({n for n in _names if _names.count(n) > 1})
    if _dupes:
        print(f"  FAIL  mneme/{_mod}.py defines twice: {', '.join(_dupes)}")
        print("        A shadowed duplicate is invisible to every byte-level "
              "check in this file. Delete the dead one.")
        FAIL += 1
    else:
        print(f"  ok  mneme/{_mod}.py")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
