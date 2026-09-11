"""
MNEME — counterfactual non-interference tests. SQLite :memory: only.

The claim under test is the strongest one MNEME makes, so it gets the
most adversarial reading:

    "Given this sealed state, removing the tainted memories does not
     change the decision except in these explicitly enumerated outputs."

What must hold for that to mean anything:
  - the measurement changes nothing it measures (no writes, no status
    moved, byte-identical field before and after);
  - it is reproducible (same state, same query -> same seal, always);
  - it detects interference when interference exists, in each of the
    forms an analyst cares about: dropped, entered, reranked, rescored,
    a claim flipped, a recorded decision's input removed;
  - it reports NON-INTERFERENCE only when the delta is genuinely empty,
    never as a default;
  - a counterfactual receipt can never be laundered into evidence about
    the real field.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import (authority, bundle, causality, counterfactual,  # noqa: E402
                   custody, field, trust)

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


def raises(name: str, fn, exc=Exception, needle: str = "") -> None:
    try:
        fn()
    except exc as e:
        check(name, needle in str(e), f"message was {e!r}")
        return
    except Exception as e:                                    # noqa: BLE001
        check(name, False, f"raised {type(e).__name__}: {e}")
        return
    check(name, False, "did not raise")


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


def field_snapshot(cur) -> str:
    """Everything a measurement must not have touched."""
    rows = []
    for table in ("memories", "custody_chain", "authority_chain",
                  "taint_sweeps", "recall_receipts", "decisions", "cell_links"):
        cur.execute(f"SELECT * FROM {table}")
        rows.append((table, sorted(str(r) for r in cur.fetchall())))
    return json.dumps(rows, sort_keys=True)


conn = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn.executescript(f.read())
cur = conn.cursor()

authority.bootstrap_root(cur, actor_id="root", display_name="Root",
                         reason="field genesis")
for aid, caps in [("ingest", ["STORE", "REINFORCE"]),
                  ("agent", ["STORE", "DECIDE"]),
                  ("ir", ["QUARANTINE_ACTOR", "QUARANTINE_MEMORY"])]:
    authority.register_actor(cur, actor_id=aid, display_name=aid, kind="AGENT",
                             issuer_id="root", reason="staffing")
    authority.grant(cur, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty")

# Two claims on one topic; the poison is close to the query, the truth is
# closer. A third, unrelated memory is the control that must never move.
field.store(cur, memory_id="mem-truth", content="Deploys require the gate.",
            embedding=emb(1.0, 0.10, 0.0), embedding_model="dev",
            actor_id="ingest", reason="runbook",
            topic="deploy-policy", claim="gate-required")
field.store(cur, memory_id="mem-poison", content="The gate is optional.",
            embedding=emb(0.97, 0.05, 0.0), embedding_model="dev",
            actor_id="ingest", reason="feed sync",
            topic="deploy-policy", claim="gate-optional")
field.store(cur, memory_id="mem-far", content="Rollbacks use ops rollback.",
            embedding=emb(0.0, 0.0, 1.0), embedding_model="dev",
            actor_id="ingest", reason="runbook")
conn.commit()

query = emb(0.97, 0.03, 0.0)

# ============================================= forecast BEFORE containment
print("\n[before containment: what would quarantining this actually do?]")
before = field_snapshot(cur)
forecast = counterfactual.exclusion_effect(
    cur, query_embedding=query, excluded=["mem-poison"], top_k=5)
check("the measurement changed nothing it measured",
      field_snapshot(cur) == before)
check("the forecast is reproducible",
      counterfactual.exclusion_effect(
          cur, query_embedding=query, excluded=["mem-poison"],
          top_k=5).delta_sha256 == forecast.delta_sha256)
check("it forecasts the poison leaving the served set",
      "mem-poison" in forecast.removed_from_serving,
      str(forecast.removed_from_serving))
check("it reports interference", forecast.interference)
check("the unrelated memory is not named anywhere in the delta",
      "mem-far" not in (set(forecast.removed_from_serving)
                        | set(forecast.entered_top_k)
                        | {r[0] for r in forecast.rank_changed}
                        | {r[0] for r in forecast.score_changed}),
      forecast.summary())
raises("a counterfactual over an empty set is refused",
       lambda: counterfactual.exclusion_effect(cur, query_embedding=query,
                                               excluded=[], top_k=5),
       ValueError, "compares a world with itself")
raises("a counterfactual about a memory this field lacks is refused",
       lambda: counterfactual.exclusion_effect(cur, query_embedding=query,
                                               excluded=["mem-ghost"], top_k=5),
       ValueError, "or it is fiction")

# =================================== the agent decides, then we contain it
print("\n[the incident: a decision was taken on the poison]")
hits, receipt = field.recall(cur, query_embedding=query, top_k=5)
field.persist_receipt(cur, receipt)
decision = causality.record_decision(
    cur, receipt=receipt, used_memory_ids=["mem-poison"],
    decision_sha256=causality.decision_hash("Shipped hotfix without the gate."),
    policy_version="deploy-policy@3", actor_id="agent",
    reason="answered the on-call operator")
conn.commit()

trust.quarantine_memory(cur, memory_id="mem-poison", actor_id="ir",
                        reason="poisoned feed content, INC-1207")
conn.commit()
check("the poison is contained",
      cur.execute("SELECT custody_status FROM memories WHERE memory_id="
                  "'mem-poison'").fetchone()[0] == "QUARANTINED")

# ================================= after containment: what did it actually do?
print("\n[after containment: the exact observable causal effect]")
before = field_snapshot(cur)
effect = counterfactual.containment_effect(
    cur, query_embedding=query, contained=["mem-poison"], top_k=5)
check("measuring after the fact also changes nothing",
      field_snapshot(cur) == before)
check("the poison is named as removed from serving",
      "mem-poison" in effect.removed_from_serving,
      str(effect.removed_from_serving))
check("the delta names the contaminated decision",
      decision.decision_id in effect.decision_dependency_changed,
      str(effect.decision_dependency_changed))
check("the delta carries both worlds' receipts",
      effect.receipt_a_sha256 != effect.receipt_b_sha256)
check("the two worlds are distinguishable in the receipts themselves",
      bool(effect.world_a_override) and not effect.world_b_override,
      f"{effect.world_a_override} vs {effect.world_b_override}")
check("the effect is sealed", len(effect.delta_sha256) == 64)
check("the summary says interference, with counts",
      effect.summary().startswith("INTERFERENCE:"), effect.summary())

# ================================================ the claim outcome flipping
print("\n[the epistemic output, not only the ranking]")
flip = counterfactual.exclusion_effect(
    cur, query_embedding=emb(0.97, 0.04, 0.0), excluded=["mem-truth"], top_k=1)
check("removing the truth flips the winning claim on the topic",
      any(t == "deploy-policy" for t, _, _ in flip.claim_outcome_changed),
      str(flip.claim_outcome_changed))

# ================================================= NON-INTERFERENCE, proven
print("\n[the finding people least expect: the poison changed nothing]")
# A query far from the poison: excluding it moves no output at all.
quiet = counterfactual.containment_effect(
    cur, query_embedding=emb(0.0, 0.0, 1.0), contained=["mem-poison"], top_k=1)
check("no memory left the served set", quiet.removed_from_serving == ())
check("no memory entered it", quiet.entered_top_k == ())
check("nothing was reranked", quiet.rank_changed == ())
check("nothing was rescored", quiet.score_changed == ())
check("no claim flipped", quiet.claim_outcome_changed == ())
check("NON-INTERFERENCE is reported, not assumed",
      (not quiet.interference)
      and quiet.summary().startswith("NON-INTERFERENCE:"), quiet.summary())
check("...and the field-wide decision fact is said beside it, not folded in",
      "not about this query" in quiet.summary(), quiet.summary())
check("...and it is sealed, so the claim is recomputable",
      counterfactual.containment_effect(
          cur, query_embedding=emb(0.0, 0.0, 1.0), contained=["mem-poison"],
          top_k=1).delta_sha256 == quiet.delta_sha256)
check("a decision that used the poison still counts as dependency-changed",
      decision.decision_id in quiet.decision_dependency_changed,
      "input removal is a fact about the decision, not about this query")

# ============================== a counterfactual receipt is not real evidence
print("\n[a simulation must never become the record]")
_, cf_receipt = field.recall(cur, query_embedding=query, top_k=5,
                             custody_override={"mem-poison": "CLEAN"})
_, real_receipt = field.recall(cur, query_embedding=query, top_k=5)
check("the two receipts have different digests",
      cf_receipt.receipt_sha256 != real_receipt.receipt_sha256)
check("the counterfactual receipt declares its world",
      cf_receipt.custody_override == (("mem-poison", "CLEAN"),))
check("a real receipt declares an empty one",
      real_receipt.custody_override == ())
field.persist_receipt(cur, cf_receipt)
conn.commit()
check("persisted counterfactual receipts still verify as receipts",
      field.verify_receipts(cur)[0])
raises("but no decision may cite one",
       lambda: causality.record_decision(
           cur, receipt=cf_receipt, used_memory_ids=["mem-poison"],
           decision_sha256=causality.decision_hash("x"),
           policy_version="p@1", actor_id="agent", reason="r"),
       ValueError, "COUNTERFACTUAL")
conn.rollback()
raises("a hypothetical world must still be a possible one",
       lambda: field.recall(cur, query_embedding=query,
                            custody_override={"mem-poison": "DELETED"}),
       ValueError, "not a custody status")

check("the field still exports and verifies after all of it",
      bundle.verify_bundle(bundle.export_bundle(cur))[0],
      str(bundle.verify_bundle(bundle.export_bundle(cur))[1][:3]))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
