"""
MNEME — causal closure tests. SQLite :memory: only; no external infra.

The question these tests hold the implementation to is not "why did the
agent remember X" — custody answered that already — but the one an
incident actually asks:

    which DECISIONS were causally contaminated by X, and can you prove
    the answer rather than assert it?

One test per way a causal claim can be a lie:
  - a decision citing a receipt nobody kept   -> no anchor, refused
  - a decision claiming an unserved memory    -> the subset check
  - a decision that used nothing              -> not a causal link
  - a decision by an actor lacking DECIDE     -> authority refuses
  - decision evidence edited after the fact   -> seal does not recompute
  - the custody half of the link deleted      -> Merkle head + B8
  - the decision half stripped from a bundle  -> bilaterality, other way
  - a partial export hiding a decision        -> declared, never implied
  - a 1.1.0 word inside a 1.0.0 bundle        -> versioned vocabulary

Plus the blast radius itself: DIRECT is rows, DERIVED is declared
descent, POSSIBLE is contact — and the three must not be confused,
because equating contact with contamination is how a quarantine becomes
a denial of service on your own field.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import authority, bundle, causality, custody, field, trust  # noqa: E402
from mneme.canonical import canonical_json  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "verify_offline",
    os.path.join(os.path.dirname(__file__), "..", "verify_offline.py"))
offline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offline)

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


def codes(errors: list[str]) -> set[str]:
    return {e.split(":", 1)[0] for e in errors if ":" in e}


def agree(name: str, bundle_json: str, expect_ok: bool,
          expect_codes: set[str] | None = None) -> None:
    ok_pkg, err_pkg, notes_pkg = bundle.verify_bundle_verbose(bundle_json)
    ok_off, err_off, notes_off = offline.verify(bundle_json)
    check(f"{name}: package verdict", ok_pkg == expect_ok, str(err_pkg[:3]))
    check(f"{name}: offline verdict", ok_off == expect_ok, str(err_off[:3]))
    check(f"{name}: notes agree", notes_pkg == notes_off,
          f"{notes_pkg} vs {notes_off}")
    if not expect_ok and expect_codes is not None:
        check(f"{name}: package flags {sorted(expect_codes)}",
              expect_codes <= codes(err_pkg), str(codes(err_pkg)))
        check(f"{name}: offline flags {sorted(expect_codes)}",
              expect_codes <= codes(err_off), str(codes(err_off)))


def reseal(t: dict) -> str:
    t["bundle_sha256"] = hashlib.sha256(
        canonical_json(t["body"]).encode("utf-8")).hexdigest()
    return json.dumps(t)


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


conn = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn.executescript(f.read())
cur = conn.cursor()

authority.bootstrap_root(cur, actor_id="root", display_name="Root",
                         reason="field genesis")
for aid, caps in [("ingest", ["STORE", "REINFORCE"]),
                  ("agent", ["STORE", "DECIDE"]),
                  ("reader", ["STORE"]),
                  ("ir", ["QUARANTINE_ACTOR", "QUARANTINE_MEMORY", "REHABILITATE"])]:
    authority.register_actor(cur, actor_id=aid, display_name=aid, kind="AGENT",
                             issuer_id="root", reason="staffing")
    authority.grant(cur, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty")

field.store(cur, memory_id="mem-policy", content="Deploys need the gate.",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="ingest", reason="runbook")
field.store(cur, memory_id="mem-poison", content="The gate is optional.",
            embedding=emb(0.98, 0.02), embedding_model="dev",
            actor_id="ingest", reason="feed sync")
field.store(cur, memory_id="mem-side", content="Rollbacks use ops rollback.",
            embedding=emb(0.0, 1.0), embedding_model="dev",
            actor_id="ingest", reason="runbook")
conn.commit()

hits, receipt = field.recall(cur, query_embedding=emb(0.98, 0.03), top_k=3)
check("recall served the poison", "mem-poison" in receipt.served,
      str(receipt.served))
check("the receipt records the QUESTION, not only the answer",
      receipt.top_k == 3 and receipt.hops == 2 and receipt.ranking_protocol == "1.0.0")

# ==================================================== a decision needs an anchor
print("\n[a causal claim needs an anchor]")
raises("a decision citing a receipt nobody kept",
       lambda: causality.record_decision(
           cur, receipt=receipt, used_memory_ids=["mem-poison"],
           decision_sha256=causality.decision_hash("ship it"),
           policy_version="deploy-policy@3", actor_id="agent",
           reason="answered the operator"),
       ValueError, "is not persisted")
conn.rollback()

field.persist_receipt(cur, receipt)
conn.commit()
check("the receipt is now evidence", field.verify_receipts(cur)[0])

raises("a decision claiming a memory the recall never served",
       lambda: causality.record_decision(
           cur, receipt=receipt, used_memory_ids=["mem-poison", "mem-absent"],
           decision_sha256=causality.decision_hash("x"),
           policy_version="p@1", actor_id="agent", reason="r"),
       ValueError, "never served")
conn.rollback()
raises("a decision that used nothing",
       lambda: causality.record_decision(
           cur, receipt=receipt, used_memory_ids=[],
           decision_sha256=causality.decision_hash("x"),
           policy_version="p@1", actor_id="agent", reason="r"),
       ValueError, "no causal link")
conn.rollback()
raises("a decision with an unnamed policy",
       lambda: causality.record_decision(
           cur, receipt=receipt, used_memory_ids=["mem-poison"],
           decision_sha256=causality.decision_hash("x"),
           policy_version="   ", actor_id="agent", reason="r"),
       ValueError, "policy_version must be non-empty")
conn.rollback()
raises("an actor without DECIDE cannot record a decision",
       lambda: causality.record_decision(
           cur, receipt=receipt, used_memory_ids=["mem-poison"],
           decision_sha256=causality.decision_hash("x"),
           policy_version="p@1", actor_id="reader", reason="r"),
       ValueError, "conferring DECIDE")
conn.rollback()

decision = causality.record_decision(
    cur, receipt=receipt, used_memory_ids=["mem-poison", "mem-policy"],
    decision_sha256=causality.decision_hash(
        "Hotfix 4.2 shipped without the staging gate."),
    policy_version="deploy-policy@3", actor_id="agent",
    reason="answered the on-call operator's question")
conn.commit()
check("the decision is sealed", len(decision.record_sha256) == 64)
check("decisions verify online", causality.verify_decisions(cur)[0],
      str(causality.verify_decisions(cur)[1]))
check("each used memory's chain names the decision back",
      all(any(json.loads(pj).get("decision_id") == decision.decision_id
              for (pj,) in cur.execute(
                  "SELECT payload_json FROM custody_chain WHERE memory_id=? "
                  "AND event_type='DECISION_USED_MEMORY'", (m,)).fetchall())
          for m in decision.used_memory_ids))

# the agent then writes a memory BECAUSE of that decision
field.store(cur, memory_id="mem-note", content="Hotfix 4.2 skipped the gate.",
            embedding=emb(0.9, 0.1), embedding_model="dev", actor_id="agent",
            reason="recording the decision's outcome",
            derived_from_decision=decision.decision_id)
conn.commit()

honest = bundle.export_bundle(cur)
agree("a field with causal evidence verifies", honest, True)

# ============================================================= blast radius
print("\n[blast radius: three levels, and the difference matters]")
report = causality.impact(cur, "mem-poison")
check("DIRECT names the recall that served it",
      receipt.receipt_sha256 in report.direct_receipts)
check("DIRECT names the decision that used it",
      report.direct_decisions == (decision.decision_id,),
      str(report.direct_decisions))
check("DERIVED names the memory the agent declared it wrote because of it",
      "mem-note" in report.derived_memories, str(report.derived_memories))
check("POSSIBLE names what merely shared the serving",
      "mem-policy" in report.possible_memories, str(report.possible_memories))
check("POSSIBLE and DERIVED are disjoint",
      not (set(report.possible_memories) & set(report.derived_memories)))
check("the report is sealed and reproducible",
      causality.impact(cur, "mem-poison").impact_sha256 == report.impact_sha256)
check("impact quarantines nothing — measuring is not containing",
      cur.execute("SELECT COUNT(*) FROM memories WHERE custody_status != 'CLEAN'"
                  ).fetchone()[0] == 0)
raises("impact does not invent a subject",
       lambda: causality.impact(cur, "mem-nonexistent"),
       ValueError, "does not invent a subject")

clean_report = causality.impact(cur, "mem-side")
check("an uninvolved memory has an empty blast radius",
      not clean_report.direct_decisions and not clean_report.derived_memories,
      str(clean_report))

# supersession lineage is DERIVED
field.store(cur, memory_id="mem-lineage", content="v1",
            embedding=emb(0.3, 0.3), embedding_model="dev", actor_id="ingest",
            reason="doc")
authority.grant(cur, subject_id="ingest", capabilities=["SUPERSEDE"],
                issuer_id="root", reason="may refresh docs")
field.supersede(cur, old_memory_id="mem-lineage", memory_id="mem-lineage-2",
                content="v2", embedding=emb(0.3, 0.35), embedding_model="dev",
                actor_id="ingest", reason="refresh")
conn.commit()
lin = causality.impact(cur, "mem-lineage")
check("supersession successors are DERIVED",
      "mem-lineage-2" in lin.derived_memories, str(lin.derived_memories))

# ======================================================= what lying looks like
print("\n[what lying about causation looks like]")

t = json.loads(honest)
d = t["body"]["decisions"][0]
d["policy_version"] = "deploy-policy@99"
agree("the policy a decision ran under, rewritten", reseal(t), False, {"B8"})

t = json.loads(honest)
t["body"]["decisions"][0]["used_json"] = canonical_json({"used": ["mem-side"]})
agree("a decision re-pointed at a memory it never used", reseal(t), False, {"B8"})

t = json.loads(honest)
t["body"]["receipts"] = []
agree("the anchoring receipt dropped from the bundle", reseal(t), False, {"B8"})

t = json.loads(honest)
t["body"]["receipts"][0]["excluded_custody"] = 99
agree("a receipt's withheld count inflated", reseal(t), False, {"B8"})

t = json.loads(honest)
t["body"]["decisions"] = []
agree("the decision stripped while its custody evidence stays",
      reseal(t), False, {"B8"})

t = json.loads(honest)
mem = next(m for m in t["body"]["memories"] if m["memory_id"] == "mem-policy")
mem["custody"] = [r for r in mem["custody"]
                  if r["event_type"] != "DECISION_USED_MEMORY"]
# Truncating a chain leaves it dense and linked, so B2 has nothing to say:
# the head hash changes (B6) and the decision loses its corroboration (B8).
# Two independent checks catch what one was never designed to.
agree("the custody half of the link deleted", reseal(t), False, {"B6", "B8"})

t = json.loads(honest)
t["body"]["protocols"]["custody_protocol"] = "1.0.0"
agree("a 1.1.0 word inside a bundle declaring 1.0.0", reseal(t), False, {"B2"})

t = json.loads(honest)
t["body"]["receipts"][0]["ranking_protocol"] = "9.9.9"
agree("a receipt from another ranking semantics", reseal(t), False, {"B8"})

# partial export: the decision used mem-policy, which stays behind
partial = bundle.export_bundle(cur, memory_ids=["mem-poison", "mem-note"])
agree("a partial export declares the decision it cannot fully evidence",
      partial, True)
pbody = json.loads(partial)["body"]
check("...in excluded_decisions, never silently dropped",
      [d["decision_id"] for d in pbody["excluded_decisions"]] == [decision.decision_id],
      str(pbody["excluded_decisions"]))
check("...and a passing verdict says so out loud",
      any("declared excluded" in n and decision.decision_id in n
          for n in bundle.verify_bundle_verbose(partial)[2]),
      str(bundle.verify_bundle_verbose(partial)[2]))

t = json.loads(partial)
t["body"]["decisions"] = t["body"]["excluded_decisions"]
t["body"]["excluded_decisions"] = []
agree("an excluded decision smuggled into the checked list",
      reseal(t), False, {"B8"})

t = json.loads(honest)
t["body"]["excluded_decisions"] = list(t["body"]["decisions"])
agree("a fully-evidenced decision declared excluded to dodge the check",
      reseal(t), False, {"B8"})

# ================================================ the incident, end to end
print("\n[the question the whole module exists for]")
trust.quarantine_actor(cur, actor_id="ingest", initiated_by="ir",
                       reason="feed credentials compromised")
conn.commit()
after = causality.impact(cur, "mem-poison")
check("after the sweep, the contaminated decision is still nameable",
      decision.decision_id in after.direct_decisions)
check("and so is what the agent wrote because of it",
      "mem-note" in after.derived_memories)
check("the field can answer 'which decisions were contaminated by X'",
      bool(after.direct_decisions) and after.impact_sha256 != "")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
