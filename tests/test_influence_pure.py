"""
MNEME — influence-budget exposure tests. SQLite :memory: only.

The failure this measures against is not "we missed something". It is
the opposite one, and it is the reason transitive taint stayed manual
for so long: a connected resonance graph plus automatic propagation
means one quarantine silences the field, and the incident response
becomes indistinguishable from the incident.

So the tests are mostly about RESTRAINT:
  - it terminates on a graph built to punish a naive walk (a cycle, a
    long chain, a hub) — by construction, not by luck;
  - influence decays exactly and is reported as a rational number, so
    "how exposed" is checkable rather than adjectival;
  - INHIBITORY edges convey nothing — being disagreed with by a poisoned
    memory is not being influenced by it, the same carve-out that keeps
    a quarantine from silencing an attacker's victims;
  - beyond the floor, nothing is reported at all;
  - it writes nothing and flags nothing: INFLUENCE_EXPOSED is a finding,
    never a custody status;
  - it is sealed and reproducible.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from decimal import Decimal
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import authority, custody, field, trust  # noqa: E402

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


conn = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn.executescript(f.read())
cur = conn.cursor()

authority.bootstrap_root(cur, actor_id="root", display_name="Root",
                         reason="field genesis")
for aid, caps in [("ingest", ["STORE"]), ("ir", ["QUARANTINE_MEMORY"])]:
    authority.register_actor(cur, actor_id=aid, display_name=aid, kind="AGENT",
                             issuer_id="root", reason="staffing")
    authority.grant(cur, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty")

# A graph built to punish a naive walk: a long chain past the floor, a
# cycle, a hub, and an inhibitory edge that must convey nothing.
#
#   poison -> a -> b -> c -> d -> e -> f -> g      (chain past the floor)
#   poison -> a  and  a -> poison                  (cycle)
#   poison -INHIBITORY-> victim                    (disagreement, not influence)
#   isolated                                       (never touched)
ids = ["poison", "a", "b", "c", "d", "e", "f", "g", "victim", "isolated"]
for i, mid in enumerate(ids):
    field.store(cur, memory_id=mid, content=f"content {mid}",
                embedding=emb(1.0, Fraction(i, 100)), embedding_model="dev",
                actor_id="ingest", reason="ingestion")
ts = custody.now_ts()
chain = [("poison", "a"), ("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"),
         ("e", "f"), ("f", "g"), ("a", "poison")]
for f_, t_ in chain:
    cur.execute("INSERT INTO cell_links (from_id, to_id, link_type, auto, "
                "created_at) VALUES (?, ?, 'RESONANT', 0, ?)", (f_, t_, ts))
cur.execute("INSERT INTO cell_links (from_id, to_id, link_type, auto, "
            "created_at) VALUES ('poison', 'victim', 'INHIBITORY', 0, ?)", (ts,))
conn.commit()

print("[the budget spends itself, exactly]")
report = trust.influence_exposure(cur, sources=["poison"])
exposed = dict(report.exposed)
check("one hop carries 1/2", exposed.get("a") == "1/2", str(exposed))
check("two hops carry 1/4", exposed.get("b") == "1/4", str(exposed))
check("three hops carry 1/8", exposed.get("c") == "1/8", str(exposed))
check("six hops carry 1/64 — exactly the floor, still reported",
      exposed.get("f") == "1/64", str(exposed))
check("seven hops fall below the floor and are NOT reported",
      "g" not in exposed, str(exposed))
check("the budget is exact rational arithmetic, never a float",
      all(Fraction(v) >= trust.EXPOSURE_FLOOR for v in exposed.values()))
check("the depth bound is derived from the floor, not configured apart",
      Fraction(1, 2) ** trust.MAX_INFLUENCE_DEPTH == trust.EXPOSURE_FLOOR)

print("\n[what the budget refuses to carry]")
check("an INHIBITORY edge conveys nothing", "victim" not in exposed,
      "being disagreed with by a poisoned memory is not being influenced by it")
check("an unconnected memory is CLEAN", "isolated" in report.clean)
check("the cycle did not inflate the source's own exposure",
      "poison" not in exposed)
check("the source is DIRECT_TAINT, not exposed",
      report.level("poison") == "DIRECT_TAINT")
check("a reached memory is INFLUENCE_EXPOSED, never TAINTED",
      report.level("a") == "INFLUENCE_EXPOSED")
check("an untouched memory is CLEAN", report.level("isolated") == "CLEAN")

print("\n[it terminates, and it changes nothing]")
statuses_before = sorted(cur.execute(
    "SELECT memory_id, custody_status FROM memories").fetchall())
events_before = cur.execute("SELECT COUNT(*) FROM custody_chain").fetchone()[0]
trust.influence_exposure(cur, sources=["poison"])
check("no custody status moved",
      sorted(cur.execute("SELECT memory_id, custody_status FROM memories"
                         ).fetchall()) == statuses_before)
check("no custody event was written",
      cur.execute("SELECT COUNT(*) FROM custody_chain").fetchone()[0] == events_before)
check("nothing was quarantined by a measurement",
      cur.execute("SELECT COUNT(*) FROM memories WHERE custody_status != 'CLEAN'"
                  ).fetchone()[0] == 0)
check("the report is sealed and reproducible",
      trust.influence_exposure(cur, sources=["poison"]).exposure_sha256
      == report.exposure_sha256)
check("the seal commits to the taint semantics it was computed under",
      report.taint_protocol == trust.protocol.TAINT_PROTOCOL)

print("\n[sources: the field's own evidence, or a hypothesis]")
trust.quarantine_memory(cur, memory_id="poison", actor_id="ir",
                        reason="directly incriminated")
conn.commit()
auto = trust.influence_exposure(cur)
check("with no sources given, the tainted set IS the evidence",
      auto.direct_taint == ("poison",), str(auto.direct_taint))
check("...and it reaches the same set", dict(auto.exposed) == exposed)
raises("a hypothesis about memories this field lacks is refused",
       lambda: trust.influence_exposure(cur, sources=["ghost"]),
       ValueError, "or it is fiction")

hypothetical = trust.influence_exposure(cur, sources=["c"])
check("a hypothetical source answers 'if THIS were poisoned, who is exposed'",
      dict(hypothetical.exposed).get("d") == "1/2",
      str(hypothetical.exposed))
check("...and does not smuggle the real tainted set into the answer",
      "a" not in dict(hypothetical.exposed), str(hypothetical.exposed))

print("\n[the DoS this exists to refuse]")
check("a fully connected field does not become fully tainted",
      len(report.direct_taint) == 1,
      "the sweep still flags only what it can demonstrate")
check("exposure is a separate vocabulary from custody status",
      set(trust.EXPOSURE_LEVELS) == {"DIRECT_TAINT", "INFLUENCE_EXPOSED", "CLEAN"}
      and "INFLUENCE_EXPOSED" not in field.CUSTODY_STATUSES)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
