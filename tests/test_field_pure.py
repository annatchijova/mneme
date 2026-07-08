"""
MNEME — pure field tests. SQLite :memory:, zero external dependencies.

The claims under test, one section per claim:
  - the custody gate: TAINT_FLAGGED/QUARANTINED memories are never
    served, never seed, and their exclusion is counted in the receipt
  - exact ranking: t²/n ordering agrees with float cosine ordering on
    random-ish vectors, and is bit-identical across permuted insertion
  - inhibition silences, REINFORCED rescues
  - contradiction at store time writes CONTRADICTED_BY on BOTH chains
  - reinforcement follows the closed form c + α(1−c) exactly and
    promotes at the exact threshold, all under verifying custody chains
  - receipts are deterministic: same state + same query ⇒ same digest
  - supersession is bilateral evidence: successor's STORED and
    predecessor's SUPERSEDED_BY are written together, lineage never forks
  - persisted receipts recompute from their own columns; edits are
    self-revealing
"""

from __future__ import annotations

import os
import sqlite3
import sys
from decimal import Decimal
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import custody, field, trust  # noqa: E402

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


def fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
        conn.executescript(f.read())
    cur = conn.cursor()
    ts = custody.now_ts()
    for aid, kind in [("agent-1", "AGENT"), ("pipeline-x", "PIPELINE"),
                      ("analyst-anna", "HUMAN")]:
        cur.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
                    "VALUES (?, ?, ?, ?)", (aid, aid, kind, ts))
    conn.commit()
    return conn


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


# ---------------------------------------------------------------- boundary
print("[embedding boundary]")
e = emb(0.5, -0.25, 1.0)
check("floats quantized at boundary", all(isinstance(x, Decimal) for x in e))
rt = field.embedding_from_json(field.embedding_to_json(e))
check("storage round-trip is exact",
      rt == [Fraction(1, 2), Fraction(-1, 4), Fraction(1, 1)])
try:
    field.quantize_embedding([float("nan"), 0.0])
    check("NaN refused", False)
except ValueError:
    check("NaN refused", True)

# ---------------------------------------------------------------- exact ranking
print("[exact ranking]")
conn = fresh_db()
cur = conn.cursor()
vectors = {
    "mem-a": (1.0, 0.0, 0.0),
    "mem-b": (0.9, 0.1, 0.0),
    "mem-c": (0.0, 1.0, 0.0),
    "mem-d": (-1.0, 0.0, 0.0),   # anti-correlated: must clamp to 0
    "mem-e": (0.7, 0.7, 0.0),
}
for mid, v in vectors.items():
    field.store(cur, memory_id=mid, content=f"content {mid}",
                embedding=emb(*v), embedding_model="dev",
                actor_id="agent-1", reason="ingestion")
conn.commit()

query = emb(1.0, 0.05, 0.0)
hits, receipt = field.recall(cur, query_embedding=query, top_k=5)
order = [h.memory_id for h in hits]

# Float ground truth for the same formula (no links, all NEUTRAL, hop
# decay only affects graph-reachable — there are no links, so pure sim):
import math
qf = (1.0, 0.05, 0.0)
def cos(a, b):
    d = sum(x * y for x, y in zip(a, b))
    return d / math.sqrt(sum(x * x for x in a) * sum(y * y for y in b))
float_order = sorted(vectors, key=lambda m: (-max(cos(qf, vectors[m]), 0.0), m))
check("exact order matches float ground truth", order == float_order,
      f"{order} vs {float_order}")
check("anti-correlated memory scores exactly zero",
      [h.score for h in hits if h.memory_id == "mem-d"] == [Decimal("0.0000000000")])
check("seed is the argmax", receipt.seed_memory_id == order[0])

# Permutation invariance: rebuild inserting in reverse order.
conn2 = fresh_db()
cur2 = conn2.cursor()
for mid in sorted(vectors, reverse=True):
    field.store(cur2, memory_id=mid, content=f"content {mid}",
                embedding=emb(*vectors[mid]), embedding_model="dev",
                actor_id="agent-1", reason="ingestion")
conn2.commit()
hits2, receipt2 = field.recall(cur2, query_embedding=query, top_k=5)
check("ranking invariant under insertion order",
      [h.memory_id for h in hits2] == order)
check("receipt digest is deterministic across databases",
      receipt2.receipt_sha256 == receipt.receipt_sha256)

# ---------------------------------------------------------------- custody gate
print("[custody gate]")
sweep = trust.quarantine_actor(cur, actor_id="agent-1",
                               initiated_by="analyst-anna",
                               reason="test incident")
conn.commit()
hits3, receipt3 = field.recall(cur, query_embedding=query, top_k=5)
check("tainted memories are not served", hits3 == [])
check("exclusions are counted", receipt3.excluded_custody == 5,
      str(receipt3.excluded_custody))
check("no seed when nothing is servable", receipt3.seed_memory_id is None)

trust.rehabilitate_memory(cur, memory_id="mem-a", actor_id="analyst-anna",
                          reason="reviewed")
conn.commit()
hits4, receipt4 = field.recall(cur, query_embedding=query, top_k=5)
check("rehabilitated memory is servable again",
      [h.memory_id for h in hits4] == ["mem-a"])
check("chains verify after gate exercise",
      all(custody.verify_custody_chain(cur, m)[0] for m in vectors))

# ---------------------------------------------------------------- contradiction
print("[contradiction at birth]")
conn = fresh_db()
cur = conn.cursor()
field.store(cur, memory_id="mem-sky-1", content="the sky is blue",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="agent-1", reason="ingestion",
            topic="sky-color", claim="blue")
res = field.store(cur, memory_id="mem-sky-2", content="the sky is green",
                  embedding=emb(0.99, 0.01), embedding_model="dev",
                  actor_id="pipeline-x", reason="ingestion",
                  topic="sky-color", claim="green")
conn.commit()
check("contradiction detected at store", res.inhibitory_links == ("mem-sky-1",))
for mid in ("mem-sky-1", "mem-sky-2"):
    cur.execute("SELECT COUNT(*) FROM custody_chain WHERE memory_id = ? "
                "AND event_type = 'CONTRADICTED_BY'", (mid,))
    check(f"CONTRADICTED_BY on chain of {mid}", cur.fetchone()[0] == 1)
    ok, errs = custody.verify_custody_chain(cur, mid)
    check(f"chain of {mid} verifies", ok, str(errs))
cur.execute("SELECT COUNT(*) FROM cell_links WHERE link_type='INHIBITORY'")
check("bidirectional INHIBITORY links", cur.fetchone()[0] == 2)

# ---------------------------------------------------------------- inhibition + rescue
print("[inhibition and rescue]")
# Query lands on mem-sky-2's neighbourhood; sky-1 gets inhibited via the
# link from the seed. NEUTRAL sky-1 is silenced.
q2 = emb(0.99, 0.011)
hits, receipt = field.recall(cur, query_embedding=q2, top_k=5)
check("seed inhibits its contradictor", receipt.seed_memory_id == "mem-sky-2"
      and "mem-sky-1" not in [h.memory_id for h in hits],
      str([h.memory_id for h in hits]))
check("silenced memory counted", receipt.excluded_inhibited == 1)

# Promote sky-1 to REINFORCED via exact reinforcement, then it must be rescued.
conf, state = field.reinforce(cur, memory_id="mem-sky-1",
                              actor_id="analyst-anna", reason="verified")
check("first reinforcement: 0.5 -> 0.625 exactly", conf == Decimal("0.6250000000"))
check("not yet promoted", state == "NEUTRAL")
conf, state = field.reinforce(cur, memory_id="mem-sky-1",
                              actor_id="analyst-anna", reason="verified again")
check("second reinforcement: 0.625 -> 0.71875 exactly",
      conf == Decimal("0.7187500000"))
conf, state = field.reinforce(cur, memory_id="mem-sky-1",
                              actor_id="analyst-anna", reason="third verification")
check("third crosses 3/4 exactly and promotes",
      conf == Decimal("0.7890625000") and state == "REINFORCED")
conn.commit()

hits, receipt = field.recall(cur, query_embedding=q2, top_k=5)
rescued = [h for h in hits if h.memory_id == "mem-sky-1"]
check("REINFORCED memory is rescued from inhibition",
      len(rescued) == 1 and rescued[0].inhibition_rescued)
ok, errs = custody.verify_custody_chain(cur, "mem-sky-1")
cur.execute("SELECT event_type FROM custody_chain WHERE memory_id='mem-sky-1' "
            "ORDER BY seq ASC")
events = [r[0] for r in cur.fetchall()]
check("full history on one chain and it verifies",
      ok and events == ["STORED", "CONTRADICTED_BY", "REINFORCED",
                        "REINFORCED", "REINFORCED", "STATE_CHANGED"],
      f"{events} / {errs}")

# Reinforcing a tainted memory must be refused (taint laundering).
sweep = trust.quarantine_actor(cur, actor_id="pipeline-x",
                               initiated_by="analyst-anna", reason="incident")
conn.commit()
try:
    field.reinforce(cur, memory_id="mem-sky-2", actor_id="agent-1", reason="r")
    check("reinforcing tainted memory refused", False)
except ValueError as e:
    check("reinforcing tainted memory refused", "launder" in str(e))

# ---------------------------------------------------------------- supersession
print("[supersession]")
import json

conn = fresh_db()
cur = conn.cursor()
field.store(cur, memory_id="mem-old", content="v1 of the doc",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="agent-1", reason="ingestion")
field.supersede(cur, old_memory_id="mem-old", memory_id="mem-new",
                content="v2 of the doc", embedding=emb(1.0, 0.05),
                embedding_model="dev", actor_id="analyst-anna",
                reason="doc refreshed")
conn.commit()
row = cur.execute("SELECT custody_status, superseded_by FROM memories "
                  "WHERE memory_id='mem-old'").fetchone()
check("predecessor is SUPERSEDED and points forward",
      row == ("SUPERSEDED", "mem-new"), str(row))
last = cur.execute("SELECT event_type, payload_json FROM custody_chain "
                   "WHERE memory_id='mem-old' ORDER BY seq DESC LIMIT 1").fetchone()
check("SUPERSEDED_BY names the successor",
      last[0] == "SUPERSEDED_BY"
      and json.loads(last[1])["successor_memory_id"] == "mem-new", str(last))
birth = cur.execute("SELECT payload_json FROM custody_chain "
                    "WHERE memory_id='mem-new' AND seq=0").fetchone()[0]
check("successor's STORED names its predecessor",
      json.loads(birth).get("supersedes") == "mem-old")
check("both chains verify",
      custody.verify_custody_chain(cur, "mem-old")[0]
      and custody.verify_custody_chain(cur, "mem-new")[0])

hits, receipt = field.recall(cur, query_embedding=emb(1.0, 0.0), top_k=5)
check("recall serves the successor, never the superseded",
      [h.memory_id for h in hits] == ["mem-new"]
      and receipt.excluded_custody == 1,
      str(([h.memory_id for h in hits], receipt.excluded_custody)))

try:
    field.supersede(cur, old_memory_id="mem-old", memory_id="mem-new-2",
                    content="v3", embedding=emb(1.0, 0.1),
                    embedding_model="dev", actor_id="agent-1", reason="again")
    check("second supersession refused — lineage never forks", False)
except ValueError as e:
    check("second supersession refused — lineage never forks",
          "SUPERSEDED" in str(e), str(e))

try:
    field.reinforce(cur, memory_id="mem-old", actor_id="agent-1", reason="r")
    check("reinforcing a superseded memory refused", False)
except ValueError:
    check("reinforcing a superseded memory refused", True)

# ---------------------------------------------------------------- receipts
print("[receipt persistence]")
import dataclasses

forged = dataclasses.replace(receipt, served=("mem-else",))
try:
    field.persist_receipt(cur, forged)
    check("forged receipt refused at persist", False)
except ValueError as e:
    check("forged receipt refused at persist", "recompute" in str(e), str(e))

field.persist_receipt(cur, receipt)
field.persist_receipt(cur, receipt)   # same evidence, same digest, one row
conn.commit()
n = cur.execute("SELECT COUNT(*) FROM recall_receipts").fetchone()[0]
check("persist is idempotent by digest", n == 1, str(n))
ok, errs = field.verify_receipts(cur)
check("persisted receipt recomputes from its columns", ok, str(errs))

cur.execute("UPDATE recall_receipts SET served_json = ?",
            (json.dumps({"served": ["mem-old"]}, separators=(",", ":")),))
conn.commit()
ok, errs = field.verify_receipts(cur)
check("edited receipt evidence is self-revealing", not ok and len(errs) == 1,
      str(errs))

# ------------------------------------------------- custody gate covers influence
# Security audit Round 1, finding H2: a non-CLEAN memory must exert ZERO
# influence on the recall of CLEAN memories — not merely be unserved. A
# quarantined node sitting on a RESONANT path between a clean seed and a
# clean target must not perturb the target's ranking. RESONANT links have
# no public creation API in Phase 1, so we insert them by hand: the
# invariant must hold for the Phase-2 state too.
print("[custody gate covers influence, not just serving]")

def _score_of_t(*, with_q: bool, quarantine: bool) -> str:
    c = fresh_db()
    cu = c.cursor()
    ts = custody.now_ts()
    field.store(cu, memory_id="mem-s", content="s", embedding=emb(1.0, 0.0),
                embedding_model="d", actor_id="agent-1", reason="i")
    field.store(cu, memory_id="mem-t", content="t", embedding=emb(0.0, 1.0),
                embedding_model="d", actor_id="agent-1", reason="i")
    if with_q:
        field.store(cu, memory_id="mem-q", content="q", embedding=emb(0.5, 0.5),
                    embedding_model="d", actor_id="agent-1", reason="i")
        cu.execute("INSERT INTO cell_links VALUES ('mem-s','mem-q','RESONANT',1,?)", (ts,))
        cu.execute("INSERT INTO cell_links VALUES ('mem-q','mem-t','RESONANT',1,?)", (ts,))
        if quarantine:
            trust.quarantine_memory(cu, memory_id="mem-q", actor_id="analyst-anna",
                                    reason="poison on the resonant path")
    c.commit()
    hits, _ = field.recall(cu, query_embedding=emb(1.0, 1.0), top_k=5, hops=3)
    return next(str(h.score) for h in hits if h.memory_id == "mem-t")

absent = _score_of_t(with_q=False, quarantine=False)
clean = _score_of_t(with_q=True, quarantine=False)
quar = _score_of_t(with_q=True, quarantine=True)
check("a quarantined intermediary exerts no influence (== its absence)",
      quar == absent, f"absent={absent} clean={clean} quarantined={quar}")
check("a genuinely CLEAN intermediary still resonates (mechanic intact)",
      clean != absent, f"absent={absent} clean={clean}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
