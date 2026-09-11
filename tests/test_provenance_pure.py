"""
MNEME — embedding provenance and temporal replay. SQLite :memory: only.

Two frontiers, both previously named in KNOWN_LIMITATIONS as trusted or
absent, and neither of them closed by these tests — only made checkable.

EMBEDDING PROVENANCE. The boundary has not moved: nothing here proves a
model computed a vector honestly, and no hash can. What the record makes
possible is the one thing a bare `embedding_model` string could not —
DRIFT becomes detectable, because for a fixed (provider, model, revision,
preprocessing) and a fixed input, the output vector is supposed to be a
function. Two memories agreeing on the left and differing on the right
are proof that something changed underneath.

TEMPORAL REPLAY. "Why does this decision look absurd today?" is
unanswerable. "With what the agent legitimately had at 14:03:17, what
would it have retrieved?" is arithmetic, and these tests hold it to
refusing every convenient shortcut: no future events, no future links,
no memories that did not exist yet quietly counted as exclusions.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import authority, bundle, custody, field, trust  # noqa: E402
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


def agree(name: str, bundle_json: str, expect_ok: bool,
          expect_codes: set[str] | None = None) -> None:
    ok_p, err_p, notes_p = bundle.verify_bundle_verbose(bundle_json)
    ok_o, err_o, notes_o = offline.verify(bundle_json)
    check(f"{name}: package verdict", ok_p == expect_ok, str(err_p[:3]))
    check(f"{name}: offline verdict", ok_o == expect_ok, str(err_o[:3]))
    check(f"{name}: notes agree", notes_p == notes_o, f"{notes_p} vs {notes_o}")
    if not expect_ok and expect_codes is not None:
        check(f"{name}: flags {sorted(expect_codes)}",
              expect_codes <= {e.split(':', 1)[0] for e in err_p},
              str(err_p[:3]))


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
authority.register_actor(cur, actor_id="ingest", display_name="Ingest",
                         kind="PIPELINE", issuer_id="root", reason="staffing")
authority.grant(cur, subject_id="ingest",
                capabilities=["STORE", "REINFORCE", "SUPERSEDE"],
                issuer_id="root", reason="ingest duty")
authority.register_actor(cur, actor_id="ir", display_name="IR", kind="HUMAN",
                         issuer_id="root", reason="responder")
authority.grant(cur, subject_id="ir", capabilities=["QUARANTINE_MEMORY"],
                issuer_id="root", reason="incident duty")
conn.commit()

# ============================================================ provenance
print("[a provenance record must describe the vector it travels with]")
vec = emb(1.0, 0.0, 0.0)
text = "Deploys require the staging gate."
prov = field.declare_embedding(provider="acme", model="embed-3",
                               revision="2026-07-01", embedding=vec,
                               model_input=text)
check("dimension is taken from the vector, never declared by hand",
      prov.dimension == 3)
check("the quantization protocol is derived, not free text",
      prov.quantization_protocol == field.QUANTIZATION_PROTOCOL
      and "scale=10" in prov.quantization_protocol)
check("with no preprocessing, the model's input IS the content",
      prov.input_content_hash == custody.content_sha256(text))
check("the output hash is the hash of the QUANTIZED vector, not the floats",
      prov.output_vector_hash == field.embedding_sha256(vec))

field.store(cur, memory_id="mem-1", content=text, embedding=vec,
            embedding_model="acme/embed-3@2026-07-01",
            embedding_provenance=prov, actor_id="ingest", reason="runbook")
conn.commit()
check("the provenance is sealed into the birth event",
      json.loads(cur.execute(
          "SELECT payload_json FROM custody_chain WHERE memory_id='mem-1' "
          "AND seq=0").fetchone()[0])["embedding_provenance"]["model"] == "embed-3")

raises("a record describing a different vector is refused at write",
       lambda: field.store(
           cur, memory_id="mem-bad", content="other", embedding=emb(0.5, 0.5, 0.5),
           embedding_model="m", embedding_provenance=prov,
           actor_id="ingest", reason="r"),
       ValueError, "does not hash the vector being stored")
conn.rollback()
raises("declaring no preprocessing while hashing something else is refused",
       lambda: field.store(
           cur, memory_id="mem-bad", content="something else entirely",
           embedding=vec, embedding_model="m", embedding_provenance=prov,
           actor_id="ingest", reason="r"),
       ValueError, "name the preprocessing")
conn.rollback()
raises("an empty provider is refused; 'unknown' would be honest",
       lambda: field.declare_embedding(provider="", model="m", revision="r",
                                       embedding=vec, model_input=text),
       ValueError, "'unknown' is a legitimate value")

# preprocessing that is NAMED is fine, and the two hashes then differ
chunked = field.declare_embedding(
    provider="acme", model="embed-3", revision="2026-07-01",
    embedding=emb(0.9, 0.1, 0.0), model_input="deploys require the staging gate",
    preprocessing="lowercase+strip-punctuation")
field.store(cur, memory_id="mem-2", content="Deploys require the staging gate!",
            embedding=emb(0.9, 0.1, 0.0),
            embedding_model="acme/embed-3@2026-07-01",
            embedding_provenance=chunked, actor_id="ingest", reason="runbook")
conn.commit()
check("named preprocessing lets input and content hashes differ, honestly",
      chunked.input_content_hash
      != custody.content_sha256("Deploys require the staging gate!"))

honest = bundle.export_bundle(cur)
agree("a field with declared provenance verifies", honest, True)

t = json.loads(honest)
m = next(x for x in t["body"]["memories"] if x["memory_id"] == "mem-1")
p = json.loads(m["custody"][0]["payload_json"])
p["embedding_provenance"]["revision"] = "2026-09-01"
m["custody"][0]["payload_json"] = canonical_json(p)
agree("a revision rewritten after the fact", reseal(t), False, {"B2"})

t = json.loads(honest)
m = next(x for x in t["body"]["memories"] if x["memory_id"] == "mem-1")
m["embedding_sha256"] = "0" * 64
agree("the shipped vector swapped for another", reseal(t), False, {"B3"})

# ================================================================= drift
print("\n[drift: the thing a model-name string could never show you]")
check("no drift in an honest field", field.detect_embedding_drift(cur) == [])
# Same provider/model/revision/preprocessing, same input, different vector.
same_input = field.declare_embedding(
    provider="acme", model="embed-3", revision="2026-07-01",
    embedding=emb(0.99, 0.01, 0.0), model_input=text)
# The realistic drift scenario: the SAME document re-ingested later, under
# the same declared model, returning a different vector. The validator
# refuses to let the two hashes disagree, so the drift has nowhere to hide
# except where detect_embedding_drift() looks for it.
field.store(cur, memory_id="mem-drift", content=text,
            embedding=emb(0.99, 0.01, 0.0),
            embedding_model="acme/embed-3@2026-07-01",
            embedding_provenance=same_input, actor_id="ingest",
            reason="re-ingestion after a provider incident")
conn.commit()
drift = field.detect_embedding_drift(cur)
check("the same model, the same input, two vectors — reported",
      len(drift) == 1 and drift[0]["distinct_vectors"] == 2, str(drift))
check("and it names which memories disagree",
      sorted(sum(drift[0]["memories"].values(), [])) == ["mem-1", "mem-drift"],
      str(drift[0]["memories"]))

inv = field.embedding_inventory(cur)
check("the inventory reports one model family and two preprocessings",
      {(r["model"], r["preprocessing"]) for r in inv}
      == {("embed-3", "none"), ("embed-3", "lowercase+strip-punctuation")},
      str(inv))

# a memory with NO provenance: the boundary is trusted and SAID so
field.store(cur, memory_id="mem-legacy", content="written without provenance",
            embedding=emb(0.0, 1.0, 0.0), embedding_model="legacy",
            actor_id="ingest", reason="legacy path")
conn.commit()
mixed = bundle.export_bundle(cur)
agree("undeclared provenance does not fail verification", mixed, True)
check("...but a passing verdict names it out loud",
      any("declare no embedding provenance" in n
          for n in bundle.verify_bundle_verbose(mixed)[2]),
      str(bundle.verify_bundle_verbose(mixed)[2]))
check("the inventory declares the undeclared too",
      any(r["model"] is None and r["memories"] == 1
          for r in field.embedding_inventory(cur)),
      str(field.embedding_inventory(cur)))

# =========================================================== as-of replay
print("\n[what did MNEME know at T?]")
base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def at(minutes: int) -> str:
    return custody.format_ts(base + timedelta(minutes=minutes))


conn2 = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn2.executescript(f.read())
c2 = conn2.cursor()
authority.bootstrap_root(c2, actor_id="root", display_name="R",
                         reason="genesis", created_at=at(0))
authority.register_actor(c2, actor_id="ingest", display_name="I", kind="AGENT",
                         issuer_id="root", reason="s", created_at=at(0))
authority.grant(c2, subject_id="ingest", capabilities=["STORE", "REINFORCE"],
                issuer_id="root", reason="d", created_at=at(0))
authority.register_actor(c2, actor_id="ir", display_name="IR", kind="HUMAN",
                         issuer_id="root", reason="s", created_at=at(0))
authority.grant(c2, subject_id="ir", capabilities=["QUARANTINE_MEMORY"],
                issuer_id="root", reason="d", created_at=at(0))

field.store(c2, memory_id="mem-truth", content="The gate is required.",
            embedding=emb(1.0, 0.1), embedding_model="dev", actor_id="ingest",
            reason="runbook", created_at=at(10))
field.store(c2, memory_id="mem-poison", content="The gate is optional.",
            embedding=emb(0.97, 0.05), embedding_model="dev", actor_id="ingest",
            reason="feed", created_at=at(20))
field.store(c2, memory_id="mem-later", content="Written after the fact.",
            embedding=emb(0.96, 0.06), embedding_model="dev", actor_id="ingest",
            reason="hindsight", created_at=at(60))
trust.quarantine_memory(c2, memory_id="mem-poison", actor_id="ir",
                        reason="INC-1207", created_at=at(50))
conn2.commit()

q = emb(0.97, 0.04)
now_hits, now_receipt = field.recall(c2, query_embedding=q, top_k=5)
check("today, the poison is gated", "mem-poison" not in now_receipt.served)
check("today, the hindsight memory is servable",
      "mem-later" in now_receipt.served, str(now_receipt.served))

then_hits, then_receipt = field.recall(c2, query_embedding=q, top_k=5,
                                       as_of=at(30))
check("at T, the poison WAS served — the agent had it legitimately",
      "mem-poison" in then_receipt.served, str(then_receipt.served))
check("at T, the hindsight memory did not exist and is not served",
      "mem-later" not in then_receipt.served, str(then_receipt.served))
check("a memory that did not exist is ABSENT, never counted as withheld",
      then_receipt.excluded_custody == 0, str(then_receipt.excluded_custody))
check("the receipt records the instant it reconstructed",
      then_receipt.as_of == at(30))
check("a historical receipt is a different object from today's",
      then_receipt.receipt_sha256 != now_receipt.receipt_sha256)

before_birth = field.recall(c2, query_embedding=q, top_k=5, as_of=at(15))[1]
check("before the poison was written, only the truth existed",
      list(before_birth.served) == ["mem-truth"], str(before_birth.served))
after_quarantine = field.recall(c2, query_embedding=q, top_k=5, as_of=at(55))[1]
check("one minute after containment, the poison is already gone",
      "mem-poison" not in after_quarantine.served,
      str(after_quarantine.served))

check("as-of is reproducible",
      field.recall(c2, query_embedding=q, top_k=5,
                   as_of=at(30))[1].receipt_sha256 == then_receipt.receipt_sha256)
raises("a non-canonical instant is refused",
       lambda: field.recall(c2, query_embedding=q, as_of="2026-03-01 12:30"),
       ValueError, "canonical UTC microsecond timestamp")

state = field.logical_state_at(c2, at(30))
check("the logical state at T comes from chains, not from status columns",
      state["mem-poison"] == ("CLEAN", "NEUTRAL") and "mem-later" not in state,
      str(state))
check("and today's columns say otherwise, as they should",
      c2.execute("SELECT custody_status FROM memories WHERE memory_id="
                 "'mem-poison'").fetchone()[0] == "QUARANTINED")

# as-of composes with the counterfactual: the caller's hypothesis wins
combined = field.recall(c2, query_embedding=q, top_k=5, as_of=at(30),
                        custody_override={"mem-poison": "QUARANTINED"})[1]
check("as-of and counterfactual compose, hypothesis over reconstruction",
      "mem-poison" not in combined.served
      and combined.as_of == at(30)
      and combined.custody_override == (("mem-poison", "QUARANTINED"),),
      str(combined))

field.persist_receipt(c2, then_receipt)
conn2.commit()
check("historical receipts persist and verify like any other",
      field.verify_receipts(c2)[0])
check("the field still exports and verifies",
      bundle.verify_bundle(bundle.export_bundle(c2))[0],
      str(bundle.verify_bundle(bundle.export_bundle(c2))[1][:2]))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
