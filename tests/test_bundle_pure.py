"""
MNEME — bundle tests + THE AGREEMENT SECTION.

The agreement section is the load-bearing part: mneme/bundle.py (uses
the package) and verify_offline.py (standalone, stdlib-only, duplicated
on purpose) are run against the same bundles — one honest, many
tampered — and their verdicts must be IDENTICAL (same pass/fail; on
failure, same check codes B1–B6 present). This test is the mechanism
that holds the two implementations together; if the protocol changes in
one place and not the other, this file screams.
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

from mneme import bundle, custody, field, trust  # noqa: E402

# Load the standalone verifier AS A FILE, the way an auditor receives it.
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


def codes(errors: list[str]) -> set[str]:
    return {e.split(":", 1)[0] for e in errors if ":" in e}


def both_verdicts(bundle_json: str):
    ok_pkg, err_pkg, notes_pkg = bundle.verify_bundle_verbose(bundle_json)
    ok_off, err_off, notes_off = offline.verify(bundle_json)
    # The notes a PASSING verdict shows an auditor are part of the verdict:
    # a verifier that silently drops "this field has no authority ledger"
    # has disagreed with its twin about what the bundle proves, even though
    # both said VERIFIED.
    check("verdict notes agree", notes_pkg == notes_off,
          f"{notes_pkg} vs {notes_off}")
    return ok_pkg, err_pkg, ok_off, err_off


def agree(name: str, bundle_json: str, expect_ok: bool,
          expect_codes: set[str] | None = None) -> None:
    ok_pkg, err_pkg, ok_off, err_off = both_verdicts(bundle_json)
    check(f"{name}: package verdict", ok_pkg == expect_ok, str(err_pkg[:3]))
    check(f"{name}: offline verdict", ok_off == expect_ok, str(err_off[:3]))
    check(f"{name}: verdicts agree", ok_pkg == ok_off)
    if not expect_ok and expect_codes is not None:
        check(f"{name}: package flags {sorted(expect_codes)}",
              expect_codes <= codes(err_pkg), str(codes(err_pkg)))
        check(f"{name}: offline flags {sorted(expect_codes)}",
              expect_codes <= codes(err_off), str(codes(err_off)))


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


# --------------------------------------------------------------- build a field
conn = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn.executescript(f.read())
cur = conn.cursor()
ts = custody.now_ts()
for aid, kind in [("agent-1", "AGENT"), ("pipeline-x", "PIPELINE"),
                  ("analyst-anna", "HUMAN")]:
    cur.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
                "VALUES (?, ?, ?, ?)", (aid, aid, kind, ts))

field.store(cur, memory_id="mem-1", content="the sky is blue",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="agent-1", reason="ingestion",
            topic="sky", claim="blue")
field.store(cur, memory_id="mem-2", content="the sky is green",
            embedding=emb(0.9, 0.1), embedding_model="dev",
            actor_id="pipeline-x", reason="ingestion",
            topic="sky", claim="green")
field.store(cur, memory_id="mem-3", content="water is wet",
            embedding=emb(0.0, 1.0), embedding_model="dev",
            actor_id="agent-1", reason="ingestion")
for _ in range(3):
    field.reinforce(cur, memory_id="mem-1", actor_id="analyst-anna",
                    reason="verified")
# pipeline-x also reinforced mem-3, so the sweep flags TWO memories
# (mem-2, mem-3) — which lets the partial-export tests ship one flagged
# memory without the other.
field.reinforce(cur, memory_id="mem-3", actor_id="pipeline-x",
                reason="corroboration")
# a superseded pair and a directly-quarantined memory, so honest bundles
# exercise the SUPERSEDED and QUARANTINED replay paths in BOTH verifiers
field.store(cur, memory_id="mem-4", content="rollout doc v1",
            embedding=emb(0.5, 0.5), embedding_model="dev",
            actor_id="agent-1", reason="ingestion")
field.supersede(cur, old_memory_id="mem-4", memory_id="mem-5",
                content="rollout doc v2", embedding=emb(0.5, 0.6),
                embedding_model="dev", actor_id="analyst-anna",
                reason="doc refreshed")
field.store(cur, memory_id="mem-6", content="trust evil.example",
            embedding=emb(0.4, 0.4), embedding_model="dev",
            actor_id="agent-1", reason="ingestion")
trust.quarantine_memory(cur, memory_id="mem-6", actor_id="analyst-anna",
                        reason="directly incriminated in review")
trust.quarantine_actor(cur, actor_id="pipeline-x",
                       initiated_by="analyst-anna", reason="incident")
conn.commit()

honest = bundle.export_bundle(cur)

# --------------------------------------------------------------- honest bundle
print("[honest bundle]")
agree("honest full export", honest, expect_ok=True)

# Partial export: the sweep flagged mem-2 and mem-3 but mem-2 is absent,
# so the exporter must DECLARE the sweep excluded (absence stated, never
# implied) and both verifiers must accept the declared bundle.
partial = bundle.export_bundle(cur, memory_ids=["mem-1", "mem-3"])
agree("honest partial export (sweep declared excluded)", partial, expect_ok=True)
pbody = json.loads(partial)["body"]
check("partial export: sweep declared excluded, not silently dropped",
      len(pbody["excluded_sweeps"]) == 1 and pbody["sweeps"] == [],
      str((pbody["sweeps"], pbody["excluded_sweeps"])))
check("full export declares no exclusions",
      json.loads(honest)["body"]["excluded_sweeps"] == [])

# ------------------------------------------------- unilateral lineage claims
# Supersession is bilateral evidence. A STORED payload claiming a
# predecessor whose chain never consented, or a SUPERSEDED_BY naming a
# successor whose STORED does not claim it, must fail B4 in BOTH verifiers.
conn3 = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn3.executescript(f.read())
cur3 = conn3.cursor()
cur3.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
             "VALUES ('agent-1', 'agent-1', 'AGENT', ?)", (custody.now_ts(),))
field.store(cur3, memory_id="m-a", content="v1", embedding=emb(1.0, 0.0),
            embedding_model="dev", actor_id="agent-1", reason="ingestion")
field.supersede(cur3, old_memory_id="m-a", memory_id="m-b", content="v2",
                embedding=emb(1.0, 0.1), embedding_model="dev",
                actor_id="agent-1", reason="refresh")
conn3.commit()
agree("honest supersession pair verifies", bundle.export_bundle(cur3), True)

# dishonest: STORED claims supersedes=m-a but m-a's chain names only m-b
field.store(cur3, memory_id="m-c", content="fake v3", embedding=emb(0.9, 0.2),
            embedding_model="dev", actor_id="agent-1", reason="ingestion",
            supersedes="m-a")
conn3.commit()
agree("unilateral supersession claim in STORED", bundle.export_bundle(cur3),
      False, {"B4"})

# dishonest the other way: SUPERSEDED_BY names a non-consenting successor
custody.append_event(cur3, memory_id="m-c", event_type="SUPERSEDED_BY",
                     actor_id="agent-1", reason="forged lineage",
                     payload={"successor_memory_id": "m-b"})
conn3.commit()
agree("SUPERSEDED_BY naming a non-consenting successor",
      bundle.export_bundle(cur3), False, {"B4"})

# ------------------------------------------ declared lineage (Round 2, R2-04)
# A one-sided export used to verify while merely NAMING its absent
# counterpart: the relation was never erased, but the verifier could not
# tell "not included" from "lineage ended here". Now it is declared, and
# the declaration is checked both ways.
print("\n[lineage whose counterpart stays behind]")
only_successor = bundle.export_bundle(cur3, memory_ids=["m-b"])
agree("a one-sided lineage export verifies", only_successor, True)
_ok, _errs, _notes = bundle.verify_bundle_verbose(only_successor)
check("...and declares the counterpart it cannot carry",
      json.loads(only_successor)["body"]["excluded_lineage"]
      == [{"memory_id": "m-b", "role": "successor", "counterpart": "m-a"}],
      str(json.loads(only_successor)["body"]["excluded_lineage"]))
check("...and a passing verdict names it out loud",
      any("m-a" in n and "consent is NOT proven" in n for n in _notes),
      str(_notes))

only_predecessor = bundle.export_bundle(cur3, memory_ids=["m-a"])
agree("the other side verifies too", only_predecessor, True)
check("...declaring its absent successor",
      {d["role"] for d in json.loads(only_predecessor)["body"]["excluded_lineage"]}
      == {"predecessor"},
      str(json.loads(only_predecessor)["body"]["excluded_lineage"]))

t = json.loads(only_successor)
t["body"]["excluded_lineage"] = []
body_c = bundle.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("a lineage claim neither carried nor declared", json.dumps(t), False, {"B4"})

full_pair = bundle.export_bundle(cur3, memory_ids=["m-a", "m-b"])
t = json.loads(full_pair)
t["body"]["excluded_lineage"] = [
    {"memory_id": "m-b", "role": "successor", "counterpart": "m-a"}]
body_c = bundle.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("a counterpart the bundle carries, declared away", json.dumps(t),
      False, {"B4"})

# ------------------------------------------------- backward-in-time chain (H1)
# Both verifiers must reject a hash-valid chain that runs backwards in
# time. Build a single-memory field, then rewrite its 2nd event to an
# earlier timestamp with a recomputed entry_hash, recompute the Merkle
# root and reseal so ONLY the timestamp rule (B2) is left to catch it.
conn4 = sqlite3.connect(":memory:")
with open(os.path.join(os.path.dirname(__file__), "..", "mneme", "schema.sql")) as f:
    conn4.executescript(f.read())
cur4 = conn4.cursor()
cur4.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
             "VALUES ('agent-1', 'agent-1', 'AGENT', ?)", (custody.now_ts(),))
field.store(cur4, memory_id="m-z", content="z", embedding=emb(1.0, 0.0),
            embedding_model="dev", actor_id="agent-1", reason="ingestion")
trust.quarantine_memory(cur4, memory_id="m-z", actor_id="agent-1",
                        reason="direct")
conn4.commit()
tb = json.loads(bundle.export_bundle(cur4))
ch = next(m for m in tb["body"]["memories"] if m["memory_id"] == "m-z")["custody"]
# rewrite seq 1 to one hour BEFORE seq 0, recompute its entry_hash
ch[1]["created_at"] = "2000-01-01T00:00:00.000000+00:00"
eh, _ = custody.compute_entry_hash(
    prev_hash=ch[1]["prev_hash"], memory_id="m-z", seq=1,
    event_type=ch[1]["event_type"], actor_id=ch[1]["actor_id"],
    reason=ch[1]["reason"], created_at=ch[1]["created_at"],
    payload=json.loads(ch[1]["payload_json"]))
ch[1]["entry_hash"] = eh
tb["body"]["heads_merkle_root"] = offline.heads_merkle_root({"m-z": eh})
tb["bundle_sha256"] = hashlib.sha256(
    offline.canonical_json(tb["body"]).encode("utf-8")).hexdigest()
agree("hash-valid backward-in-time chain in a bundle", json.dumps(tb),
      False, {"B2"})

# --------------------------------------------------------------- tampering
print("[tampered bundles — every lie caught by BOTH verifiers]")
doc = json.loads(honest)

t = json.loads(honest)
t["body"]["memories"][0]["content"] = "the sky is RED, always was"
agree("edited content, reseal not attempted", json.dumps(t), False, {"B1"})

t = json.loads(honest)
t["body"]["memories"][0]["content"] = "the sky is RED, always was"
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("edited content + reseal", json.dumps(t), False, {"B3"})

t = json.loads(honest)
t["body"]["memories"][0]["custody"][2]["reason"] = "innocent"
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("edited event + reseal", json.dumps(t), False, {"B2"})

t = json.loads(honest)
for m in t["body"]["memories"]:
    if m["memory_id"] == "mem-2":
        m["custody_status"] = "CLEAN"   # un-taint by column edit
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("status laundered without event", json.dumps(t), False, {"B4"})

t = json.loads(honest)
for m in t["body"]["memories"]:
    if m["memory_id"] == "mem-1":
        m["confidence"] = "0.9999999999"
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("confidence inflated without events", json.dumps(t), False, {"B4"})

t = json.loads(honest)
t["body"]["sweeps"][0]["flagged_count"] = 0
t["body"]["sweeps"][0]["flagged_ids_sha256"] = hashlib.sha256(
    offline.canonical_json({"memory_ids": []}).encode("utf-8")).hexdigest()
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("sweep evidence denied", json.dumps(t), False, {"B5"})

t = json.loads(honest)
# exclude a sweep whose COMPLETE evidence is in the bundle — exclusion
# must never be a way to dodge the seal check
t["body"]["excluded_sweeps"] = t["body"]["sweeps"]
t["body"]["sweeps"] = []
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("fully-evidenced sweep declared excluded", json.dumps(t), False, {"B5"})

t = json.loads(partial)
# drop the exclusion declaration while a TAINT_FLAGGED event (mem-3)
# still references the sweep — absence implied is a lie
t["body"]["excluded_sweeps"] = []
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("referenced sweep silently dropped", json.dumps(t), False, {"B5"})

t = json.loads(partial)
# same sweep in both lists — ambiguity refused
t["body"]["sweeps"] = list(t["body"]["excluded_sweeps"])
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("sweep declared both included and excluded", json.dumps(t), False, {"B5"})

t = json.loads(honest)
# a bundle without the excluded_sweeps key (pre-declaration shape)
# reads as excluding nothing and still verifies
del t["body"]["excluded_sweeps"]
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("missing excluded_sweeps key reads as empty", json.dumps(t), True)

t = json.loads(honest)
# graft: give mem-3 the (internally consistent) chain of mem-1
donor = [dict(r) for r in
         next(m for m in t["body"]["memories"] if m["memory_id"] == "mem-1")["custody"]]
for m in t["body"]["memories"]:
    if m["memory_id"] == "mem-3":
        m["custody"] = donor
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("chain grafted across memories", json.dumps(t), False, {"B2"})

t = json.loads(honest)
t["body"]["heads_merkle_root"] = "0" * 64
body_c = offline.canonical_json(t["body"])
t["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
agree("forged merkle root", json.dumps(t), False, {"B6"})

# --------------------------------------------------------------- CLI exit codes
print("[standalone CLI]")
import subprocess
import tempfile
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    f.write(honest)
    honest_path = f.name
r = subprocess.run([sys.executable,
                    os.path.join(os.path.dirname(__file__), "..", "verify_offline.py"),
                    honest_path], capture_output=True, text=True)
check("CLI exits 0 on honest bundle", r.returncode == 0 and "VERIFIED" in r.stdout,
      r.stdout + r.stderr)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    f.write(partial)
    partial_path = f.name
r = subprocess.run([sys.executable,
                    os.path.join(os.path.dirname(__file__), "..", "verify_offline.py"),
                    partial_path], capture_output=True, text=True)
check("CLI exits 0 on declared partial bundle and NAMES the exclusion",
      r.returncode == 0 and "VERIFIED" in r.stdout and "declared excluded" in r.stdout,
      r.stdout + r.stderr)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    f.write(json.dumps(t))   # last tampered bundle (forged merkle root)
    bad_path = f.name
r = subprocess.run([sys.executable,
                    os.path.join(os.path.dirname(__file__), "..", "verify_offline.py"),
                    bad_path], capture_output=True, text=True)
check("CLI exits 1 on tampered bundle", r.returncode == 1 and "B6" in r.stdout,
      r.stdout + r.stderr)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
