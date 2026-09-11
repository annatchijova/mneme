"""
MNEME — authority tests. SQLite :memory: only; no external infra.

Custody tests ask "what does lying look like". These ask the question
Round 2 exposed: WHAT DOES ACTING WITHOUT PERMISSION LOOK LIKE — and is
it as self-revealing as tampering?

One test per unauthorized act:
  - an actor nobody registered writes           -> no chain, no capability
  - an actor holding STORE quarantines          -> wrong capability
  - a grantor confers what it lacks             -> A3, no amplification
  - the root act performed twice                -> structurally refused
  - a quarantined actor stores / reinforces     -> A5, the write barrier
    (Round 2 R2-01, confirmed by induction, closed here)
  - a caller rehabilitates its own evidence     -> A5 + REHABILITATE
    (Round 2 R2-02, Induction A)
  - a caller quarantines another actor          -> QUARANTINE_ACTOR
    (Round 2 R2-02, Induction B)
  - an actor quarantines or reinstates itself   -> refused with words
  - the last GRANT-bearing grant is revoked     -> A6, ungovernable field
  - a grant is edited after the fact            -> chain does not recompute
  - one actor's grants presented as another's   -> authority genesis binding
  - a forged grant_id in a custody payload      -> B7
  - an act backdated under a revoked grant      -> B7 temporal check
  - a bundle declaring semantics we do not have -> B0 refusal

Plus the agreement discipline: every bundle verdict here is demanded of
BOTH implementations (package and standalone), because an authority
check that exists in only one of them is a check an auditor cannot rely
on.
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

from mneme import authority, bundle, custody, field, protocol, trust  # noqa: E402
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


def reseal(tampered: dict) -> str:
    body_c = canonical_json(tampered["body"])
    tampered["bundle_sha256"] = hashlib.sha256(body_c.encode("utf-8")).hexdigest()
    return json.dumps(tampered)


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


def fresh_db():
    conn = sqlite3.connect(":memory:")
    with open(os.path.join(os.path.dirname(__file__), "..",
                           "mneme", "schema.sql")) as f:
        conn.executescript(f.read())
    return conn, conn.cursor()


# ============================================================ the bootstrap
print("[the root act]")
conn, cur = fresh_db()

root_grant = authority.bootstrap_root(
    cur, actor_id="root-op", display_name="Root Operator",
    reason="field genesis: operator provisioned out of band")
conn.commit()

check("root holds the whole vocabulary",
      authority.effective_capabilities(cur, "root-op") == authority.CAPABILITIES)
check("root chain verifies", authority.verify_authority_chain(cur, "root-op")[0])
raises("a second root act is refused",
       lambda: authority.bootstrap_root(cur, actor_id="usurper",
                                        display_name="U", reason="me too"),
       ValueError, "unrepeatable by construction")

# ============================================ registration confers nothing
print("\n[registration is not empowerment]")
authority.register_actor(cur, actor_id="ingestor", display_name="Ingest",
                         kind="PIPELINE", issuer_id="root-op",
                         reason="new ingestion pipeline")
conn.commit()
check("a registered actor holds nothing until granted",
      authority.effective_capabilities(cur, "ingestor") == frozenset())
raises("an unempowered actor cannot store",
       lambda: field.store(cur, memory_id="m-nope", content="x", embedding=emb(1.0, 0.0),
                           embedding_model="dev", actor_id="ingestor", reason="ingest"),
       ValueError, "holds no active grant conferring STORE")
conn.rollback()
raises("an actor nobody registered cannot be granted",
       lambda: authority.grant(cur, subject_id="ghost", capabilities=["STORE"],
                               issuer_id="root-op", reason="r"),
       ValueError, "no authority chain")
conn.rollback()

ingest_grant = authority.grant(cur, subject_id="ingestor",
                               capabilities=["STORE", "REINFORCE"],
                               issuer_id="root-op", reason="ingestion duty")
conn.commit()
check("granted capabilities take effect",
      authority.effective_capabilities(cur, "ingestor") == frozenset({"STORE", "REINFORCE"}))

# ================================================== capabilities are narrow
print("\n[a capability is not a role]")
field.store(cur, memory_id="mem-1", content="the sky is blue",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="ingestor", reason="ingestion", topic="sky", claim="blue")
conn.commit()
check("STORE lets the actor store", True)
check("the STORED event names its grant",
      json.loads(cur.execute(
          "SELECT payload_json FROM custody_chain WHERE memory_id='mem-1' AND seq=0"
      ).fetchone()[0])["grant_id"] == ingest_grant)

raises("STORE does not confer QUARANTINE_MEMORY",
       lambda: trust.quarantine_memory(cur, memory_id="mem-1",
                                       actor_id="ingestor", reason="x"),
       ValueError, "QUARANTINE_MEMORY")
conn.rollback()
raises("STORE does not confer SUPERSEDE",
       lambda: field.supersede(cur, old_memory_id="mem-1", memory_id="mem-1b",
                               content="v2", embedding=emb(1.0, 0.1),
                               embedding_model="dev", actor_id="ingestor",
                               reason="refresh"),
       ValueError, "SUPERSEDE")
conn.rollback()
raises("STORE does not confer GRANT",
       lambda: authority.grant(cur, subject_id="ingestor",
                               capabilities=["SUPERSEDE"],
                               issuer_id="ingestor", reason="self-service"),
       ValueError, "holds no active grant conferring GRANT")
conn.rollback()

# ====================================================== A3: no amplification
print("\n[A3 — authority is delegated, never invented]")
authority.register_actor(cur, actor_id="team-lead", display_name="Lead",
                         kind="HUMAN", issuer_id="root-op",
                         reason="delegation point")
authority.grant(cur, subject_id="team-lead", capabilities=["GRANT", "STORE"],
                issuer_id="root-op", reason="may staff the ingest team")
conn.commit()
check("a delegate can pass on what it holds",
      isinstance(authority.grant(cur, subject_id="ingestor",
                                 capabilities=["STORE"], issuer_id="team-lead",
                                 reason="second store grant"), str))
conn.rollback()
raises("a delegate cannot confer what it lacks",
       lambda: authority.grant(cur, subject_id="ingestor",
                               capabilities=["QUARANTINE_ACTOR"],
                               issuer_id="team-lead", reason="overreach"),
       ValueError, "Invariant A3")
conn.rollback()

# ====================================================== revocation semantics
print("\n[A4 — revocation is an event, and it is not retroactive]")
authority.register_actor(cur, actor_id="analyst", display_name="Analyst",
                         kind="HUMAN", issuer_id="root-op", reason="reviewer")
analyst_grant = authority.grant(
    cur, subject_id="analyst",
    capabilities=["QUARANTINE_ACTOR", "QUARANTINE_MEMORY", "REHABILITATE"],
    issuer_id="root-op", reason="incident response duty")
conn.commit()

field.store(cur, memory_id="mem-2", content="water is wet",
            embedding=emb(0.0, 1.0), embedding_model="dev",
            actor_id="ingestor", reason="ingestion")
trust.quarantine_memory(cur, memory_id="mem-2", actor_id="analyst",
                        reason="directly incriminated in review")
conn.commit()
pre_revocation_bundle = bundle.export_bundle(cur)
agree("acts under a live grant verify", pre_revocation_bundle, True)

authority.revoke(cur, subject_id="analyst", grant_id=analyst_grant,
                 issuer_id="root-op", reason="rotation off incident duty")
conn.commit()
check("a revoked grant confers nothing",
      authority.effective_capabilities(cur, "analyst") == frozenset())
raises("a revoked actor cannot act",
       lambda: trust.quarantine_memory(cur, memory_id="mem-1",
                                       actor_id="analyst", reason="late"),
       ValueError, "holds no active grant")
conn.rollback()
agree("acts performed BEFORE the revocation still verify",
      bundle.export_bundle(cur), True)
raises("a grant cannot be revoked twice",
       lambda: authority.revoke(cur, subject_id="analyst",
                                grant_id=analyst_grant, issuer_id="root-op",
                                reason="again"),
       ValueError, "already revoked")
conn.rollback()

# ======================================================== A6: governability
print("\n[A6 — the field is never left ungovernable]")
root_chain = authority.load_authority_rows(cur, "root-op")
root_gid = json.loads(root_chain[1]["payload_json"])["grant_id"]
check("root grant id recovered from evidence", root_gid == root_grant)
# team-lead also holds GRANT, so revoking root's is currently allowed;
# revoke team-lead's first and the root grant becomes the last one.
lead_state = authority.load_state(cur, "team-lead")
lead_gid = sorted(lead_state.grants)[0]
authority.revoke(cur, subject_id="team-lead", grant_id=lead_gid,
                 issuer_id="root-op", reason="lead left the team")
conn.commit()
raises("the last GRANT-bearing grant cannot be revoked",
       lambda: authority.revoke(cur, subject_id="root-op", grant_id=root_gid,
                                issuer_id="root-op", reason="disarm the field"),
       ValueError, "Invariant A6")
conn.rollback()

# ============================================== A5: quarantine is a barrier
print("\n[A5 — Round 2 R2-01: quarantine is a write barrier, not a note]")
authority.grant(cur, subject_id="analyst",
                capabilities=["QUARANTINE_ACTOR", "REHABILITATE"],
                issuer_id="root-op", reason="re-issued for this incident")
conn.commit()

sweep = trust.quarantine_actor(cur, actor_id="ingestor",
                               initiated_by="analyst",
                               reason="ingestion source compromised")
conn.commit()
check("the sweep flagged what the actor touched",
      set(sweep.flagged_memory_ids) == {"mem-1", "mem-2"},
      str(sweep.flagged_memory_ids))
check("the actor's authority chain records the quarantine",
      authority.load_state(cur, "ingestor").status == "QUARANTINED")
check("a quarantined actor's effective capabilities are empty",
      authority.effective_capabilities(cur, "ingestor") == frozenset())

raises("R2-01a: a quarantined actor cannot store a fresh CLEAN memory",
       lambda: field.store(cur, memory_id="mem-post", content="post-quarantine",
                           embedding=emb(0.7, 0.7), embedding_model="dev",
                           actor_id="ingestor", reason="still here"),
       ValueError, "is QUARANTINED")
conn.rollback()
field.store(cur, memory_id="mem-3", content="unrelated truth",
            embedding=emb(0.2, 0.9), embedding_model="dev",
            actor_id="root-op", reason="ingestion by a clean actor")
conn.commit()
raises("R2-01b: a quarantined actor cannot reinforce a clean memory",
       lambda: field.reinforce(cur, memory_id="mem-3", actor_id="ingestor",
                               reason="inflate"),
       ValueError, "is QUARANTINED")
conn.rollback()
raises("R2-02a: a quarantined actor cannot rehabilitate its own evidence",
       lambda: trust.rehabilitate_memory(cur, memory_id="mem-1",
                                         actor_id="ingestor",
                                         reason="self-declared false positive"),
       ValueError, "QUARANTINED")
conn.rollback()
raises("R2-02b: an actor without QUARANTINE_ACTOR cannot sweep another actor",
       lambda: trust.quarantine_actor(cur, actor_id="team-lead",
                                      initiated_by="ingestor",
                                      reason="retaliation"),
       ValueError, "QUARANTINED")
conn.rollback()

authority.register_actor(cur, actor_id="bystander", display_name="Bystander",
                         kind="AGENT", issuer_id="root-op", reason="reader")
authority.grant(cur, subject_id="bystander", capabilities=["STORE"],
                issuer_id="root-op", reason="may write its own notes")
conn.commit()
raises("R2-02c: a registered-but-unauthorized caller cannot rehabilitate",
       lambda: trust.rehabilitate_memory(cur, memory_id="mem-1",
                                         actor_id="bystander",
                                         reason="nominating myself reviewer"),
       ValueError, "holds no active grant conferring REHABILITATE")
conn.rollback()
raises("granting to a quarantined subject is refused",
       lambda: authority.grant(cur, subject_id="ingestor",
                               capabilities=["STORE"], issuer_id="root-op",
                               reason="quietly rearm"),
       ValueError, "refusing to write a grant onto a contained actor")
conn.rollback()

# ============================================ self-containment is no containment
print("\n[an actor is not its own reviewer]")
raises("an actor cannot quarantine itself",
       lambda: authority.quarantine_actor_authority(
           cur, subject_id="analyst", issuer_id="analyst", reason="self"),
       ValueError, "cannot quarantine itself")
conn.rollback()
raises("an actor cannot reinstate itself",
       lambda: authority.reinstate_actor(cur, subject_id="ingestor",
                                         issuer_id="ingestor", reason="I am fine"),
       ValueError, "cannot reinstate itself")
conn.rollback()

authority.reinstate_actor(cur, subject_id="ingestor", issuer_id="analyst",
                          reason="investigation cleared the pipeline")
conn.commit()
check("reinstatement restores the actor's capabilities",
      authority.effective_capabilities(cur, "ingestor") == frozenset({"STORE", "REINFORCE"}))
check("reinstatement does NOT rehabilitate the memories the sweep flagged",
      cur.execute("SELECT custody_status FROM memories WHERE memory_id='mem-1'"
                  ).fetchone()[0] == "TAINT_FLAGGED")
field.store(cur, memory_id="mem-4", content="after reinstatement",
            embedding=emb(0.3, 0.8), embedding_model="dev",
            actor_id="ingestor", reason="back to work")
conn.commit()
check("a reinstated actor can write again", True)

honest = bundle.export_bundle(cur)
agree("the whole authorized field verifies", honest, True)
check("the honest bundle claims no unauthorized events",
      not any("UNAUTHORIZED" in n for n in bundle.verify_bundle_verbose(honest)[2]),
      str(bundle.verify_bundle_verbose(honest)[2]))

# ====================================================== tampering: authority
print("\n[what lying about authority looks like]")

t = json.loads(honest)
entry = next(e for e in t["body"]["authority"] if e["subject_id"] == "ingestor")
ev = next(r for r in entry["chain"] if r["event_type"] == "GRANTED")
p = json.loads(ev["payload_json"])
p["capabilities"] = sorted(set(p["capabilities"]) | {"REHABILITATE"})
ev["payload_json"] = canonical_json(p)
agree("a grant widened after the fact", reseal(t), False, {"B7"})

t = json.loads(honest)
entry = next(e for e in t["body"]["authority"] if e["subject_id"] == "ingestor")
entry["status"] = "QUARANTINED"
agree("a hand-edited actor status", reseal(t), False, {"B7"})

t = json.loads(honest)
# graft: present the analyst's grant history as the bystander's
src = next(e for e in t["body"]["authority"] if e["subject_id"] == "ingestor")
dst = next(e for e in t["body"]["authority"] if e["subject_id"] == "analyst")
dst["chain"] = src["chain"]
agree("one actor's grants presented as another's", reseal(t), False, {"B7"})

t = json.loads(honest)
mem = next(m for m in t["body"]["memories"] if m["memory_id"] == "mem-4")
p = json.loads(mem["custody"][0]["payload_json"])
p["grant_id"] = "grant-does-not-exist"
mem["custody"][0]["payload_json"] = canonical_json(p)
agree("a custody event naming a grant nobody issued", reseal(t), False, {"B2"})

t = json.loads(honest)
t["body"]["authority"] = []
t["body"]["authority_genesis_at"] = None
agree("authority evidence simply dropped", reseal(t), False, {"B7"})

t = json.loads(honest)
t["body"]["authority_genesis_at"] = "2099-01-01T00:00:00.000000+00:00"
agree("the genesis raised to excuse every event", reseal(t), False, {"B7"})

# An event written by an actor while quarantined, with a grant that was
# real before the quarantine. Custody is perfect; authority is not.
conn5, cur5 = fresh_db()
authority.bootstrap_root(cur5, actor_id="root2", display_name="R",
                         reason="genesis")
authority.register_actor(cur5, actor_id="evil", display_name="E", kind="AGENT",
                         issuer_id="root2", reason="ingest")
evil_grant = authority.grant(cur5, subject_id="evil", capabilities=["STORE"],
                             issuer_id="root2", reason="ingest duty")
authority.register_actor(cur5, actor_id="ir", display_name="IR", kind="HUMAN",
                         issuer_id="root2", reason="responder")
authority.grant(cur5, subject_id="ir", capabilities=["QUARANTINE_ACTOR"],
                issuer_id="root2", reason="incident duty")
field.store(cur5, memory_id="e-1", content="poison", embedding=emb(1.0, 0.0),
            embedding_model="dev", actor_id="evil", reason="ingest")
trust.quarantine_actor(cur5, actor_id="evil", initiated_by="ir",
                       reason="source compromised")
conn5.commit()
# Bypass the gate the way an attacker with raw database access would:
# insert a perfectly-chained custody event under the old, real grant.
cur5.execute("INSERT INTO memories (memory_id, content, content_sha256, "
             "embedding_json, embedding_model, created_by, created_at) "
             "VALUES ('e-2','smuggled',?,?,'dev','evil',?)",
             (custody.content_sha256("smuggled"),
              field.embedding_to_json(emb(0.9, 0.1)), custody.now_ts()))
custody.append_event(cur5, memory_id="e-2", event_type="STORED",
                     actor_id="evil", reason="smuggled past the gate",
                     payload={"content_sha256": custody.content_sha256("smuggled"),
                              "embedding_model": "dev",
                              "grant_id": evil_grant})
conn5.commit()
agree("a flawless chain for an act the actor had no right to perform",
      bundle.export_bundle(cur5), False, {"B7"})

# ========================================================= B0: the semantics
print("\n[B0 — a seal over bytes with undeclared meaning is not evidence]")
t = json.loads(honest)
del t["body"]["protocols"]
agree("a bundle declaring no semantics", reseal(t), False, {"B0"})

t = json.loads(honest)
t["body"]["protocols"]["replay_protocol"] = "2.0.0"
agree("a bundle sealed under replay semantics we do not implement",
      reseal(t), False, {"B0"})

t = json.loads(honest)
# This test named "claim_protocol" until claim_protocol became real, which
# is the mechanism working: a name this build has never heard of is a
# bundle from a newer MNEME, and a verdict from an older verifier on newer
# evidence is the retroactive-semantics problem read backwards.
t["body"]["protocols"]["stylometry_protocol"] = "1.0.0"
agree("a bundle from a newer MNEME naming a protocol we never heard of",
      reseal(t), False, {"B0"})

t = json.loads(honest)
t["body"]["format"] = "MNEME_BUNDLE_V1"
ok_pkg, err_pkg = bundle.verify_bundle(reseal(t))
check("a V1 bundle is refused, not reinterpreted",
      (not ok_pkg) and "older format" in err_pkg[0], str(err_pkg))
check("protocol table and support table name the same protocols",
      set(protocol.CURRENT_PROTOCOLS) == set(protocol.SUPPORTED_PROTOCOLS)
      == set(protocol.PROTOCOL_NAMES))
check("every current version is one this build supports",
      all(v in protocol.SUPPORTED_PROTOCOLS[k]
          for k, v in protocol.CURRENT_PROTOCOLS.items()))
check("both implementations declare the same support table",
      {k: set(v) for k, v in protocol.SUPPORTED_PROTOCOLS.items()}
      == {k: set(v) for k, v in offline.SUPPORTED_PROTOCOLS.items()})
# Versioning is not decorative: the SAME bundle must get DIFFERENT
# verdicts under two declared replay semantics, or "a bundle commits to
# the rules it was checked under" is a slogan rather than a mechanism.
conn7, cur7 = fresh_db()
cur7.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
             "VALUES ('w','w','AGENT',?)", (custody.now_ts(),))
field.store(cur7, memory_id="p-1", content="corroborated", embedding=emb(1.0, 0.0),
            embedding_model="dev", actor_id="w", reason="doc")
# Reinforce past the threshold while the writer thinks the bar is higher:
# confidence crosses 3/4 with no promotion event recorded.
import mneme.field as _f  # noqa: E402
_saved = _f.PROMOTION_THRESHOLD
_f.PROMOTION_THRESHOLD = __import__("fractions").Fraction(99, 100)
for _ in range(3):
    field.reinforce(cur7, memory_id="p-1", actor_id="w", reason="corroboration")
_f.PROMOTION_THRESHOLD = _saved
conn7.commit()
undue = json.loads(bundle.export_bundle(cur7))
undue["body"]["protocols"]["replay_protocol"] = "1.0.0"
check("under replay 1.0.0 an undue promotion is derivable, so it passes",
      bundle.verify_bundle(reseal(undue))[0],
      str(bundle.verify_bundle(reseal(undue))[1][:2]))
agree("under replay 1.1.0 the same bundle is refused",
      bundle.export_bundle(cur7), False, {"B4"})
check("...and the two verifiers agree about BOTH versions",
      offline.verify(reseal(undue))[0] is True)

check("both implementations map events to the same capabilities",
      authority.REQUIRED_CAPABILITY == offline.REQUIRED_CAPABILITY
      and authority.AUTHORITY_EVENT_CAPABILITY == offline.AUTHORITY_EVENT_CAPABILITY
      and set(authority.CAPABILITIES) == set(offline.CAPABILITIES))

# ============================== A6 covers every path that can lose a holder
print("\n[a field nobody can govern is indistinguishable from an attack]")
conn9, cur9 = fresh_db()
authority.bootstrap_root(cur9, actor_id="root", display_name="R",
                         reason="genesis")
for aid, caps in [("ir", ["QUARANTINE_ACTOR", "REVOKE"]), ("ops", ["GRANT"])]:
    authority.register_actor(cur9, actor_id=aid, display_name=aid, kind="HUMAN",
                             issuer_id="root", reason="staffing")
    authority.grant(cur9, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty")
conn9.commit()
check("governance is a counter, derived from the chains and cached",
      cur9.execute("SELECT grant_holders FROM governance").fetchone()[0]
      == len(authority.actors_holding_grant(cur9, custody.now_ts())) == 2)

# The brick: quarantine the only GRANT holder, then let the responder rotate
# itself off. Two individually legitimate acts; a field that can never grant,
# register or reinstate again. A6 guarded the revoke and not the quarantine.
authority.quarantine_actor_authority(cur9, subject_id="root", issuer_id="ir",
                                     reason="root credentials compromised")
cur9.execute("UPDATE actors SET status='QUARANTINED' WHERE actor_id='root'")
conn9.commit()
check("quarantining a non-last holder is still allowed",
      authority.actors_holding_grant(cur9, custody.now_ts()) == ["ops"])
raises("quarantining the LAST holder is refused",
       lambda: authority.quarantine_actor_authority(
           cur9, subject_id="ops", issuer_id="ir",
           reason="and now the other one"),
       ValueError, "Invariant A6")
conn9.rollback()
ops_grant = sorted(authority.load_state(cur9, "ops").grants)[0]
raises("...and so is revoking it, by the same counter",
       lambda: authority.revoke(cur9, subject_id="ops", grant_id=ops_grant,
                                issuer_id="ir", reason="rotate"),
       ValueError, "Invariant A6")
conn9.rollback()
check("reinstatement gives the holder back",
      (authority.reinstate_actor(cur9, subject_id="root", issuer_id="ir",
                                 reason="investigation cleared it") or True)
      and authority.actors_holding_grant(cur9, custody.now_ts()) == ["ops", "root"])
conn9.commit()
check("the cached counter never drifts from the chains",
      cur9.execute("SELECT grant_holders FROM governance").fetchone()[0]
      == len(authority.actors_holding_grant(cur9, custody.now_ts())))
raises("and the CHECK backs the guard even if a caller forgets it",
       lambda: cur9.execute("UPDATE governance SET grant_holders = 0"),
       Exception, "CHECK")
conn9.rollback()
agree("a governed field still verifies", bundle.export_bundle(cur9), True)

# ============ an event is authorized by the state BEFORE it, never by its own
print("\n[an act judged by the state it creates is judged by its own effect]")
conn10, cur10 = fresh_db()
authority.bootstrap_root(cur10, actor_id="root", display_name="R",
                         reason="genesis")
authority.register_actor(cur10, actor_id="ir", display_name="ir", kind="HUMAN",
                         issuer_id="root", reason="staffing")
ir_grant = authority.grant(cur10, subject_id="ir",
                           capabilities=["QUARANTINE_ACTOR", "REVOKE"],
                           issuer_id="root", reason="incident duty")
conn10.commit()
authority.revoke(cur10, subject_id="ir", grant_id=ir_grant, issuer_id="ir",
                 reason="rotating myself off the incident")
conn10.commit()
check("an actor may rotate itself off",
      authority.effective_capabilities(cur10, "ir") == frozenset())
agree("...and the bundle of that ordinary act verifies",
      bundle.export_bundle(cur10), True)
check("the write path and B7 agree about the same act",
      bundle.verify_bundle(bundle.export_bundle(cur10))[0])

# ================================================== two roots, and the export
print("\n[a check that cannot see what it checks is not a check]")
raises("the root act is now refused by a CONSTRAINT, not only a read",
       lambda: cur.execute(
           "INSERT INTO ledger_root (singleton, actor_id, created_at) "
           "VALUES (1, 'root-op', ?)", (custody.now_ts(),)),
       Exception, "UNIQUE")
conn.rollback()

# A field that already carries two self-issued roots — the state a racing
# pair of bootstraps used to be able to reach. Built by direct SQL, because
# the constraint above now makes it unreachable through the API.
conn8, cur8 = fresh_db()
authority.bootstrap_root(cur8, actor_id="root-a", display_name="A",
                         reason="genesis")
ts8 = custody.now_ts()
cur8.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
             "VALUES ('root-b','B','HUMAN',?)", (ts8,))
authority.append_authority_event(
    cur8, subject_id="root-b", event_type="ACTOR_REGISTERED",
    issuer_id="root-b", reason="a second, racing bootstrap",
    payload={"display_name": "B", "kind": "HUMAN", "root": True},
    created_at=ts8)
authority.append_authority_event(
    cur8, subject_id="root-b", event_type="GRANTED", issuer_id="root-b",
    reason="a second, racing bootstrap",
    payload={"grant_id": "grant-b",
             "capabilities": sorted(authority.CAPABILITIES), "root": True},
    created_at=ts8)
conn8.commit()
check("both roots are found from evidence, not just the first",
      authority.root_subjects(cur8) == ["root-a", "root-b"],
      str(authority.root_subjects(cur8)))
agree("a two-root ledger is refused", bundle.export_bundle(cur8), False, {"B7"})
check("...and the error names the count rather than hinting at it",
      any("2 root grants" in e
          for e in bundle.verify_bundle(bundle.export_bundle(cur8))[1]),
      str(bundle.verify_bundle(bundle.export_bundle(cur8))[1][:2]))

# =============================================== the pre-authority carve-out
print("\n[a field that never had a ledger says so]")
conn6, cur6 = fresh_db()
cur6.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
             "VALUES ('legacy','legacy','AGENT',?)", (custody.now_ts(),))
field.store(cur6, memory_id="l-1", content="written before authority existed",
            embedding=emb(1.0, 0.0), embedding_model="dev",
            actor_id="legacy", reason="ingestion")
conn6.commit()
legacy_bundle = bundle.export_bundle(cur6)
agree("a ledgerless field verifies", legacy_bundle, True)
check("...and says every event is unauthorized by declaration",
      any("UNAUTHORIZED BY DECLARATION" in n
          for n in bundle.verify_bundle_verbose(legacy_bundle)[2]),
      str(bundle.verify_bundle_verbose(legacy_bundle)[2]))

# Bootstrap mid-life: events before the genesis are excused BY NAME, and
# everything after must be authorized.
authority.bootstrap_root(cur6, actor_id="late-root", display_name="Late",
                         reason="ledger introduced")
authority.grant(cur6, subject_id="late-root", capabilities=["STORE"],
                issuer_id="late-root", reason="self, already held")
conn6.commit()
mixed = bundle.export_bundle(cur6)
agree("a field that gained a ledger mid-life verifies", mixed, True)
check("...and names the events that predate it",
      any("predate this field's authority genesis" in n
          for n in bundle.verify_bundle_verbose(mixed)[2]),
      str(bundle.verify_bundle_verbose(mixed)[2]))
raises("after the ledger exists, an ungranted legacy actor cannot write",
       lambda: field.store(cur6, memory_id="l-2", content="after",
                           embedding=emb(0.5, 0.5), embedding_model="dev",
                           actor_id="legacy", reason="ingestion"),
       ValueError, "no authority chain")
conn6.rollback()

t = json.loads(mixed)
mem = next(m for m in t["body"]["memories"] if m["memory_id"] == "l-1")
p = json.loads(mem["custody"][0]["payload_json"])
p["grant_id"] = "grant-backdated"
mem["custody"][0]["payload_json"] = canonical_json(p)
agree("a pre-authority event retrofitted with a grant", reseal(t), False, {"B2"})

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
