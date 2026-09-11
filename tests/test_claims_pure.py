"""
MNEME — epistemic claims and n-ary contradiction. SQLite :memory: only.

The conflation these tests hold the implementation apart from: a memory
is a CONTAINER, a claim is a PROPOSITION, and the field's belief is
NEITHER — it is derived from both, every time it is asked.

Four sentences that used to be one, each with its own test:
  "this text was stored"            a memory and its custody chain
  "this actor asserts P"            a claim chain, with its own genesis
  "two artifacts support P"         evidence links, each an audited event
  "MNEME holds P"                   a standing, recomputed and never stored

And the n-ary part: `A contradicts B` is too poor for a date that is one
of three candidates. A set is a CONSTRAINT, resolution is an operation
over the whole hypothesis space, and a resolution that leaves its own
constraint violated is refused.
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

from mneme import authority, bundle, claims, custody, field, trust  # noqa: E402
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
              expect_codes <= {e.split(':', 1)[0] for e in err_p}, str(err_p[:2]))


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
for aid, caps in [("archivist", ["STORE", "ASSERT"]),
                  ("adjudicator", ["ADJUDICATE"]),
                  ("clerk", ["STORE"]),
                  ("ir", ["QUARANTINE_MEMORY"])]:
    authority.register_actor(cur, actor_id=aid, display_name=aid, kind="HUMAN",
                             issuer_id="root", reason="staffing")
    authority.grant(cur, subject_id=aid, capabilities=caps, issuer_id="root",
                    reason="duty")
conn.commit()

# Three documents, each saying something about one release date.
docs = {
    "doc-changelog": "CHANGELOG: 1.4.0 released 2026-03-03.",
    "doc-ticket": "REL-88 closed 2026-03-05, shipping 1.4.0.",
    "doc-blog": "Our 1.4.0 launch post, published 2026-03-03.",
}
for mid, text in docs.items():
    field.store(cur, memory_id=mid, content=text, embedding=emb(1.0, 0.1),
                embedding_model="dev", actor_id="archivist", reason="archive")
conn.commit()

# ===================================== the container is not the proposition
print("[four sentences that used to be one]")
c_mar3 = claims.assert_claim(cur, statement="1.4.0 shipped on 2026-03-03.",
                             actor_id="archivist", topic="release-date",
                             reason="two sources appear to say so")
c_mar5 = claims.assert_claim(cur, statement="1.4.0 shipped on 2026-03-05.",
                             actor_id="archivist", topic="release-date",
                             reason="the ticket says so")
conn.commit()
check("a claim has its own id, distinct from any memory",
      c_mar3 != c_mar5 and not c_mar3.startswith("doc-"))
check("its chain has its own genesis, bound to the claim id",
      claims.load_claim_rows(cur, c_mar3)[0]["prev_hash"]
      == claims.claim_genesis_hash(c_mar3))
check("a claim chain cannot be grafted from another claim",
      claims.claim_genesis_hash(c_mar3) != claims.claim_genesis_hash(c_mar5))
raises("asserting into an existing claim id is refused",
       lambda: claims.assert_claim(cur, statement="x", actor_id="archivist",
                                   reason="r", claim_id=c_mar3),
       ValueError, "already exists")
conn.rollback()
raises("STORE does not confer ASSERT",
       lambda: claims.assert_claim(cur, statement="a clerk's opinion",
                                   actor_id="clerk", reason="r"),
       ValueError, "conferring ASSERT")
conn.rollback()

# Two artifacts support one proposition; one document, two propositions.
for mid in ("doc-changelog", "doc-blog"):
    claims.link_evidence(cur, claim_id=c_mar3, memory_id=mid, stance="SUPPORTS",
                         actor_id="archivist", reason="states the date")
claims.link_evidence(cur, claim_id=c_mar5, memory_id="doc-ticket",
                     stance="SUPPORTS", actor_id="archivist",
                     reason="the ticket's close date")
claims.link_evidence(cur, claim_id=c_mar3, memory_id="doc-ticket",
                     stance="CONTRADICTS", actor_id="archivist",
                     reason="the ticket disagrees")
conn.commit()
st = claims.standing(cur, c_mar3)
check("two artifacts support one proposition",
      st.supporting == ("doc-blog", "doc-changelog"), str(st.supporting))
check("and one of them contradicts it", st.contradicting == ("doc-ticket",))
check("a single document can bear on two propositions at once",
      "doc-ticket" in claims.standing(cur, c_mar5).supporting
      and "doc-ticket" in st.contradicting)
check("standing is DERIVED — no confidence column exists to store it",
      "confidence" not in
      [r[1] for r in cur.execute("PRAGMA table_info(claims)").fetchall()])
raises("evidence must point at something the field holds",
       lambda: claims.link_evidence(cur, claim_id=c_mar3, memory_id="doc-ghost",
                                    stance="SUPPORTS", actor_id="archivist",
                                    reason="r"),
       ValueError, "a pointer at something the field actually holds")
conn.rollback()

# ============================================================ n-ary sets
print("\n[a date is one of three, not a pair of links]")
c_mar4 = claims.assert_claim(cur, statement="1.4.0 shipped on 2026-03-04.",
                             actor_id="archivist", topic="release-date",
                             reason="a third reading of the ticket")
sid = claims.declare_set(cur, members=[c_mar3, c_mar4, c_mar5],
                         constraint_type="EXACTLY_ONE", actor_id="archivist",
                         topic="release-date",
                         reason="a release ships on exactly one date")
conn.commit()
ev = claims.evaluate_set(cur, sid)
check("with every hypothesis still open, the set is UNDETERMINED",
      ev.status == "UNDETERMINED", ev.explanation)
check("'nobody has objected yet' is never read as 'true'",
      all(s == "ASSERTED" for _, s in ev.member_states))
check("membership is recorded on every member's chain, not only in the row",
      all(sid in claims.load_claim_state(cur, c).sets
          for c in (c_mar3, c_mar4, c_mar5)))
raises("a constraint over fewer than two claims is refused",
       lambda: claims.declare_set(cur, members=[c_mar3],
                                  constraint_type="AT_MOST_ONE",
                                  actor_id="archivist", reason="r"),
       ValueError, "constrains nothing")
conn.rollback()
raises("ASSERT does not confer ADJUDICATE",
       lambda: claims.resolve_set(cur, set_id=sid, validate=[c_mar3],
                                  refute=[c_mar4, c_mar5],
                                  actor_id="archivist", reason="r"),
       ValueError, "conferring ADJUDICATE")
conn.rollback()
raises("a resolution that leaves the constraint violated is refused",
       lambda: claims.resolve_set(cur, set_id=sid, validate=[c_mar3, c_mar5],
                                  refute=[c_mar4], actor_id="adjudicator",
                                  reason="both, somehow"),
       ValueError, "Invariant C5")
conn.rollback()
raises("a resolution cannot decide a claim outside its own set",
       lambda: claims.resolve_set(cur, set_id=sid, validate=[c_mar3],
                                  refute=["claim-elsewhere"],
                                  actor_id="adjudicator", reason="r"),
       ValueError, "not members of")
conn.rollback()

after = claims.resolve_set(cur, set_id=sid, validate=[c_mar3],
                           refute=[c_mar4, c_mar5], actor_id="adjudicator",
                           reason="changelog and launch post outweigh the "
                                  "ticket's close date")
conn.commit()
check("the resolution leaves the set SATISFIED", after.status == "SATISFIED",
      after.explanation)
check("the surviving hypothesis is VALIDATED",
      claims.standing(cur, c_mar3).state == "VALIDATED")
check("the rejected ones are REFUTED, not deleted",
      claims.standing(cur, c_mar5).state == "REFUTED"
      and cur.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 3)
raises("an adjudicated claim cannot be quietly withdrawn",
       lambda: claims.append_claim_event(
           cur, claim_id=c_mar3, event_type="CLAIM_WITHDRAWN",
           actor_id="adjudicator", reason="r", payload={}) or
       claims.load_claim_state(cur, c_mar3),
       ValueError, "cannot be taken back")
conn.rollback()
raises("evidence cannot be attached to a refuted claim",
       lambda: claims.link_evidence(cur, claim_id=c_mar5,
                                    memory_id="doc-changelog",
                                    stance="SUPPORTS", actor_id="archivist",
                                    reason="late"),
       ValueError, "no longer live")
conn.rollback()

# INCOMPATIBLE is genuinely weaker than AT_MOST_ONE
print("\n[three constraints, three different things to know]")
a = claims.assert_claim(cur, statement="The service was degraded.",
                        actor_id="archivist", reason="r")
b = claims.assert_claim(cur, statement="The cache was cold.",
                        actor_id="archivist", reason="r")
c = claims.assert_claim(cur, statement="The deploy was clean.",
                        actor_id="archivist", reason="r")
inc = claims.declare_set(cur, members=[a, b, c], constraint_type="INCOMPATIBLE",
                         actor_id="archivist",
                         reason="these three cannot all be true at once")
conn.commit()
claims.resolve_set(cur, set_id=inc, validate=[a, b], refute=[c],
                   actor_id="adjudicator", reason="two of three held")
conn.commit()
check("INCOMPATIBLE tolerates two of three holding",
      claims.evaluate_set(cur, inc).status == "SATISFIED")
check("...which AT_MOST_ONE would have called a violation",
      claims.evaluate_constraint("AT_MOST_ONE",
                                 {a: "VALIDATED", b: "VALIDATED",
                                  c: "REFUTED"})[0] == "VIOLATED")
check("and EXACTLY_ONE refuses a set where nothing survives",
      claims.evaluate_constraint("EXACTLY_ONE",
                                 {a: "REFUTED", b: "REFUTED"})[0] == "VIOLATED")

# ======================================= the custody gate reaches the claims
print("\n[a claim cannot stand on material the field refuses to serve]")
trust.quarantine_memory(cur, memory_id="doc-changelog", actor_id="ir",
                        reason="the changelog entry was forged")
conn.commit()
st = claims.standing(cur, c_mar3)
check("quarantined evidence drops out of the tally",
      "doc-changelog" not in st.supporting, str(st.supporting))
check("...and is reported, not silently discarded",
      ("doc-changelog", "QUARANTINED") in st.withheld_evidence,
      str(st.withheld_evidence))
check("the link itself survives — the history of what was believed stays "
      "readable",
      "doc-changelog" in claims.load_claim_state(cur, c_mar3).supports)
check("the claim's adjudicated state is unchanged by the quarantine",
      st.state == "VALIDATED",
      "containment is evidence about a document, not a ruling about a claim")

# ============================================================= bilaterality
print("\n[a relation only one side asserts is not a relation]")
claims.relate(cur, from_claim=c_mar3, to_claim=c_mar5, relation="CONTRADICTS",
              actor_id="archivist", reason="two dates, one release")
conn.commit()
check("both chains record the relation, in opposite directions",
      ("CONTRADICTS", "OUT", c_mar5) in claims.load_claim_state(cur, c_mar3).relations
      and ("CONTRADICTS", "IN", c_mar3) in claims.load_claim_state(cur, c_mar5).relations)
raises("a claim cannot relate to itself",
       lambda: claims.relate(cur, from_claim=c_mar3, to_claim=c_mar3,
                             relation="SUPPORTS", actor_id="archivist",
                             reason="r"),
       ValueError, "cannot relate to itself")
conn.rollback()

honest = bundle.export_bundle(cur)
agree("a field with an epistemic layer verifies", honest, True)

# ======================================================= what lying looks like
print("\n[what lying about a proposition looks like]")

t = json.loads(honest)
e = next(x for x in t["body"]["claims"] if x["claim_id"] == c_mar3)
e["statement"] = "1.4.0 shipped on 2026-03-05."
agree("a proposition rewritten under its own seal", reseal(t), False, {"B9"})

t = json.loads(honest)
e = next(x for x in t["body"]["claims"] if x["claim_id"] == c_mar5)
e["state"] = "VALIDATED"
agree("a refuted claim declared validated", reseal(t), False, {"B9"})

t = json.loads(honest)
e = next(x for x in t["body"]["claims"] if x["claim_id"] == c_mar5)
e["chain"] = [r for r in e["chain"] if r["event_type"] != "RELATED_TO"]
agree("one side of a relation deleted", reseal(t), False, {"B9"})

t = json.loads(honest)
sw = next(x for x in t["body"]["claim_sets"] if x["set_id"] == sid)
sw["status"] = "SATISFIED" if sw["status"] != "SATISFIED" else "UNDETERMINED"
agree("a constraint status that the shipped claims contradict",
      reseal(t), False, {"B9"})

t = json.loads(honest)
sw = next(x for x in t["body"]["claim_sets"] if x["set_id"] == sid)
sw["members_json"] = canonical_json({"members": [c_mar3]})
agree("a member quietly dropped from a constrained set",
      reseal(t), False, {"B9"})

t = json.loads(honest)
e = next(x for x in t["body"]["claims"] if x["claim_id"] == c_mar3)
p = json.loads(e["chain"][0]["payload_json"])
p["topic"] = "something-else"
e["chain"][0]["payload_json"] = canonical_json(p)
agree("an assertion event edited after the fact", reseal(t), False, {"B9"})

# an adjudication by an actor that never held ADJUDICATE
t = json.loads(honest)
e = next(x for x in t["body"]["claims"] if x["claim_id"] == c_mar3)
ev_row = next(r for r in e["chain"] if r["event_type"] == "CLAIM_VALIDATED")
p = json.loads(ev_row["payload_json"])
p["grant_id"] = "grant-does-not-exist"
ev_row["payload_json"] = canonical_json(p)
agree("an adjudication under a grant nobody issued", reseal(t), False, {"B9"})

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
