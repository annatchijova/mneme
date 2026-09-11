"""
MNEME — SEMANTIC mutation testing. SQLite :memory: only.

Line coverage says which code ran. Operator mutation (mutmut and its
relatives) says which arithmetic a test would notice. Neither asks the
question that matters for a forensic system:

    if someone reimplemented MNEME and got a RULE wrong — dropped the
    bilaterality of supersession, let a quarantined actor write, promoted
    a memory that was not due, flagged a contradiction victim — would the
    evidence it produced still verify?

So the mutants here are PROTOCOL mutants. Each one patches the semantics,
lets the patched code produce real evidence, and then asks whether any
MNEME check refuses it. A mutant is KILLED if something refuses: a write
that raises, a bundle check that fails, or an invariant that no longer
holds. It SURVIVES if the evidence verifies clean.

The metric is semantic mutants killed / total, and a surviving mutant is
only acceptable if it is DECLARED here with a reason — a boundary MNEME
never claimed to cover. An undeclared survivor fails this suite, because
the alternative is a metric that improves by lowering its standards.

Two of the mutants below are declared survivors, and they are the most
useful entries in the file: they are exactly the boundaries
KNOWN_LIMITATIONS already names, now with an executable demonstration
that MNEME does not catch them.

This suite found two real gaps while it was being written. Both are
closed, and both are in the protocol versions: replay_protocol 1.1.0
(a promotion must be arithmetically DUE, not merely recorded) and
taint_protocol 2.0.0 (an included sweep's flagged set is re-derived from
custody evidence rather than trusted to agree with its own seal).

It did NOT find the two that Round 3 did — the counterfactual disclosure
oracle and the unreachable root check — and that is the more useful fact
about it. The author of a mutant who also wrote the defenses writes
killable mutants. Both are now mutants here, and the reason to keep them
is that they mark the blind spot rather than the coverage.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from decimal import Decimal
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import (authority, bundle, causality, counterfactual,  # noqa: E402
                   custody, field, trust)
from mneme.canonical import canonical_json  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "verify_offline",
    os.path.join(os.path.dirname(__file__), "..", "verify_offline.py"))
offline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offline)


# --------------------------------------------------------------- harness

@contextlib.contextmanager
def patched(target, name, value):
    """Replace one piece of semantics for the duration of a mutant."""
    old = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, old)


def emb(*vals) -> list[Decimal]:
    return field.quantize_embedding(list(vals))


def fresh():
    conn = sqlite3.connect(":memory:")
    with open(os.path.join(os.path.dirname(__file__), "..",
                           "mneme", "schema.sql")) as f:
        conn.executescript(f.read())
    cur = conn.cursor()
    authority.bootstrap_root(cur, actor_id="root", display_name="Root",
                             reason="field genesis")
    for aid, caps in [
        ("ingest", ["STORE", "REINFORCE", "SUPERSEDE"]),
        ("agent", ["STORE", "DECIDE"]),
        ("ir", ["QUARANTINE_ACTOR", "QUARANTINE_MEMORY", "REHABILITATE"]),
    ]:
        authority.register_actor(cur, actor_id=aid, display_name=aid,
                                 kind="AGENT", issuer_id="root",
                                 reason="staffing")
        authority.grant(cur, subject_id=aid, capabilities=caps,
                        issuer_id="root", reason="duty")
    conn.commit()
    return conn, cur


def verdict(bundle_json: str) -> tuple[bool, list[str]]:
    """
    Both verifiers must agree about a mutant, or the duplication has
    stopped being a decision and become the bug it warns about.
    """
    ok_p, err_p = bundle.verify_bundle(bundle_json)
    ok_o, err_o, _ = offline.verify(bundle_json)
    if ok_p != ok_o:
        return False, [f"VERIFIERS DISAGREE: package={ok_p} offline={ok_o}"]
    return ok_p, err_p


MUTANTS: list = []
KILLED: list = []
SURVIVED: list = []

# A survivor is acceptable only if it is named here with the boundary it
# demonstrates. These are not excuses; they are the two limits MNEME has
# always declared, now with a test that proves they are real.
DECLARED_SURVIVORS = {
    "a hostile exporter omits an authority chain entirely": (
        "A verifier cannot detect the absence of evidence it has no other "
        "pointer to. Already stated for sweeps — a partial export proves what "
        "it carries, never what it omits — and it holds identically for an "
        "authority chain belonging to an actor that wrote nothing. What the "
        "Round 3 fix changed is real and smaller: MNEME's own exporter no "
        "longer hides a second root, so an honest export of a two-root field "
        "now fails instead of passing."),
    "the model returns a vector it never computed": (
        "The embedding boundary. MNEME records what a provider HANDED it and "
        "makes drift across memories detectable; it cannot witness the "
        "model's arithmetic. Stated in KNOWN_LIMITATIONS since Phase 1 and "
        "unchanged by the provenance record."),
    "an attacker fabricates the entire field, coherently": (
        "A hash proves integrity, not truth. An adversary who controls every "
        "write can emit a monotonic, canonical, internally consistent history "
        "that verifies perfectly and never happened. Binding time and identity "
        "to something outside the field is the only answer, and it is a "
        "deployment decision, not a protocol one."),
}


def mutant(name: str, expect: str = "killed"):
    def deco(fn):
        MUTANTS.append((name, fn, expect))
        return fn
    return deco


# ------------------------------------------------------------- the mutants

@mutant("supersession loses its bilaterality")
def m_supersession_unilateral():
    """The successor claims a predecessor; the predecessor's chain is silent."""
    conn, cur = fresh()
    real_append = custody.append_event

    def swallow(cur_, **kw):
        if kw.get("event_type") == "SUPERSEDED_BY":
            return None
        return real_append(cur_, **kw)

    with patched(custody, "append_event", swallow), \
            patched(field.custody, "append_event", swallow):
        field.store(cur, memory_id="m-a", content="v1", embedding=emb(1.0, 0.0),
                    embedding_model="dev", actor_id="ingest", reason="doc")
        try:
            field.supersede(cur, old_memory_id="m-a", memory_id="m-b",
                            content="v2", embedding=emb(1.0, 0.1),
                            embedding_model="dev", actor_id="ingest",
                            reason="refresh")
        except Exception as exc:                              # noqa: BLE001
            conn.close()
            return True, f"refused at write: {exc}"
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("the authority gate is removed entirely")
def m_no_authority_gate():
    """Every mutator writes without asking whether it may."""
    conn, cur = fresh()
    trust.quarantine_actor(cur, actor_id="ingest", initiated_by="ir",
                           reason="compromised")
    conn.commit()
    with patched(authority, "gate", lambda cur_, **kw: None):
        field.store(cur, memory_id="m-post", content="written after quarantine",
                    embedding=emb(1.0, 0.0), embedding_model="dev",
                    actor_id="ingest", reason="still here")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("rehabilitation is allowed from QUARANTINED")
def m_rehabilitate_from_quarantined():
    """The asymmetry between a sweep's false positive and direct evidence,
    dropped."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-q", content="incriminated",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="ingest", reason="doc")
    trust.quarantine_memory(cur, memory_id="m-q", actor_id="ir",
                            reason="direct evidence")
    gid = sorted(authority.load_state(cur, "ir").grants)[0]
    custody.append_event(cur, memory_id="m-q", event_type="REHABILITATED",
                         actor_id="ir", reason="mutant: reversing a direct "
                         "quarantine", payload={"from_status": "QUARANTINED",
                                                "grant_id": gid})
    cur.execute("UPDATE memories SET custody_status='CLEAN' WHERE memory_id='m-q'")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("the promotion comparison is quietly narrowed")
def m_promotion_threshold():
    """The writer promotes later than the protocol says — the classic
    >= becomes > mutant, in the form it actually takes in a reimplementation."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-p", content="corroborated",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="ingest", reason="doc")
    with patched(field, "PROMOTION_THRESHOLD", Fraction(99, 100)):
        for _ in range(3):
            field.reinforce(cur, memory_id="m-p", actor_id="ingest",
                            reason="corroboration")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("the sweep's non-influence carve-out is dropped")
def m_sweep_over_flags():
    """Contradicting an actor becomes 'being touched by' it — the lever the
    carve-out exists to deny."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-truth", content="the gate is required",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="agent", reason="runbook",
                topic="policy", claim="required")
    field.store(cur, memory_id="m-lie", content="the gate is optional",
                embedding=emb(0.9, 0.1), embedding_model="dev",
                actor_id="ingest", reason="feed",
                topic="policy", claim="optional")
    conn.commit()
    with patched(trust, "NON_INFLUENCE_EVENTS", ("__none__",)):
        trust.quarantine_actor(cur, actor_id="ingest", initiated_by="ir",
                               reason="compromised feed")
    conn.commit()
    flagged = cur.execute(
        "SELECT custody_status FROM memories WHERE memory_id='m-truth'"
    ).fetchone()[0]
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    if flagged == "CLEAN":
        return True, "the mutation did not even take effect"
    return (not ok), (errs[0] if errs else "")


@mutant("the sweep silently misses what the actor reinforced")
def m_sweep_under_flags():
    """Under-flagging: the inflation of a legitimate memory drops out of the
    incident."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-a", content="a", embedding=emb(1.0, 0.0),
                embedding_model="dev", actor_id="agent", reason="doc")
    field.store(cur, memory_id="m-b", content="b", embedding=emb(0.0, 1.0),
                embedding_model="dev", actor_id="ingest", reason="doc")
    field.reinforce(cur, memory_id="m-a", actor_id="ingest",
                    reason="corroboration")
    conn.commit()
    with patched(trust, "NON_INFLUENCE_EVENTS",
                 ("CONTRADICTED_BY", "DECISION_USED_MEMORY", "REINFORCED")):
        trust.quarantine_actor(cur, actor_id="ingest", initiated_by="ir",
                               reason="compromised feed")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("a custody event is written without a reason")
def m_unreasoned_event():
    conn, cur = fresh()
    field.store(cur, memory_id="m-r", content="x", embedding=emb(1.0, 0.0),
                embedding_model="dev", actor_id="ingest", reason="doc")
    try:
        custody.append_event(cur, memory_id="m-r", event_type="REINFORCED",
                             actor_id="ingest", reason="   ", payload={})
    except Exception as exc:                                  # noqa: BLE001
        conn.close()
        return True, f"refused at write: {exc}"
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("a decision cites a memory the recall never served")
def m_decision_unserved():
    conn, cur = fresh()
    field.store(cur, memory_id="m-served", content="served",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="agent", reason="doc")
    field.store(cur, memory_id="m-never", content="never served",
                embedding=emb(0.0, 1.0), embedding_model="dev",
                actor_id="agent", reason="doc")
    _, receipt = field.recall(cur, query_embedding=emb(1.0, 0.0), top_k=1)
    field.persist_receipt(cur, receipt)
    conn.commit()
    try:
        causality.record_decision(
            cur, receipt=receipt, used_memory_ids=list(receipt.served) + ["m-never"],
            decision_sha256=causality.decision_hash("x"),
            policy_version="p@1", actor_id="agent", reason="mutant")
    except Exception as exc:                                  # noqa: BLE001
        conn.close()
        return True, f"refused at write: {exc}"
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("a decision cites a counterfactual recall")
def m_decision_counterfactual():
    """A simulation laundered into the causal record."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-1", content="x", embedding=emb(1.0, 0.0),
                embedding_model="dev", actor_id="agent", reason="doc")
    trust.quarantine_memory(cur, memory_id="m-1", actor_id="ir", reason="poison")
    field.store(cur, memory_id="m-2", content="y", embedding=emb(0.9, 0.1),
                embedding_model="dev", actor_id="agent", reason="doc")
    _, cf = field.recall(cur, query_embedding=emb(1.0, 0.0), top_k=2,
                         custody_override={"m-1": "CLEAN"})
    field.persist_receipt(cur, cf)
    conn.commit()
    try:
        causality.record_decision(
            cur, receipt=cf, used_memory_ids=["m-1"],
            decision_sha256=causality.decision_hash("x"),
            policy_version="p@1", actor_id="agent", reason="mutant")
    except Exception as exc:                                  # noqa: BLE001
        conn.close()
        return True, f"refused at write: {exc}"
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("an issuer grants a capability it does not hold")
def m_grant_amplification():
    """Authority invented rather than delegated."""
    conn, cur = fresh()
    with patched(authority, "effective_capabilities",
                 lambda cur_, a, t=None: authority.CAPABILITIES):
        authority.grant(cur, subject_id="agent",
                        capabilities=["QUARANTINE_ACTOR"], issuer_id="ingest",
                        reason="mutant: ingest holds no GRANT")
    field.store(cur, memory_id="m-1", content="x", embedding=emb(1.0, 0.0),
                embedding_model="dev", actor_id="agent", reason="doc")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("the Merkle rule duplicates the odd leaf")
def m_merkle_bitcoin_rule():
    """Bitcoin's rule admits two leaf sets with one root — an ambiguity
    MNEME refuses, so a sealer that adopts it disagrees with every verifier."""
    def bitcoin_root(heads):
        if not heads:
            return hashlib.sha256(b"MNEME_EMPTY_HEADS").hexdigest()
        level = [hashlib.sha256(f"{m}:{h}".encode("utf-8")).hexdigest()
                 for m, h in sorted(heads.items())]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]        # the mutation
            level = [hashlib.sha256((level[i] + level[i + 1]).encode("ascii")
                                    ).hexdigest()
                     for i in range(0, len(level), 2)]
        return level[0]

    conn, cur = fresh()
    for i in range(3):
        field.store(cur, memory_id=f"m-{i}", content=f"c{i}",
                    embedding=emb(1.0, Fraction(i, 10)), embedding_model="dev",
                    actor_id="ingest", reason="doc")
    conn.commit()
    with patched(bundle, "heads_merkle_root", bitcoin_root):
        b = bundle.export_bundle(cur)
    ok, errs = verdict(b)
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("recall traverses a quarantined intermediary")
def m_recall_traverses_tainted():
    """The custody gate applied to serving but not to influence — the Round-1
    finding, reintroduced. No bundle check covers this: it is a property of
    RANKING, so the invariant has to do the killing."""
    conn, cur = fresh()
    # m-far must have a POSITIVE similarity to the query, or its score is
    # clamped to zero and the resonant boost has nothing to move — which
    # is how an earlier version of this mutant looked inert while the bug
    # it models was perfectly real.
    for mid, vec in [("m-seed", (1.0, 0.0)), ("m-mid", (0.6, 0.4)),
                     ("m-far", (0.3, 0.9))]:
        field.store(cur, memory_id=mid, content=mid, embedding=emb(*vec),
                    embedding_model="dev", actor_id="ingest", reason="doc")
    ts = custody.now_ts()
    for a, b_ in (("m-seed", "m-mid"), ("m-mid", "m-far")):
        cur.execute("INSERT INTO cell_links (from_id, to_id, link_type, auto, "
                    "created_at) VALUES (?, ?, 'RESONANT', 0, ?)", (a, b_, ts))
    trust.quarantine_memory(cur, memory_id="m-mid", actor_id="ir",
                            reason="poison on the path")
    conn.commit()

    # The mutation, expressed as the world it produces: m-mid conducts
    # resonance again. The invariant says a non-CLEAN memory must exert
    # ZERO influence on the CLEAN ones, so the comparison is over SCORES,
    # not membership — a resonant boost moves a score long before it
    # moves a top-k set, and checking only membership is how this class
    # of bug survived the first time.
    honest = {h.memory_id: format(h.score, "f")
              for h in field.recall(cur, query_embedding=emb(1.0, 0.0),
                                    top_k=5)[0]}
    mutated = {h.memory_id: format(h.score, "f")
               for h in field.recall(cur, query_embedding=emb(1.0, 0.0),
                                     top_k=5,
                                     custody_override={"m-mid": "CLEAN"})[0]}
    conn.close()
    honest.pop("m-mid", None)
    mutated.pop("m-mid", None)
    if honest != mutated:
        return True, ("invariant: a non-CLEAN memory moved the scores of "
                      f"CLEAN ones ({honest} -> {mutated})")
    return False, "the mutation changed nothing observable"


@mutant("the custody gate is widened by an unauthorized read")
def m_counterfactual_disclosure():
    """
    The hole this project put in itself. `custody_override` can force a
    QUARANTINED memory CLEAN, which makes its CONTENT servable — and
    recall has never required a capability. The mutation removes the
    COUNTERFACTUAL gate; the invariant that catches it is the one the
    whole system rests on: a non-CLEAN memory is invisible to the agent.
    """
    conn, cur = fresh()
    field.store(cur, memory_id="m-secret",
                content="SECRET: the admin password is hunter2",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="ingest", reason="doc")
    trust.quarantine_memory(cur, memory_id="m-secret", actor_id="ir",
                            reason="contains a leaked credential")
    conn.commit()
    try:
        hits, _ = field.recall(cur, query_embedding=emb(1.0, 0.0), top_k=3,
                               custody_override={"m-secret": "CLEAN"})
    except ValueError as exc:
        conn.close()
        return True, f"refused at read: {exc}"
    conn.close()
    leaked = [h.content for h in hits if h.memory_id == "m-secret"]
    if leaked:
        return False, f"withheld content served to an unauthorized caller: {leaked[0][:40]}"
    return True, "the gate held"


@mutant("a field carries two self-issued roots")
def m_second_root():
    """
    B7 counts root grants among the chains a bundle CARRIES, and the
    export used to seed its authority closure from a SINGULAR root — so a
    two-root field shipped only the first, the verifier counted one, and
    the bundle verified clean. A check that cannot see the thing it
    checks is not a check.
    """
    conn, cur = fresh()
    ts = custody.now_ts()
    cur.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
                "VALUES ('root-b','B','HUMAN',?)", (ts,))
    authority.append_authority_event(
        cur, subject_id="root-b", event_type="ACTOR_REGISTERED",
        issuer_id="root-b", reason="a second, racing bootstrap",
        payload={"display_name": "B", "kind": "HUMAN", "root": True},
        created_at=ts)
    authority.append_authority_event(
        cur, subject_id="root-b", event_type="GRANTED", issuer_id="root-b",
        reason="a second, racing bootstrap",
        payload={"grant_id": "grant-b",
                 "capabilities": sorted(authority.CAPABILITIES), "root": True},
        created_at=ts)
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("a hostile exporter omits an authority chain entirely",
        expect="survives")
def m_hostile_export_omission():
    """
    The boundary the previous mutant sits next to, and the reason the two
    are separate entries. Fixing the EXPORT means MNEME's own tooling can
    no longer hide a second root: an honest export of a two-root field now
    fails. It does not mean a hostile exporter cannot omit the chain — and
    a verifier cannot detect the absence of evidence it has no other
    pointer to.

    Exactly the limitation KNOWN_LIMITATIONS already states for sweeps: a
    partial export proves what it carries, never what it omits. The
    full-field export is the only one that proves absence.
    """
    conn, cur = fresh()
    ts = custody.now_ts()
    cur.execute("INSERT INTO actors (actor_id, display_name, kind, created_at) "
                "VALUES ('root-b','B','HUMAN',?)", (ts,))
    for et, payload in (
        ("ACTOR_REGISTERED", {"display_name": "B", "kind": "HUMAN", "root": True}),
        ("GRANTED", {"grant_id": "grant-b",
                     "capabilities": sorted(authority.CAPABILITIES),
                     "root": True}),
    ):
        authority.append_authority_event(
            cur, subject_id="root-b", event_type=et, issuer_id="root-b",
            reason="a second, racing bootstrap", payload=payload, created_at=ts)
    conn.commit()
    b = json.loads(bundle.export_bundle(cur))
    b["body"]["authority"] = [e for e in b["body"]["authority"]
                              if e["subject_id"] != "root-b"]
    b["body"]["authority_merkle_root"] = bundle.heads_merkle_root(
        {e["subject_id"]: e["chain"][-1]["entry_hash"]
         for e in b["body"]["authority"]})
    b["bundle_sha256"] = hashlib.sha256(
        canonical_json(b["body"]).encode("utf-8")).hexdigest()
    ok, errs = verdict(json.dumps(b))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("the model returns a vector it never computed", expect="survives")
def m_model_lies():
    """The declared boundary, demonstrated rather than asserted."""
    conn, cur = fresh()
    text = "Deploys require the staging gate."
    honest_vector = emb(1.0, 0.0, 0.0)
    lying_vector = emb(0.0, 0.0, 1.0)          # what the provider hands back
    prov = field.declare_embedding(provider="acme", model="embed-3",
                                   revision="2026-07-01",
                                   embedding=lying_vector, model_input=text)
    field.store(cur, memory_id="m-1", content=text, embedding=lying_vector,
                embedding_model="acme/embed-3@2026-07-01",
                embedding_provenance=prov, actor_id="ingest", reason="doc")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


@mutant("an attacker fabricates the entire field, coherently",
        expect="survives")
def m_fabricated_field():
    """Every write is the adversary's, every timestamp monotonic and
    canonical, every chain perfect. The field is a complete fiction."""
    conn, cur = fresh()
    field.store(cur, memory_id="m-fake", content="a lie with a perfect chain",
                embedding=emb(1.0, 0.0), embedding_model="dev",
                actor_id="ingest", reason="fabricated by the adversary")
    conn.commit()
    ok, errs = verdict(bundle.export_bundle(cur))
    conn.close()
    return (not ok), (errs[0] if errs else "")


# ------------------------------------------------------------------- run

print("[semantic mutants]")
FAILURES = 0
for name, fn, expect in MUTANTS:
    try:
        killed, detail = fn()
    except Exception as exc:                                  # noqa: BLE001
        killed, detail = True, f"refused at write: {type(exc).__name__}: {exc}"
    if killed:
        KILLED.append(name)
        print(f"  KILLED    {name}")
        print(f"            by: {str(detail)[:120]}")
    else:
        SURVIVED.append(name)
        print(f"  SURVIVED  {name}")

print("\n[verdict]")
undeclared = [n for n in SURVIVED if n not in DECLARED_SURVIVORS]
unexpected_kills = [n for n, _, e in MUTANTS
                    if e == "survives" and n in KILLED]
killable = [n for n, _, e in MUTANTS if e == "killed"]
killed_killable = [n for n in killable if n in KILLED]

print(f"  semantic mutants killed: {len(killed_killable)}/{len(killable)}")
print(f"  declared survivors:      {len(SURVIVED)} "
      f"(boundaries MNEME never claimed to cover)")
for n in SURVIVED:
    if n in DECLARED_SURVIVORS:
        print(f"    - {n}")
        print(f"      {DECLARED_SURVIVORS[n]}")

for n in undeclared:
    print(f"FAIL  UNDECLARED SURVIVOR: {n}")
    print("      Either close the gap or declare the boundary. A metric that "
          "improves by lowering its standards is not a metric.")
    FAILURES += 1
for n in unexpected_kills:
    print(f"FAIL  a declared survivor was KILLED: {n}")
    print("      Good news, but the declaration is now false. Move it.")
    FAILURES += 1
for n in killable:
    if n not in KILLED:
        FAILURES += 1

print(f"\n{len(KILLED)} killed, {len(SURVIVED)} survived, {FAILURES} failed")
sys.exit(1 if FAILURES else 0)
