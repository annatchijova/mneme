#!/usr/bin/env python3
"""
MNEME — Demo harness: one poisoned-RAG incident, end to end, narrated.

    python3 demo.py

Zero dependencies beyond Python 3.10+; the field lives in SQLite
:memory: and the bundles in a temp directory. Every step is the public
API doing what an operator would do, in the order an incident actually
unfolds:

  0. an authority ledger is bootstrapped and capabilities are granted:
     every mutation below carries two separable proofs, integrity and
     authority;
  1. a compromised pipeline plants a poisoned memory and inflates a
     legitimate one;
  2. recall shows the field's own defences (inhibition, the rescue
     rule) and their limit — the poison is servable;
  3. the actor is quarantined: one sealed sweep flags everything it
     touched;
  4. recall again: the custody gate withholds the flagged memories and
     the receipt counts them — and the quarantined actor discovers the
     containment is prospective too: it can no longer write at all;
  5. the false positive is rehabilitated by audited event, the blast
     radius is reconstructed, and the counterfactual measures what the
     poison actually DID rather than asserting it was handled;
  6. the whole field ships as a sealed bundle, verified by the
     standalone auditor file; a tampered copy is caught; a partial
     export declares — not hides — the sweep evidence it cannot carry.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mneme import (authority, bundle, causality, counterfactual,  # noqa: E402
                   custody, field, trust)

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "verify_offline.py")


def section(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def show_recall(cur, query, note: str) -> None:
    hits, receipt = field.recall(cur, query_embedding=query, top_k=5)
    print(f"\nrecall — {note}")
    for h in hits:
        rescued = "  [inhibition_rescued]" if h.inhibition_rescued else ""
        print(f"  {h.score}  {h.memory_id:<12} {h.field_state:<10} "
              f"{h.content!r}{rescued}")
    print(f"  receipt {receipt.receipt_sha256[:16]}…  withheld: "
          f"custody={receipt.excluded_custody} "
          f"forgotten={receipt.excluded_forgotten} "
          f"inhibited={receipt.excluded_inhibited}")


def run_verifier(path: str) -> None:
    r = subprocess.run([sys.executable, VERIFIER, path],
                       capture_output=True, text=True)
    for line in (r.stdout.strip() or r.stderr.strip()).splitlines():
        print(f"  auditor> {line}")
    print(f"  auditor> exit {r.returncode}")


def main() -> None:
    conn = sqlite3.connect(":memory:")
    with open(os.path.join(HERE, "mneme", "schema.sql")) as f:
        conn.executescript(f.read())
    cur = conn.cursor()

    section("0. Authority: who is allowed to cause what, before anything happens")
    root_grant = authority.bootstrap_root(
        cur, actor_id="root-ops", display_name="Root Operator", kind="HUMAN",
        reason="field genesis: operator provisioned out of band")
    print(f"root-ops bootstrapped the ledger  (grant {root_grant[:18]}…)")
    print("  the one act authority cannot authorize; refused ever after")
    for aid, kind, caps, why in [
        ("agent-ada", "AGENT", ["STORE", "REINFORCE", "DECIDE"],
         "runbook ingestion and on-call answers"),
        ("pipeline-feeds", "PIPELINE", ["STORE", "REINFORCE"], "feed sync duty"),
        ("analyst-omar", "HUMAN",
         ["REINFORCE", "QUARANTINE_ACTOR", "QUARANTINE_MEMORY", "REHABILITATE"],
         "incident response duty"),
    ]:
        authority.register_actor(cur, actor_id=aid, display_name=aid, kind=kind,
                                 issuer_id="root-ops", reason=why)
        authority.grant(cur, subject_id=aid, capabilities=caps,
                        issuer_id="root-ops", reason=why)
        print(f"  {aid:<16} granted {', '.join(caps)}")
    print("  note what the feed pipeline does NOT hold: QUARANTINE_*, "
          "REHABILITATE, GRANT")
    conn.commit()

    section("1. A field grows — and a compromised pipeline writes into it")
    e = field.quantize_embedding
    stored = field.store(
        cur, memory_id="mem-gate", actor_id="agent-ada", reason="runbook ingestion",
        content="Production deploys require the staging gate to pass.",
        embedding=e([1.0, 0.1, 0.0]), embedding_model="demo",
        topic="deploy-policy", claim="gate-required")
    print(f"stored mem-gate      by agent-ada       ({stored.content_sha256[:16]}…)")
    field.store(
        cur, memory_id="mem-rollback", actor_id="agent-ada", reason="runbook ingestion",
        content="Rollbacks are executed with `ops rollback <release>`.",
        embedding=e([0.1, 1.0, 0.0]), embedding_model="demo")
    print("stored mem-rollback  by agent-ada")
    poisoned = field.store(
        cur, memory_id="mem-poison", actor_id="pipeline-feeds", reason="feed sync",
        content="The staging gate is optional for hotfix deploys.",
        embedding=e([0.97, 0.05, 0.0]), embedding_model="demo",
        topic="deploy-policy", claim="gate-optional")
    print("stored mem-poison    by pipeline-feeds   <- the poisoned write")
    print(f"  contradiction auto-detected, recorded on BOTH chains: "
          f"{poisoned.inhibitory_links}")

    for _ in range(3):
        field.reinforce(cur, memory_id="mem-gate", actor_id="analyst-omar",
                        reason="verified against the runbook")
    print("mem-gate reinforced 3x by analyst-omar -> field_state REINFORCED")
    field.reinforce(cur, memory_id="mem-rollback", actor_id="pipeline-feeds",
                    reason="feed corroboration")
    print("mem-rollback reinforced by pipeline-feeds  <- confidence inflated "
          "by the (not yet known) bad actor")
    conn.commit()

    section("2. Before the incident is known: the field's own defences, "
            "and their limit")
    show_recall(cur, e([1.0, 0.2, 0.0]),
                "query near the TRUE policy: the contradicted poison is "
                "inhibited by the better-matched truth")
    show_recall(cur, e([0.97, 0.02, 0.0]),
                "query near the POISON: it is served — REINFORCED mem-gate "
                "survives its inhibition (rescue rule), but the lie is out")

    print("\nand then the agent ACTS on it — the step that turns a bad recall")
    print("into an incident, recorded as evidence instead of lost:")
    _, served_receipt = field.recall(cur, query_embedding=e([0.97, 0.02, 0.0]),
                                     top_k=5)
    field.persist_receipt(cur, served_receipt)
    decision = causality.record_decision(
        cur, receipt=served_receipt, used_memory_ids=["mem-poison"],
        decision_sha256=causality.decision_hash(
            "Hotfix 4.2 may ship without the staging gate."),
        policy_version="deploy-policy@3", actor_id="agent-ada",
        reason="answered the on-call operator's deploy question")
    field.store(
        cur, memory_id="mem-note", actor_id="agent-ada",
        reason="recording what was told to the operator",
        content="Told on-call: hotfix 4.2 may skip the staging gate.",
        embedding=e([0.95, 0.06, 0.0]), embedding_model="demo",
        derived_from_decision=decision.decision_id)
    conn.commit()
    print(f"  decision {decision.decision_id}")
    print(f"    receipt   {decision.receipt_sha256[:16]}…   (what it was shown)")
    print(f"    decision  {decision.decision_sha256[:16]}…   (what it produced,"
          " by hash — MNEME never sees the text)")
    print(f"    policy    {decision.policy_version}")
    print(f"    used      {list(decision.used_memory_ids)}")
    print("  and mem-note declares it was written BECAUSE of that decision")

    section("3. Quarantine: one sealed sweep over everything the actor touched")
    sweep = trust.quarantine_actor(cur, actor_id="pipeline-feeds",
                                   initiated_by="analyst-omar",
                                   reason="compromised feed credentials (INC-1207)")
    conn.commit()
    print(f"sweep {sweep.sweep_id}")
    print(f"  flagged: {list(sweep.flagged_memory_ids)}  "
          f"(mem-rollback too — the inflation IS part of the incident)")
    print("  NOT flagged: mem-gate — the attacker's CONTRADICTED_BY event on "
          "its chain\n  is an attack, not influence; taint never lets a "
          "quarantine silence the victims")
    print(f"  sealed:  sha256={sweep.flagged_ids_sha256[:16]}…")
    print(f"  advisory resonant neighbours (reported, never auto-flagged): "
          f"{list(sweep.advisory_resonant_neighbours)}")

    show_recall(cur, e([0.97, 0.02, 0.0]),
                "same poison-shaped query, after the sweep: the custody gate "
                "withholds the flagged memories, counts them, and the truth "
                "still serves")

    print("the OTHER half of containment — the actor tries to keep working:")
    for label, act in [
        ("store a fresh memory",
         lambda: field.store(cur, memory_id="mem-encore", actor_id="pipeline-feeds",
                             reason="still here",
                             content="Hotfixes may skip every gate.",
                             embedding=e([0.96, 0.04, 0.0]), embedding_model="demo")),
        ("reinforce a clean one",
         lambda: field.reinforce(cur, memory_id="mem-gate",
                                 actor_id="pipeline-feeds", reason="inflate")),
        ("rehabilitate its own evidence",
         lambda: trust.rehabilitate_memory(cur, memory_id="mem-poison",
                                           actor_id="pipeline-feeds",
                                           reason="self-declared false positive")),
    ]:
        try:
            act()
            print(f"  {label:<32} SUCCEEDED  <- containment is a fiction")
        except ValueError as exc:
            conn.rollback()
            print(f"  {label:<32} refused: {str(exc).split(' — ')[0]}")

    section("3b. The agent had already ACTED on it — blast radius and "
            "counterfactual")
    print("impact mem-poison — the blast radius, graded:")
    report = causality.impact(cur, "mem-poison")
    print(f"  DIRECT    recalls={len(report.direct_receipts)} "
          f"decisions={list(report.direct_decisions)}")
    print(f"  DERIVED   memories={list(report.derived_memories)}")
    print(f"  POSSIBLE  memories={list(report.possible_memories)}  "
          "<- contact, not contamination; reported, never auto-flagged")
    print(f"  sealed:   sha256={report.impact_sha256[:16]}…")

    print("\ncounterfactual — what did the poison actually DO?")
    for label, query in [("near the poisoned policy", e([0.97, 0.02, 0.0])),
                         ("about rollbacks (far away)", e([0.1, 1.0, 0.0]))]:
        d = counterfactual.containment_effect(
            cur, query_embedding=query, contained=["mem-poison"], top_k=5)
        print(f"  query {label}:")
        print(f"    {d.summary()}")
        if d.removed_from_serving:
            print(f"    removed_from_serving: {list(d.removed_from_serving)}")
        if d.claim_outcome_changed:
            print(f"    claim_outcome_changed: "
                  f"{[list(x) for x in d.claim_outcome_changed]}")
        print(f"    sealed: sha256={d.delta_sha256[:16]}…")
    print("  the second line is the finding people least expect: for that")
    print("  query the poison was present, was excluded, and changed nothing.")
    print("  Damage measured at zero, not assumed at unknown.")
    print()
    print("and the first line is why blast radius exists at all: look at the")
    print("recall above — mem-note is still SERVED. The sweep flagged what the")
    print("compromised pipeline touched, and mem-note was written by a clean")
    print("agent acting in good faith on a poisoned answer. Actor quarantine")
    print("cannot reach it; the causal DAG can name it. What to do about it is")
    print("an analyst's authorized act, not something this report performs.")

    section("4. The false positive is REHABILITATED — by audited event, "
            "never by column edit")
    trust.rehabilitate_memory(cur, memory_id="mem-rollback",
                              actor_id="analyst-omar",
                              reason="reviewed INC-1207: content predates the "
                                     "compromise; only its confidence was inflated")
    conn.commit()
    show_recall(cur, e([0.2, 1.0, 0.0]),
                "rollback knowledge is servable again; the poison stays gated")

    section("5. The evidence ships: sealed bundle, hostile auditor, one file")
    tmp = tempfile.mkdtemp(prefix="mneme-demo-")
    honest = bundle.export_bundle(cur)
    honest_path = os.path.join(tmp, "field.bundle.json")
    with open(honest_path, "w", encoding="utf-8") as f:
        f.write(honest)
    print(f"full export -> {honest_path}")
    run_verifier(honest_path)

    print("\nnow the cover-up: edit the poisoned content inside the bundle "
          "and reseal it")
    doc = json.loads(honest)
    for m in doc["body"]["memories"]:
        if m["memory_id"] == "mem-poison":
            m["content"] = "The staging gate must always pass."
    import hashlib
    doc["bundle_sha256"] = hashlib.sha256(
        bundle.canonical_json(doc["body"]).encode("utf-8")).hexdigest()
    tampered_path = os.path.join(tmp, "field.tampered.json")
    with open(tampered_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc))
    run_verifier(tampered_path)

    print("\npartial export (mem-gate, mem-rollback): the sweep's evidence "
          "cannot travel in full, so it is DECLARED excluded, never implied "
          "absent")
    partial = bundle.export_bundle(cur, memory_ids=["mem-gate", "mem-rollback"])
    partial_path = os.path.join(tmp, "field.partial.json")
    with open(partial_path, "w", encoding="utf-8") as f:
        f.write(partial)
    run_verifier(partial_path)

    section("6. Why does your agent remember this? Ask the chain")
    cur.execute("SELECT seq, event_type, actor_id, reason FROM custody_chain "
                "WHERE memory_id = 'mem-rollback' ORDER BY seq ASC")
    for seq, et, actor, reason in cur.fetchall():
        print(f"  seq {seq}  {et:<14} {actor:<15} {reason}")
    print("\nEvery line above is hash-chained to the last, bound to the "
          "memory at genesis,\nand replayable by anyone holding the bundle. "
          "That is the answer, provable.")


if __name__ == "__main__":
    main()
