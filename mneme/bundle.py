"""
MNEME — Evidence bundles: export, seal, verify. PHYLO's EBS pattern
applied to memory: everything an auditor needs travels in ONE canonical
JSON file, verifiable offline, with zero dependencies beyond a Python
interpreter.

A bundle contains, for each exported memory: content, its declared
final state (custody_status, field_state, confidence), and the FULL
custody chain. Plus every taint sweep, a Merkle root over all chain
heads, and a bundle seal.

What verification proves (implemented twice ON PURPOSE — here, using
the package, and in verify_offline.py, standalone stdlib-only; the two
are held together by tests/test_bundle_pure.py's agreement section,
which runs both against the same valid and tampered bundles and demands
identical verdicts. Two implementations that must agree, and a test
that makes disagreement loud):

  B1  bundle_sha256 recomputes over the canonical body.
  B2  every custody chain verifies: genesis bound to its memory_id,
      dense seq, linkage, entry hashes recompute, closed vocabulary,
      payloads stored in canonical form, and created_at values that are
      canonical UTC form and non-decreasing along seq (a hash-valid
      chain that runs backwards in time is a history that cannot have
      happened).
  B3  content integrity: sha256(content) equals the content_sha256
      sealed in the STORED event — the content shipped is the content
      born.
  B4  STATE IS DERIVABLE FROM EVIDENCE: replaying the chain's events
      through the documented state machine reproduces the declared
      custody_status, field_state and confidence. A hand-edited status
      column without its corresponding event is self-revealing.
      Supersession lineage is bilateral, like contradiction: when both
      parties travel in the bundle, a STORED payload naming
      "supersedes": X requires a SUPERSEDED_BY event on X's chain
      naming this memory back, and vice versa. (With one party absent
      — a partial export — the cross-check has nothing to compare and
      is skipped; each chain still verifies alone.)
  B5  sweep evidence — absence stated, never implied. The body
      partitions sweep rows into "sweeps" (flagged evidence carried in
      full) and "excluded_sweeps" (evidence declared absent: a partial
      export that does not carry every memory the sweep flagged).
      Rules, in order:
        1. no sweep_id may appear in both lists — ambiguity refused;
        2. every included sweep's flagged set (TAINT_FLAGGED events
           carrying its sweep_id) matches its count and hashes to its
           seal;
        3. an excluded sweep must be genuinely partial: the bundle
           must carry strictly fewer distinct flagged memories for it
           than its flagged_count — excluding a fully-evidenced sweep
           would dodge its seal check;
        4. every sweep_id referenced by a TAINT_FLAGGED event in the
           bundle must appear in one of the two lists.
      An excluded sweep's seal is NOT checked (its evidence lives
      outside this bundle); exclusion is a declared claim the auditor
      can see, not a verified one. A bundle without the
      "excluded_sweeps" key reads as excluding nothing.
  B6  the Merkle root over chain heads recomputes (leaves sorted by
      memory_id ASC; odd leaf promoted unpaired — duplicating the last
      leaf, Bitcoin-style, admits two leaf sets with one root, an
      ambiguity we refuse; same rule as STIGMERGY's ledger).
  B7  AUTHORITY PROVENANCE: every custody event was not merely recorded
      but AUTHORIZED. Integrity provenance (B2) and authority provenance
      (B7) are separable proofs over different evidence, and a bundle
      must carry both. In order:
        1. every authority chain verifies structurally (genesis bound to
           the actor id, dense seq, linkage, recomputation, canonical
           payload bytes, canonical non-decreasing UTC) and replays
           without contradiction;
        2. the declared actor status reproduces from that replay — the
           authority analogue of B4;
        3. the ledger has exactly one root grant, self-issued, conferring
           the whole capability vocabulary;
        4. NO AMPLIFICATION, re-derived offline: every non-root authority
           event names an issuer whose own chain travels in the bundle
           and who held, at that event's instant, the capability the
           event required — and, for a GRANT, every capability it
           conferred. Authority is delegated, never invented;
        5. every custody event at or after the declared authority genesis
           names a grant_id that was active for its actor at that
           event's instant, conferred the capability the event type
           requires, and belonged to an actor not under quarantine then;
        6. events BEFORE the declared genesis are UNAUTHORIZED BY
           DECLARATION — counted, named on a successful verdict, never
           silently passed as authorized. A field with no authority
           ledger at all declares authority_genesis_at: null and every
           one of its events is in this category. Absence stated, never
           implied — the same contract B5 holds sweeps to.
      The declared genesis must equal the earliest instant in the carried
      authority evidence, so an exporter cannot raise it to excuse more
      events than the ledger actually predates.
  B8  CAUSAL PROVENANCE: recall -> decision, closed and bilateral. A
      receipt proves what an agent was shown; a decision record proves
      what it did with it. In order:
        1. every carried receipt's digest recomputes from its own
           columns, and its ranking_protocol matches the one the bundle
           declares — a receipt produced under other ranking semantics is
           not comparable evidence, it is a category error;
        2. no decision_id appears in both "decisions" and
           "excluded_decisions";
        3. every decision (in either list) re-derives its record seal,
           cites a receipt carried here, and claims only memories that
           receipt actually SERVED — a decision naming a memory the
           recall never handed it is refused;
        4. an included decision's used memories all travel here, and each
           one's custody chain carries a DECISION_USED_MEMORY event
           naming that decision back. Bilateral, like contradiction and
           lineage: neither side can hide the causal link alone;
        5. an excluded decision must be genuinely partial — at least one
           used memory absent — so exclusion cannot dodge check 4;
        6. every decision_id referenced by a DECISION_USED_MEMORY event
           appears in one of the two lists, and that event's memory
           appears in that decision's used list.

Replay state machine (B4), the single normative statement — the
standalone verifier transcribes it verbatim:

  custody_status: starts CLEAN at STORED.
      QUARANTINED      -> QUARANTINED
      SUPERSEDED_BY    -> SUPERSEDED
      TAINT_FLAGGED    -> TAINT_FLAGGED only if currently CLEAN
                          (stronger statuses are retained; the event
                          still exists — the chain records that the
                          sweep saw the memory)
      REHABILITATED    -> CLEAN, valid only from TAINT_FLAGGED
  field_state: starts NEUTRAL; STATE_CHANGED applies payload["to"] and
      its payload["from"] must equal the current state.
  confidence: starts 0.5000000000; each REINFORCED must declare
      confidence_before equal to current, and sets confidence_after.

Authority replay (B7) has its own normative statement, in
authority.replay_authority's docstring, for the same reason: one place
where the rule is written down, transcribed verbatim by the standalone
verifier.

FORMAT V2 AND WHY THE VERSION MOVED. A V1 bundle sealed bytes without
sealing the SEMANTICS those bytes were checked under, which left exactly
one lie available: change a rule tomorrow, and every bundle sealed today
silently acquires the new rule when a new verifier reads it. A V2 body
carries a "protocols" block naming, by version, every semantics its
checks depend on (see protocol.py), and a verifier that meets a version
it does not implement refuses rather than assuming. V1 bundles are not
readable by this verifier and that is the point — they were sealed under
undeclared semantics, so verify them with a verifier of their era.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .canonical import canonical_json
from . import authority, causality, custody, field as _field, protocol

BUNDLE_FORMAT = "MNEME_BUNDLE_V2"
INITIAL_CONFIDENCE = "0.5000000000"


# ---------------------------------------------------------------------------
# Merkle over chain heads (STIGMERGY's rule: odd leaf promoted unpaired)
# ---------------------------------------------------------------------------

def heads_merkle_root(heads: dict[str, str]) -> str:
    if not heads:
        return hashlib.sha256(b"MNEME_EMPTY_HEADS").hexdigest()
    level = [
        hashlib.sha256(f"{mid}:{h}".encode("utf-8")).hexdigest()
        for mid, h in sorted(heads.items())
    ]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(
                (level[i] + level[i + 1]).encode("ascii")).hexdigest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promoted unpaired, never duplicated
        level = nxt
    return level[0]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

_CHAIN_COLS = ["memory_id", "seq", "event_type", "actor_id", "reason",
               "created_at", "payload_json", "prev_hash", "entry_hash"]


def _authority_closure(cur, seed_actors: set[str]) -> list[str]:
    """
    Every authority chain the bundle must carry to make B7 checkable, as a
    sorted list.

    Seeded with the actors that wrote the exported custody events, then
    closed under ISSUANCE: an actor's chain is worthless to an auditor
    without the chain of whoever empowered it, and that one without ITS
    issuer, up to the root. No-amplification (A3) is only re-derivable
    offline if the whole delegation path travels. The closure terminates
    because issuance is acyclic by construction — the root is self-issued
    on an empty ledger and every other issuer predates its subject's
    grant.
    """
    seen: set[str] = set()
    frontier = set(seed_actors)
    while frontier:
        sid = min(frontier)
        frontier.discard(sid)
        if sid in seen:
            continue
        seen.add(sid)
        cur.execute(
            "SELECT issuer_id FROM authority_chain WHERE subject_id = ?", (sid,))
        for (issuer,) in cur.fetchall():
            if issuer not in seen:
                frontier.add(issuer)
    return sorted(seen)


def export_bundle(cur, *, memory_ids: list[str] | None = None) -> str:
    """
    Export a sealed evidence bundle as a canonical JSON string.
    memory_ids=None exports the whole field. The bundle is self-
    contained: nothing in it requires the database to interpret.
    """
    if memory_ids is None:
        cur.execute("SELECT memory_id FROM memories ORDER BY memory_id ASC")
        memory_ids = [r[0] for r in cur.fetchall()]
    else:
        memory_ids = sorted(set(memory_ids))

    memories: list[dict[str, Any]] = []
    heads: dict[str, str] = {}
    for mid in memory_ids:
        cur.execute(
            "SELECT content, content_sha256, custody_status, field_state, "
            "confidence FROM memories WHERE memory_id = ?", (mid,))
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"Unknown memory {mid!r} — a bundle does not invent evidence.")
        content, csha, status, fstate, conf = row
        cur.execute(
            "SELECT memory_id, seq, event_type, actor_id, reason, created_at, "
            "payload_json, prev_hash, entry_hash FROM custody_chain "
            "WHERE memory_id = ? ORDER BY seq ASC", (mid,))
        chain = [dict(zip(_CHAIN_COLS, r)) for r in cur.fetchall()]
        if not chain:
            raise ValueError(f"{mid} has no custody chain — refusing to export a memory without a birth.")
        heads[mid] = chain[-1]["entry_hash"]
        memories.append({
            "memory_id": mid,
            "content": content,
            "content_sha256": csha,
            "custody_status": status,
            "field_state": fstate,
            "confidence": conf,
            "custody": chain,
        })

    cur.execute(
        "SELECT sweep_id, quarantined_actor, initiated_by, reason, created_at, "
        "flagged_count, flagged_ids_sha256 FROM taint_sweeps ORDER BY sweep_id ASC")
    all_sweeps = [dict(zip(["sweep_id", "quarantined_actor", "initiated_by",
                            "reason", "created_at", "flagged_count",
                            "flagged_ids_sha256"], r)) for r in cur.fetchall()]

    # Partition (B5): a sweep travels in "sweeps" only if this bundle
    # carries its ENTIRE flagged set, so its seal is checkable; any other
    # sweep is DECLARED in "excluded_sweeps" — absence stated, never
    # implied. The flagged set is re-derived from custody evidence here,
    # not trusted from the sweep row: a tampered row lands in "sweeps"
    # and fails its seal check instead of hiding behind an exclusion.
    cur.execute("SELECT memory_id, payload_json FROM custody_chain "
                "WHERE event_type = 'TAINT_FLAGGED'")
    flagged_by_sweep: dict[str, set[str]] = {}
    for mid, pj in cur.fetchall():
        sid = json.loads(pj).get("sweep_id")
        if isinstance(sid, str):
            flagged_by_sweep.setdefault(sid, set()).add(mid)
    exported = set(memory_ids)
    sweeps = [s for s in all_sweeps
              if flagged_by_sweep.get(s["sweep_id"], set()) <= exported]
    excluded_sweeps = [s for s in all_sweeps if s not in sweeps]

    # Authority evidence (B7). Always exported — an authority chain is a
    # few rows and an unauthorized-looking bundle that merely omitted the
    # proof is the worst of both outcomes.
    actors_in_evidence: set[str] = set()
    for mem in memories:
        for r in mem["custody"]:
            actors_in_evidence.add(r["actor_id"])
    # The root always travels, even when no exported memory's actor leads
    # to it. Without it a bundle could declare an authority genesis whose
    # evidence it does not carry — a claim about a ledger nobody can see —
    # and the earliest-instant check (B7) would have nothing to compare.
    root = authority.root_subject(cur)
    if root is not None:
        actors_in_evidence.add(root)
    authority_rows: list[dict[str, Any]] = []
    auth_heads: dict[str, str] = {}
    for sid in _authority_closure(cur, actors_in_evidence):
        chain = authority.load_authority_rows(cur, sid)
        if not chain:
            continue   # a legacy actor with no ledger presence; B7 names it
        cur.execute("SELECT status FROM actors WHERE actor_id = ?", (sid,))
        row = cur.fetchone()
        auth_heads[sid] = chain[-1]["entry_hash"]
        authority_rows.append({
            "subject_id": sid,
            "status": row[0] if row else "ACTIVE",
            "chain": chain,
        })

    # Causal evidence (B8). A decision travels in "decisions" only when the
    # bundle carries EVERY memory it claims to have used, so its bilateral
    # custody evidence is checkable; any other decision is DECLARED in
    # "excluded_decisions" — absence stated, never implied, the same
    # contract B5 holds sweeps to. Receipts cited by either list always
    # travel: a decision citing a receipt nobody can read is a causal claim
    # with no anchor.
    all_decisions = causality.load_decision_rows(cur)
    exported_ids = set(memory_ids)
    decisions, excluded_decisions = [], []
    for d in all_decisions:
        used = set(json.loads(d["used_json"])["used"])
        (decisions if used <= exported_ids else excluded_decisions).append(d)
    cited = sorted({d["receipt_sha256"] for d in all_decisions})
    receipts = {r["receipt_sha256"]: r for r in _field.load_receipt_rows(cur, cited)}
    for r in _field.load_receipt_rows(cur):
        if set(json.loads(r["served_json"])["served"]) <= exported_ids:
            receipts[r["receipt_sha256"]] = r

    body = {
        "format": BUNDLE_FORMAT,
        "protocols": dict(protocol.CURRENT_PROTOCOLS),
        "created_at": custody.now_ts(),
        "memories": memories,
        "sweeps": sweeps,
        "excluded_sweeps": excluded_sweeps,
        "receipts": [receipts[k] for k in sorted(receipts)],
        "decisions": decisions,
        "excluded_decisions": excluded_decisions,
        "authority": authority_rows,
        "authority_genesis_at": authority.genesis_at(cur),
        "authority_merkle_root": heads_merkle_root(auth_heads),
        "heads_merkle_root": heads_merkle_root(heads),
    }
    body_canonical = canonical_json(body)
    seal = hashlib.sha256(body_canonical.encode("utf-8")).hexdigest()
    return canonical_json({"body": body, "bundle_sha256": seal})


# ---------------------------------------------------------------------------
# Verification (package side; the state-machine replay is shared logic)
# ---------------------------------------------------------------------------

def replay_state(chain: list[dict[str, Any]]) -> tuple[str, str, str, list[str]]:
    """
    Replay a verified chain's events through the normative state machine
    (module header). Returns (custody_status, field_state, confidence,
    errors). Pure; the standalone verifier transcribes this function.
    """
    errors: list[str] = []
    status, fstate, conf = "CLEAN", "NEUTRAL", INITIAL_CONFIDENCE
    for r in chain:
        et = r["event_type"]
        where = f"{r['memory_id']} seq {r['seq']}"
        payload = json.loads(r["payload_json"])
        if et == "QUARANTINED":
            status = "QUARANTINED"
        elif et == "SUPERSEDED_BY":
            status = "SUPERSEDED"
        elif et == "TAINT_FLAGGED":
            if status == "CLEAN":
                status = "TAINT_FLAGGED"
        elif et == "REHABILITATED":
            if status != "TAINT_FLAGGED":
                errors.append(f"{where}: REHABILITATED from {status}, "
                              "valid only from TAINT_FLAGGED.")
            status = "CLEAN"
        elif et == "STATE_CHANGED":
            if payload.get("from") != fstate:
                errors.append(f"{where}: STATE_CHANGED claims from="
                              f"{payload.get('from')!r} but replay says {fstate!r}.")
            to = payload.get("to")
            if to not in ("REINFORCED", "NEUTRAL", "FORGOTTEN"):
                errors.append(f"{where}: STATE_CHANGED to unknown state {to!r}.")
            else:
                fstate = to
        elif et == "REINFORCED":
            before = payload.get("confidence_before")
            after = payload.get("confidence_after")
            if before != conf:
                errors.append(f"{where}: REINFORCED claims before={before!r} "
                              f"but replay says {conf!r}.")
            if not isinstance(after, str):
                errors.append(f"{where}: REINFORCED without confidence_after.")
            else:
                conf = after
    return status, fstate, conf, errors


def verify_authority(
    body: dict[str, Any],
    memory_chains: list[tuple[str, list[dict[str, Any]]]],
) -> tuple[list[str], list[str]]:
    """
    B7 — authority provenance. Returns (errors, notes); notes are claims an
    auditor must SEE on a PASSING verdict, not things buried by one.

    Pure over the bundle body and the memory chains that already passed
    B2 (an event whose integrity is unproven is not worth authorizing).
    The standalone verifier transcribes this function.
    """
    errors: list[str] = []
    notes: list[str] = []

    entries = body.get("authority", [])
    declared_genesis = body.get("authority_genesis_at")
    if not isinstance(entries, list):
        return ["B7: 'authority' is not a list."], notes

    all_events = [(mid, r) for mid, chain in memory_chains for r in chain]
    with_grant = [(mid, r) for mid, r in all_events
                  if isinstance(json.loads(r["payload_json"]).get("grant_id"), str)]

    # --- The no-ledger regime: stated, never assumed.
    if not entries:
        if declared_genesis is not None:
            errors.append(
                "B7: the bundle declares an authority genesis but carries no "
                "authority evidence — a claim about a ledger nobody can see.")
        for mid, r in with_grant:
            errors.append(
                f"B7: {mid} seq {r['seq']}: names a grant_id, but the bundle "
                "carries no authority chain that could have issued it.")
        if heads_merkle_root({}) != body.get("authority_merkle_root"):
            errors.append("B7: authority_merkle_root does not recompute.")
        if not errors:
            notes.append(
                f"this field has NO authority ledger: all {len(all_events)} "
                "custody event(s) are UNAUTHORIZED BY DECLARATION. Their "
                "integrity is proven; nobody's permission to cause them is.")
        return errors, notes

    if not isinstance(declared_genesis, str):
        return (["B7: the bundle carries authority evidence but declares no "
                 "authority_genesis_at — without it, 'this event predates the "
                 "ledger' is indistinguishable from 'this event dodged it'."],
                notes)

    # --- 1/2. Structure, then meaning, then the declared status column.
    states: dict[str, authority.AuthorityState] = {}
    auth_heads: dict[str, str] = {}
    earliest: str | None = None
    for entry in sorted(entries, key=lambda e: str(e.get("subject_id"))):
        sid = entry.get("subject_id")
        chain = entry.get("chain")
        if not isinstance(sid, str) or not isinstance(chain, list) or not chain:
            errors.append(f"B7: malformed authority entry for {sid!r}.")
            continue
        try:
            ok, errs = authority.verify_authority_rows(sid, chain)
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(f"B7: {sid}: authority chain is unreadable ({exc}).")
            continue
        if not ok:
            errors.extend(f"B7: {e}" for e in errs)
            continue
        state, rerrs = authority.replay_authority(sid, chain)
        if rerrs:
            errors.extend(f"B7: {e}" for e in rerrs)
            continue
        states[sid] = state
        auth_heads[sid] = chain[-1]["entry_hash"]
        first_ts = chain[0]["created_at"]
        if earliest is None or first_ts < earliest:
            earliest = first_ts
        if entry.get("status") != state.status:
            errors.append(
                f"B7: {sid}: declared actor status {entry.get('status')!r}, "
                f"authority replay says {state.status!r}.")

    if heads_merkle_root(auth_heads) != body.get("authority_merkle_root"):
        errors.append("B7: authority_merkle_root does not recompute.")
    if earliest is not None and declared_genesis != earliest:
        errors.append(
            f"B7: declared authority_genesis_at {declared_genesis} is not the "
            f"earliest instant in the carried ledger ({earliest}) — raising it "
            "would excuse events the ledger did not actually predate.")
    if errors:
        return errors, notes

    # --- 3. Exactly one root, self-issued, conferring everything.
    roots = sorted(sid for sid, st in states.items() if st.is_root)
    if len(roots) != 1:
        errors.append(
            f"B7: the ledger declares {len(roots)} root grants ({roots}); "
            "authority hangs from exactly one auditable act or it hangs from "
            "nothing checkable.")

    # --- 4. No amplification (A3), re-derived offline.
    for sid in sorted(states):
        state = states[sid]
        for r in next(e["chain"] for e in entries if e.get("subject_id") == sid):
            payload = json.loads(r["payload_json"])
            issuer = r["issuer_id"]
            at = r["created_at"]
            where = f"B7: {sid} authority seq {r['seq']}"
            if issuer == sid and payload.get("root") is True:
                continue                      # the bootstrap, exempt by design
            if issuer not in states:
                errors.append(
                    f"{where}: issued by {issuer!r}, whose authority chain is "
                    "not in this bundle — the delegation path is unprovable.")
                continue
            needed = authority.AUTHORITY_EVENT_CAPABILITY[r["event_type"]]
            issuer_caps = authority.capabilities_at(states[issuer], at)
            if needed not in issuer_caps:
                errors.append(
                    f"{where}: issuer {issuer!r} did not hold {needed} at {at} "
                    "(never granted, revoked by then, or quarantined).")
                continue
            if r["event_type"] == "GRANTED":
                conferred = set(payload.get("capabilities", []))
                missing = sorted(conferred - issuer_caps)
                if missing:
                    errors.append(
                        f"{where}: issuer {issuer!r} conferred {missing} it did "
                        "not hold — authority invented, not delegated (A3).")

    # --- 5/6. Every custody event: authorized, or declared pre-authority.
    pre_authority = 0
    for mid, r in all_events:
        payload = json.loads(r["payload_json"])
        gid = payload.get("grant_id")
        at = r["created_at"]
        where = f"B7: {mid} seq {r['seq']} ({r['event_type']})"
        if at < declared_genesis:
            pre_authority += 1
            if isinstance(gid, str):
                errors.append(
                    f"{where}: names grant {gid!r} but is timestamped before "
                    "the ledger existed.")
            continue
        if not isinstance(gid, str):
            errors.append(
                f"{where}: no grant_id, and it postdates the authority genesis "
                f"{declared_genesis}. Recorded is not authorized.")
            continue
        actor = r["actor_id"]
        if actor not in states:
            errors.append(f"{where}: actor {actor!r} has no authority chain in "
                          "this bundle.")
            continue
        if authority.quarantined_at(states[actor], at):
            errors.append(f"{where}: actor {actor!r} was QUARANTINED at {at} "
                          "and held no capability (A5).")
            continue
        caps = authority.grant_capabilities_at(states[actor], gid, at)
        if caps is None:
            errors.append(f"{where}: grant {gid!r} was not active for {actor!r} "
                          f"at {at}.")
            continue
        try:
            needed = authority.required_capability(r["event_type"], payload)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        if needed not in caps:
            errors.append(f"{where}: grant {gid!r} confers {sorted(caps)}, "
                          f"which does not include {needed}.")

    if pre_authority and not errors:
        notes.append(
            f"{pre_authority} custody event(s) predate this field's authority "
            f"genesis ({declared_genesis}) and are UNAUTHORIZED BY "
            "DECLARATION — their integrity is proven, their authorization is "
            "not claimed.")
    return errors, notes


def verify_causality(
    body: dict[str, Any],
    memory_chains: list[tuple[str, list[dict[str, Any]]]],
) -> tuple[list[str], list[str]]:
    """
    B8 — causal provenance. Returns (errors, notes). Pure over the bundle
    body and the chains that already passed B2. The standalone verifier
    transcribes this function.
    """
    errors: list[str] = []
    notes: list[str] = []

    receipts_by_sha: dict[str, dict[str, Any]] = {}
    declared_ranking = body.get("protocols", {}).get("ranking_protocol")
    for row in body.get("receipts", []):
        try:
            sha = row["receipt_sha256"]
            served = json.loads(row["served_json"])["served"]
        except Exception:
            errors.append("B8: a carried receipt is malformed.")
            continue
        if _field.receipt_digest_from_row(row, served) != sha:
            errors.append(f"B8: receipt {sha[:16]}…: does not recompute from "
                          "its own columns — receipt evidence edited.")
            continue
        if row.get("ranking_protocol") != declared_ranking:
            errors.append(
                f"B8: receipt {sha[:16]}…: was produced under ranking_protocol "
                f"{row.get('ranking_protocol')!r} but this bundle declares "
                f"{declared_ranking!r}. Two recalls are only comparable under "
                "one ranking semantics.")
            continue
        receipts_by_sha[sha] = {"served": served}

    carried_memories = {mid for mid, _ in memory_chains}
    used_events: dict[str, set[str]] = {}     # decision_id -> memories claiming it
    for mid, chain in memory_chains:
        for r in chain:
            if r["event_type"] != "DECISION_USED_MEMORY":
                continue
            did = json.loads(r["payload_json"]).get("decision_id")
            if isinstance(did, str):
                used_events.setdefault(did, set()).add(mid)

    included = body.get("decisions", [])
    excluded = body.get("excluded_decisions", [])   # absent key reads as none
    included_ids = {d.get("decision_id") for d in included}
    excluded_ids = {d.get("decision_id") for d in excluded}
    for did in sorted(included_ids & excluded_ids):
        errors.append(f"B8: decision {did}: declared both included and "
                      "excluded — ambiguity refused.")

    for d, is_included in [(d, True) for d in included] + [(d, False) for d in excluded]:
        did = d.get("decision_id")
        try:
            used = json.loads(d["used_json"])["used"]
        except Exception:
            errors.append(f"B8: decision {did}: used_json is not valid JSON.")
            continue
        body_d = causality.decision_body(
            decision_id=did, receipt_sha256=d["receipt_sha256"],
            decision_sha256=d["decision_sha256"],
            policy_version=d["policy_version"], actor_id=d["actor_id"],
            reason=d["reason"], used_memory_ids=used,
            created_at=d["created_at"])
        if hashlib.sha256(
                canonical_json(body_d).encode("utf-8")).hexdigest() != d.get("record_sha256"):
            errors.append(f"B8: decision {did}: record seal does not recompute "
                          "— decision evidence edited.")
            continue
        rec = receipts_by_sha.get(d["receipt_sha256"])
        if rec is None:
            errors.append(f"B8: decision {did}: cites receipt "
                          f"{d['receipt_sha256'][:16]}…, which this bundle does "
                          "not carry — a causal claim with no anchor.")
            continue
        not_served = sorted(set(used) - set(rec["served"]))
        if not_served:
            errors.append(f"B8: decision {did}: claims memories {not_served} "
                          "its cited recall never served.")
        if is_included:
            absent = sorted(set(used) - carried_memories)
            if absent:
                errors.append(f"B8: decision {did}: declared fully evidenced "
                              f"but {absent} do not travel in this bundle.")
            for mid in sorted(set(used) & carried_memories):
                if mid not in used_events.get(did, set()):
                    errors.append(
                        f"B8: decision {did}: names {mid}, but {mid}'s custody "
                        "chain has no DECISION_USED_MEMORY naming it back — a "
                        "causal claim only one side makes.")
        else:
            if set(used) <= carried_memories:
                errors.append(f"B8: decision {did}: declared excluded but the "
                              "bundle carries every memory it used — complete "
                              "evidence must be included and checked, not "
                              "excluded.")

    by_id = {d.get("decision_id"): d for d in list(included) + list(excluded)}
    for did in sorted(used_events):
        if did not in included_ids and did not in excluded_ids:
            errors.append(f"B8: decision {did}: DECISION_USED_MEMORY events "
                          "reference it but the bundle neither carries it nor "
                          "declares it excluded.")
            continue
        try:
            claimed = set(json.loads(by_id[did]["used_json"])["used"])
        except Exception:
            continue
        strays = sorted(used_events[did] - claimed)
        if strays:
            errors.append(f"B8: decision {did}: {strays} carry a "
                          "DECISION_USED_MEMORY naming it, but the decision "
                          "does not claim them — a causal link asserted from "
                          "one side only.")

    for d in excluded:
        notes.append(f"decision {d.get('decision_id')} declared excluded — it "
                     "used memories outside this bundle, so its causal "
                     "evidence was NOT checked in full here.")
    return errors, notes



def verify_bundle(bundle_json: str) -> tuple[bool, list[str]]:
    """
    Full B1–B7 verification of an exported bundle string.

    Returns (ok, errors). For the notes an auditor must see on a PASSING
    verdict — declared sweep exclusions, unauthorized-by-declaration
    counts — use verify_bundle_verbose().
    """
    ok, errors, _ = verify_bundle_verbose(bundle_json)
    return ok, errors


def verify_bundle_verbose(bundle_json: str) -> tuple[bool, list[str], list[str]]:
    """B1–B7, plus the notes a passing verdict must not bury."""
    errors: list[str] = []
    notes: list[str] = []
    try:
        outer = json.loads(bundle_json)
        body, seal = outer["body"], outer["bundle_sha256"]
    except Exception:
        return False, ["Bundle is not valid JSON with body/bundle_sha256."], notes

    # B1 — seal
    if hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest() != seal:
        return (False,
                ["B1: bundle_sha256 does not recompute — bundle tampered as a whole."],
                notes)
    if body.get("format") != BUNDLE_FORMAT:
        return (False,
                [f"Unknown bundle format {body.get('format')!r} (this verifier "
                 f"implements {BUNDLE_FORMAT}). A bundle sealed under an older "
                 "format was checked under semantics it never declared; verify "
                 "it with a verifier of its era."],
                notes)

    # Protocol declaration — before any check that depends on a semantics.
    perrors = protocol.check_protocols(body.get("protocols"))
    if perrors:
        return False, [f"B0: {e}" for e in perrors], notes
    notes.append("semantics: " + ", ".join(
        f"{k} {body['protocols'][k]}" for k in protocol.PROTOCOL_NAMES))
    vocabulary = custody.EVENT_TYPES_BY_PROTOCOL[body["protocols"]["custody_protocol"]]

    heads: dict[str, str] = {}
    tf_by_sweep: dict[str, list[str]] = {}
    stored_supersedes: dict[str, str] = {}   # successor -> claimed predecessor
    successors: dict[str, set[str]] = {}     # predecessor -> SUPERSEDED_BY names
    verified_chains: list[tuple[str, list[dict[str, Any]]]] = []

    for mem in body.get("memories", []):
        mid = mem["memory_id"]
        chain = mem["custody"]

        # B2 — chain integrity, against the vocabulary of the custody
        # protocol THIS BUNDLE DECLARES. A bundle sealed under 1.0.0 is
        # checked against 1.0.0's eight words, so a 1.1.0 event smuggled
        # into it fails rather than being silently accepted by a newer
        # verifier that happens to know the word.
        ok, errs = custody.verify_custody_rows(mid, chain, vocabulary)
        if not ok:
            errors.extend(f"B2: {e}" for e in errs)
            continue
        heads[mid] = chain[-1]["entry_hash"]
        verified_chains.append((mid, chain))

        # B3 — content integrity against the birth seal
        birth = json.loads(chain[0]["payload_json"])
        if isinstance(birth.get("supersedes"), str):
            stored_supersedes[mid] = birth["supersedes"]
        born = birth["content_sha256"]
        if custody.content_sha256(mem["content"]) != born:
            errors.append(f"B3: {mid}: content does not hash to the STORED seal.")
        if mem.get("content_sha256") != born:
            errors.append(f"B3: {mid}: declared content_sha256 disagrees with birth event.")

        # B4 — state replay
        status, fstate, conf, rerrs = replay_state(chain)
        errors.extend(f"B4: {e}" for e in rerrs)
        if mem.get("custody_status") != status:
            errors.append(f"B4: {mid}: declared custody_status "
                          f"{mem.get('custody_status')!r}, replay says {status!r}.")
        if mem.get("field_state") != fstate:
            errors.append(f"B4: {mid}: declared field_state "
                          f"{mem.get('field_state')!r}, replay says {fstate!r}.")
        if mem.get("confidence") != conf:
            errors.append(f"B4: {mid}: declared confidence "
                          f"{mem.get('confidence')!r}, replay says {conf!r}.")

        for r in chain:
            if r["event_type"] == "TAINT_FLAGGED":
                sid = json.loads(r["payload_json"]).get("sweep_id")
                if isinstance(sid, str):
                    tf_by_sweep.setdefault(sid, []).append(mid)
            elif r["event_type"] == "SUPERSEDED_BY":
                succ = json.loads(r["payload_json"]).get("successor_memory_id")
                if isinstance(succ, str):
                    successors.setdefault(mid, set()).add(succ)

    # B4 — supersession lineage is bilateral when both parties are present
    for s, x in sorted(stored_supersedes.items()):
        if x in heads and s not in successors.get(x, set()):
            errors.append(f"B4: {s}: STORED claims it supersedes {x}, but "
                          f"{x}'s chain has no SUPERSEDED_BY naming {s}.")
    for x in sorted(successors):
        for s in sorted(successors[x]):
            if s in heads and stored_supersedes.get(s) != x:
                errors.append(f"B4: {x}: SUPERSEDED_BY names {s}, but {s}'s "
                              f"STORED does not claim to supersede {x}.")

    # B5 — sweep evidence (normative rules in the module header)
    included = body.get("sweeps", [])
    excluded = body.get("excluded_sweeps", [])  # absent key reads as empty
    included_ids = {sw["sweep_id"] for sw in included}
    excluded_ids = {sw["sweep_id"] for sw in excluded}
    for sid in sorted(included_ids & excluded_ids):
        errors.append(f"B5: sweep {sid}: declared both included and excluded "
                      "— ambiguity refused.")
    for sw in included:
        sid = sw["sweep_id"]
        flagged = sorted(tf_by_sweep.get(sid, []))
        if len(flagged) != sw["flagged_count"]:
            errors.append(f"B5: sweep {sid}: {len(flagged)} TAINT_FLAGGED events "
                          f"in bundle, row claims {sw['flagged_count']}.")
        derived = hashlib.sha256(
            canonical_json({"memory_ids": flagged}).encode("utf-8")).hexdigest()
        if derived != sw["flagged_ids_sha256"]:
            errors.append(f"B5: sweep {sid}: flagged set does not hash to the seal.")
    for sw in excluded:
        sid = sw["sweep_id"]
        carried = len(set(tf_by_sweep.get(sid, [])))
        if carried >= sw["flagged_count"]:
            errors.append(f"B5: sweep {sid}: declared excluded but the bundle "
                          f"carries {carried} of {sw['flagged_count']} flagged "
                          "memories — complete evidence must be included and "
                          "checked, not excluded.")
    for sid in sorted(set(tf_by_sweep) - included_ids - excluded_ids):
        errors.append(f"B5: sweep {sid}: TAINT_FLAGGED events reference it but "
                      "the bundle neither carries it nor declares it excluded.")

    for sw in excluded:
        notes.append(f"sweep {sw['sweep_id']} declared excluded — its seal was "
                     "NOT checked against evidence in this bundle.")

    # B6 — heads Merkle root
    if heads_merkle_root(heads) != body.get("heads_merkle_root"):
        errors.append("B6: heads_merkle_root does not recompute.")

    # B7 — authority provenance
    aerrors, anotes = verify_authority(body, verified_chains)
    errors.extend(aerrors)
    notes.extend(anotes)

    # B8 — causal provenance
    cerrors, cnotes = verify_causality(body, verified_chains)
    errors.extend(cerrors)
    notes.extend(cnotes)

    return (not errors), errors, notes
