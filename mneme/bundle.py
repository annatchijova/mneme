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
      payloads stored in canonical form.
  B3  content integrity: sha256(content) equals the content_sha256
      sealed in the STORED event — the content shipped is the content
      born.
  B4  STATE IS DERIVABLE FROM EVIDENCE: replaying the chain's events
      through the documented state machine reproduces the declared
      custody_status, field_state and confidence. A hand-edited status
      column without its corresponding event is self-revealing.
  B5  every sweep's flagged set (TAINT_FLAGGED events carrying its
      sweep_id) matches its count and hashes to its seal.
  B6  the Merkle root over chain heads recomputes (leaves sorted by
      memory_id ASC; odd leaf promoted unpaired — duplicating the last
      leaf, Bitcoin-style, admits two leaf sets with one root, an
      ambiguity we refuse; same rule as STIGMERGY's ledger).

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
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .canonical import canonical_json
from . import custody

BUNDLE_FORMAT = "MNEME_BUNDLE_V1"
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
    sweeps = [dict(zip(["sweep_id", "quarantined_actor", "initiated_by",
                        "reason", "created_at", "flagged_count",
                        "flagged_ids_sha256"], r)) for r in cur.fetchall()]

    body = {
        "format": BUNDLE_FORMAT,
        "created_at": custody.now_ts(),
        "memories": memories,
        "sweeps": sweeps,
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


def verify_bundle(bundle_json: str) -> tuple[bool, list[str]]:
    """Full B1–B6 verification of an exported bundle string."""
    errors: list[str] = []
    try:
        outer = json.loads(bundle_json)
        body, seal = outer["body"], outer["bundle_sha256"]
    except Exception:
        return False, ["Bundle is not valid JSON with body/bundle_sha256."]

    # B1 — seal
    if hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest() != seal:
        return False, ["B1: bundle_sha256 does not recompute — bundle tampered as a whole."]
    if body.get("format") != BUNDLE_FORMAT:
        return False, [f"Unknown bundle format {body.get('format')!r}."]

    heads: dict[str, str] = {}
    tf_by_sweep: dict[str, list[str]] = {}

    for mem in body.get("memories", []):
        mid = mem["memory_id"]
        chain = mem["custody"]

        # B2 — chain integrity (shared pure implementation)
        ok, errs = custody.verify_custody_rows(mid, chain)
        if not ok:
            errors.extend(f"B2: {e}" for e in errs)
            continue
        heads[mid] = chain[-1]["entry_hash"]

        # B3 — content integrity against the birth seal
        born = json.loads(chain[0]["payload_json"])["content_sha256"]
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

    # B5 — sweep seals against evidence
    for sw in body.get("sweeps", []):
        sid = sw["sweep_id"]
        flagged = sorted(tf_by_sweep.get(sid, []))
        if len(flagged) != sw["flagged_count"]:
            errors.append(f"B5: sweep {sid}: {len(flagged)} TAINT_FLAGGED events "
                          f"in bundle, row claims {sw['flagged_count']}.")
        derived = hashlib.sha256(
            canonical_json({"memory_ids": flagged}).encode("utf-8")).hexdigest()
        if derived != sw["flagged_ids_sha256"]:
            errors.append(f"B5: sweep {sid}: flagged set does not hash to the seal.")

    # B6 — heads Merkle root
    if heads_merkle_root(heads) != body.get("heads_merkle_root"):
        errors.append("B6: heads_merkle_root does not recompute.")

    return (not errors), errors
