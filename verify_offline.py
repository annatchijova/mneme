#!/usr/bin/env python3
"""
MNEME — Standalone offline bundle verifier. ZERO dependencies beyond a
Python 3.10+ interpreter. Send this file and a bundle to anyone; they
need nothing else — not the mneme package, not the database, not pip.

    python3 verify_offline.py bundle.json

Exit 0: every check passed. Exit 1: verdict is printed, one line per lie.

This file deliberately DUPLICATES the verification logic that also
lives in mneme/bundle.py and mneme/custody.py. Duplication is a cost we
pay for a property we value more: an auditor must be able to read ONE
short file and convince themselves of what "verified" means, with no
import graph to chase. The two implementations are held together by
tests/test_bundle_pure.py's agreement section, which runs both against
the same valid and tampered bundles and demands identical verdicts.
If you change the protocol, you change it in three places or the tests
scream. That is the design.

Checks (normative statement in mneme/bundle.py's header):
  B1  bundle seal recomputes
  B2  every custody chain: genesis bound to memory_id, dense seq,
      linkage, entry hashes recompute, closed vocabulary, canonical
      payload bytes, canonical UTC timestamps that never run backwards
  B3  content hashes to the seal in its STORED (birth) event
  B4  declared custody_status / field_state / confidence reproduce
      from replaying the chain's events; supersession lineage is
      bilateral when both parties travel in the bundle (a STORED
      "supersedes": X needs X's chain to name this memory back in a
      SUPERSEDED_BY event, and vice versa)
  B5  sweep evidence — absence stated, never implied: no sweep_id in
      both "sweeps" and "excluded_sweeps"; every included sweep's
      flagged set matches its count and seal; an excluded sweep must
      be genuinely partial (strictly fewer flagged memories carried
      than its flagged_count); every sweep_id referenced by a
      TAINT_FLAGGED event appears in one of the two lists. Excluded
      sweeps' seals are NOT checked — exclusion is a declared claim
      the auditor sees (this verifier names them on success), not a
      verified one.
  B6  Merkle root over chain heads recomputes (leaves sorted by
      memory_id ASC, odd leaf promoted unpaired)
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

FORMAT = "MNEME_BUNDLE_V1"
GENESIS_PREFIX = b"MNEME_CUSTODY_GENESIS:"
EVENT_TYPES = frozenset({
    "STORED", "REINFORCED", "CONTRADICTED_BY", "SUPERSEDED_BY",
    "QUARANTINED", "TAINT_FLAGGED", "REHABILITATED", "STATE_CHANGED",
})
INITIAL_CONFIDENCE = "0.5000000000"
# Canonical timestamp shape (UTC, microseconds, +00:00). Verification
# re-asserts it so lexicographic order equals chronological order.
TS_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")


# --- canonical JSON (protocol transcription; floats are forbidden) ---------

def _canon(obj, path="payload"):
    if obj is None or isinstance(obj, bool) or isinstance(obj, str):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        raise ValueError(f"{path}: float found — canonical payloads never contain bare floats.")
    if isinstance(obj, dict):
        return {k: _canon(v, f"{path}.{k}") for k, v in obj.items()}
    if isinstance(obj, list):
        return [_canon(v, f"{path}[{i}]") for i, v in enumerate(obj)]
    raise ValueError(f"{path}: unserializable type {type(obj).__name__}.")


def canonical_json(payload: dict) -> str:
    return json.dumps(_canon(payload), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- B2: custody chain ------------------------------------------------------

def verify_chain(memory_id: str, chain: list[dict], errors: list[str]) -> bool:
    if not chain:
        errors.append(f"B2: {memory_id}: empty custody chain — a memory without a birth event.")
        return False
    expected_prev = sha256_hex(GENESIS_PREFIX + memory_id.encode("utf-8"))
    prev_ts = None
    for i, r in enumerate(chain):
        where = f"B2: {memory_id} seq {r.get('seq')}"
        if r.get("seq") != i:
            errors.append(f"{where}: seq not dense (expected {i})."); return False
        et = r.get("event_type")
        if et not in EVENT_TYPES:
            errors.append(f"{where}: unknown event_type {et!r}."); return False
        if i == 0 and et != "STORED":
            errors.append(f"{where}: chain does not begin with STORED."); return False
        if i > 0 and et == "STORED":
            errors.append(f"{where}: STORED after birth."); return False
        if r.get("prev_hash") != expected_prev:
            errors.append(f"{where}: prev_hash does not link (broken or grafted)."); return False
        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            errors.append(f"{where}: payload_json is not valid JSON."); return False
        try:
            if canonical_json(payload) != r["payload_json"]:
                errors.append(f"{where}: payload_json is not canonical bytes."); return False
        except ValueError as e:
            errors.append(f"{where}: {e}"); return False
        envelope = {
            "memory_id": memory_id, "seq": r["seq"], "event_type": et,
            "actor_id": r["actor_id"], "reason": r["reason"],
            "created_at": r["created_at"], "payload": payload,
        }
        recomputed = sha256_hex(r["prev_hash"].encode("ascii")
                                + canonical_json(envelope).encode("utf-8"))
        if recomputed != r["entry_hash"]:
            errors.append(f"{where}: entry_hash does not recompute — content tampered.")
            return False
        ts = r["created_at"]
        if not isinstance(ts, str) or not TS_PATTERN.match(ts):
            errors.append(f"{where}: created_at {ts!r} is not canonical UTC "
                          "microsecond ISO 8601 (…+00:00)."); return False
        if prev_ts is not None and ts < prev_ts:
            errors.append(f"{where}: created_at {ts} precedes the previous "
                          f"event's {prev_ts} — chain runs backwards in time."); return False
        prev_ts = ts
        expected_prev = r["entry_hash"]
    born = json.loads(chain[0]["payload_json"]).get("content_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", born or ""):
        errors.append(f"B2: {memory_id}: STORED payload lacks a valid content_sha256.")
        return False
    return True


# --- B4: state replay (transcribed from mneme/bundle.py) --------------------

def replay_state(chain: list[dict], errors: list[str]) -> tuple[str, str, str]:
    status, fstate, conf = "CLEAN", "NEUTRAL", INITIAL_CONFIDENCE
    for r in chain:
        et = r["event_type"]
        where = f"B4: {r['memory_id']} seq {r['seq']}"
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
                errors.append(f"{where}: REHABILITATED from {status}, valid only from TAINT_FLAGGED.")
            status = "CLEAN"
        elif et == "STATE_CHANGED":
            if payload.get("from") != fstate:
                errors.append(f"{where}: STATE_CHANGED claims from={payload.get('from')!r} "
                              f"but replay says {fstate!r}.")
            to = payload.get("to")
            if to not in ("REINFORCED", "NEUTRAL", "FORGOTTEN"):
                errors.append(f"{where}: STATE_CHANGED to unknown state {to!r}.")
            else:
                fstate = to
        elif et == "REINFORCED":
            if payload.get("confidence_before") != conf:
                errors.append(f"{where}: REINFORCED claims before="
                              f"{payload.get('confidence_before')!r} but replay says {conf!r}.")
            after = payload.get("confidence_after")
            if not isinstance(after, str):
                errors.append(f"{where}: REINFORCED without confidence_after.")
            else:
                conf = after
    return status, fstate, conf


# --- B6: Merkle over heads ---------------------------------------------------

def heads_merkle_root(heads: dict[str, str]) -> str:
    if not heads:
        return sha256_hex(b"MNEME_EMPTY_HEADS")
    level = [sha256_hex(f"{mid}:{h}".encode("utf-8"))
             for mid, h in sorted(heads.items())]
    while len(level) > 1:
        nxt = [sha256_hex((level[i] + level[i + 1]).encode("ascii"))
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promoted unpaired, never duplicated
        level = nxt
    return level[0]


# --- driver -------------------------------------------------------------------

def verify(bundle_json: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        outer = json.loads(bundle_json)
        body, seal = outer["body"], outer["bundle_sha256"]
    except Exception:
        return False, ["Bundle is not valid JSON with body/bundle_sha256."]

    try:
        if sha256_hex(canonical_json(body).encode("utf-8")) != seal:
            return False, ["B1: bundle_sha256 does not recompute — bundle tampered as a whole."]
    except ValueError as e:
        return False, [f"B1: body is not canonicalizable: {e}"]
    if body.get("format") != FORMAT:
        return False, [f"Unknown bundle format {body.get('format')!r}."]

    heads: dict[str, str] = {}
    tf_by_sweep: dict[str, list[str]] = {}
    stored_supersedes: dict[str, str] = {}   # successor -> claimed predecessor
    successors: dict[str, set[str]] = {}     # predecessor -> SUPERSEDED_BY names

    for mem in body.get("memories", []):
        mid = mem["memory_id"]
        chain = mem["custody"]
        if not verify_chain(mid, chain, errors):
            continue
        heads[mid] = chain[-1]["entry_hash"]

        birth = json.loads(chain[0]["payload_json"])
        if isinstance(birth.get("supersedes"), str):
            stored_supersedes[mid] = birth["supersedes"]
        born = birth["content_sha256"]
        if sha256_hex(mem["content"].encode("utf-8")) != born:
            errors.append(f"B3: {mid}: content does not hash to the STORED seal.")
        if mem.get("content_sha256") != born:
            errors.append(f"B3: {mid}: declared content_sha256 disagrees with birth event.")

        status, fstate, conf = replay_state(chain, errors)
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

    for s, x in sorted(stored_supersedes.items()):
        if x in heads and s not in successors.get(x, set()):
            errors.append(f"B4: {s}: STORED claims it supersedes {x}, but "
                          f"{x}'s chain has no SUPERSEDED_BY naming {s}.")
    for x in sorted(successors):
        for s in sorted(successors[x]):
            if s in heads and stored_supersedes.get(s) != x:
                errors.append(f"B4: {x}: SUPERSEDED_BY names {s}, but {s}'s "
                              f"STORED does not claim to supersede {x}.")

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
        derived = sha256_hex(canonical_json({"memory_ids": flagged}).encode("utf-8"))
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

    if heads_merkle_root(heads) != body.get("heads_merkle_root"):
        errors.append("B6: heads_merkle_root does not recompute.")

    return (not errors), errors


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        raw = f.read()
    ok, errors = verify(raw)
    if ok:
        print("VERIFIED: every check (B1-B6) passed.")
        # A declared exclusion is a claim the auditor must SEE, not
        # something a passing verdict may bury.
        try:
            excluded = json.loads(raw)["body"].get("excluded_sweeps", [])
        except Exception:
            excluded = []
        for sw in excluded:
            print(f"  NOTE: sweep {sw['sweep_id']} declared excluded — its seal "
                  "was NOT checked against evidence in this bundle.")
        return 0
    print(f"FAILED: {len(errors)} problem(s).")
    for e in errors:
        print(f"  {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
