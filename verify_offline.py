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
  B3  content hashes to the seal in its STORED (birth) event; and where
      a memory declares embedding provenance, the vector shipped is the
      vector that record describes, under a quantization this verifier
      implements, with the model's input matching the content whenever
      the record claims no preprocessing. Memories that declare none are
      COUNTED and named on success: the boundary is trusted there, and
      that is stated rather than hidden
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
  B7  authority provenance: every authority chain verifies and replays;
      declared actor status reproduces from it; exactly one self-issued
      root grant conferring the whole vocabulary; NO AMPLIFICATION —
      every authority event's issuer held, at that instant, the
      capability the event required and (for a grant) every capability
      it conferred; and every custody event at or after the declared
      authority genesis names a grant that was active for its actor at
      that instant, conferred the capability its event type requires,
      and belonged to an actor not then quarantined. Events before the
      genesis — and every event in a field with no ledger at all — are
      UNAUTHORIZED BY DECLARATION: named on success, never passed as
      authorized.
  B8  causal provenance: carried receipts recompute from their own
      columns under the bundle's declared ranking semantics; every
      decision re-derives its seal, cites a receipt carried here, and
      claims only memories that receipt actually served; an included
      decision's used memories all travel and each names the decision
      back in a DECISION_USED_MEMORY event (bilateral, like lineage); an
      excluded decision must be genuinely partial; and no
      DECISION_USED_MEMORY event references a decision the bundle
      neither carries nor declares excluded.

  B0 comes last in this list and first in the code: a V2 bundle declares
      the VERSION of every semantics its checks depend on, and a
      verifier that meets a version it does not implement refuses rather
      than applying today's rules to yesterday's evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

FORMAT = "MNEME_BUNDLE_V2"
GENESIS_PREFIX = b"MNEME_CUSTODY_GENESIS:"
AUTHORITY_GENESIS_PREFIX = b"MNEME_AUTHORITY_GENESIS:"
_V1_EVENT_TYPES = frozenset({
    "STORED", "REINFORCED", "CONTRADICTED_BY", "SUPERSEDED_BY",
    "QUARANTINED", "TAINT_FLAGGED", "REHABILITATED", "STATE_CHANGED",
})
# Versioned vocabulary: a bundle is checked against the words that existed
# under the custody_protocol IT DECLARES, so a newer verifier cannot
# silently accept a newer word inside an older bundle.
EVENT_TYPES_BY_PROTOCOL = {
    "1.0.0": _V1_EVENT_TYPES,
    "1.1.0": _V1_EVENT_TYPES | {"DECISION_USED_MEMORY"},
}
AUTHORITY_EVENT_TYPES = frozenset({
    "ACTOR_REGISTERED", "GRANTED", "REVOKED",
    "ACTOR_QUARANTINED", "ACTOR_REINSTATED",
})
CAPABILITIES = frozenset({
    "STORE", "REINFORCE", "SUPERSEDE", "QUARANTINE_ACTOR",
    "QUARANTINE_MEMORY", "REHABILITATE", "GRANT", "REVOKE", "DECIDE",
    "ASSERT", "ADJUDICATE", "COUNTERFACTUAL",
})
# Custody event type -> capability its actor had to hold (authority.py).
REQUIRED_CAPABILITY = {
    "STORED": "STORE",
    "REINFORCED": "REINFORCE",
    "CONTRADICTED_BY": "STORE",
    "SUPERSEDED_BY": "SUPERSEDE",
    "QUARANTINED": "QUARANTINE_MEMORY",
    "TAINT_FLAGGED": "QUARANTINE_ACTOR",
    "REHABILITATED": "REHABILITATE",
    "STATE_CHANGED": "REINFORCE",
    "DECISION_USED_MEMORY": "DECIDE",
}
# Authority event type -> capability its ISSUER had to hold.
AUTHORITY_EVENT_CAPABILITY = {
    "ACTOR_REGISTERED": "GRANT",
    "GRANTED": "GRANT",
    "REVOKED": "REVOKE",
    "ACTOR_QUARANTINED": "QUARANTINE_ACTOR",
    "ACTOR_REINSTATED": "QUARANTINE_ACTOR",
}
PROTOCOL_NAMES = ("custody_protocol", "replay_protocol", "ranking_protocol",
                  "taint_protocol", "authority_protocol", "receipt_protocol",
                  "claim_protocol")
CLAIM_GENESIS_PREFIX = b"MNEME_CLAIM_GENESIS:"
CLAIM_EVENT_TYPES = frozenset({
    "CLAIM_ASSERTED", "EVIDENCE_LINKED", "RELATED_TO", "SET_MEMBERSHIP",
    "CLAIM_VALIDATED", "CLAIM_REFUTED", "CLAIM_WITHDRAWN", "CLAIM_SUPERSEDED",
})
STANCES = ("SUPPORTS", "CONTRADICTS")
RELATIONS = ("SUPPORTS", "CONTRADICTS", "SUPERSEDES", "DERIVED_FROM")
# Which capability each claim event required of its actor. Asserting a
# proposition and ruling between hypotheses are their own authorities.
CLAIM_EVENT_CAPABILITY = {
    "CLAIM_ASSERTED": "ASSERT", "EVIDENCE_LINKED": "ASSERT",
    "RELATED_TO": "ASSERT", "SET_MEMBERSHIP": "ASSERT",
    "CLAIM_VALIDATED": "ADJUDICATE", "CLAIM_REFUTED": "ADJUDICATE",
    "CLAIM_WITHDRAWN": "ASSERT", "CLAIM_SUPERSEDED": "ASSERT",
}
# Every version this verifier actually implements (mneme/protocol.py).
SUPPORTED_PROTOCOLS = {
    "custody_protocol": frozenset({"1.0.0", "1.1.0"}),
    "replay_protocol": frozenset({"1.0.0", "1.1.0"}),
    "ranking_protocol": frozenset({"1.0.0"}),
    "taint_protocol": frozenset({"1.0.0", "1.1.0", "2.0.0"}),
    "authority_protocol": frozenset({"1.0.0", "1.1.0", "1.2.0"}),
    # receipt 1.0.0 is absent on purpose: its digest body differs, so this
    # verifier genuinely cannot check one.
    "receipt_protocol": frozenset({"2.0.0"}),
    "claim_protocol": frozenset({"1.0.0"}),
}
GRANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:]{1,64}$")
SUPPORTED_QUANTIZATION = frozenset({
    "canonical-decimal/scale=10/rounding=ROUND_HALF_EVEN",
})
INITIAL_CONFIDENCE = "0.5000000000"
# replay_protocol 1.1.0: a promotion must be arithmetically DUE, not merely
# recorded. Held as an exact integer ratio — no float ever decides here.
PROMOTION_THRESHOLD_NUM, PROMOTION_THRESHOLD_DEN = 3, 4
# Events through which an actor writes its identity onto a chain WITHOUT
# influencing the memory (taint_protocol 2.0.0).
NON_INFLUENCE_EVENTS = ("CONTRADICTED_BY", "DECISION_USED_MEMORY")
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


# --- B0: declared semantics (transcribed from mneme/protocol.py) ------------

def check_protocols(declared) -> list[str]:
    errors: list[str] = []
    if not isinstance(declared, dict):
        return ["protocols: block absent or not an object — a bundle that "
                "declares no semantics commits to none."]
    for name in PROTOCOL_NAMES:
        if name not in declared:
            errors.append(f"protocols: {name} is not declared — this verifier "
                          "will not apply today's rules to evidence that never "
                          "named them.")
            continue
        version = declared[name]
        if not isinstance(version, str):
            errors.append(f"protocols: {name} version is not a string.")
        elif version not in SUPPORTED_PROTOCOLS[name]:
            errors.append(
                f"protocols: {name} {version} is not implemented by this "
                f"verifier (supported: "
                f"{', '.join(sorted(SUPPORTED_PROTOCOLS[name]))}).")
    for name in sorted(set(declared) - set(PROTOCOL_NAMES)):
        errors.append(f"protocols: {name!r} is unknown to this verifier — the "
                      "bundle was sealed by a newer MNEME.")
    return errors


# --- B2: custody chain ------------------------------------------------------

def verify_chain(memory_id: str, chain: list[dict], errors: list[str],
                 vocabulary: frozenset) -> bool:
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
        if et not in vocabulary:
            errors.append(f"{where}: event_type {et!r} is not in the custody "
                          "vocabulary being verified."); return False
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

def _at_least_threshold(conf: str) -> bool:
    """conf >= 3/4, by exact integer arithmetic on the fixed-point string."""
    whole, _, frac = conf.partition(".")
    scaled = int(whole) * (10 ** len(frac)) + int(frac or 0)
    return scaled * PROMOTION_THRESHOLD_DEN >= \
        PROMOTION_THRESHOLD_NUM * (10 ** len(frac))


def replay_state(chain: list[dict], errors: list[str],
                 replay_protocol: str = "1.1.0") -> tuple[str, str, str]:
    check_promotion = replay_protocol != "1.0.0"
    promotion_due = False
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
            if check_promotion and payload.get("to") == "REINFORCED" \
                    and payload.get("from") == "NEUTRAL" \
                    and not _at_least_threshold(conf):
                errors.append(f"{where}: promotion to REINFORCED at confidence "
                              f"{conf}, below the threshold "
                              f"{PROMOTION_THRESHOLD_NUM}/"
                              f"{PROMOTION_THRESHOLD_DEN} — a promotion that "
                              "was not arithmetically due.")
            promotion_due = False
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
                if check_promotion and fstate == "NEUTRAL" \
                        and _at_least_threshold(conf):
                    promotion_due = True
    if check_promotion and promotion_due:
        errors.append(f"B4: {chain[-1]['memory_id']}: confidence reached "
                      f"{conf}, at or past the promotion threshold "
                      f"{PROMOTION_THRESHOLD_NUM}/{PROMOTION_THRESHOLD_DEN}, "
                      "with no STATE_CHANGED to REINFORCED — a promotion that "
                      "was due and never recorded.")
    return status, fstate, conf


# --- B7: authority chains (transcribed from mneme/authority.py) -------------

def verify_authority_chain(subject_id: str, chain: list, errors: list) -> bool:
    if not chain:
        errors.append(f"B7: {subject_id}: empty authority chain.")
        return False
    expected_prev = sha256_hex(AUTHORITY_GENESIS_PREFIX + subject_id.encode("utf-8"))
    prev_ts = None
    for i, r in enumerate(chain):
        where = f"B7: {subject_id} authority seq {r.get('seq')}"
        if r.get("seq") != i:
            errors.append(f"{where}: seq not dense (expected {i})."); return False
        et = r.get("event_type")
        if et not in AUTHORITY_EVENT_TYPES:
            errors.append(f"{where}: unknown event_type {et!r}."); return False
        if i == 0 and et != "ACTOR_REGISTERED":
            errors.append(f"{where}: chain does not begin with ACTOR_REGISTERED."); return False
        if i > 0 and et == "ACTOR_REGISTERED":
            errors.append(f"{where}: ACTOR_REGISTERED after birth."); return False
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
            "subject_id": subject_id, "seq": r["seq"], "event_type": et,
            "issuer_id": r["issuer_id"], "reason": r["reason"],
            "created_at": r["created_at"], "payload": payload,
        }
        recomputed = sha256_hex(r["prev_hash"].encode("ascii")
                                + canonical_json(envelope).encode("utf-8"))
        if recomputed != r["entry_hash"]:
            errors.append(f"{where}: entry_hash does not recompute — grant tampered.")
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
    return True


def replay_authority(subject_id: str, chain: list, errors: list) -> dict:
    """
    The authority state machine (normative statement in
    mneme/authority.py's replay_authority docstring), transcribed.
    """
    state = {"status": "ACTIVE", "grants": {}, "quarantine": [], "root": False}
    for r in chain:
        et, payload = r["event_type"], json.loads(r["payload_json"])
        where = f"B7: {subject_id} authority seq {r['seq']}"
        if et == "GRANTED":
            gid, caps = payload.get("grant_id"), payload.get("capabilities")
            is_root = payload.get("root", False)
            if not (isinstance(gid, str) and GRANT_ID_PATTERN.match(gid)):
                errors.append(f"{where}: GRANTED without a well-formed grant_id."); continue
            if gid in state["grants"]:
                errors.append(f"{where}: grant_id {gid!r} reused."); continue
            if not (isinstance(caps, list) and caps and all(isinstance(c, str) for c in caps)):
                errors.append(f"{where}: GRANTED without a capability list."); continue
            unknown = [c for c in caps if c not in CAPABILITIES]
            if unknown:
                errors.append(f"{where}: unknown capabilities {sorted(unknown)}."); continue
            if list(caps) != sorted(set(caps)):
                errors.append(f"{where}: capability list is not sorted and "
                              "duplicate-free."); continue
            if not isinstance(is_root, bool):
                errors.append(f"{where}: GRANTED 'root' is not a boolean."); continue
            if is_root:
                if r["issuer_id"] != subject_id:
                    errors.append(f"{where}: a root grant must be self-issued."); continue
                if set(caps) != set(CAPABILITIES):
                    errors.append(f"{where}: a root grant must confer the whole "
                                  "capability vocabulary."); continue
                state["root"] = True
            state["grants"][gid] = {"capabilities": tuple(caps),
                                    "granted_at": r["created_at"],
                                    "revoked_at": None, "root": is_root}
        elif et == "REVOKED":
            gid = payload.get("grant_id")
            if not isinstance(gid, str) or gid not in state["grants"]:
                errors.append(f"{where}: REVOKED names grant {gid!r}, which this "
                              "chain never granted."); continue
            if state["grants"][gid]["revoked_at"] is not None:
                errors.append(f"{where}: grant {gid} revoked twice."); continue
            state["grants"][gid]["revoked_at"] = r["created_at"]
        elif et == "ACTOR_QUARANTINED":
            if state["status"] != "ACTIVE":
                errors.append(f"{where}: ACTOR_QUARANTINED from {state['status']}, "
                              "valid only from ACTIVE.")
            state["status"] = "QUARANTINED"
            state["quarantine"].append([r["created_at"], None])
        elif et == "ACTOR_REINSTATED":
            if state["status"] != "QUARANTINED":
                errors.append(f"{where}: ACTOR_REINSTATED from {state['status']}, "
                              "valid only from QUARANTINED.")
            elif state["quarantine"]:
                state["quarantine"][-1][1] = r["created_at"]
            state["status"] = "ACTIVE"
    return state


def quarantined_at(state: dict, at_ts: str) -> bool:
    """Half-open [from, to): a write sharing a microsecond with its own
    quarantine is refused, not admitted."""
    return any(lo <= at_ts and (hi is None or at_ts < hi)
               for lo, hi in state["quarantine"])


def grant_capabilities_at(state: dict, grant_id: str, at_ts: str):
    g = state["grants"].get(grant_id)
    if g is None or g["granted_at"] > at_ts:
        return None
    if g["revoked_at"] is not None and g["revoked_at"] <= at_ts:
        return None
    return frozenset(g["capabilities"])


def capabilities_at(state: dict, at_ts: str) -> frozenset:
    if quarantined_at(state, at_ts):
        return frozenset()
    out = set()
    for gid in state["grants"]:
        caps = grant_capabilities_at(state, gid, at_ts)
        if caps:
            out |= caps
    return frozenset(out)


def required_capability(event_type: str, payload: dict):
    if event_type == "STORED" and isinstance(payload.get("supersedes"), str):
        return "SUPERSEDE"
    return REQUIRED_CAPABILITY.get(event_type)


def verify_authority(body: dict, memory_chains: list) -> tuple[list, list]:
    """
    Returns (errors, notes). Deliberately owns its OWN error list rather
    than appending to the caller's: the package implementation does the
    same, and "did B7 find anything" must not silently become "did any
    check anywhere find anything" in one implementation and not the other.
    The agreement test caught exactly that divergence.
    """
    errors: list = []
    notes: list = []
    entries = body.get("authority", [])
    declared_genesis = body.get("authority_genesis_at")
    if not isinstance(entries, list):
        return ["B7: 'authority' is not a list."], notes

    all_events = [(mid, r) for mid, chain in memory_chains for r in chain]

    if not entries:
        if declared_genesis is not None:
            errors.append("B7: the bundle declares an authority genesis but "
                          "carries no authority evidence.")
        for mid, r in all_events:
            if isinstance(json.loads(r["payload_json"]).get("grant_id"), str):
                errors.append(f"B7: {mid} seq {r['seq']}: names a grant_id, but "
                              "the bundle carries no authority chain that could "
                              "have issued it.")
        if heads_merkle_root({}) != body.get("authority_merkle_root"):
            errors.append("B7: authority_merkle_root does not recompute.")
        if not errors:
            notes.append(f"this field has NO authority ledger: all "
                         f"{len(all_events)} custody event(s) are UNAUTHORIZED "
                         "BY DECLARATION. Their integrity is proven; nobody's "
                         "permission to cause them is.")
        return errors, notes

    if not isinstance(declared_genesis, str):
        return (errors + ["B7: the bundle carries authority evidence but declares no authority_genesis_at."]), notes

    states, auth_heads, chains_by_id = {}, {}, {}
    earliest = None
    broken = False
    for entry in sorted(entries, key=lambda e: str(e.get("subject_id"))):
        sid, chain = entry.get("subject_id"), entry.get("chain")
        if not isinstance(sid, str) or not isinstance(chain, list) or not chain:
            errors.append(f"B7: malformed authority entry for {sid!r}.")
            broken = True; continue
        if not verify_authority_chain(sid, chain, errors):
            broken = True; continue
        before = len(errors)
        state = replay_authority(sid, chain, errors)
        if len(errors) != before:
            broken = True; continue
        states[sid], chains_by_id[sid] = state, chain
        auth_heads[sid] = chain[-1]["entry_hash"]
        if earliest is None or chain[0]["created_at"] < earliest:
            earliest = chain[0]["created_at"]
        if entry.get("status") != state["status"]:
            errors.append(f"B7: {sid}: declared actor status "
                          f"{entry.get('status')!r}, authority replay says "
                          f"{state['status']!r}.")

    if heads_merkle_root(auth_heads) != body.get("authority_merkle_root"):
        errors.append("B7: authority_merkle_root does not recompute.")
    if earliest is not None and declared_genesis != earliest:
        errors.append(f"B7: declared authority_genesis_at {declared_genesis} is "
                      f"not the earliest instant in the carried ledger "
                      f"({earliest}).")
    if broken or errors:
        return errors, notes

    roots = sorted(sid for sid, st in states.items() if st["root"])
    if len(roots) != 1:
        errors.append(f"B7: the ledger declares {len(roots)} root grants "
                      f"({roots}); authority hangs from exactly one auditable "
                      "act or from nothing checkable.")

    # No amplification (A3), re-derived offline.
    for sid in sorted(states):
        for r in chains_by_id[sid]:
            payload = json.loads(r["payload_json"])
            issuer, at = r["issuer_id"], r["created_at"]
            where = f"B7: {sid} authority seq {r['seq']}"
            if issuer == sid and payload.get("root") is True:
                continue
            if issuer not in states:
                errors.append(f"{where}: issued by {issuer!r}, whose authority "
                              "chain is not in this bundle — the delegation "
                              "path is unprovable.")
                continue
            needed = AUTHORITY_EVENT_CAPABILITY[r["event_type"]]
            issuer_caps = capabilities_at(states[issuer], at)
            if needed not in issuer_caps:
                errors.append(f"{where}: issuer {issuer!r} did not hold {needed} "
                              f"at {at} (never granted, revoked by then, or "
                              "quarantined).")
                continue
            if r["event_type"] == "GRANTED":
                missing = sorted(set(payload.get("capabilities", [])) - issuer_caps)
                if missing:
                    errors.append(f"{where}: issuer {issuer!r} conferred "
                                  f"{missing} it did not hold — authority "
                                  "invented, not delegated (A3).")

    pre_authority = 0
    for mid, r in all_events:
        payload = json.loads(r["payload_json"])
        gid, at = payload.get("grant_id"), r["created_at"]
        where = f"B7: {mid} seq {r['seq']} ({r['event_type']})"
        if at < declared_genesis:
            pre_authority += 1
            if isinstance(gid, str):
                errors.append(f"{where}: names grant {gid!r} but is timestamped "
                              "before the ledger existed.")
            continue
        if not isinstance(gid, str):
            errors.append(f"{where}: no grant_id, and it postdates the authority "
                          f"genesis {declared_genesis}. Recorded is not "
                          "authorized.")
            continue
        actor = r["actor_id"]
        if actor not in states:
            errors.append(f"{where}: actor {actor!r} has no authority chain in "
                          "this bundle.")
            continue
        if quarantined_at(states[actor], at):
            errors.append(f"{where}: actor {actor!r} was QUARANTINED at {at} and "
                          "held no capability (A5).")
            continue
        caps = grant_capabilities_at(states[actor], gid, at)
        if caps is None:
            errors.append(f"{where}: grant {gid!r} was not active for {actor!r} "
                          f"at {at}.")
            continue
        needed = required_capability(r["event_type"], payload)
        if needed is None:
            errors.append(f"{where}: no capability is mapped for this event "
                          "type — an authority hole.")
        elif needed not in caps:
            errors.append(f"{where}: grant {gid!r} confers {sorted(caps)}, which "
                          f"does not include {needed}.")

    if pre_authority and not errors:
        notes.append(f"{pre_authority} custody event(s) predate this field's "
                     f"authority genesis ({declared_genesis}) and are "
                     "UNAUTHORIZED BY DECLARATION — their integrity is proven, "
                     "their authorization is not claimed.")
    return errors, notes


# --- B3: embedding provenance (transcribed from mneme/bundle.py) -----------

def check_embedding_provenance(mid: str, prov: dict, mem: dict, born: str) -> list:
    """
    Proves: the vector shipped is the vector the record describes, under a
    quantization this verifier implements, and — when the record claims no
    preprocessing — that the model was given exactly the carried content.

    Does NOT prove the model computed it honestly or deterministically.
    The record makes drift detectable and a model change a formal
    migration; it does not make the model trustworthy, and no hash can.
    """
    errors: list = []
    required = ("provider", "model", "revision", "dimension", "preprocessing",
                "input_content_hash", "output_vector_hash",
                "quantization_protocol")
    missing = [k for k in required if k not in prov]
    if missing:
        return [f"{mid}: embedding provenance is missing {missing}."]
    if prov["quantization_protocol"] not in SUPPORTED_QUANTIZATION:
        errors.append(f"{mid}: embedding quantized as "
                      f"{prov['quantization_protocol']!r}, which this verifier "
                      "does not implement — two quantizations are two vectors.")
    if not (isinstance(prov["dimension"], int) and prov["dimension"] > 0):
        errors.append(f"{mid}: embedding provenance dimension "
                      f"{prov['dimension']!r} is not a positive integer.")
    if prov["output_vector_hash"] != mem.get("embedding_sha256"):
        errors.append(f"{mid}: embedding provenance names vector "
                      f"{str(prov['output_vector_hash'])[:16]}… but the bundle "
                      f"carries {str(mem.get('embedding_sha256'))[:16]}… — the "
                      "record describes a different vector than the one shipped.")
    if prov["preprocessing"] == "none" and prov["input_content_hash"] != born:
        errors.append(f"{mid}: embedding provenance declares preprocessing "
                      "'none' but its input_content_hash is not this memory's "
                      "content.")
    return errors


# --- B8: causal provenance (transcribed from mneme/bundle.py) --------------

def receipt_digest_from_row(row: dict, served: list) -> str:
    """The exact body a persisted receipt's digest covers (field.py)."""
    body = {
        "query_sha256": row["query_sha256"],
        "seed_memory_id": row["seed_memory_id"],
        "served": served,
        "excluded_custody": int(row["excluded_custody"]),
        "excluded_forgotten": int(row["excluded_forgotten"]),
        "excluded_inhibited": int(row["excluded_inhibited"]),
        "top_k": int(row["top_k"]),
        "hops": int(row["hops"]),
        "ranking_protocol": row["ranking_protocol"],
        "custody_override": json.loads(row["custody_override_json"])["override"],
        "as_of": row["as_of"],
    }
    return sha256_hex(canonical_json(body).encode("utf-8"))


def decision_body(d: dict, used: list) -> dict:
    """The exact body a decision record's seal covers (causality.py).
    used_memory_ids is sorted: citation order carries no fact the receipt
    does not already hold, so leaving it free would admit two
    representations of one claim."""
    return {
        "decision_id": d["decision_id"],
        "receipt_sha256": d["receipt_sha256"],
        "decision_sha256": d["decision_sha256"],
        "policy_version": d["policy_version"],
        "actor_id": d["actor_id"],
        "reason": d["reason"],
        "used_memory_ids": sorted(used),
        "created_at": d["created_at"],
    }


def verify_causality(body: dict, memory_chains: list) -> tuple[list, list]:
    errors: list = []
    notes: list = []

    receipts_by_sha: dict = {}
    declared_ranking = body.get("protocols", {}).get("ranking_protocol")
    for row in body.get("receipts", []):
        try:
            sha = row["receipt_sha256"]
            served = json.loads(row["served_json"])["served"]
        except Exception:
            errors.append("B8: a carried receipt is malformed.")
            continue
        if receipt_digest_from_row(row, served) != sha:
            errors.append(f"B8: receipt {sha[:16]}…: does not recompute from "
                          "its own columns — receipt evidence edited.")
            continue
        if row.get("ranking_protocol") != declared_ranking:
            errors.append(f"B8: receipt {sha[:16]}…: was produced under "
                          f"ranking_protocol {row.get('ranking_protocol')!r} but "
                          f"this bundle declares {declared_ranking!r}.")
            continue
        try:
            cf = json.loads(row["custody_override_json"])["override"]
        except Exception:
            errors.append(f"B8: receipt {sha[:16]}…: custody_override_json is "
                          "not valid JSON.")
            continue
        receipts_by_sha[sha] = {"served": served, "counterfactual": bool(cf)}

    carried_memories = {mid for mid, _ in memory_chains}
    used_events: dict = {}
    for mid, chain in memory_chains:
        for r in chain:
            if r["event_type"] != "DECISION_USED_MEMORY":
                continue
            did = json.loads(r["payload_json"]).get("decision_id")
            if isinstance(did, str):
                used_events.setdefault(did, set()).add(mid)

    included = body.get("decisions", [])
    excluded = body.get("excluded_decisions", [])
    included_ids = {d.get("decision_id") for d in included}
    excluded_ids = {d.get("decision_id") for d in excluded}
    for did in sorted(included_ids & excluded_ids):
        errors.append(f"B8: decision {did}: declared both included and "
                      "excluded — ambiguity refused.")

    for d, is_included in ([(d, True) for d in included]
                           + [(d, False) for d in excluded]):
        did = d.get("decision_id")
        try:
            used = json.loads(d["used_json"])["used"]
        except Exception:
            errors.append(f"B8: decision {did}: used_json is not valid JSON.")
            continue
        if sha256_hex(canonical_json(decision_body(d, used)).encode("utf-8")) \
                != d.get("record_sha256"):
            errors.append(f"B8: decision {did}: record seal does not recompute "
                          "— decision evidence edited.")
            continue
        rec = receipts_by_sha.get(d["receipt_sha256"])
        if rec is None:
            errors.append(f"B8: decision {did}: cites receipt "
                          f"{d['receipt_sha256'][:16]}…, which this bundle does "
                          "not carry — a causal claim with no anchor.")
            continue
        if rec["counterfactual"]:
            errors.append(f"B8: decision {did}: cites a COUNTERFACTUAL receipt "
                          "— one taken against a hypothetical custody state. "
                          "No agent ever decided from a world that did not "
                          "exist.")
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
                    errors.append(f"B8: decision {did}: names {mid}, but {mid}'s "
                                  "custody chain has no DECISION_USED_MEMORY "
                                  "naming it back.")
        elif set(used) <= carried_memories:
            errors.append(f"B8: decision {did}: declared excluded but the bundle "
                          "carries every memory it used — complete evidence must "
                          "be included and checked, not excluded.")

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
                          "DECISION_USED_MEMORY naming it, but the decision does "
                          "not claim them — a causal link asserted from one side "
                          "only.")

    for d in excluded:
        notes.append(f"decision {d.get('decision_id')} declared excluded — it "
                     "used memories outside this bundle, so its causal evidence "
                     "was NOT checked in full here.")
    return errors, notes


# --- B9: epistemic provenance (transcribed from mneme/claims.py) -----------

def verify_claim_chain(claim_id: str, chain: list, errors: list) -> bool:
    if not chain:
        errors.append(f"B9: {claim_id}: empty claim chain.")
        return False
    expected_prev = sha256_hex(CLAIM_GENESIS_PREFIX + claim_id.encode("utf-8"))
    prev_ts = None
    for i, r in enumerate(chain):
        where = f"B9: {claim_id} claim seq {r.get('seq')}"
        if r.get("seq") != i:
            errors.append(f"{where}: seq not dense (expected {i})."); return False
        et = r.get("event_type")
        if et not in CLAIM_EVENT_TYPES:
            errors.append(f"{where}: unknown event_type {et!r}."); return False
        if i == 0 and et != "CLAIM_ASSERTED":
            errors.append(f"{where}: chain does not begin with CLAIM_ASSERTED."); return False
        if i > 0 and et == "CLAIM_ASSERTED":
            errors.append(f"{where}: CLAIM_ASSERTED after birth."); return False
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
        envelope = {"claim_id": claim_id, "seq": r["seq"], "event_type": et,
                    "actor_id": r["actor_id"], "reason": r["reason"],
                    "created_at": r["created_at"], "payload": payload}
        if sha256_hex(r["prev_hash"].encode("ascii")
                      + canonical_json(envelope).encode("utf-8")) != r["entry_hash"]:
            errors.append(f"{where}: entry_hash does not recompute — claim "
                          "evidence tampered."); return False
        ts = r["created_at"]
        if not isinstance(ts, str) or not TS_PATTERN.match(ts):
            errors.append(f"{where}: created_at {ts!r} is not canonical UTC."); return False
        if prev_ts is not None and ts < prev_ts:
            errors.append(f"{where}: created_at {ts} precedes the previous "
                          "event — a claim's history cannot run backwards."); return False
        prev_ts = ts
        expected_prev = r["entry_hash"]
    return True


def replay_claim(claim_id: str, chain: list, errors: list) -> dict:
    """The claim state machine (normative statement in claims.replay_claim)."""
    st = {"state": "ASSERTED", "statement_sha256": "", "supports": [],
          "contradicts": [], "relations": [], "sets": []}
    for r in chain:
        et, payload = r["event_type"], json.loads(r["payload_json"])
        where = f"B9: {claim_id} claim seq {r['seq']}"
        if et == "CLAIM_ASSERTED":
            sha = payload.get("statement_sha256")
            if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
                errors.append(f"{where}: CLAIM_ASSERTED without a statement hash.")
            st["statement_sha256"] = sha or ""
        elif et == "EVIDENCE_LINKED":
            mid, stance = payload.get("memory_id"), payload.get("stance")
            if not isinstance(mid, str) or stance not in STANCES:
                errors.append(f"{where}: EVIDENCE_LINKED without a memory and a stance.")
            elif stance == "SUPPORTS":
                st["supports"].append(mid)
            else:
                st["contradicts"].append(mid)
        elif et == "RELATED_TO":
            other, rel = payload.get("other_claim_id"), payload.get("relation")
            direction = payload.get("direction")
            if not isinstance(other, str) or rel not in RELATIONS \
                    or direction not in ("OUT", "IN"):
                errors.append(f"{where}: RELATED_TO without a claim, a relation "
                              "and a direction.")
            else:
                st["relations"].append((rel, direction, other))
        elif et == "SET_MEMBERSHIP":
            sid = payload.get("set_id")
            if not isinstance(sid, str):
                errors.append(f"{where}: SET_MEMBERSHIP without a set_id.")
            else:
                st["sets"].append(sid)
        elif et == "CLAIM_VALIDATED":
            if st["state"] != "ASSERTED":
                errors.append(f"{where}: CLAIM_VALIDATED from {st['state']}, "
                              "valid only from ASSERTED.")
            st["state"] = "VALIDATED"
        elif et == "CLAIM_REFUTED":
            if st["state"] not in ("ASSERTED", "VALIDATED"):
                errors.append(f"{where}: CLAIM_REFUTED from {st['state']}.")
            st["state"] = "REFUTED"
        elif et == "CLAIM_WITHDRAWN":
            if st["state"] != "ASSERTED":
                errors.append(f"{where}: CLAIM_WITHDRAWN from {st['state']} — an "
                              "adjudicated claim cannot be taken back.")
            st["state"] = "WITHDRAWN"
        elif et == "CLAIM_SUPERSEDED":
            if st["state"] not in ("ASSERTED", "VALIDATED"):
                errors.append(f"{where}: CLAIM_SUPERSEDED from {st['state']}.")
            st["state"] = "SUPERSEDED"
    st["supports"] = sorted(set(st["supports"]))
    st["contradicts"] = sorted(set(st["contradicts"]))
    st["relations"] = sorted(set(st["relations"]))
    st["sets"] = sorted(set(st["sets"]))
    return st


def evaluate_constraint(constraint_type: str, states: dict) -> tuple:
    """"Holds" means VALIDATED — adjudicated to hold. ASSERTED is under
    consideration; reading "nobody objected yet" as "true" would be
    manufacturing agreement."""
    held = sorted(c for c, s in states.items() if s == "VALIDATED")
    open_ = sorted(c for c, s in states.items() if s == "ASSERTED")
    n = len(states)
    if constraint_type == "AT_MOST_ONE":
        if len(held) > 1:
            return "VIOLATED", f"{len(held)} members hold simultaneously: {held}"
        return ("SATISFIED" if not open_ else "UNDETERMINED",
                f"{len(held)} holding, {len(open_)} still open")
    if constraint_type == "EXACTLY_ONE":
        if len(held) > 1:
            return "VIOLATED", f"{len(held)} members hold simultaneously: {held}"
        if len(held) == 1:
            return ("SATISFIED" if not open_ else "UNDETERMINED",
                    f"{held[0]} holds, {len(open_)} still open")
        if not open_:
            return "VIOLATED", "no member holds, and none is still open"
        return "UNDETERMINED", f"no member holds yet, {len(open_)} still open"
    if len(held) == n:
        return "VIOLATED", "every member holds, and they cannot all hold"
    return ("SATISFIED" if not open_ else "UNDETERMINED",
            f"{len(held)} of {n} holding, {len(open_)} still open")


def verify_claims(body: dict, memory_chains: list) -> tuple:
    errors: list = []
    notes: list = []
    claim_entries = body.get("claims", [])
    if not isinstance(claim_entries, list):
        return ["B9: 'claims' is not a list."], notes

    states, chains = {}, {}
    for entry in sorted(claim_entries, key=lambda e: str(e.get("claim_id"))):
        cid, chain = entry.get("claim_id"), entry.get("chain")
        if not isinstance(cid, str) or not isinstance(chain, list) or not chain:
            errors.append(f"B9: malformed claim entry for {cid!r}.")
            continue
        if not verify_claim_chain(cid, chain, errors):
            continue
        before = len(errors)
        st = replay_claim(cid, chain, errors)
        if len(errors) != before:
            continue
        states[cid], chains[cid] = st, chain
        if entry.get("state") != st["state"]:
            errors.append(f"B9: {cid}: declared state {entry.get('state')!r}, "
                          f"claim replay says {st['state']!r}.")
        statement = entry.get("statement")
        if not isinstance(statement, str) or \
                sha256_hex(statement.encode("utf-8")) != st["statement_sha256"]:
            errors.append(f"B9: {cid}: the statement shipped does not hash to "
                          "the one its assertion sealed.")
        elif entry.get("statement_sha256") != st["statement_sha256"]:
            errors.append(f"B9: {cid}: declared statement_sha256 disagrees with "
                          "the assertion event.")

    for cid in sorted(states):
        for rel, direction, other in states[cid]["relations"]:
            if other not in states:
                errors.append(f"B9: {cid}: relates to {other}, whose chain is "
                              "not in this bundle.")
                continue
            mirror = "IN" if direction == "OUT" else "OUT"
            if (rel, mirror, cid) not in states[other]["relations"]:
                errors.append(f"B9: {cid}: records {rel} {direction} {other}, "
                              f"but {other}'s chain has no matching {rel} "
                              f"{mirror} back — a relation only one side asserts.")

    declared_members = {}
    for sw in body.get("claim_sets", []):
        sid = sw.get("set_id")
        try:
            members = json.loads(sw["members_json"])["members"]
        except Exception:
            errors.append(f"B9: set {sid}: members_json is not valid JSON.")
            continue
        declared_members[sid] = set(members)
        derived = sha256_hex(canonical_json(
            {"members": sorted(members)}).encode("utf-8"))
        if derived != sw.get("members_sha256"):
            errors.append(f"B9: set {sid}: member list does not hash to the seal.")
        absent = sorted(set(members) - set(states))
        if absent:
            errors.append(f"B9: set {sid}: members {absent} are not carried.")
            continue
        for cid in sorted(members):
            if sid not in states[cid]["sets"]:
                errors.append(f"B9: set {sid}: names {cid}, but {cid}'s chain "
                              "carries no SET_MEMBERSHIP for it.")
        status, explanation = evaluate_constraint(
            sw.get("constraint_type"), {c: states[c]["state"] for c in members})
        if sw.get("status") != status:
            errors.append(f"B9: set {sid}: declared {sw.get('status')!r}, but the "
                          f"claim states carried here evaluate to {status!r} "
                          f"({explanation}).")
        if status == "VIOLATED":
            notes.append(f"claim set {sid} is VIOLATED: {explanation}. The bundle "
                         "reports the conflict rather than resolving it.")
    for cid in sorted(states):
        for sid in states[cid]["sets"]:
            if sid not in declared_members:
                errors.append(f"B9: {cid}: claims membership of set {sid}, which "
                              "the bundle does not carry.")
            elif cid not in declared_members[sid]:
                errors.append(f"B9: {cid}: claims membership of set {sid}, whose "
                              "member list does not include it.")

    carried = {mid for mid, _ in memory_chains}
    outside = sorted({m for cid in states
                      for m in (states[cid]["supports"] + states[cid]["contradicts"])
                      if m not in carried})
    if outside:
        notes.append(f"{len(outside)} evidence link(s) point at memories this "
                     "bundle does not carry; those links are named by the claim "
                     "chains but not checkable here.")

    declared_genesis = body.get("authority_genesis_at")
    if isinstance(declared_genesis, str):
        auth = {}
        for entry in body.get("authority", []):
            sid, chain = entry.get("subject_id"), entry.get("chain")
            if isinstance(sid, str) and isinstance(chain, list) and chain:
                local: list = []
                st_ = replay_authority(sid, chain, local)
                if not local:
                    auth[sid] = st_
        for cid in sorted(chains):
            for r in chains[cid]:
                at, payload = r["created_at"], json.loads(r["payload_json"])
                if at < declared_genesis:
                    continue
                where = f"B9: {cid} claim seq {r['seq']} ({r['event_type']})"
                gid, actor = payload.get("grant_id"), r["actor_id"]
                if not isinstance(gid, str):
                    errors.append(f"{where}: no grant_id, and it postdates the "
                                  "authority genesis. Recorded is not authorized.")
                    continue
                if actor not in auth:
                    errors.append(f"{where}: actor {actor!r} has no authority "
                                  "chain in this bundle.")
                    continue
                if quarantined_at(auth[actor], at):
                    errors.append(f"{where}: actor {actor!r} was QUARANTINED at "
                                  f"{at} and held no capability (A5).")
                    continue
                caps = grant_capabilities_at(auth[actor], gid, at)
                needed = CLAIM_EVENT_CAPABILITY[r["event_type"]]
                if caps is None:
                    errors.append(f"{where}: grant {gid!r} was not active for "
                                  f"{actor!r} at {at}.")
                elif needed not in caps:
                    errors.append(f"{where}: grant {gid!r} confers {sorted(caps)}, "
                                  f"which does not include {needed}.")
    return errors, notes


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

def verify(bundle_json: str) -> tuple[bool, list[str], list[str]]:
    """Returns (ok, errors, notes). Notes are claims a PASSING verdict must
    show the auditor rather than bury: declared sweep exclusions, declared
    protocol semantics, unauthorized-by-declaration counts."""
    errors: list[str] = []
    notes: list[str] = []
    try:
        outer = json.loads(bundle_json)
        body, seal = outer["body"], outer["bundle_sha256"]
    except Exception:
        return False, ["Bundle is not valid JSON with body/bundle_sha256."], notes

    try:
        if sha256_hex(canonical_json(body).encode("utf-8")) != seal:
            return False, ["B1: bundle_sha256 does not recompute — bundle tampered as a whole."], notes
    except ValueError as e:
        return False, [f"B1: body is not canonicalizable: {e}"], notes
    if body.get("format") != FORMAT:
        return False, [f"Unknown bundle format {body.get('format')!r} (this "
                       f"verifier implements {FORMAT}). A bundle sealed under "
                       "an older format was checked under semantics it never "
                       "declared; verify it with a verifier of its era."], notes

    perrors = check_protocols(body.get("protocols"))
    if perrors:
        return False, [f"B0: {e}" for e in perrors], notes
    notes.append("semantics: " + ", ".join(
        f"{k} {body['protocols'][k]}" for k in PROTOCOL_NAMES))
    vocabulary = EVENT_TYPES_BY_PROTOCOL[body["protocols"]["custody_protocol"]]

    heads: dict[str, str] = {}
    tf_by_sweep: dict[str, list[str]] = {}
    stored_supersedes: dict[str, str] = {}   # successor -> claimed predecessor
    successors: dict[str, set[str]] = {}     # predecessor -> SUPERSEDED_BY names
    verified_chains: list = []
    declared_provenance = 0
    undeclared_provenance = 0

    for mem in body.get("memories", []):
        mid = mem["memory_id"]
        chain = mem["custody"]
        if not verify_chain(mid, chain, errors, vocabulary):
            continue
        heads[mid] = chain[-1]["entry_hash"]
        verified_chains.append((mid, chain))

        birth = json.loads(chain[0]["payload_json"])
        if isinstance(birth.get("supersedes"), str):
            stored_supersedes[mid] = birth["supersedes"]
        born = birth["content_sha256"]
        if sha256_hex(mem["content"].encode("utf-8")) != born:
            errors.append(f"B3: {mid}: content does not hash to the STORED seal.")
        if mem.get("content_sha256") != born:
            errors.append(f"B3: {mid}: declared content_sha256 disagrees with birth event.")
        prov = birth.get("embedding_provenance")
        if isinstance(prov, dict):
            declared_provenance += 1
            errors.extend(f"B3: {e}" for e in
                          check_embedding_provenance(mid, prov, mem, born))
        else:
            undeclared_provenance += 1

        status, fstate, conf = replay_state(
            chain, errors, body["protocols"]["replay_protocol"])
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

    # taint_protocol 2.0.0: RE-DERIVE the flagged set from custody evidence
    # rather than only checking that the sweep agrees with itself. Under 1.x
    # a sweep could over-flag or under-flag and pass every check, because
    # its seal was computed over whatever it chose to flag.
    if body["protocols"]["taint_protocol"] == "2.0.0":
        for sw in included:
            sid, actor, at = (sw["sweep_id"], sw["quarantined_actor"],
                              sw["created_at"])
            flagged = set(tf_by_sweep.get(sid, []))
            for mid, chain in verified_chains:
                influenced = any(
                    r["actor_id"] == actor
                    and r["event_type"] not in NON_INFLUENCE_EVENTS
                    and r["created_at"] <= at
                    for r in chain)
                if influenced and mid not in flagged:
                    errors.append(f"B5: sweep {sid}: {mid} carries an "
                                  f"influencing event by {actor} at or before "
                                  "the sweep, but the sweep did not flag it — "
                                  "under-flagged.")
                elif mid in flagged and not influenced:
                    errors.append(f"B5: sweep {sid}: {mid} was flagged, but "
                                  f"nothing in its chain shows {actor} "
                                  "influencing it before the sweep — "
                                  "over-flagged.")

    if undeclared_provenance:
        notes.append(f"{undeclared_provenance} of "
                     f"{declared_provenance + undeclared_provenance} memories "
                     "declare no embedding provenance: for those, the embedding "
                     "boundary is trusted and its drift undetectable. Stated, "
                     "not hidden.")

    for sw in excluded:
        notes.append(f"sweep {sw['sweep_id']} declared excluded — its seal was "
                     "NOT checked against evidence in this bundle.")

    if heads_merkle_root(heads) != body.get("heads_merkle_root"):
        errors.append("B6: heads_merkle_root does not recompute.")

    aerrors, anotes = verify_authority(body, verified_chains)
    errors.extend(aerrors)
    notes.extend(anotes)

    cerrors, cnotes = verify_causality(body, verified_chains)
    errors.extend(cerrors)
    notes.extend(cnotes)

    clerrors, clnotes = verify_claims(body, verified_chains)
    errors.extend(clerrors)
    notes.extend(clnotes)

    return (not errors), errors, notes


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        raw = f.read()
    ok, errors, notes = verify(raw)
    if ok:
        print("VERIFIED: every check (B0-B9) passed.")
        # A declared exclusion is a claim the auditor must SEE, not
        # something a passing verdict may bury. So is a field whose events
        # nobody was ever authorized to cause.
        for n in notes:
            print(f"  NOTE: {n}")
        return 0
    print(f"FAILED: {len(errors)} problem(s).")
    for e in errors:
        print(f"  {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
