"""
MNEME — The authority ledger. Custody says WHAT happened; authority says
who was ALLOWED to cause it.

Security audit Round 2 found the conceptual gap this module closes, and
stated it better than a feature request could: *an audit trail is not an
authorization system*. A quarantined actor could keep storing and
reinforcing; any caller could nominate itself as the rehabilitation
authority by choosing a string. Every one of those actions was recorded
perfectly. None of them was authorized by anything.

So a mutation in MNEME now carries TWO separable proofs:

    integrity provenance   the per-memory custody chain (custody.py) —
                           this event happened, in this order, unedited.

    authority provenance   the per-actor authority chain (this module) —
                           the actor that caused it held, at that instant,
                           an unrevoked grant of the capability the event
                           required, and was not under quarantine.

Neither implies the other. A chain can be perfect and the act
unauthorized; a grant can be valid and the chain forged. Bundle check B7
demands both, and the two are checked against different evidence.

WHY NOT `role == "ADMIN"`
    Because a role is a claim about a person and a capability is a claim
    about an act. "Anna is an admin" is unfalsifiable in a bundle; "grant
    g-4f2 conferred REHABILITATE on analyst-anna at 14:02:11, was issued
    by root-operator who held REHABILITATE and GRANT, and had not been
    revoked when the REHABILITATED event was written at 14:03:17" is an
    arithmetic statement an auditor can check offline with a hash
    function. Capabilities are what fits in an evidence bundle.

Design decisions, each load-bearing:

  GENESIS IS BOUND TO THE ACTOR ID.
      Same rule as custody, same reason: prev_hash of seq 0 is
      sha256(b"MNEME_AUTHORITY_GENESIS:" || actor_id), so one actor's
      grant history cannot be presented as another's.

  AUTHORITY IS REPLAYED, NEVER READ FROM A COLUMN.
      `actors.status` and "what can X do" are derived by replaying the
      chain. The column is a cache that B7 re-derives, exactly as B4
      re-derives custody_status. A hand-edited status is self-revealing.

  NO AMPLIFICATION (A3).
      A grantor cannot confer a capability it does not itself hold. This
      is the invariant that makes the ledger a tree rooted at one
      auditable act rather than a graph where authority can appear from
      nowhere. Its consequence: every capability any actor holds traces
      back, by a path of checkable grants, to the root bootstrap.

  QUARANTINE IS A WRITE BARRIER, NOT ONLY A SWEEP (A5).
      Round 2's R2-01. A QUARANTINED actor holds NO effective capability
      — not "its old memories are flagged", but "it cannot write".
      Enforced in the same transaction as the mutation, and re-checked
      at verification time against the event's own timestamp.

  THE FIELD IS NEVER LEFT UNGOVERNABLE (A6).
      The field always retains at least one ACTIVE actor holding GRANT,
      and EVERY path that could reduce that set is guarded: revoking the
      last GRANT-conferring grant, and QUARANTINING its last holder.
      Enforced by a counter under a CHECK with the guard inside the
      UPDATE, so it is a constraint rather than a promise and two
      concurrent losses serialise on one row rather than on an isolation
      level. Without it, two individually legitimate acts — quarantine the
      only GRANT holder, then let the responder rotate itself off — leave
      a field that can never grant, register or reinstate again.

Invariants (A for Authority):
  A1  Every custody event sealed under authority_protocol names the grant
      it acted under; both proofs travel or neither does.
  A2  Authority chains are per-actor, append-only, hash-linked, genesis
      bound to actor_id, seq dense from 0.
  A3  No amplification: a grantor may only grant what it holds.
  A4  Revocation is an event, never a deletion. A revoked grant stays on
      the chain with the instant it died.
  A5  A QUARANTINED actor's effective capability set is empty, at every
      instant inside the quarantine interval.
  A6  The field always retains at least one ACTIVE actor holding GRANT.
      Guarded on every path that could reduce the set — revocation AND
      quarantine — by a constraint, not by a read.

THE BOOTSTRAP, stated plainly because hiding it would be the one
dishonest thing this module could do: authority has to start somewhere,
and the first grant cannot itself be authorized. `bootstrap_root()` is
that act. It is refused if ANY authority chain already exists, so it can
happen exactly once per field and the whole ledger hangs from it. What
this buys: the root act is a single, named, timestamped, hash-chained
event an auditor can point at. What it does not buy: proof that the
right party performed it. Whoever bootstraps an empty field is its root;
binding that to an external identity (an operator key, a notarised
ceremony) is a deployment concern, not a protocol one.

Hash formula (mirrors custody's, different genesis prefix and envelope):

    entry_hash = sha256(
        prev_hash
        || canonical_json({
             "subject_id": subject_id,
             "seq":        seq,
             "event_type": event_type,
             "issuer_id":  issuer_id,
             "reason":     reason,
             "created_at": <canonical timestamp string>,
             "payload":    payload,
           })
    )

As everywhere: every function takes a live cursor and NEVER commits.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field as _dc_field
from typing import Any

from .canonical import canonical_json
from . import chain as _chain
from . import custody

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# The closed capability set. Closed for the same reason the custody event
# vocabulary is closed: an open set is where unaudited power gets minted.
CAPABILITIES = frozenset(
    {
        "STORE",             # create memories
        "REINFORCE",         # raise confidence (and the promotion it triggers)
        "SUPERSEDE",         # replace a memory, both sides of the lineage
        "QUARANTINE_ACTOR",  # run a taint sweep; reinstate an actor
        "QUARANTINE_MEMORY", # direct evidence against one memory
        "REHABILITATE",      # reverse a taint flag
        "GRANT",             # confer capabilities on another actor
        "REVOKE",            # end a grant
        "DECIDE",            # emit a decision record binding a recall receipt
        "ASSERT",            # assert a proposition, link evidence, relate claims
        "ADJUDICATE",        # decide between mutually exclusive hypotheses
        "COUNTERFACTUAL",    # run a recall against a WIDER custody state
    }
)

AUTHORITY_EVENT_TYPES = frozenset(
    {
        "ACTOR_REGISTERED",   # seq 0, always; the identity begins
        "GRANTED",            # payload: grant_id, capabilities, root
        "REVOKED",            # payload: grant_id
        "ACTOR_QUARANTINED",  # A5 begins: effective capabilities become empty
        "ACTOR_REINSTATED",   # A5 ends
    }
)

# Which capability each CUSTODY event type requires of its actor. This map
# is part of authority_protocol: changing a row here changes what old
# bundles would be checked against, so it changes the version.
#
# STATE_CHANGED maps to REINFORCE because reinforce() is its only emitter
# today (the promotion across the confidence threshold). A second emitter —
# the stylometry pipeline named in KNOWN_LIMITATIONS is the obvious
# candidate — arrives with its own capability and its own version bump, not
# by widening this row.
#
# COUNTERFACTUAL is the one capability that governs a READ, and it exists
# because of a hole this project put there itself. `custody_override` lets
# a recall run against a hypothetical custody state — the primitive the
# whole counterfactual analysis is built on — and forcing a QUARANTINED
# memory to CLEAN made its CONTENT servable to anyone who could call
# recall(). The custody gate is the thing MNEME is for, and a read path
# that steps around it is not a smaller problem for being a read.
#
# Only the WIDENING direction is gated, and the asymmetry is the point: an
# override that makes something servable can reveal what the gate withheld;
# one that only makes something UNservable can show a caller strictly less
# than it could already see. So `exclusion_effect` ("what would quarantining
# these do?") stays open to anyone, and `containment_effect` ("what would
# they have shown?") does not.
#
# ASSERT and ADJUDICATE are separate from STORE and from each other because
# the acts are different in kind: storing a document, asserting that a
# proposition is true, and ruling between competing hypotheses are three
# different authorities, and a model that cannot tell them apart is a role
# system wearing capability vocabulary.
#
# DECISION_USED_MEMORY maps to DECIDE and to nothing else. Recording that a
# decision consumed a memory changes no memory state, but it is a claim
# about causation that an incident will later be reconstructed from, so an
# actor that may merely read must not be able to write one.
REQUIRED_CAPABILITY: dict[str, str] = {
    "STORED": "STORE",
    "REINFORCED": "REINFORCE",
    "CONTRADICTED_BY": "STORE",   # written as a side effect of storing
    "SUPERSEDED_BY": "SUPERSEDE",
    "QUARANTINED": "QUARANTINE_MEMORY",
    "TAINT_FLAGGED": "QUARANTINE_ACTOR",
    "REHABILITATED": "REHABILITATE",
    "STATE_CHANGED": "REINFORCE",
    "DECISION_USED_MEMORY": "DECIDE",
}

# Which capability each AUTHORITY event type requires of its ISSUER. The
# ledger governs itself by the same rule it governs memories by: an
# authority event is an act, and every act needs a grant behind it.
#
# The root bootstrap is the one exemption, and it is structural rather than
# discretionary: its two events are self-issued on an empty ledger, which
# can happen exactly once per field.
AUTHORITY_EVENT_CAPABILITY: dict[str, str] = {
    "ACTOR_REGISTERED": "GRANT",
    "GRANTED": "GRANT",
    "REVOKED": "REVOKE",
    "ACTOR_QUARANTINED": "QUARANTINE_ACTOR",
    "ACTOR_REINSTATED": "QUARANTINE_ACTOR",
}

_GRANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:]{1,64}$")

# ---------------------------------------------------------------------------
# The chain shape, declared
# ---------------------------------------------------------------------------

# Authority's instance of the shared chain core (mneme/chain.py). Same
# shape as custody's — genesis bound to the subject, the same hashed
# envelope, dense seq, one birth event — over a different table, a
# different prefix, and different words. What is NOT here is what an
# authority event means: that is replay_authority(), below, and it is the
# part that has no custody analogue.
#
# birth_payload_check is absent on purpose: registering an identity seals
# nothing. Custody's birth seals content, claims' birth seals a statement;
# an actor is simply declared to exist, and what it may DO arrives later,
# as GRANTED events an issuer had to be authorized to write.
SPEC = _chain.ChainSpec(
    kind="authority",
    table="authority_chain",
    genesis_prefix=b"MNEME_AUTHORITY_GENESIS:",
    subject_key="subject_id",
    actor_key="issuer_id",
    birth_event="ACTOR_REGISTERED",
    event_types=AUTHORITY_EVENT_TYPES,
    where_fmt="{subject} authority seq {seq}",
    empty_chain=("{subject}: empty authority chain — an actor with no "
                 "registration event."),
    birth_required=("First authority event for {subject} must be "
                    "ACTOR_REGISTERED, got {event}. An identity is "
                    "registered before it is empowered."),
    birth_repeated=("{subject} already has an authority chain; registration "
                    "is a birth event and an identity is born once."),
    unknown_event=("Unknown authority event_type {event!r}. The vocabulary "
                   "is closed; extending it is a protocol change, not a "
                   "call-site choice."),
    unreasoned=("reason must be a non-empty string — an unreasoned grant "
                "is a grant nobody can review."),
    tampered="grant tampered",
    rogue_offset="grant lifetimes",
)

_AUTHORITY_GENESIS_PREFIX = SPEC.genesis_prefix

AUTHORITY_COLS = SPEC.columns


def required_capability(event_type: str, payload: dict[str, Any]) -> str:
    """
    The capability a custody event demanded of its actor.

    One payload-sensitive case: a STORED event whose payload names a
    predecessor is the successor half of a supersession, so it requires
    SUPERSEDE and not merely STORE. Otherwise an actor holding STORE
    alone could retire any memory in the field by storing over it.
    """
    if event_type == "STORED" and isinstance(payload.get("supersedes"), str):
        return "SUPERSEDE"
    try:
        return REQUIRED_CAPABILITY[event_type]
    except KeyError:
        raise ValueError(
            f"No capability is mapped for custody event_type {event_type!r}. "
            "An event nobody is required to be authorized for is an "
            "authority hole; map it or do not emit it."
        ) from None


def authority_genesis_hash(subject_id: str) -> str:
    return _chain.genesis_hash(SPEC, subject_id)


# ---------------------------------------------------------------------------
# Hashing / append
# ---------------------------------------------------------------------------

def compute_authority_hash(
    *,
    prev_hash: str,
    subject_id: str,
    seq: int,
    event_type: str,
    issuer_id: str,
    reason: str,
    created_at: str,
    payload: dict[str, Any],
) -> tuple[str, str]:
    """Returns (entry_hash, canonical_payload_json). Same contract as custody —
    now literally the same code, in chain.compute_hash."""
    return _chain.compute_hash(
        SPEC, prev_hash=prev_hash, subject_id=subject_id, seq=seq,
        event_type=event_type, actor_id=issuer_id, reason=reason,
        created_at=created_at, payload=payload)


@dataclass(frozen=True)
class AuthorityEntry:
    subject_id: str
    seq: int
    event_type: str
    issuer_id: str
    reason: str
    created_at: str
    payload_json: str
    prev_hash: str
    entry_hash: str


def append_authority_event(
    cur,
    *,
    subject_id: str,
    event_type: str,
    issuer_id: str,
    reason: str,
    payload: dict[str, Any],
    created_at: str | None = None,
) -> AuthorityEntry:
    """
    Append one authority event. NEVER commits — the caller's transaction
    also carries whatever this event authorizes or records.
    """
    seq, prev_hash, entry_hash, payload_canon, ts = _chain.append(
        cur, SPEC, subject_id=subject_id, event_type=event_type,
        actor_id=issuer_id, reason=reason, payload=payload,
        created_at=created_at)
    return AuthorityEntry(
        subject_id=subject_id, seq=seq, event_type=event_type,
        issuer_id=issuer_id, reason=reason, created_at=ts,
        payload_json=payload_canon, prev_hash=prev_hash, entry_hash=entry_hash,
    )


# ---------------------------------------------------------------------------
# Verification + replay (pure over rows; the offline verifier transcribes both)
# ---------------------------------------------------------------------------

def verify_authority_rows(subject_id: str,
                          rows: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """
    Verify one actor's full authority chain, given rows in ASCENDING seq.
    Pure — the same checks as custody's chain verification, because it is
    the same implementation (chain.verify_rows) against the authority
    envelope and genesis. Structure first; meaning comes after, in
    replay_authority().
    """
    return _chain.verify_rows(SPEC, subject_id, rows)


@dataclass
class AuthorityState:
    """
    The replayed meaning of one actor's authority chain.

    grants maps grant_id -> {"capabilities": tuple, "granted_at": ts,
    "revoked_at": ts | None}. quarantine_intervals is a list of
    [from_ts, to_ts | None] half-open windows. Both are what capability
    questions are answered from — never a column.
    """
    subject_id: str
    registered_at: str = ""
    registered_by: str = ""
    status: str = "ACTIVE"
    grants: dict[str, dict[str, Any]] = _dc_field(default_factory=dict)
    quarantine_intervals: list[list[str | None]] = _dc_field(default_factory=list)
    is_root: bool = False


def replay_authority(subject_id: str,
                     rows: list[dict[str, Any]]) -> tuple[AuthorityState, list[str]]:
    """
    Replay a (structurally verified) authority chain into its meaning.
    Pure; the standalone verifier transcribes this function.

    Normative statement — the single place authority semantics are written
    down, transcribed verbatim by verify_offline.py:

      status: starts ACTIVE at ACTOR_REGISTERED.
          ACTOR_QUARANTINED  -> QUARANTINED, valid only from ACTIVE, opens
                                a quarantine interval at its created_at
          ACTOR_REINSTATED   -> ACTIVE, valid only from QUARANTINED, closes
                                the open interval at its created_at
      grants: GRANTED introduces grant_id with its capability list and
          granted_at; a grant_id already on the chain is refused (reuse
          would make "which grant" ambiguous at verification time).
          Capabilities must be a non-empty, sorted, duplicate-free list
          drawn from the closed vocabulary — canonical form, so two
          writers describing one grant produce one hash.
          REVOKED sets revoked_at on a named, not-yet-revoked grant.
      root: exactly one grant on one chain in a field may carry
          "root": true; it is the bootstrap and its issuer is its own
          subject. A non-root grant claiming root, or a root grant issued
          by anyone else, is refused here.
    """
    state = AuthorityState(subject_id=subject_id)
    errors: list[str] = []
    for r in rows:
        et = r["event_type"]
        where = f"{subject_id} authority seq {r['seq']}"
        payload = json.loads(r["payload_json"])

        if et == "ACTOR_REGISTERED":
            state.registered_at = r["created_at"]
            state.registered_by = r["issuer_id"]

        elif et == "GRANTED":
            gid = payload.get("grant_id")
            caps = payload.get("capabilities")
            is_root = payload.get("root", False)
            if not (isinstance(gid, str) and _GRANT_ID_PATTERN.match(gid)):
                errors.append(f"{where}: GRANTED without a well-formed grant_id.")
                continue
            if gid in state.grants:
                errors.append(f"{where}: grant_id {gid!r} reused — 'which grant '"
                              "authorized this' must have one answer.")
                continue
            if not (isinstance(caps, list) and caps
                    and all(isinstance(c, str) for c in caps)):
                errors.append(f"{where}: GRANTED without a capability list.")
                continue
            unknown = [c for c in caps if c not in CAPABILITIES]
            if unknown:
                errors.append(f"{where}: unknown capabilities "
                              f"{sorted(unknown)} — the vocabulary is closed.")
                continue
            if list(caps) != sorted(set(caps)):
                errors.append(f"{where}: capability list is not sorted and "
                              "duplicate-free — one grant, one canonical form.")
                continue
            if not isinstance(is_root, bool):
                errors.append(f"{where}: GRANTED 'root' is not a boolean.")
                continue
            if is_root:
                if r["issuer_id"] != subject_id:
                    errors.append(f"{where}: a root grant must be self-issued; "
                                  f"this one names issuer {r['issuer_id']!r}.")
                    continue
                if set(caps) != set(CAPABILITIES):
                    errors.append(f"{where}: a root grant must confer the whole "
                                  "capability vocabulary — a partial root is a "
                                  "field that can never be fully governed.")
                    continue
                state.is_root = True
            state.grants[gid] = {
                "capabilities": tuple(caps),
                "granted_at": r["created_at"],
                "granted_by": r["issuer_id"],
                "revoked_at": None,
                "root": is_root,
            }

        elif et == "REVOKED":
            gid = payload.get("grant_id")
            if not isinstance(gid, str) or gid not in state.grants:
                errors.append(f"{where}: REVOKED names grant {gid!r}, which this "
                              "chain never granted.")
                continue
            if state.grants[gid]["revoked_at"] is not None:
                errors.append(f"{where}: grant {gid} revoked twice — the second "
                              "revocation records nothing the first did not.")
                continue
            state.grants[gid]["revoked_at"] = r["created_at"]

        elif et == "ACTOR_QUARANTINED":
            if state.status != "ACTIVE":
                errors.append(f"{where}: ACTOR_QUARANTINED from {state.status}, "
                              "valid only from ACTIVE.")
            state.status = "QUARANTINED"
            state.quarantine_intervals.append([r["created_at"], None])

        elif et == "ACTOR_REINSTATED":
            if state.status != "QUARANTINED":
                errors.append(f"{where}: ACTOR_REINSTATED from {state.status}, "
                              "valid only from QUARANTINED.")
            elif state.quarantine_intervals:
                state.quarantine_intervals[-1][1] = r["created_at"]
            state.status = "ACTIVE"

    return state, errors


def quarantined_at(state: AuthorityState, at_ts: str) -> bool:
    """
    Half-open [from, to): an actor is quarantined from the exact instant
    the ACTOR_QUARANTINED event bears, and free again from the exact
    instant of its reinstatement. The inclusive lower bound is the safe
    direction — a write sharing a microsecond with its own quarantine is
    refused, not admitted.
    """
    for lo, hi in state.quarantine_intervals:
        if lo <= at_ts and (hi is None or at_ts < hi):
            return True
    return False


def capabilities_before(rows: list[dict[str, Any]], subject_id: str,
                        seq: int, at_ts: str) -> frozenset[str]:
    """
    What the issuer held IMMEDIATELY BEFORE its own event at `seq`.

    THE RULE, and it took an audit to find that it was missing: an
    authority event is authorized by the state BEFORE it, never by the
    state it creates. Evaluating the full replay at the event's timestamp
    reads the event's own effect back into its own authorization, and for
    exactly one act that is fatal — SELF-REVOCATION. An actor rotating
    itself off revokes its own grant; the grant dies at that instant; and
    B7, replaying everything, then finds the issuer did not hold REVOKE
    when it revoked. An ordinary, honest operation produced an
    unverifiable bundle, while the write path — which checks before
    appending — allowed it. The two halves of the same rule disagreed.

    Only the issuer's OWN chain can contain the event under evaluation,
    so the prefix is taken only when issuer and subject coincide.
    """
    prefix = [r for r in rows if r["seq"] < seq]
    if not prefix:
        return frozenset()
    state, errors = replay_authority(subject_id, prefix)
    if errors:
        return frozenset()
    return capabilities_at(state, at_ts)


def grant_capabilities_at(state: AuthorityState, grant_id: str,
                          at_ts: str) -> frozenset[str] | None:
    """
    What grant_id conferred at at_ts, or None if it did not exist yet, was
    already revoked, or never existed. Quarantine is NOT applied here —
    callers combine the two, and keeping them separate lets an auditor see
    'the grant was valid but the actor was contained', which is a
    different sentence from 'there was no such grant'.
    """
    g = state.grants.get(grant_id)
    if g is None:
        return None
    if g["granted_at"] > at_ts:
        return None
    if g["revoked_at"] is not None and g["revoked_at"] <= at_ts:
        return None
    return frozenset(g["capabilities"])


def capabilities_at(state: AuthorityState, at_ts: str) -> frozenset[str]:
    """Effective capability set at an instant. A5: quarantine empties it."""
    if quarantined_at(state, at_ts):
        return frozenset()
    out: set[str] = set()
    for gid in state.grants:
        caps = grant_capabilities_at(state, gid, at_ts)
        if caps:
            out |= caps
    return frozenset(out)


def verify_authority_chain(cur, subject_id: str) -> tuple[bool, list[str]]:
    """Load and verify one actor's authority chain (structure, then meaning)."""
    rows = load_authority_rows(cur, subject_id)
    ok, errors = verify_authority_rows(subject_id, rows)
    if not ok:
        return False, errors
    _, rerrors = replay_authority(subject_id, rows)
    return (not rerrors), rerrors


def load_authority_rows(cur, subject_id: str) -> list[dict[str, Any]]:
    return _chain.load_rows(cur, SPEC, subject_id)


def load_state(cur, subject_id: str) -> AuthorityState:
    """
    Replay one actor's authority from the database. Raises if the chain
    does not verify — a capability question answered from a broken chain
    is worse than no answer.
    """
    rows = load_authority_rows(cur, subject_id)
    ok, errors = verify_authority_rows(subject_id, rows)
    if not ok:
        raise ValueError(
            f"Authority chain for {subject_id!r} does not verify: {errors[0]}"
        )
    state, rerrors = replay_authority(subject_id, rows)
    if rerrors:
        raise ValueError(
            f"Authority chain for {subject_id!r} does not replay: {rerrors[0]}"
        )
    return state


# ---------------------------------------------------------------------------
# The write gate
# ---------------------------------------------------------------------------

def require(cur, *, actor_id: str, capability: str, at_ts: str,
            grant_id: str | None = None) -> str:
    """
    THE gate. Returns the grant_id the actor acts under, or raises with
    our words. Every mutator calls this BEFORE it changes anything, in the
    caller's transaction, with the timestamp the custody event will bear —
    so the authority proof and the integrity proof describe the same
    instant.

    grant_id=None resolves deterministically: the lexicographically
    smallest active grant conferring the capability. Determinism matters
    because the chosen id is sealed into the custody payload — two runs of
    the same operation against the same state must name the same grant or
    the evidence is not reproducible.
    """
    if capability not in CAPABILITIES:
        raise ValueError(f"Unknown capability {capability!r}.")
    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,))
    if cur.fetchone() is None:
        raise ValueError(
            f"Unknown actor {actor_id!r} — a mutation names a registered "
            "identity, and registering one is itself an authorized act."
        )
    rows = load_authority_rows(cur, actor_id)
    if not rows:
        raise ValueError(
            f"Actor {actor_id!r} has no authority chain. It was registered "
            "outside the ledger (a legacy row) and holds nothing; grant it "
            "what it needs, on the record, or refuse the write."
        )
    state = load_state(cur, actor_id)

    if quarantined_at(state, at_ts):
        raise ValueError(
            f"Actor {actor_id!r} is QUARANTINED at {at_ts} and holds no "
            f"capability — {capability} refused. Quarantine is a write "
            "barrier, not a note in the margin (Invariant A5)."
        )

    if grant_id is not None:
        caps = grant_capabilities_at(state, grant_id, at_ts)
        if caps is None:
            raise ValueError(
                f"Grant {grant_id!r} was not active for {actor_id!r} at "
                f"{at_ts} (never issued, not yet issued, or already revoked)."
            )
        if capability not in caps:
            raise ValueError(
                f"Grant {grant_id!r} confers {sorted(caps)} and does not "
                f"include {capability}."
            )
        return grant_id

    candidates = sorted(
        gid for gid in state.grants
        if capability in (grant_capabilities_at(state, gid, at_ts) or frozenset())
    )
    if not candidates:
        raise ValueError(
            f"Actor {actor_id!r} holds no active grant conferring "
            f"{capability} at {at_ts}. Custody would have recorded this act "
            "perfectly; authority refuses it."
        )
    return candidates[0]


def ledger_exists(cur) -> bool:
    cur.execute("SELECT 1 FROM authority_chain LIMIT 1")
    return cur.fetchone() is not None


def root_subjects(cur) -> list[str]:
    """
    EVERY actor whose chain carries a self-issued root grant, sorted.

    Plural on purpose, and the plural is the fix. B7 checks that a ledger
    declares exactly ONE root — but `export_bundle` used to seed its
    authority closure from a singular `root_subject()`, so a field with
    two roots shipped only the first and the check counted one and passed.
    A check that cannot see the thing it checks is not a check.

    Found from evidence — the chains themselves — never from
    `ledger_root`, which is a write-time constraint and not the record.
    """
    cur.execute(
        "SELECT subject_id, payload_json FROM authority_chain "
        "WHERE event_type = 'GRANTED' ORDER BY subject_id ASC, seq ASC")
    out: list[str] = []
    for sid, pj in cur.fetchall():
        if json.loads(pj).get("root") is True and sid not in out:
            out.append(sid)
    return out


def root_subject(cur) -> str | None:
    """The first root, for callers that want to name one. Prefer
    root_subjects() anywhere the COUNT matters."""
    roots = root_subjects(cur)
    return roots[0] if roots else None


def genesis_at(cur) -> str | None:
    """
    When authority began in this field, or None if it never did. Bundles
    declare this value so a verifier can tell 'this event predates the
    ledger' from 'this event dodged it' — see B7.
    """
    cur.execute("SELECT MIN(created_at) FROM authority_chain")
    row = cur.fetchone()
    return row[0] if row and row[0] else None


def gate(cur, *, actor_id: str, capability: str, at_ts: str,
         grant_id: str | None = None) -> str | None:
    """
    The gate as the mutators call it. Two regimes, and which one a field is
    in is a fact about the field, never a flag someone passes:

      NO LEDGER    No authority chain exists. Every write is
                   UNAUTHORIZED BY DECLARATION: it proceeds, records no
                   grant_id, and the bundle says so in words on every
                   successful verification. This is the pre-authority
                   state of the world, stated rather than assumed — and
                   the only reason it exists is that fields written before
                   this module must stay verifiable as what they are, not
                   be retroactively described as authorized.

      LEDGER       Someone bootstrapped a root. From that instant the gate
                   is live for every actor, permanently: nothing deletes
                   an authority chain, so a field cannot leave this regime.

    Returns the grant_id to seal into the custody payload, or None in the
    no-ledger regime.
    """
    if not ledger_exists(cur):
        return None
    return require(cur, actor_id=actor_id, capability=capability,
                   at_ts=at_ts, grant_id=grant_id)


def effective_capabilities(cur, actor_id: str, at_ts: str | None = None) -> frozenset[str]:
    """What actor_id can do right now (or at a stated instant)."""
    rows = load_authority_rows(cur, actor_id)
    if not rows:
        return frozenset()
    return capabilities_at(load_state(cur, actor_id),
                           at_ts if at_ts is not None else custody.now_ts())


def actors_holding_grant(cur, at_ts: str) -> list[str]:
    """
    Every actor with an effective GRANT at at_ts, derived from the chains.
    This is the TRUTH; `governance.grant_holders` is a cache of its size,
    and B7 re-derives it the same way.
    """
    cur.execute("SELECT DISTINCT subject_id FROM authority_chain ORDER BY subject_id ASC")
    holders: list[str] = []
    for (sid,) in cur.fetchall():
        state = load_state(cur, sid)
        if "GRANT" in capabilities_at(state, at_ts):
            holders.append(sid)
    return holders


def _holds_grant(cur, subject_id: str, at_ts: str) -> bool:
    cur.execute("SELECT 1 FROM authority_chain WHERE subject_id = ? LIMIT 1",
                (subject_id,))
    if cur.fetchone() is None:
        return False
    return "GRANT" in capabilities_at(load_state(cur, subject_id), at_ts)


def _governance_row(cur, at_ts: str) -> None:
    """
    Materialise the A6 counter for a field bootstrapped before it existed.
    The count is derived from the chains, so a lazy migration is a cache
    fill and not a new claim.
    """
    cur.execute("SELECT grant_holders FROM governance WHERE singleton = 1")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO governance (singleton, grant_holders) "
                    "VALUES (1, ?)", (max(1, len(actors_holding_grant(cur, at_ts))),))


def _governance_gain(cur, at_ts: str) -> None:
    """One more actor holds GRANT. Unconditional: A6 only ever refuses a loss."""
    _governance_row(cur, at_ts)
    cur.execute("UPDATE governance SET grant_holders = grant_holders + 1 "
                "WHERE singleton = 1")


def _governance_lose(cur, at_ts: str, what: str) -> None:
    """
    One fewer actor holds GRANT — refused if it would be the last.

    A6 as a CONSTRAINT rather than a promise. The guard lives inside the
    UPDATE, so two concurrent losses serialise on the governance row's lock
    under every engine rather than on an isolation level a config flip can
    change; and the column's CHECK (grant_holders >= 1) makes zero a
    constraint violation even if some future caller forgets this function.
    """
    _governance_row(cur, at_ts)
    cur.execute("UPDATE governance SET grant_holders = grant_holders - 1 "
                "WHERE singleton = 1 AND grant_holders > 1")
    if cur.rowcount != 1:
        raise ValueError(
            f"Refusing to {what}: it would leave the field with no actor "
            "holding GRANT — unable to authorize any future act, including "
            "its own repair (Invariant A6). A field nobody can govern is "
            "indistinguishable from a successful attack."
        )


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

def _new_grant_id() -> str:
    return f"grant-{uuid.uuid4().hex[:16]}"


def bootstrap_root(
    cur,
    *,
    actor_id: str,
    display_name: str,
    reason: str,
    kind: str = "HUMAN",
    created_at: str | None = None,
) -> str:
    """
    The one act authority cannot authorize. Refused if ANY authority chain
    exists in the field, so it happens exactly once and everything else
    hangs from it.

    Returns the root grant_id. The root grant confers the entire
    capability vocabulary: a partial root is a field with powers nobody
    can ever exercise or delegate.
    """
    cur.execute("SELECT COUNT(*) FROM authority_chain")
    if int(cur.fetchone()[0]) != 0:
        raise ValueError(
            "This field already has an authority ledger. The root act is "
            "unrepeatable by construction — a second root would be a second "
            "source of power with no grant behind it, which is the exact "
            "thing this module exists to make impossible."
        )
    custody.require_id(actor_id, "actor_id")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be non-empty — least of all here.")
    ts = created_at if created_at is not None else custody.now_ts()

    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO actors (actor_id, display_name, kind, status, created_at) "
            "VALUES (?, ?, ?, 'ACTIVE', ?)",
            (actor_id, display_name, kind, ts),
        )
    # The structural guard. The COUNT above is a read, and two writers can
    # both pass a read before either commits; this INSERT cannot both
    # succeed. A second root is now a constraint violation rather than a
    # race outcome — the idiom UNIQUE(memory_id, prev_hash) already uses
    # against forked chains.
    cur.execute(
        "INSERT INTO ledger_root (singleton, actor_id, created_at) "
        "VALUES (1, ?, ?)", (actor_id, ts))
    cur.execute("INSERT INTO governance (singleton, grant_holders) VALUES (1, 1)")
    append_authority_event(
        cur, subject_id=actor_id, event_type="ACTOR_REGISTERED",
        issuer_id=actor_id, reason=reason,
        payload={"display_name": display_name, "kind": kind, "root": True},
        created_at=ts,
    )
    grant_id = _new_grant_id()
    append_authority_event(
        cur, subject_id=actor_id, event_type="GRANTED", issuer_id=actor_id,
        reason=reason,
        payload={"grant_id": grant_id,
                 "capabilities": sorted(CAPABILITIES),
                 "root": True},
        created_at=ts,
    )
    return grant_id


def register_actor(
    cur,
    *,
    actor_id: str,
    display_name: str,
    kind: str,
    issuer_id: str,
    reason: str,
    created_at: str | None = None,
) -> None:
    """
    Register an identity. It holds NOTHING until granted — which is the
    whole correction to Round 2's R2-02, where an unknown caller became a
    registered AGENT on the same call it used to spend authority.

    Registering requires GRANT: minting identities is the first half of
    minting power, so it is held to the same bar as the second half.
    """
    custody.require_id(actor_id, "actor_id")
    if kind not in ("AGENT", "PIPELINE", "HUMAN", "SYSTEM"):
        raise ValueError(f"Unknown actor kind {kind!r}.")
    ts = created_at if created_at is not None else custody.now_ts()
    require(cur, actor_id=issuer_id, capability="GRANT", at_ts=ts)

    cur.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,))
    if cur.fetchone() is not None:
        cur.execute("SELECT 1 FROM authority_chain WHERE subject_id = ?", (actor_id,))
        if cur.fetchone() is not None:
            raise ValueError(f"Actor {actor_id!r} is already registered.")
    else:
        cur.execute(
            "INSERT INTO actors (actor_id, display_name, kind, status, created_at) "
            "VALUES (?, ?, ?, 'ACTIVE', ?)",
            (actor_id, display_name, kind, ts),
        )
    append_authority_event(
        cur, subject_id=actor_id, event_type="ACTOR_REGISTERED",
        issuer_id=issuer_id, reason=reason,
        payload={"display_name": display_name, "kind": kind},
        created_at=ts,
    )


def grant(
    cur,
    *,
    subject_id: str,
    capabilities: list[str] | set[str] | frozenset[str],
    issuer_id: str,
    reason: str,
    grant_id: str | None = None,
    created_at: str | None = None,
) -> str:
    """
    Confer capabilities on an actor. Enforces A3 (no amplification): the
    issuer must itself hold every capability it confers, at this instant.

    Self-granting needs no special case and gets none: A3 makes it a
    no-op by construction, since an issuer can only confer what it
    already holds.

    Granting to a QUARANTINED subject is refused. A5 would zero the grant
    anyway, so the write would be inert — but writing an inert grant onto
    a contained actor's chain is precisely the preparation an attacker
    makes for a later reinstatement, and an audit that shows the refusal
    is worth more than one that shows a harmless-looking row.
    """
    caps = sorted(set(capabilities))
    if not caps:
        raise ValueError("An empty grant confers nothing; refusing to record it.")
    unknown = [c for c in caps if c not in CAPABILITIES]
    if unknown:
        raise ValueError(f"Unknown capabilities {unknown} — the vocabulary is closed.")
    ts = created_at if created_at is not None else custody.now_ts()

    require(cur, actor_id=issuer_id, capability="GRANT", at_ts=ts)
    issuer_caps = effective_capabilities(cur, issuer_id, ts)
    missing = [c for c in caps if c not in issuer_caps]
    if missing:
        raise ValueError(
            f"Actor {issuer_id!r} cannot grant {missing} — it does not hold "
            "them. Authority is delegated, never invented (Invariant A3)."
        )

    cur.execute("SELECT 1 FROM authority_chain WHERE subject_id = ?", (subject_id,))
    if cur.fetchone() is None:
        raise ValueError(
            f"Actor {subject_id!r} has no authority chain — register the "
            "identity before empowering it."
        )
    subject_state = load_state(cur, subject_id)
    if quarantined_at(subject_state, ts):
        raise ValueError(
            f"Actor {subject_id!r} is QUARANTINED; refusing to write a grant "
            "onto a contained actor's chain. Reinstate first, on the record."
        )

    gid = grant_id if grant_id is not None else _new_grant_id()
    if not _GRANT_ID_PATTERN.match(gid):
        raise ValueError(f"Malformed grant_id {gid!r}.")
    if gid in subject_state.grants:
        raise ValueError(
            f"grant_id {gid!r} already exists on {subject_id}'s chain — "
            "'which grant authorized this' must have one answer."
        )
    held_before = _holds_grant(cur, subject_id, ts)
    append_authority_event(
        cur, subject_id=subject_id, event_type="GRANTED", issuer_id=issuer_id,
        reason=reason, payload={"grant_id": gid, "capabilities": caps,
                                "root": False},
        created_at=ts,
    )
    if "GRANT" in caps and not held_before:
        _governance_gain(cur, ts)
    return gid


def revoke(
    cur,
    *,
    subject_id: str,
    grant_id: str,
    issuer_id: str,
    reason: str,
    created_at: str | None = None,
) -> None:
    """
    End a grant. The grant stays on the chain forever with the instant it
    died (A4) — every act it authorized before that instant stays
    authorized, which is what makes old bundles keep verifying after a
    revocation.

    A6: the last active grant conferring GRANT cannot be revoked. An
    actor holding REVOKE could otherwise strand the field in a state
    where no further grant can ever be issued — containment by bricking,
    indistinguishable from a successful attack.
    """
    ts = created_at if created_at is not None else custody.now_ts()
    require(cur, actor_id=issuer_id, capability="REVOKE", at_ts=ts)

    state = load_state(cur, subject_id)
    if grant_id not in state.grants:
        raise ValueError(f"{subject_id} has no grant {grant_id!r}.")
    if state.grants[grant_id]["revoked_at"] is not None:
        raise ValueError(
            f"Grant {grant_id!r} was already revoked at "
            f"{state.grants[grant_id]['revoked_at']} — a second revocation "
            "records nothing the first did not."
        )
    held_before = _holds_grant(cur, subject_id, ts)
    append_authority_event(
        cur, subject_id=subject_id, event_type="REVOKED", issuer_id=issuer_id,
        reason=reason, payload={"grant_id": grant_id}, created_at=ts,
    )
    if held_before and not _holds_grant(cur, subject_id, ts):
        _governance_lose(cur, ts, f"revoke {grant_id!r}")


def quarantine_actor_authority(
    cur, *, subject_id: str, issuer_id: str, reason: str,
    created_at: str | None = None,
) -> None:
    """
    Open a quarantine interval on the subject's authority chain. Called by
    trust.quarantine_actor() inside its transaction: the sweep's
    retrospective half (taint-flagging what the actor touched) and its
    prospective half (the actor can no longer write) land together or
    not at all.
    """
    ts = created_at if created_at is not None else custody.now_ts()
    require(cur, actor_id=issuer_id, capability="QUARANTINE_ACTOR", at_ts=ts)
    if subject_id == issuer_id:
        raise ValueError(
            "An actor cannot quarantine itself — a containment action whose "
            "subject and authority are the same identity contains nothing."
        )
    state = load_state(cur, subject_id)
    if quarantined_at(state, ts):
        raise ValueError(f"Actor {subject_id!r} is already QUARANTINED.")
    held_before = _holds_grant(cur, subject_id, ts)
    append_authority_event(
        cur, subject_id=subject_id, event_type="ACTOR_QUARANTINED",
        issuer_id=issuer_id, reason=reason, payload={}, created_at=ts,
    )
    # A5 empties a quarantined actor's capabilities, so quarantining the
    # last GRANT holder bricks the field exactly as revoking its grant
    # would. A6 guarded the revoke and not this, which an audit found by
    # walking the path: quarantine the only GRANT holder, then have the
    # responder revoke its own grant, and nothing can ever be authorized
    # again. Containment must never be a way to destroy governance.
    if held_before:
        _governance_lose(cur, ts, f"quarantine {subject_id!r}")


def reinstate_actor(
    cur, *, subject_id: str, issuer_id: str, reason: str,
    created_at: str | None = None,
) -> None:
    """
    Close a quarantine interval: the investigation cleared the actor.

    Requires QUARANTINE_ACTOR — the capability to contain is the
    capability to release, and splitting them would create a role that
    can only ever add suspicion. Self-reinstatement is refused: A5 would
    have made the call impossible anyway (a quarantined actor holds
    nothing), and the explicit refusal says why rather than leaving an
    auditor to derive it.

    Memories flagged by the sweep stay flagged. Reinstating the actor
    does not rehabilitate its memories — those are separate claims with
    separate evidence, and conflating them would let one act quietly
    reverse a whole sweep.
    """
    ts = created_at if created_at is not None else custody.now_ts()
    if subject_id == issuer_id:
        raise ValueError(
            "An actor cannot reinstate itself — an actor under investigation "
            "is not its own reviewer."
        )
    require(cur, actor_id=issuer_id, capability="QUARANTINE_ACTOR", at_ts=ts)
    state = load_state(cur, subject_id)
    if not quarantined_at(state, ts):
        raise ValueError(f"Actor {subject_id!r} is not QUARANTINED.")
    append_authority_event(
        cur, subject_id=subject_id, event_type="ACTOR_REINSTATED",
        issuer_id=issuer_id, reason=reason, payload={}, created_at=ts,
    )
    if _holds_grant(cur, subject_id, ts):
        _governance_gain(cur, ts)
    cur.execute("UPDATE actors SET status = 'ACTIVE' WHERE actor_id = ?",
                (subject_id,))
