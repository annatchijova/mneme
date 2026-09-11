"""
MNEME — Protocol versions: the semantics a seal commits to.

A hash proves that bytes did not change. It says nothing about what
those bytes MEAN. Until this module existed, MNEME had a schema version
and no semantic version, which left one specific lie available:

    Today the replay rule says REHABILITATED is valid only from
    TAINT_FLAGGED. Suppose tomorrow it also becomes valid from
    QUARANTINED. Every bundle sealed YESTERDAY — never touched, seal
    intact, chains verifying — silently acquires the new rule when a new
    verifier reads it. The bundle proves its bytes; it proves nothing
    about the rule it was checked against, because the rule was never in
    the bundle.

So the rule goes in the bundle. A MNEME_BUNDLE_V2 body carries a
"protocols" block naming, by version, every semantics its checks depend
on. A verifier that meets a version it does not implement REFUSES —
loudly, naming the version — instead of quietly applying today's rules
to yesterday's evidence.

The six protocols, and what "changing" each one means:

  custody_protocol    The custody envelope and its chain rules: the hash
                      formula, the genesis derivation, seq density, the
                      CLOSED event vocabulary, canonical payload bytes,
                      the canonical-UTC non-decreasing timestamp rule.
                      Adding one event_type changes this version.

  replay_protocol     The B4 state machine: which event moves
                      custody_status where, the field_state transition
                      rule, the confidence arithmetic. Relaxing
                      "REHABILITATED only from TAINT_FLAGGED" changes
                      this version.

  ranking_protocol    The recall scoring semantics: STATE_BOOST values,
                      DECAY_BASE, RESONANT_BOOST_STEP, the rescue rule,
                      the exact ranking key and its tiebreak, the custody
                      gate's extension to graph traversal. Two recalls
                      are only comparable under one ranking_protocol.

  taint_protocol      What a sweep flags, what it deliberately does not
                      (the CONTRADICTED_BY carve-out), how the flagged
                      set is sealed, and the influence-budget rules that
                      separate DIRECT_TAINT from INFLUENCE_EXPOSED.

  authority_protocol  The capability vocabulary, the grant/revocation
                      chain rules, no-amplification, and which capability
                      each custody event type requires (B7).

  receipt_protocol    The recall-receipt digest body, and the decision
                      record that binds a receipt to the decision it
                      served (B8).

Versioning discipline, stated once so nobody has to guess:

  MAJOR  a bundle sealed under the old version can no longer be
         verified by the new rules at all (the evidence means something
         different).
  MINOR  new checkable facts exist; everything the old version checked
         is still checked identically.
  PATCH  wording, messages, non-semantic refactors.

THIS MODULE IS PART OF THE PROTOCOL. verify_offline.py transcribes the
version table and the support policy; tests/test_bundle_pure.py's
agreement section holds the two together.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# The versions this build implements
# ---------------------------------------------------------------------------

# 1.0.0 — envelope, genesis binding, dense seq, closed 8-event vocabulary,
#         canonical payload bytes, canonical-UTC non-decreasing timestamps.
CUSTODY_PROTOCOL = "1.0.0"

# 1.0.0 — the B4 state machine exactly as stated in bundle.py's header.
REPLAY_PROTOCOL = "1.0.0"

# 1.0.0 — exact Fraction ranking: STATE_BOOST {3/2, 1, 0}, DECAY_BASE 43/50,
#         RESONANT_BOOST_STEP 1/2, rescue rule, t²/n key, memory_id tiebreak,
#         custody gate on serving AND on traversal.
RANKING_PROTOCOL = "1.0.0"

# 1.1.0 — 1.0.0's direct sweep (actor in chain, CONTRADICTED_BY carved out,
#         sorted-id seal) PLUS the influence-budget exposure report. Every
#         1.0.0 check is unchanged, so this is a MINOR bump: a 1.0.0 bundle
#         is still checked identically, it simply carries no exposure rows.
TAINT_PROTOCOL = "1.1.0"

# 1.0.0 — capability vocabulary, per-actor authority chains, no-amplification,
#         quarantine as a write barrier, the event_type -> capability map.
AUTHORITY_PROTOCOL = "1.0.0"

# 1.1.0 — 1.0.0's recall-receipt digest body PLUS the decision record that
#         binds receipt_sha256 + decision_sha256 + policy_version.
RECEIPT_PROTOCOL = "1.1.0"

PROTOCOL_NAMES = (
    "custody_protocol",
    "replay_protocol",
    "ranking_protocol",
    "taint_protocol",
    "authority_protocol",
    "receipt_protocol",
)

CURRENT_PROTOCOLS: dict[str, str] = {
    "custody_protocol": CUSTODY_PROTOCOL,
    "replay_protocol": REPLAY_PROTOCOL,
    "ranking_protocol": RANKING_PROTOCOL,
    "taint_protocol": TAINT_PROTOCOL,
    "authority_protocol": AUTHORITY_PROTOCOL,
    "receipt_protocol": RECEIPT_PROTOCOL,
}

# Every version this build can still verify, per protocol. A version is in
# this table only if the code to check it is actually present — the table is
# a claim about implemented behaviour, not a compatibility wish.
#
# taint 1.0.0 and receipt 1.0.0 remain supported because their MINOR
# successors added rows without changing a single 1.0.0 check. When a MAJOR
# bump happens, the old version leaves this table unless its rules are kept
# alongside the new ones — and if they are kept, they are kept as code, in
# both verifiers, with tests, or the entry is a lie.
SUPPORTED_PROTOCOLS: dict[str, frozenset[str]] = {
    "custody_protocol": frozenset({"1.0.0"}),
    "replay_protocol": frozenset({"1.0.0"}),
    "ranking_protocol": frozenset({"1.0.0"}),
    "taint_protocol": frozenset({"1.0.0", "1.1.0"}),
    "authority_protocol": frozenset({"1.0.0"}),
    "receipt_protocol": frozenset({"1.0.0", "1.1.0"}),
}


def check_protocols(declared: object) -> list[str]:
    """
    Validate a bundle's declared "protocols" block against what this
    build implements. Pure; returns one error string per problem.

    Refusal, not tolerance, is the whole point:
      - a missing block means the bundle commits to no semantics at all;
      - a missing name means the bundle is silent about a semantics its
        checks depend on;
      - an unknown version means this verifier would be applying rules
        the sealer never agreed to.

    An unknown EXTRA name is also refused: a bundle that names a protocol
    this build has never heard of was sealed by a newer MNEME, and a
    verdict from an older verifier on newer evidence is exactly the
    retroactive-semantics problem read backwards.
    """
    errors: list[str] = []
    if not isinstance(declared, dict):
        return ["protocols: block absent or not an object — a bundle that "
                "declares no semantics commits to none, and a seal over "
                "bytes with undeclared meaning is not evidence."]
    for name in PROTOCOL_NAMES:
        if name not in declared:
            errors.append(
                f"protocols: {name} is not declared — this verifier will not "
                "apply today's rules to evidence that never named them.")
            continue
        version = declared[name]
        if not isinstance(version, str):
            errors.append(f"protocols: {name} version is not a string.")
            continue
        if version not in SUPPORTED_PROTOCOLS[name]:
            errors.append(
                f"protocols: {name} {version} is not implemented by this "
                f"verifier (supported: "
                f"{', '.join(sorted(SUPPORTED_PROTOCOLS[name]))}). Verify "
                "this bundle with a verifier of its era, or port the rules "
                "forward deliberately — never by assuming they are the same.")
    for name in sorted(set(declared) - set(PROTOCOL_NAMES)):
        errors.append(
            f"protocols: {name!r} is unknown to this verifier — the bundle "
            "was sealed by a newer MNEME whose semantics this build cannot "
            "assert anything about.")
    return errors
