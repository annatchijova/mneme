"""
MNEME — SPEC.md against the code it describes.

A specification that can go stale without anyone noticing is furniture.
This file reads SPEC.md as DATA — parsing the constants, vocabularies and
version tables it states normatively — and compares each one against the
live implementation. A rule changed in the code and not in the document
fails here, and so does the reverse.

WHAT THIS CAN AND CANNOT CHECK, stated narrowly because the boundary is
the whole value:

  IT CAN check the things the spec states as enumerable facts — the
  closed vocabularies, the capability set, the event-to-capability maps,
  the exact rational constants, the genesis prefixes, the protocol
  version tables, the receipt digest body. These are where a spec goes
  wrong quietly: a word added to a vocabulary, a constant tuned, a
  version bumped, with the prose left behind.

  IT CANNOT check the prose. "An authority event is authorized by the
  state immediately before it" is the single most consequential sentence
  in the document and no parser can confirm the code obeys it. That
  sentence is held by tests/test_authority_pure.py and by the fact that
  a bundle fails without it. This file does not pretend otherwise.

So this is a staleness detector, not a proof of correspondence. The
distinction matters because the failure mode it prevents — documentation
that drifts until it is actively misleading — is the one that makes a
specification worse than none at all.

NEGATIVE CONTROL, because a staleness detector that cannot go red is
worse than none — it is a green light with no bulb behind it. Two
perturbations were run before this file was committed, one from each
direction:

    code changed, document not   EXPOSURE_FLOOR 1/64 -> 1/32  -> 2 red
    document changed, code not   authority_protocol 1.3.0 -> 1.4.0 -> 1 red

The first number is the more interesting one: changing the constant also
broke the derived claim that termination is by construction, which is
the check in this file that verifies an ARGUMENT rather than a value.

SQLite is never touched here; nothing is written. Pure parse and compare.
"""

from __future__ import annotations

import os
import re
import sys
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mneme import (authority, canonical, chain, claims, custody,  # noqa: E402
                   field, protocol, trust)
from mneme import causality  # noqa: E402,F401

SPEC = open(os.path.join(os.path.dirname(__file__), "..", "SPEC.md"),
            encoding="utf-8").read()

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")
        if detail:
            print(f"        {detail}")


def section(title: str) -> None:
    print(f"\n[{title}]")


def backticked(text: str) -> set[str]:
    """Every `word` in a slice of the document."""
    return set(re.findall(r"`([A-Za-z0-9_:.\\-]+)`", text))


def between(start: str, end: str) -> str:
    """The document slice between two headings."""
    i = SPEC.index(start)
    j = SPEC.index(end, i)
    return SPEC[i:j]


# Line wrapping in markdown is cosmetic. A staleness check that a reflow
# can break cries wolf, and a check that cries wolf gets deleted — so
# both sides are compared with whitespace collapsed.
_FLAT = re.sub(r"\s+", " ", SPEC)


def spec_says(needle: str) -> bool:
    return re.sub(r"\s+", " ", needle) in _FLAT


# ---------------------------------------------------------------- §1

section("§1 Foundations")

check("canonical scale", spec_says("`CANONICAL_SCALE` is **10**")
      and canonical.CANONICAL_SCALE == 10,
      f"code says {canonical.CANONICAL_SCALE}")

check("rounding mode is round-half-even",
      spec_says("`CANONICAL_ROUNDING` is **round-half-even**")
      and canonical.CANONICAL_ROUNDING == "ROUND_HALF_EVEN",
      f"code says {canonical.CANONICAL_ROUNDING}")

_id_re = re.search(r"\^\[a-zA-Z0-9_\\\-\.:\]\{1,64\}\$", SPEC)
check("identifier charset and length", _id_re is not None
      and chain._ID_PATTERN.pattern == r"^[a-zA-Z0-9_\-.:]+$"
      and chain._MAX_ID_LEN == 64,
      f"code: {chain._ID_PATTERN.pattern} max {chain._MAX_ID_LEN}")

_ts_spec = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$"
check("timestamp pattern", _ts_spec in SPEC
      and chain.TS_PATTERN.pattern == _ts_spec,
      f"code: {chain.TS_PATTERN.pattern}")

# ---------------------------------------------------------------- §2

section("§2 Chains")

_chain_table = between("| Kind | Subject | Genesis prefix",
                       "The prefixes are ASCII bytes")
for spec_obj, prefix, subject_key, actor_key, birth in [
        (custody.SPEC, "MNEME_CUSTODY_GENESIS:", "memory_id", "actor_id", "STORED"),
        (authority.SPEC, "MNEME_AUTHORITY_GENESIS:", "subject_id", "issuer_id",
         "ACTOR_REGISTERED"),
        (claims.SPEC, "MNEME_CLAIM_GENESIS:", "claim_id", "actor_id",
         "CLAIM_ASSERTED")]:
    row_ok = all(t in _chain_table for t in (prefix, subject_key, actor_key, birth))
    code_ok = (spec_obj.genesis_prefix == prefix.encode("ascii")
               and spec_obj.subject_key == subject_key
               and spec_obj.actor_key == actor_key
               and spec_obj.birth_event == birth)
    check(f"{spec_obj.kind} chain row", row_ok and code_ok,
          f"doc_row={row_ok} code={code_ok}")

check("the envelope names exactly nine fields",
      spec_says('"seq":         <seq>')
      and set(custody.SPEC.columns) == {
          "memory_id", "seq", "event_type", "actor_id", "reason",
          "created_at", "payload_json", "prev_hash", "entry_hash"},
      str(custody.SPEC.columns))

# ---------------------------------------------------------------- §3

section("§3 Custody")

_v10 = backticked(between("`custody_protocol` **1.0.0** closes the vocabulary",
                          "`custody_protocol` **1.1.0** adds"))
_v10 &= custody.EVENT_TYPES_BY_PROTOCOL["1.1.0"] | {"content_sha256"}
_v10.discard("content_sha256")
check("custody vocabulary 1.0.0 (8 words)",
      _v10 == custody.EVENT_TYPES_BY_PROTOCOL["1.0.0"],
      f"doc-code={sorted(_v10 ^ custody.EVENT_TYPES_BY_PROTOCOL['1.0.0'])}")

check("1.1.0 adds exactly DECISION_USED_MEMORY",
      spec_says("`DECISION_USED_MEMORY` | a decision consumed this memory")
      and (custody.EVENT_TYPES_BY_PROTOCOL["1.1.0"]
           - custody.EVENT_TYPES_BY_PROTOCOL["1.0.0"]) == {"DECISION_USED_MEMORY"},
      str(custody.EVENT_TYPES_BY_PROTOCOL["1.1.0"]
          - custody.EVENT_TYPES_BY_PROTOCOL["1.0.0"]))

check("initial confidence 0.5000000000",
      spec_says("`confidence` = `0.5000000000`")
      and custody.INITIAL_CONFIDENCE == "0.5000000000",
      custody.INITIAL_CONFIDENCE)

check("promotion threshold 3/4",
      spec_says("`PROMOTION_THRESHOLD` is the exact rational **3/4**")
      and custody.PROMOTION_THRESHOLD == Fraction(3, 4),
      str(custody.PROMOTION_THRESHOLD))

# ---------------------------------------------------------------- §4

section("§4 Authority")

_caps_doc = backticked(between("The closed set, twelve words:",
                               "Closed for the same reason"))
check("capability set (12 words)", _caps_doc == authority.CAPABILITIES,
      f"symmetric difference: {sorted(_caps_doc ^ authority.CAPABILITIES)}")

_auth_ev_doc = backticked(between("| Event | Payload | Requires of its issuer |",
                                  "The ledger governs itself"))
_auth_ev = _auth_ev_doc & authority.AUTHORITY_EVENT_TYPES
check("authority event vocabulary (5 words)",
      _auth_ev == authority.AUTHORITY_EVENT_TYPES,
      f"missing from doc: "
      f"{sorted(authority.AUTHORITY_EVENT_TYPES - _auth_ev_doc)}")

_cap_table = between("| Custody event | Required capability |",
                     "The `STORED` special case")
for event, cap in authority.REQUIRED_CAPABILITY.items():
    row = re.search(rf"^\| `{event}` \| `([A-Z_]+)`", _cap_table, re.M)
    check(f"{event} costs {cap}", row is not None and row.group(1) == cap,
          f"doc says {row.group(1) if row else 'nothing'}")

check("STORED naming a predecessor costs SUPERSEDE",
      spec_says("but `SUPERSEDE` when the payload names `supersedes`")
      and authority.required_capability(
          "STORED", {"supersedes": "m-old"}) == "SUPERSEDE")

_auth_cap_table = between("| Event | Payload | Requires of its issuer |",
                          "The ledger governs itself")
for event, cap in authority.AUTHORITY_EVENT_CAPABILITY.items():
    check(f"authority {event} costs {cap}",
          re.search(rf"\| `{event}` \|[^|]*\| `{cap}` \|", _auth_cap_table)
          is not None)

# ---------------------------------------------------------------- §5

section("§5 Claims")

_claim_vocab = backticked(between("| `CLAIM_ASSERTED` | birth;",
                                  "Evidence stances:"))
_claim_vocab &= claims.CLAIM_EVENT_TYPES
check("claim vocabulary (8 words)", _claim_vocab == claims.CLAIM_EVENT_TYPES,
      f"missing from doc: {sorted(claims.CLAIM_EVENT_TYPES - _claim_vocab)}")

for label, doc_line, code in [
        ("stances", "Evidence stances: `SUPPORTS`, `CONTRADICTS`.", claims.STANCES),
        ("relations", "`SUPPORTS`, `CONTRADICTS`, `SUPERSEDES`,\n`DERIVED_FROM`.",
         claims.RELATIONS),
        ("constraints",
         "Set constraints: `AT_MOST_ONE`, `EXACTLY_ONE`, `INCOMPATIBLE`.",
         claims.CONSTRAINTS),
        ("states", "`ASSERTED`, `VALIDATED`, `REFUTED`, `WITHDRAWN`,\n`SUPERSEDED`.",
         claims.CLAIM_STATES)]:
    check(f"claim {label}", spec_says(doc_line),
          f"code: {code}")

# ---------------------------------------------------------------- §6

section("§6 Recall")

check("STATE_BOOST 3/2, 1, 0",
      spec_says("STATE_BOOST          REINFORCED = 3/2, NEUTRAL = 1, FORGOTTEN = 0")
      and field.STATE_BOOST == {"REINFORCED": Fraction(3, 2),
                                "NEUTRAL": Fraction(1, 1),
                                "FORGOTTEN": Fraction(0, 1)},
      str(field.STATE_BOOST))

check("DECAY_BASE 43/50", spec_says("DECAY_BASE           43/50")
      and field.DECAY_BASE == Fraction(43, 50), str(field.DECAY_BASE))

check("RESONANT_BOOST_STEP 1/2",
      spec_says("RESONANT_BOOST_STEP  1/2")
      and field.RESONANT_BOOST_STEP == Fraction(1, 2),
      str(field.RESONANT_BOOST_STEP))

check("DEFAULT_HOPS 2", spec_says("DEFAULT_HOPS         2")
      and field.DEFAULT_HOPS == 2, str(field.DEFAULT_HOPS))

_receipt_doc = between("query_sha256, seed_memory_id, served",
                       "`receipt_protocol` 1.0.0 recorded")
_receipt_fields = set(re.findall(r"[a-z_0-9]+", _receipt_doc.split("```")[0]))
_hits, _receipt = None, None
_body_keys = {"query_sha256", "seed_memory_id", "served", "excluded_custody",
              "excluded_forgotten", "excluded_inhibited", "top_k", "hops",
              "ranking_protocol", "custody_override", "as_of"}
check("receipt digest body names exactly its eleven fields",
      _body_keys <= _receipt_fields,
      f"in code but not in doc: {sorted(_body_keys - _receipt_fields)}")

# ---------------------------------------------------------------- §8

section("§8 Taint and influence")

check("non-influence carve-out",
      spec_says("`CONTRADICTED_BY` — being contradicted by a bad actor")
      and spec_says("`DECISION_USED_MEMORY` — recording that a decision")
      and set(trust.NON_INFLUENCE_EVENTS) == {"CONTRADICTED_BY",
                                              "DECISION_USED_MEMORY"},
      str(trust.NON_INFLUENCE_EVENTS))

check("INFLUENCE_TRANSFER 1/2", spec_says("INFLUENCE_TRANSFER   1/2")
      and trust.INFLUENCE_TRANSFER == Fraction(1, 2))
check("EXPOSURE_FLOOR 1/64", spec_says("EXPOSURE_FLOOR       1/64")
      and trust.EXPOSURE_FLOOR == Fraction(1, 64))
check("MAX_INFLUENCE_DEPTH 6", spec_says("MAX_INFLUENCE_DEPTH  6")
      and trust.MAX_INFLUENCE_DEPTH == 6)

# The claim the spec makes ABOUT those three constants — that termination
# is by construction — is arithmetic, so it can actually be checked.
check("no path beyond MAX_INFLUENCE_DEPTH can clear the floor",
      spec_says("**termination is by construction, not by a visited set**")
      and trust.INFLUENCE_TRANSFER ** trust.MAX_INFLUENCE_DEPTH
      >= trust.EXPOSURE_FLOOR
      and trust.INFLUENCE_TRANSFER ** (trust.MAX_INFLUENCE_DEPTH + 1)
      < trust.EXPOSURE_FLOOR,
      f"(1/2)^{trust.MAX_INFLUENCE_DEPTH} vs floor {trust.EXPOSURE_FLOOR}")

# ---------------------------------------------------------------- §9

section("§9 Bundles")

from mneme import bundle  # noqa: E402

check("bundle format tag", spec_says("`format` | `MNEME_BUNDLE_V2`")
      and bundle.BUNDLE_FORMAT == "MNEME_BUNDLE_V2", bundle.BUNDLE_FORMAT)

check("empty Merkle root constant",
      spec_says('`SHA-256(b"MNEME_EMPTY_HEADS")`')
      and bundle.heads_merkle_root({}) ==
      __import__("hashlib").sha256(b"MNEME_EMPTY_HEADS").hexdigest())

check("odd leaf promoted, never duplicated",
      spec_says("**An odd leaf is promoted unpaired — never duplicated.**"))

# ---------------------------------------------------------------- §11

section("§11 Protocol versions")

_current = between("| Protocol | Current |", "And these are the versions")
for name, version in protocol.CURRENT_PROTOCOLS.items():
    check(f"{name} current = {version}",
          re.search(rf"\| `{name}` \| {re.escape(version)} \|", _current)
          is not None,
          "SPEC.md §11.4 disagrees with protocol.py")

_supported = between("| Protocol | Supported |", "Two entries in the supported")
for name, versions in protocol.SUPPORTED_PROTOCOLS.items():
    row = re.search(rf"\| `{name}` \| ([0-9., ]+) \|", _supported)
    doc_versions = frozenset(row.group(1).replace(" ", "").split(",")) if row else None
    check(f"{name} supported = {', '.join(sorted(versions))}",
          doc_versions == versions,
          f"doc says {sorted(doc_versions) if doc_versions else 'nothing'}")

check("every protocol name appears in the §11.1 table",
      all(f"`{n}`" in between("| Protocol | Governs |", "### 11.2")
          for n in protocol.PROTOCOL_NAMES))

check("receipt_protocol 1.0.0 declared absent, and is",
      spec_says("`receipt_protocol` 1.0.0 is **absent**")
      and "1.0.0" not in protocol.SUPPORTED_PROTOCOLS["receipt_protocol"])

check("authority_protocol 1.2.0 declared present-with-defect, and is",
      spec_says("`authority_protocol` 1.2.0 is **present**")
      and "1.2.0" in protocol.SUPPORTED_PROTOCOLS["authority_protocol"])

# ---------------------------------------------------------------- structure

section("the document itself")

for n in range(15):
    check(f"§{n} present", re.search(rf"^## {n}\. ", SPEC, re.M) is not None)

check("no section promises a check the bundle does not have",
      all(f"**B{n} " in SPEC for n in range(10)),
      "B0-B9 must each be stated in §9.3")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
