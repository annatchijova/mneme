"""
MNEME — the committed conformance vectors, against the live code.

conformance/mneme-1.json is the artifact an independent implementation
checks itself against: a reference field expressed as an ordered list of
operations, plus every digest that field produces. This file re-runs that
operation list and compares, so the artifact cannot drift away from the
implementation it claims to describe.

WHY THIS IS NOT tests/test_protocol_vectors.py. That file pins the same
digests as Python literals, computed by a Python script, for Python. This
one pins them as DATA, in a file with no language in it, so the question
"does your implementation speak MNEME?" has an answer that does not
require reading this repository. The two overlap on purpose: if the
JSON's expectations and the Python literals ever disagreed, the
disagreement would be a real defect in one of them, and it would be loud.

WHAT THE VECTORS PROVE, and the boundary matters:

  they prove   a fixed input produces these exact digests, so a protocol
               that moves is a protocol that announces itself
  they do NOT  prove the digests are CORRECT. A golden vector inherits
               whatever was true the day it was generated. Correctness
               comes from two independent implementations that must agree
               and from adversarial testing — never from a vector file.

REGENERATING THE FILE TO MAKE THIS PASS is the one action that makes the
whole apparatus worthless: it converts "the protocol changed" into "the
file changed", silently. If this test fails, exactly one of two things is
true — the protocol moved deliberately (regenerate, and move the
version), or something is wrong. There is no third case in which the
answer is to overwrite the file and continue.
"""

from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, ".."))
sys.path.insert(0, os.path.join(_HERE, "..", "conformance"))

import runner    # noqa: E402
import vectors   # noqa: E402

from mneme import protocol  # noqa: E402

PATH = os.path.join(_HERE, "..", "conformance", "mneme-1.json")

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


with open(PATH, encoding="utf-8") as f:
    doc = json.load(f)

print("[the file describes itself]")
check("conformance_format", doc["conformance_format"] == vectors.CONFORMANCE_FORMAT,
      doc["conformance_format"])
check("declares the protocol versions it was generated under",
      doc["protocols"] == dict(protocol.CURRENT_PROTOCOLS),
      f"file says {doc['protocols']}")
check("points at the specification", doc.get("spec") == "SPEC.md")

print("\n[the operation script is still the one the generator writes]")
check("operations match", doc["operations"] == vectors.operations(),
      "the committed script and conformance/vectors.py have diverged")

print("\n[replaying the committed operations reproduces every digest]")
world = runner.run(doc["operations"])
live = {v["name"]: v["value"] for v in vectors.compute(world)}
world.conn.close()

for entry in doc["vectors"]:
    name, expected = entry["name"], entry["value"]
    actual = live.get(name)
    check(name, actual == expected,
          f"expected {expected}\n        got      {actual}")

extra = sorted(set(live) - {v["name"] for v in doc["vectors"]})
check("no vector computed that the file does not carry", not extra, str(extra))

print("\n[every vector names the protocols it exercises]")
names = set(protocol.PROTOCOL_NAMES)
for entry in doc["vectors"]:
    req = entry.get("requires")
    check(f"{entry['name']} requires {req if req else '(none)'}",
          isinstance(req, list) and set(req) <= names,
          "a vector whose requirements are unstated cannot be used for "
          "partial conformance, which is the only kind anyone starts with")

check("some vector exercises each protocol",
      all(any(n in v.get("requires", []) for v in doc["vectors"])
          for n in protocol.PROTOCOL_NAMES),
      "a protocol no vector touches is a protocol nobody can be held to")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
