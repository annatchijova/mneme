#!/usr/bin/env python3
"""
MNEME — regenerate conformance/mneme-1.json from the live implementation.

Run this ONLY when a protocol version has deliberately moved. The file it
writes is the artifact an independent implementation checks itself
against, so regenerating it to make a failing test pass is the one way to
make this whole apparatus worthless: it converts "the protocol changed"
into "the file changed", silently, which is exactly the drift the file
exists to prevent.

tests/test_conformance.py re-runs the committed operation list and
compares. If it fails, the question is which of the two is wrong — not
which one is easier to overwrite.

    python3 conformance/generate.py            write the file
    python3 conformance/generate.py --check    exit 1 if it would change
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vectors  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mneme-1.json")


def render() -> str:
    return json.dumps(vectors.document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        if not os.path.exists(OUT):
            print(f"{OUT} does not exist.")
            return 1
        with open(OUT, encoding="utf-8") as f:
            if f.read() == text:
                print("conformance/mneme-1.json is current.")
                return 0
        print("conformance/mneme-1.json is STALE — the implementation and "
              "the committed vectors disagree.")
        return 1
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    doc = json.loads(text)
    print(f"wrote {OUT}: {len(doc['operations'])} operations, "
          f"{len(doc['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
