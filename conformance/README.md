# MNEME conformance vectors

`mneme-1.json` is the artifact an independent implementation checks
itself against. It contains two things and nothing else:

- **`operations`** — a reference field, expressed as an ordered list of
  acts. Every timestamp and every identifier is explicit. There is no
  clock and no random source in this path: the field is a function of
  this list.
- **`vectors`** — every digest that field produces, each tagged with the
  protocols it exercises.

**An implementation conforms to a protocol version when it reproduces
those digests, byte for byte, from those operations.**

The rules are in [`../SPEC.md`](../SPEC.md). This file is the arbiter of
the bytes; the specification is the arbiter of the rules. Where they
disagree, that disagreement is a defect in this project — report it
rather than resolving it by judgement (SPEC.md §14).

## Partial conformance is the only kind anyone starts with

Every vector carries a `requires` list. Build the chains first and you
can already run the `genesis.*` and `head.*` vectors; claims and
counterfactuals can wait. The cheapest useful check is the three
`genesis.*` vectors — they catch a wrong prefix or a wrong subject
binding before anything downstream can, and they need nothing but
SHA-256 and a byte concatenation.

The most demanding is `seal.bundle_body`, which requires all seven
protocols: it is the canonical seal over a full export with the one
wall-clock field removed.

## Representations that will trip you up

**Embeddings travel as canonical fixed-point strings**, not JSON
numbers — `"1.0000000000"`, ten fractional digits, always. A conformance
file carrying them as floats would be asking implementations to agree
about binary64, which is the thing MNEME refuses to depend on (SPEC.md
§1.2).

**`prev_hash` is hashed as its 64 ASCII hex characters**, not as 32
decoded bytes, and is *prepended to* the canonical JSON rather than
included in it (SPEC.md §2.2).

**`root_grant_id` is an input.** The root grant's id is inside the root
chain's hash, and `bootstrap_root` normally generates it — so it is an
input to the reference field whether or not anyone names it. Writing
this generator is what surfaced that: the first run produced a different
authority Merkle root every time.

## Files

| File | Role |
|---|---|
| `mneme-1.json` | the artifact — operations and expected digests |
| `runner.py` | executes one operation list against a fresh field |
| `vectors.py` | the operation script, and what to compute from the result |
| `generate.py` | rewrites `mneme-1.json`; `--check` exits 1 if stale |

`tests/test_conformance.py` replays the committed operations and
compares. Negative control, run before this was committed: a
one-character change to a genesis prefix turns 6 vectors red and makes
`generate.py --check` report the file stale; a hand-edited digest in the
file turns 1 red.

## Do not regenerate to make a test pass

Regenerating this file to silence a failure converts "the protocol
changed" into "the file changed", silently — the exact drift the file
exists to prevent. If `test_conformance.py` fails, exactly one of two
things is true: the protocol moved deliberately, in which case
regenerate **and move the version** (SPEC.md §11.2), or something is
wrong. There is no third case.

## What these vectors do not prove

They prove that a fixed input produces these exact digests, so a
protocol that moves announces itself. They do **not** prove the digests
are correct: a golden vector inherits whatever was true the day it was
generated. Correctness comes from two independent implementations that
must agree (SPEC.md §10) and from adversarial testing — never from a
vector file.
