# MNEME — Security Audit, Round 1

**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Scope:** the custody/verification core — `custody.py`, `bundle.py`,
`verify_offline.py`, `field.py`, `trust.py`. Out of scope: the embedding
model (a trusted measurement boundary by design), SQLite/OS crash
recovery, and any Phase-2 component not yet written.
**Vulnerable base:** `e4388ac` (inductions below were run against it).
**Reproducible evidence:** the regression tests
`tests/test_custody_pure.py` `[temporal plausibility]`,
`tests/test_field_pure.py` `[custody gate covers influence…]`, and
`tests/test_bundle_pure.py` `hash-valid backward-in-time chain`. Each
encodes a prediction stated before its result.

## Threat model

- **Attacker CAN:** author memories/events through the public API
  (agent, pipeline, or compromised actor); craft the bytes of an
  exported bundle and recompute any SHA-256 (hashing is public);
  edit the SQLite tables directly for the state-tamper findings.
- **Attacker CANNOT:** alter the verifier code the auditor runs; forge
  a SHA-256 preimage/collision; change bytes of a bundle *after* an
  honest party sealed and transmitted it without that showing up.
- **Trust boundary crossed by these findings:** the exported evidence
  bundle, and the recall ranking served to the agent.

**The judge test applied:** *if a judge asked me to prove a bundle's
guarantee can never be violated, what must I assume?* Two assumptions
turned out to be unstated and unchecked — that timestamps in a chain
are temporally possible, and that a non-CLEAN memory cannot influence
what recall serves. This audit attacks both.

## Epistemic legend

CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| H1 | Low–Med | CONFIRMED BY INDUCTION | Verification completeness (Round 2, temporal) | A hash-valid custody chain could run backwards in time, or carry a non-UTC offset; verification never re-checked `created_at`. |
| H2 | Medium | CONFIRMED BY INDUCTION (latent under the Phase-1 public API) | Invariant violation (Round 3, composition) | The custody gate filtered *serving* and *seeding* but not *graph traversal*; a non-CLEAN memory on a resonant path still perturbed a CLEAN memory's ranking. |

Both are now fixed, in both verifiers where applicable, with regression
tests. Neither presupposes attacker capabilities that would already be
game-over; both are genuine gaps rather than hygiene dressed as breach.

---

## H1 — Custody verification was blind to time

**Severity:** Low–Medium **Level:** CONFIRMED BY INDUCTION
**Bucket:** verification completeness (Round 2 — temporal consistency)

- **Surprise / expectation violated:** the project's stated discipline
  is "state is derivable from evidence" and "a limitation named is a
  decision." One expects a chain that verifies to describe a history
  that *could have happened*. It need not.
- **Abduction (rivals, ranked by economy of research):**
  (a) `verify_custody_rows` checks hash/linkage/seq/vocabulary/canonical
  payload but never inspects `created_at` — cheapest to test, highest
  prior; (b) it parses and range-checks timestamps but has an ordering
  bug — costlier; (c) the DB schema constrains ordering — quickly
  refuted by reading `schema.sql` (no such constraint). Test (a) first.
- **Deduction (prediction stated before result):** if (a), a chain
  whose seq-1 event carries a `created_at` one hour *before* its seq-0
  birth — with every `entry_hash` recomputed so hash/linkage pass —
  will verify `ok=True`. And a chain with a `+05:00` offset instead of
  `+00:00` will also verify, because nothing compares or normalizes the
  offset.
- **Induction (against `e4388ac`):**
  ```
  [backward-time chain]  ok=True  errs=[]
  [non-UTC offset chain] ok=True  errs=[]
  ```
  Both predictions held → **(a) CONFIRMED**, (b) and (c) eliminated.
- **Causal chain:** `entry_hash` covers `created_at`, so editing a
  timestamp *without* rehashing already fails B2 (hash recompute). But
  an attacker who rehashes — or an honest tool with a clock bug —
  produces a chain that is internally consistent yet temporally
  impossible. The verifier proved *integrity* and *insertion order*; it
  never proved *temporal plausibility*.
- **Fix:** B2 now (i) requires `created_at` to match the canonical UTC
  microsecond form `…+00:00` (so lexicographic order equals
  chronological order — a rogue offset can no longer game the compare),
  and (ii) requires `created_at` to be non-decreasing along `seq`.
  Equal timestamps stay legal (same-transaction events legitimately
  share one). Transcribed into `verify_offline.py`; agreement test
  added.
- **After:**
  ```
  [backward-time chain]  ok=False  errs=[… cannot run backwards in time]
  [non-UTC offset chain] ok=False  errs=[… not canonical UTC …]
  ```
- **Honest boundary (Part 2 discipline):** this raises the bar; it does
  not make the system prove causal time. A forger who controls *every*
  field of an entirely fabricated field can still emit a
  fully-consistent fake history with monotonic UTC timestamps — that is
  the "a hash proves integrity, not truth" boundary, unchanged. H1
  closes the *timestamp-only tamper* and *accidental impossibility*
  classes, and enforces the canonical-timestamp discipline at read time
  where before it was only enforced at write time.

---

## H2 — The custody gate covered serving, not influence

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION (latent under
the current public API) **Bucket:** invariant violation (Round 3 —
composition of two individually-correct mechanisms)

- **Surprise / expectation violated:** `ARCHITECTURE.md` and
  `field.py` promise that non-CLEAN memories "remain in the field but
  are invisible to the agent." One reads "invisible" as *exerts no
  effect on what the agent sees*. It meant only *is not itself served*.
- **Abduction:** the gate is `WHERE custody_status='CLEAN'`, which
  removes non-CLEAN memories from *candidates* (so they are not scored
  and cannot seed). But the BFS over `cell_links` loaded **all** links
  regardless of endpoint status. Hypothesis: a non-CLEAN node on a
  resonant path can still relay influence (inhibition/resonance) to a
  CLEAN target, changing its rank.
- **Deduction (prediction stated before result):** place a node `Q` on
  a resonant path `S → Q → T` (all initially clean, `S` the seed, `T`
  clean). Quarantine `Q`. Measure `T`'s score in three worlds:
  `Q` absent, `Q` clean, `Q` quarantined. *Predicted:*
  `quarantined == clean != absent` (full pass-through leak).
- **Induction (against `e4388ac`):**
  ```
  T score, Q absent        : 0.7071067812
  T score, Q present CLEAN : 0.9616652225
  T score, Q QUARANTINED   : 0.8765295660
  ```
  My specific prediction was **FALSIFIED** — quarantined (`0.8765`) is
  *neither* the clean value *nor* the absent value. The cause, found by
  following it: quarantining `Q` also removes it as a *candidate*, which
  changes the seed (in the clean world `Q` itself is the argmax seed),
  which changes `T`'s hop distance and thus its decay. **But the
  underlying invariant — "a quarantined node exerts no influence,
  i.e. `quarantined == absent`" — is VIOLATED** (`0.8765 ≠ 0.7071`).
  So: prediction falsified, finding confirmed, vector corrected. `Q`, a
  quarantined memory, still participated in the BFS and perturbed a
  served memory's ranking.
- **Reachability, stated precisely (Part 3 / Part 7):** RESONANT links
  have **no public creation API** in Phase 1 — only INHIBITORY links
  are auto-created, and an inhibited node is never added to the BFS
  frontier, so the frontier never advances past the seed. Therefore,
  **under the current public API this leak is not reachable** (the
  induction inserts RESONANT links via SQL to reach the state). It is a
  *latent architectural fracture*: the moment a resonant-link source is
  added (Phase 2 STDP/synapse work, explicitly reserved), it becomes a
  live state-poisoning vector. It is fixed now rather than left as a
  landmine.
- **Causal chain:**
  ```
  attacker memory Q on a RESONANT path  S → Q → T
      ↓  Q quarantined (not served, not seeded)
  BFS still loads the S→Q and Q→T links (no status check)
      ↓
  Q relayed to the frontier; resonance boost propagates to T
      ↓
  T's exact ranking key changes → served order perturbed
  invariant "non-CLEAN is invisible to the agent" violated for influence
  ```
- **Fix:** recall now loads the set of CLEAN memory_ids and traverses a
  link only when **both** endpoints are CLEAN. A non-CLEAN memory is
  invisible as a result *and* as an influence. Gating is on
  `custody_status` only — `FORGOTTEN` is a weak field-state, not an
  untrusted one, so its links remain.
- **After:**
  ```
  T score, Q QUARANTINED   : 0.7071067812   (== absent → invariant HELD)
  T score, Q present CLEAN : 0.9616652225   (legitimate resonance intact)
  ```

---

## Discarded / non-exploitable vectors

Recorded so the next auditor need not re-run them (Part 8).

| Vector | Result | Why it failed |
|--------|--------|---------------|
| Merkle leaf delimiter injection via `f"{mid}:{h}"` (mid charset allows `:`) | FALSIFIED | `h` (entry_hash) is always exactly 64 lowercase hex with no colon, so the split "last 64 chars = h" is unambiguous regardless of colons in `mid`; and `entry_hash` values are SHA-256 outputs the attacker cannot steer to a collision. |
| `canonical_json` divergence: `verify_offline._canon` lacks the `Decimal`/`tuple` branches that `canonical._canonicalize` has | FALSIFIED | Both verifiers canonicalize only values coming from `json.loads` (bundle body / payloads), which never yields `Decimal` or `tuple`. Export-time bodies contain only str/int/list/dict. No divergence at any point both actually run. |
| Fabricate an entirely fake but fully hash-consistent field | Out of threat model | "A hash proves integrity, not truth." Single-field-tamper is detected; wholesale fabrication with self-consistent hashes is not what a bundle claims to prevent. Noted as a boundary, not sold as a break. |
| `supersede()` re-supersession / self-supersession to fork lineage | FALSIFIED | Refused in code: non-CLEAN predecessor rejected; a second successor hits the CLEAN precondition; self-supersession hits the memories PK. Tested. |
| `verify_receipts()` does not check that `seed_memory_id`/`served` name real memories | Threat-model / by design | Receipts verify *evidence integrity* (digest recomputes), not *truth* — same discipline as B4. A receipt is a record of what recall returned, held by the caller; it is not a claim the verifier certifies as semantically correct. |
| Quarantined memory influence via the *current* public API (INHIBITORY-only) | FALSIFIED as currently reachable | Without a resonant-link source the BFS frontier never advances past the seed, so no non-seed node (clean or not) is traversed. This is why H2 is labelled *latent* rather than *live* under Phase 1. |

## Recommendations (recorded, mostly out of scope of this change)

1. When RESONANT-link creation is added (Phase 2), it must write custody
   events on both endpoints (M2) and the H2 regression test must stay
   green — the gate is now structural, but the test pins it.
2. Consider a bundle-level check that `created_at` values across a
   memory's chain do not exceed the bundle's own `created_at` (no event
   from the future relative to sealing). Deferred: needs a decision on
   clock-skew tolerance, and belongs with the CRONOS time model.
3. Direct-quarantine reversal remains undesigned (see
   `KNOWN_LIMITATIONS.md`); when designed it is a protocol change across
   both verifiers plus the agreement tests, not a loosened check.
