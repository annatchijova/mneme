# MNEME — Security Audit

**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Scope:** the custody/verification core — `custody.py`, `bundle.py`,
`verify_offline.py`, `field.py`, `trust.py`, and (from Round 2) the MCP
transport layer, `mcp_server.py`. Out of scope: the embedding model (a
trusted measurement boundary by design), SQLite/OS crash recovery, and
any Phase-2 component not yet written.

## Round 1

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
| H1 | Low–Med | CONFIRMED BY INDUCTION | Verification completeness (Round 1, temporal) | A hash-valid custody chain could run backwards in time, or carry a non-UTC offset; verification never re-checked `created_at`. |
| H2 | Medium | CONFIRMED BY INDUCTION (latent under the Phase-1 public API) | Invariant violation (Round 1, composition) | The custody gate filtered *serving* and *seeding* but not *graph traversal*; a non-CLEAN memory on a resonant path still perturbed a CLEAN memory's ranking. |
| H3 | High | CONFIRMED BY INDUCTION | Authorization / confused deputy (Round 2) | `rehabilitate_memory()` performed zero validation on `actor_id`; the actor a sweep just quarantined could rehabilitate the very memories that sweep flagged. Compounded by `mcp_server.py` auto-registering any caller-supplied `actor_id`/`initiated_by` before the (weaker, existence-only) checks that did exist could even run. |
| H4 | High | CONFIRMED BY INDUCTION | TOCTOU / invariant violation (Round 2 — reopens a Round 1 "falsified" vector) | `supersede()` read a predecessor's `custody_status` once, then wrote later with no re-check; two concurrent callers could both pass the CLEAN check and both append a `SUPERSEDED_BY` event, forking the lineage the function's own docstring calls impossible. Neither single-chain verification nor full B1–B6 bundle verification detected the fork. |

H1 and H2 (Round 1) and H3 and H4 (Round 2) are all now fixed, with
regression tests. None presupposes attacker capabilities that would
already be game-over; all are genuine gaps rather than hygiene dressed
as breach.

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

---

## Round 2

**Vulnerable base:** `5a2e142`. Prompted by a red-team correspondence
that abduced four candidate hypotheses against the README/architecture
alone (transitive taint propagation, a confidence-threshold race, a
Merkle/quantization boundary, and MCP-layer authorization), then verified
each against the actual source. Two of the four hypotheses, refined
during verification, produced H3 and H4 below; the other two
(transitive-taint scope, and the Merkle root's leaf construction) were
confirmed as already-documented, deliberate design boundaries — recorded
in `KNOWN_LIMITATIONS.md`, not here, per this file's own rule that a
limitation named is a decision and a bug found is not one.

**Threat model addendum:** Round 1 modeled a single-threaded caller
issuing custody operations sequentially. Round 2 adds: **an MCP tool
transport that may dispatch concurrent tool calls** (the MCP Python SDK
commonly runs synchronous tool handlers off the event loop, e.g. via a
thread pool, so two `mneme_*` tool invocations can execute Python
concurrently against the same SQLite file); and **a caller who can invoke
any exposed MCP tool with any argument values**, including `actor_id`
strings that name no one in particular. Attacker capabilities are
otherwise unchanged from Round 1.

---

## H3 — Rehabilitation was unauthenticated: an actor could clear its own quarantine's evidence

**Severity:** High **Level:** CONFIRMED BY INDUCTION
**Bucket:** authorization / confused deputy

- **Surprise / expectation violated:** `quarantine_actor()` refuses an
  unregistered `initiated_by` (`trust.py`, "unknown initiator" check).
  Reversing that quarantine is at least as authority-bearing as imposing
  it — M4's own framing calls rehabilitation "an audited event," implying
  it is held to the discipline of an audit, not merely of attribution.
  `rehabilitate_memory()` checked none of it: not that `actor_id` exists,
  not its status, nothing.
- **Abduction (rivals, ranked by economy of research):** (a)
  `rehabilitate_memory()` performs no actor validation whatsoever —
  cheapest to test, and the code (`trust.py`, prior to this fix) shows no
  such check on inspection; (b) it checks existence but not standing
  (e.g. would accept a `RETIRED` actor) — costlier; (c) the gap is MCP-layer
  only and the pure function is sound — refuted immediately by reading
  `trust.py` itself, no MCP involved. Test (a) first, using the sharpest
  available instance: an actor the *same* sweep already quarantined.
- **Deduction (prediction stated before result):** in a fixture where
  `quarantine_actor(actor_id="pipeline-x", ...)` has already run and
  flagged `mem-poison-1`, calling
  `rehabilitate_memory(memory_id="mem-poison-1", actor_id="pipeline-x", ...)`
  — using the *quarantined actor itself* as the rehabilitator — will
  succeed with no exception, flipping `mem-poison-1` back to CLEAN.
- **Induction (against `5a2e142`, `tests/test_custody_pure.py`):**
  ```
  FAIL  a QUARANTINED actor cannot rehabilitate its own tainted memory  no exception raised
  FAIL  mem-poison-1 was NOT self-rehabilitated
  ```
  Prediction confirmed → **CONFIRMED**.
- **Compounding factor found while tracing the call path:** `mcp_server.py`'s
  `_ensure_actor()` auto-registers *any* caller-supplied `actor_id` string
  as `ACTIVE` before invoking `mneme_rehabilitate` / `mneme_quarantine_actor`
  — so even the weaker existence-only check that `quarantine_actor()`
  already had for `initiated_by` was neutralized in practice: the wrapper
  manufactures the very identity the check is about to trust, moments
  before trusting it. Classic confused deputy — the gate exists in the
  domain logic and is defeated one layer up, in the transport wrapper.
- **Causal chain:**
  ```
  sweep quarantines actor X (M4: nothing deleted, X stays in `actors`)
      ↓
  rehabilitate_memory(actor_id=X) checks only the MEMORY's status
      ↓
  X itself — or, via mcp_server.py, any freshly-invented actor_id — calls it
      ↓
  TAINT_FLAGGED → CLEAN, audited event written, evidence "corrected"
  by the same identity the audit exists to distrust
  ```
- **Fix:** `rehabilitate_memory()` now requires `actor_id` to name a
  registered, non-QUARANTINED actor — the same shape of check
  `quarantine_actor()` already applied to `initiated_by`. Independently,
  `mcp_server.py` no longer calls `_ensure_actor()` for `initiated_by`
  (`mneme_quarantine_actor`) or `actor_id` (`mneme_rehabilitate`); those
  two parameters must now name an actor provisioned out-of-band (e.g. by
  an operator inserting a row directly), never minted by the same call
  that spends its authority. `mneme_store` / `mneme_reinforce` keep
  auto-registration — a writer's identity is exactly what taint-tracking
  needs captured, trusted or not; only the two *authority-reversing*
  operations were tightened.
- **After:**
  ```
  ok  a QUARANTINED actor cannot rehabilitate its own tainted memory
  ok  mem-poison-1 was NOT self-rehabilitated
  ```
- **Honest boundary:** this closes the confused-deputy path — a caller
  can no longer manufacture a new "trusted" identity inline and spend it
  in the same breath. It does **not** authenticate the caller: stdio MCP
  has no session/identity model, so a caller can still claim to *be* any
  actor_id it can guess or has legitimately observed (actor_ids are
  plainly visible in `mneme_custody_chain` output). That is a
  transport-level authentication gap, not a domain-logic one, and needs
  its own design — the same class of problem named for VIGÍA's stdio
  isolation elsewhere. Recorded as open, not papered over.

---

## H4 — `supersede()`'s CLEAN check and its write were not atomic: a race forked the lineage

**Severity:** High **Level:** CONFIRMED BY INDUCTION
**Bucket:** TOCTOU / invariant violation — **reopens a vector Round 1 marked FALSIFIED**

- **Surprise / expectation violated:** `supersede()`'s own docstring
  states a CLEAN precondition exists precisely because "a second
  successor would fork the lineage." Round 1's discarded-vectors table
  recorded this exact vector as tested and safe. That test was
  single-threaded — one cursor, two sequential calls — and never modeled
  two callers observing the precondition concurrently.
- **Abduction (rivals, ranked by economy of research):** (a) the CLEAN
  read and the eventual write are separated by other writes with no
  final re-check — cheapest, and visually apparent from `field.py`'s
  control flow; (b) the schema's `PRIMARY KEY(memory_id, seq)` /
  `UNIQUE(memory_id, prev_hash)` already prevents this regardless of
  application logic — costlier, and refuted by reading `custody.append_event()`:
  it re-reads the *current* head under the writer lock at the moment
  each event is appended, so concurrent appends serialize onto
  *increasing* seq numbers without collision — the hash chain itself
  cannot fork, only the *business rule* ("one successor only") can be
  bypassed, one layer above the hash chain. Test (a).
- **Deduction (prediction stated before result):** two threads, each on
  its own SQLite connection to the same file, both reading
  `custody_status = 'CLEAN'` for the same predecessor before either
  writes (forced via a barrier placed at the exact read, so the
  interleaving is deterministic rather than hoped-for), will **both**
  successfully append a `SUPERSEDED_BY` event and both commit. The
  predecessor ends up with two `SUPERSEDED_BY` events; `verify_custody_chain`
  and `verify_bundle` (B1–B6) will both still return `ok=True`.
- **Induction (against `5a2e142`, `tests/test_field_pure.py`
  `[supersede concurrency]`, and a standalone PoC):**
  ```
  results: {'agent_legit': 'COMMITTED', 'agent_attacker': 'COMMITTED'}
  mem-race's chain:
    seq 1  SUPERSEDED_BY  agent_legit    → successor Y
    seq 2  SUPERSEDED_BY  agent_attacker → successor Z
  chain verifies (B2-style): True []
  bundle B1-B6 verified: True, errors: []
  ```
  Every prediction held → **CONFIRMED**; the Round 1 "FALSIFIED" verdict
  is corrected, not merely superseded — it was true only of the threat
  model it tested.
- **Amplifying finding, found while re-running the induction:** because
  each racer computes its own wall-clock `created_at` independently of
  write order, one repeat run produced a chain where seq 2's timestamp
  *preceded* seq 1's — the exact "backwards in time" shape H1 (Round 1)
  closed. The same race can therefore intermittently violate H1's
  temporal-monotonicity invariant as well as lineage cardinality; both
  share one root cause (a read-then-write gap with no re-check at
  commit time) and are closed by the same fix.
- **Causal chain:**
  ```
  supersede() reads custody_status once (plain SELECT, no lock)
      ↓
  two concurrent callers both observe CLEAN
      ↓
  each writer serializes correctly at the hash-chain layer (append_event
  re-reads the live head) — no collision there
      ↓
  the final UPDATE has no WHERE guard on custody_status — both succeed
      ↓
  memories.superseded_by silently keeps only the LAST writer's successor;
  the append-only chain (M4) keeps BOTH SUPERSEDED_BY events — forked
      ↓
  bundle.replay_state()/B4 track successors in a set(), never asserting
  cardinality ≤ 1 — the fork passes every existing check
  ```
- **Fix:** the final `UPDATE` now carries `AND custody_status = 'CLEAN'`;
  `cur.rowcount` is checked and a `ValueError` raised on 0 — a concurrent
  writer got there first. The whole transaction (including the
  successor's `STORED` and the `SUPERSEDED_BY` event just appended, still
  uncommitted) rolls back with the caller's rollback; nothing partially
  applies, per `custody.py`'s "the transaction belongs to the caller"
  discipline. No change to SQLite's concurrency model (WAL, one writer at
  a time) — the fix is local to the one unguarded business-rule write.
- **After:**
  ```
  outcomes: one 'committed', one 'refused: ... a concurrent writer
            raced this supersession'
  mem-race carries exactly one SUPERSEDED_BY event
  mem-race's chain still verifies
  ```
  Stable across 8 repeated runs of the concurrency test.
- **Honest boundary:** this closes the specific CLEAN-status race in
  `supersede()`. It is not a general audit of every read-then-write
  business-rule check in the codebase — see Recommendations below for
  the one sibling shape found (not yet fixed) while writing this entry.

---

## Discarded / non-exploitable vectors

Recorded so the next auditor need not re-run them (Part 8).

| Vector | Result | Why it failed |
|--------|--------|---------------|
| Merkle leaf delimiter injection via `f"{mid}:{h}"` (mid charset allows `:`) | FALSIFIED | `h` (entry_hash) is always exactly 64 lowercase hex with no colon, so the split "last 64 chars = h" is unambiguous regardless of colons in `mid`; and `entry_hash` values are SHA-256 outputs the attacker cannot steer to a collision. |
| `canonical_json` divergence: `verify_offline._canon` lacks the `Decimal`/`tuple` branches that `canonical._canonicalize` has | FALSIFIED | Both verifiers canonicalize only values coming from `json.loads` (bundle body / payloads), which never yields `Decimal` or `tuple`. Export-time bodies contain only str/int/list/dict. No divergence at any point both actually run. |
| Fabricate an entirely fake but fully hash-consistent field | Out of threat model | "A hash proves integrity, not truth." Single-field-tamper is detected; wholesale fabrication with self-consistent hashes is not what a bundle claims to prevent. Noted as a boundary, not sold as a break. |
| `supersede()` re-supersession / self-supersession to fork lineage | **SUPERSEDED BY H4 (Round 2)** — falsified only under the *sequential* threat model this table originally assumed. Under concurrent callers the CLEAN precondition and the write are not atomic; two racers both pass the check and both append a `SUPERSEDED_BY` event. Self-supersession alone (one caller, one transaction) still correctly hits the memories PK / CLEAN precondition — that half of the original entry stands. See H4 for the corrected finding, the reproduction, and the fix. |
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
4. **(Round 2, found while fixing H4, not yet fixed)** `quarantine_actor()`'s
   own idempotence check has the identical TOCTOU shape H4 had:
   `"already QUARANTINED"` is a plain `SELECT` read, and the later
   `UPDATE actors SET status = 'QUARANTINED' WHERE actor_id = ?` carries
   no guard against the read having gone stale. Two concurrent
   `quarantine_actor()` calls for the same `actor_id` could both pass the
   check and both commit — producing two `taint_sweeps` rows (two
   `sweep_id`s) for one incident, splitting the evidence exactly as the
   function's own refusal message warns against, just via a race instead
   of a sequential second call. Not exercised by a red test yet; the
   fix, if wanted, is the same shape as H4's (guard the `UPDATE` on
   `status != 'QUARANTINED'`, check `rowcount`, raise on 0).
5. **(Round 2)** MCP-layer authentication of `actor_id`/`initiated_by` is
   now "must already be registered," not "is who it claims to be" — H3's
   honest boundary. If MNEME's MCP server is ever exposed to more than one
   mutually-trusting caller, this needs a real session/identity model at
   the transport layer, not another domain-logic check.
