-- =============================================================================
-- MNEME — Core Schema, Phase 1 (SQLite WAL)
-- =============================================================================
-- Portability note: this schema is written to port to CockroachDB with
-- mechanical changes only (TEXT->STRING, INTEGER->INT8, add DECIMAL(11,10)
-- for quantized columns, changefeeds for the taint sweeper). Every
-- discipline below is inherited from STIGMERGY's schema and holds in both
-- engines.
--
-- Invariants enforced or supported here (see custody.py header for M1–M5):
--   M1  memories.content is immutable — no UPDATE path exists in the app;
--       supersession is a new row + SUPERSEDED_BY custody event.
--   M2  every state-changing write must accompany a custody_chain row in
--       the same transaction. custody_chain.reason is NOT NULL — an
--       unreasoned custody event cannot exist.
--   M3  custody chains are per-memory, append-only, seq dense from 0.
--       PRIMARY KEY (memory_id, seq) makes forks a constraint violation.
--   M4  nothing is deleted. status transitions are audited states.
--       No FK declares ON DELETE anything: default RESTRICT means an
--       accidental DELETE fails loudly instead of cascading destruction.
--   M5  floats never decide. Confidence/trust stored as TEXT holding a
--       fixed-point decimal at canonical scale 10 (SQLite has no DECIMAL;
--       storing the canonical string preserves the exact bytes that were
--       hashed — REAL would round-trip through IEEE 754, which is the
--       exact failure mode this project exists to refuse).
-- =============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- actors — every writer (agent, pipeline, human operator) has an identity.
-- Taint propagation is defined over actor identity; an anonymous write
-- would be a custody hole, so writes without a registered actor are refused
-- at the application boundary.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actors (
    actor_id      TEXT PRIMARY KEY,          -- validated: ^[a-zA-Z0-9_\-.:]{1,64}$
    display_name  TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('AGENT','PIPELINE','HUMAN','SYSTEM')),
    status        TEXT NOT NULL DEFAULT 'ACTIVE'
                  CHECK (status IN ('ACTIVE','QUARANTINED','RETIRED')),
    created_at    TEXT NOT NULL              -- canonical ts (custody.format_ts)
);

-- -----------------------------------------------------------------------------
-- memories — the field's cells. Content is immutable (M1).
-- embedding is stored as a JSON array of fixed-point strings at canonical
-- scale: the SAME bytes that participate in any hash. Phase 1 recall
-- reconstructs vectors in memory (raven-memory pattern: KDTree rebuilt on
-- load); a vector index arrives with the CockroachDB port.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memories (
    memory_id       TEXT PRIMARY KEY,
    content         TEXT NOT NULL,
    content_sha256  TEXT NOT NULL CHECK (length(content_sha256) = 64),
    embedding_json  TEXT NOT NULL,
    embedding_model TEXT NOT NULL,           -- mixing models is a migration, not a config flip
    topic           TEXT,
    created_by      TEXT NOT NULL REFERENCES actors(actor_id),
    created_at      TEXT NOT NULL,
    -- Field state (raven-memory ternary) — multiplies recall score:
    field_state     TEXT NOT NULL DEFAULT 'NEUTRAL'
                    CHECK (field_state IN ('REINFORCED','NEUTRAL','FORGOTTEN')),
    -- Custody status (MNEME) — gates whether recall may SERVE it at all:
    custody_status  TEXT NOT NULL DEFAULT 'CLEAN'
                    CHECK (custody_status IN ('CLEAN','TAINT_FLAGGED','QUARANTINED','SUPERSEDED')),
    -- Exact confidence at canonical scale 10, as fixed-point TEXT (M5):
    confidence      TEXT NOT NULL DEFAULT '0.5000000000',
    superseded_by   TEXT REFERENCES memories(memory_id)
);

CREATE INDEX IF NOT EXISTS idx_memories_status ON memories (custody_status);
CREATE INDEX IF NOT EXISTS idx_memories_topic  ON memories (topic);

-- -----------------------------------------------------------------------------
-- custody_chain — THE table. Per-memory tamper-evident hash chain.
-- entry_hash covers (prev_hash || canonical envelope) — see custody.py.
-- UNIQUE (memory_id, prev_hash) makes a fork (two entries claiming the
-- same parent) a constraint violation, not a race outcome.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS custody_chain (
    memory_id     TEXT NOT NULL REFERENCES memories(memory_id),
    seq           INTEGER NOT NULL CHECK (seq >= 0),
    event_type    TEXT NOT NULL CHECK (event_type IN (
                      'STORED','REINFORCED','CONTRADICTED_BY','SUPERSEDED_BY',
                      'QUARANTINED','TAINT_FLAGGED','REHABILITATED','STATE_CHANGED',
                      -- custody_protocol 1.1.0: the agent's explicit act of
                      -- recording that a decision consumed this memory. It
                      -- changes no state (replay treats it as a no-op); it
                      -- closes recall -> action so blast radius is evidence,
                      -- not inference.
                      'DECISION_USED_MEMORY')),
    actor_id      TEXT NOT NULL REFERENCES actors(actor_id),
    reason        TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_at    TEXT NOT NULL,
    payload_json  TEXT NOT NULL,             -- canonical bytes, exactly what was hashed
    prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
    entry_hash    TEXT NOT NULL CHECK (length(entry_hash) = 64),
    PRIMARY KEY (memory_id, seq),
    UNIQUE (memory_id, prev_hash),
    UNIQUE (entry_hash)
);

CREATE INDEX IF NOT EXISTS idx_custody_actor ON custody_chain (actor_id);

-- -----------------------------------------------------------------------------
-- authority_chain — THE OTHER table. Per-ACTOR tamper-evident hash chain
-- recording who was allowed to cause what (mneme/authority.py).
--
-- custody_chain answers "what happened to this memory". This answers "who
-- was authorized to cause it". The two are separable proofs over different
-- evidence, and bundle check B7 demands both: a perfect chain of an
-- unauthorized act is exactly the hole Round 2 confirmed.
--
-- subject_id is WHOSE authority the row describes; issuer_id is WHO wrote
-- it. They coincide only in the root bootstrap, which is refused once any
-- chain exists — so the ledger is a tree rooted at one auditable act.
--
-- Same structural disciplines as custody_chain: genesis bound to the
-- subject id (a grant history cannot be grafted between actors), seq dense
-- from 0, UNIQUE (subject_id, prev_hash) so a fork is a constraint
-- violation rather than a race outcome, reason NOT NULL so an unreasoned
-- grant cannot exist, and no ON DELETE anywhere (A4: revocation is an
-- event, never a row removal).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authority_chain (
    subject_id    TEXT NOT NULL REFERENCES actors(actor_id),
    seq           INTEGER NOT NULL CHECK (seq >= 0),
    event_type    TEXT NOT NULL CHECK (event_type IN (
                      'ACTOR_REGISTERED','GRANTED','REVOKED',
                      'ACTOR_QUARANTINED','ACTOR_REINSTATED')),
    issuer_id     TEXT NOT NULL REFERENCES actors(actor_id),
    reason        TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_at    TEXT NOT NULL,
    payload_json  TEXT NOT NULL,            -- canonical bytes, exactly what was hashed
    prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
    entry_hash    TEXT NOT NULL CHECK (length(entry_hash) = 64),
    PRIMARY KEY (subject_id, seq),
    UNIQUE (subject_id, prev_hash),
    UNIQUE (entry_hash)
);

CREATE INDEX IF NOT EXISTS idx_authority_issuer ON authority_chain (issuer_id);

-- -----------------------------------------------------------------------------
-- ledger_root — the root act, made unrepeatable by a CONSTRAINT rather than
-- by a check that a second writer could pass.
--
-- bootstrap_root() reads COUNT(authority_chain) and then writes. Two writers
-- can both pass that read before either commits, and the result is a field
-- with two self-issued root grants — each chain internally perfect, no
-- constraint violated. This table is the structural answer, in the idiom the
-- rest of the schema already uses: the PRIMARY KEY pinned to the literal 1
-- makes a second root a constraint violation, not a race outcome.
--
-- It holds no authority of its own. It is a cache of "which chain carries the
-- root grant", derivable from the chains themselves — exactly as actors.status
-- is a cache of the authority replay — and B7 re-derives the root from
-- evidence and never from here.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_root (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    actor_id   TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- cell_links — raven-memory's ternary links between memories.
-- RESONANT amplifies neighbours; INHIBITORY silences contradictions.
-- Link creation/removal is a state change => custody events on BOTH ends.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cell_links (
    from_id    TEXT NOT NULL REFERENCES memories(memory_id),
    to_id      TEXT NOT NULL REFERENCES memories(memory_id),
    link_type  TEXT NOT NULL CHECK (link_type IN ('RESONANT','INHIBITORY')),
    auto       INTEGER NOT NULL DEFAULT 1 CHECK (auto IN (0,1)),
    created_at TEXT NOT NULL,
    PRIMARY KEY (from_id, to_id)
);

-- -----------------------------------------------------------------------------
-- taint_sweeps — each quarantine of an actor produces ONE sweep row and
-- N TAINT_FLAGGED custody events, all in one transaction. The sweep is
-- itself sealed: flagged_ids_sha256 = sha256(canonical JSON of the sorted
-- list of flagged memory_ids), so "we flagged exactly these" is a claim
-- the offline verifier can check, not an assertion.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS taint_sweeps (
    sweep_id           TEXT PRIMARY KEY,
    quarantined_actor  TEXT NOT NULL REFERENCES actors(actor_id),
    initiated_by       TEXT NOT NULL REFERENCES actors(actor_id),
    reason             TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_at         TEXT NOT NULL,
    flagged_count      INTEGER NOT NULL CHECK (flagged_count >= 0),
    flagged_ids_sha256 TEXT NOT NULL CHECK (length(flagged_ids_sha256) = 64)
);

-- -----------------------------------------------------------------------------
-- recall_receipts — OPTIONAL, caller-persisted evidence of what recall
-- served and withheld. Recall itself stays read-only (serving is not a
-- state transition); field.persist_receipt() is the caller's explicit,
-- separate act. The primary key IS the receipt's digest, so a row that
-- does not recompute from its own columns is self-revealing
-- (field.verify_receipts checks). served_json holds the served ids in
-- rank order, canonical JSON. Append-only; no ON DELETE anywhere.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recall_receipts (
    receipt_sha256     TEXT PRIMARY KEY CHECK (length(receipt_sha256) = 64),
    query_sha256       TEXT NOT NULL CHECK (length(query_sha256) = 64),
    seed_memory_id     TEXT REFERENCES memories(memory_id),
    served_json        TEXT NOT NULL,
    excluded_custody   INTEGER NOT NULL CHECK (excluded_custody >= 0),
    excluded_forgotten INTEGER NOT NULL CHECK (excluded_forgotten >= 0),
    excluded_inhibited INTEGER NOT NULL CHECK (excluded_inhibited >= 0),
    -- receipt_protocol 2.0.0: the question, not only the answer. Without
    -- top_k / hops / ranking_protocol a receipt cannot be replayed, and a
    -- receipt that cannot be replayed cannot anchor a counterfactual.
    top_k              INTEGER NOT NULL CHECK (top_k > 0),
    hops               INTEGER NOT NULL CHECK (hops >= 0),
    ranking_protocol   TEXT NOT NULL,
    -- The WORLD the recall was taken in: canonical {"override": [[id, status]…]}.
    -- Empty for a real recall; non-empty for a counterfactual run against a
    -- hypothetical custody state. It is inside the receipt digest so a
    -- counterfactual receipt cannot be laundered into evidence about the
    -- actual field, and record_decision refuses to let a decision cite one.
    custody_override_json TEXT NOT NULL DEFAULT '{"override":[]}',
    -- The INSTANT this recall reconstructed, or NULL for "now". A receipt
    -- that does not say when it was looking cannot be replayed either.
    as_of              TEXT,
    persisted_at       TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- decisions — the causal closure: recall -> action (mneme/causality.py).
--
-- A recall receipt proves what the agent was SHOWN. It does not prove what
-- the agent DID with it, so "why did it remember X" was answerable while
-- "which decisions were contaminated by X" was not. A decision record is
-- the agent's own explicit, authorized act of committing that link:
-- receipt_sha256 (what it was shown) + decision_sha256 (what it produced,
-- by hash — MNEME never sees the artifact and does not pretend to) +
-- policy_version (under which rules) + the subset of the served set it
-- actually used.
--
-- used_json is a canonical, sorted claim that must be a SUBSET of the
-- cited receipt's served list: a decision cannot claim to have used a
-- memory the recall never served it. Bilateral, like contradiction and
-- lineage: each used memory's custody chain carries a matching
-- DECISION_USED_MEMORY event, so neither side can hide the link alone.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS decisions (
    decision_id     TEXT PRIMARY KEY,
    receipt_sha256  TEXT NOT NULL REFERENCES recall_receipts(receipt_sha256),
    decision_sha256 TEXT NOT NULL CHECK (length(decision_sha256) = 64),
    policy_version  TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
    actor_id        TEXT NOT NULL REFERENCES actors(actor_id),
    reason          TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    used_json       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    record_sha256   TEXT NOT NULL UNIQUE CHECK (length(record_sha256) = 64)
);

CREATE INDEX IF NOT EXISTS idx_decisions_receipt ON decisions (receipt_sha256);

-- -----------------------------------------------------------------------------
-- claims — the PROPOSITION, separated from the document (mneme/claims.py).
--
-- A memory used to do two jobs: the container (this text was stored, with
-- this chain) and the epistemic unit (this is what the field believes).
-- raven's topic+claim contradiction rule works only while every
-- proposition lives in exactly one document and every document asserts
-- exactly one proposition; neither is true of anything real.
--
-- statement is immutable (C1) — revision is supersession, an event, never
-- an edit, the same rule M1 holds memories to. No confidence column
-- exists anywhere here ON PURPOSE (C3): a claim's STANDING is recomputed
-- from evidence, because a stored confidence is a number whose derivation
-- has been thrown away.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS claims (
    claim_id         TEXT PRIMARY KEY,
    statement        TEXT NOT NULL CHECK (length(trim(statement)) > 0),
    statement_sha256 TEXT NOT NULL CHECK (length(statement_sha256) = 64),
    topic            TEXT,
    created_by       TEXT NOT NULL REFERENCES actors(actor_id),
    created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claims_topic ON claims (topic);

-- -----------------------------------------------------------------------------
-- claim_chain — per-CLAIM tamper-evident hash chain. Third of its kind, and
-- deliberately the same shape as the other two: genesis bound to claim_id,
-- seq dense from 0, forks a constraint violation, reason NOT NULL, nothing
-- deleted. Evidence links live HERE and not on the memory's chain: a claim
-- is about memories, memories are not about claims, and a document whose
-- history grew with every proposition that ever cited it would be carrying
-- the epistemic unit's weight again.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS claim_chain (
    claim_id      TEXT NOT NULL REFERENCES claims(claim_id),
    seq           INTEGER NOT NULL CHECK (seq >= 0),
    event_type    TEXT NOT NULL CHECK (event_type IN (
                      'CLAIM_ASSERTED','EVIDENCE_LINKED','RELATED_TO',
                      'SET_MEMBERSHIP','CLAIM_VALIDATED','CLAIM_REFUTED',
                      'CLAIM_WITHDRAWN','CLAIM_SUPERSEDED')),
    actor_id      TEXT NOT NULL REFERENCES actors(actor_id),
    reason        TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_at    TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
    entry_hash    TEXT NOT NULL CHECK (length(entry_hash) = 64),
    PRIMARY KEY (claim_id, seq),
    UNIQUE (claim_id, prev_hash),
    UNIQUE (entry_hash)
);

CREATE INDEX IF NOT EXISTS idx_claim_chain_actor ON claim_chain (actor_id);

-- -----------------------------------------------------------------------------
-- claim_sets — n-ary contradiction. "A contradicts B" is too poor for most
-- real conflicts: a date is one of three candidates, a policy is one of
-- several readings. A set is a CONSTRAINT over many hypotheses —
-- AT_MOST_ONE, EXACTLY_ONE, or the weaker INCOMPATIBLE (they cannot all
-- hold), which is often the only thing actually known.
--
-- members_sha256 seals the sorted member list, like a taint sweep, and
-- every member's chain carries a SET_MEMBERSHIP event so the membership is
-- RE-DERIVABLE from evidence rather than trusted to this row — the lesson
-- taint_protocol 2.0.0 learned the hard way.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS claim_sets (
    set_id          TEXT PRIMARY KEY,
    constraint_type TEXT NOT NULL CHECK (constraint_type IN (
                        'AT_MOST_ONE','EXACTLY_ONE','INCOMPATIBLE')),
    topic           TEXT,
    reason          TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_by      TEXT NOT NULL REFERENCES actors(actor_id),
    created_at      TEXT NOT NULL,
    members_json    TEXT NOT NULL,
    members_sha256  TEXT NOT NULL CHECK (length(members_sha256) = 64)
);
