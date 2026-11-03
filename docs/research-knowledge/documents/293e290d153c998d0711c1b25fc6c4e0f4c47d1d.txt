# Pinned-passive P1 empirical observer method freeze

**Status:** prospective source-only method. Exact within-run controls are green,
but no consumed producer-spool bridge, actual capture, privacy result, or source
assumption is selected. Configuration and launch remain off. The C03 v9 core
wire is frozen, but its joint model/raw-spool parser is not yet admitted.

**Scope decision:**
[ADR-0088](../../../../docs/adr/0088-passive-pinned-p1-empirical-observer-scope.md)

**Implementation:**
[`privacy_p1_empirical_observer.py`](../../../../poc/local-private-payment/private_batch_trial/privacy_p1_empirical_observer.py)
and the fixed non-authorizing reducer
[`privacy_p1_empirical_capsule.py`](../../../../poc/local-private-payment/private_batch_trial/privacy_p1_empirical_capsule.py).

## Question

For one actual frozen run, which source-enumerated structural honest-owner
assignments remain consistent with the exact raw C03 view and the other nine
sealed role leaves?

The standalone engine currently evaluates one symmetric two-hypothesis swap.
That is a bounded attack/control, not the frozen gate's exhaustive candidate
space. The selected observer must separately recompute the four views with
`derive_view_artifacts()` and their two-round candidate sets with
`workload_candidates()`, then bind empirical constraints across every edge of
every candidate before it can close a gate category. A standalone unique or
ambiguous result is always non-authorizing. Ambiguity is retained as evidence
for the exhaustive lattice; it is not by itself an automatic failure of the
final gate.

This is a bounded empirical question about the pinned, instrumented,
protocol-following P1 process plus passive owner1. It is not a theorem about
MASCOT, DDNNT, mixed group arithmetic, or Groth16. It says nothing about an
active P1, modified binary, internal OT/PRNG tape, arbitrary physical host,
network stack, or covert channel.

## Authority and provenance

The eventual observer capsule must consume one `ProducerSpoolAuthority`. That
capability gives it the private ten-stream spool, not a caller-authored JSON
event list. Inside the capsule it must derive events only from the authenticated
producer-child completion and the source/build/runtime/launch-bound ten-stream
closure:

- round, role kind, source/process/launch identity, record root, END, and EOF;
- source clock-domain identity, source monotonic timestamp, and source order;
- frame length, direction, peer, fork, payload digest or literal;
- retry attempt, stage, outcome, abort marker, and partial tail.

Every correlation event must identify a non-P1 sealed role, round, record
root, structural identity, clock domain, and source rank. The same logical join
must draw both hypotheses from the same sealed source provenance. An event may
not name the P1 source or P1 capture root. The capsule builder, not a caller,
must resolve `(source root, rank)` to typed source fields; this is what prevents
a copied P1 digest from masquerading as cross-artifact evidence.

The child performs one single-pass dual parse before discarding each raw leaf.
Each source parser returns both its existing typed model artifact and a private
`source_events` companion derived from those same bytes. The companion is
bound in child memory to that producer-private leaf identity, role, round, and
parser receipt. C03 companions retain frame order, clock-domain/time, length,
direction/peer/fork, retry/partial-tail, and payload digest. Dispatcher,
terminal, and C1 companions retain only their source event rows. The empirical
builder runs immediately on these companions. It must never reconstruct events
from typed constraints, copy P1 fields into another source, or accept event
JSON from a caller. Raw leaves and companions never cross the capsule boundary.

For each round the child also derives `public` directly from the sealed
10,685-byte projection, constructs all five typed artifacts, and recomputes
`derive_view_artifacts(public, artifacts)`. For each of the four views it
recomputes `codec.assignments()` and the exact two-round
`workload_candidates()` join using the two typed terminal artifacts. No public
batch, candidate vector, constraint set, or assignment may arrive from a
caller.

The standalone join engine validates and evaluates that event schema, but
cannot attest how a caller obtained it. Its receipt therefore always states
`requires_consumed_producer_spool_authority: true` and
`gate_authorizing_without_capsule_bridge: false`. Until the capability bridge
builds the plan internally, every result remains non-authorizing.

Even after that bridge, its fixed internal result may contain only a bounded
status enum, bounded hypothesis identifiers/edge-match flags, and coverage
flags. It contains no hashes, paths, bodies, payloads, free-form text, or
completion nonce. It never mints an opaque completion authority. The selected
observer independently verifies the ten typed leaves, four-view candidate
lattice, exhaustive empirical edge coverage, and zero unmodeled categories;
only then may the supervisor echo its pre-bound parent nonce.

Raw capture, observation, plan, payload, tail, and source-manifest hashes are
capsule-internal. They must not appear in a parent or public receipt. The
empirical reducer emits only a fixed typed internal result with numeric
hypothesis IDs, fixed edge masks, and coverage booleans; it hardcodes the
four-view bridge and gate-authorizing flags to false. The selected supervisor
must mint its fresh/session-bound completion and score authorities
independently of all internal hashes; the empirical modules cannot parse,
mint, validate, or return that parent envelope.

## Label-free extraction

Extraction accepts only every raw C03 capture leaf in retry order and its
source-bound attempt history. It accepts no mapping label or truth. A
single-capture call refuses a multi-attempt history.

Every complete frame must pass magic, reserved-byte, sequence,
message/chunk, monotonic, payload-length, and payload-digest checks. A final
partial header or payload is retained by length and digest. Attempt times must
contain their frame times. The extractor emits exact per-attempt and per-frame
observations in addition to aggregate diagnostic features.

The v9 fixed-width controls decode all 332 HELLO bytes, all 16 scalar-binding
bytes, the 32-byte projection seal, all 96 fork-binding bytes, the zero-byte
End payload, and all 496 footer bytes. Footer bytes `0:440` are the
version/count, three total counters, and all 17 three-counter lanes; bytes
`440:496` are the instrumented, owner-offset, owner-preprocessing and scalar
site bitmaps, pre-footer frame count, and first/last pre-footer monotonic
timestamps. No footer byte is merely covered by the envelope digest. The
query-store and scalar-callsite manifest hashes are HELLO fields, not footer
fields. Producer EOF/record-chain closure is separately verified by the typed
C03 source-authority parser. The standalone extractor remains diagnostic and
does not replace that strict source parser.

An aggregate feature or changed hash is inventory only. It never closes a
privacy row.

## Frozen deterministic constraints

The pre-truth plan contains exactly two structural mapping hypotheses. They
must be permutations over the same public structural domain and range. They
must have symmetric join IDs, P1 references, structural keys, source
provenance, and comparison fields; only the structural event selected within
that same source may differ. Every mapping edge needs at least one join, and
the event's structural identity must equal that hypothesis's mapped value.
Truth, correctness, or actual-owner markers are refused. Cosmetic mappings,
identical joins under different maps, and candidate-specific sources refuse.

Each actual join applies one or more of these rules:

1. Exact equality for record/semantic/flags, sequence/message/chunk, frame
   length, direction, peer, fork, and source-bound attempt/retry fields.
2. Exact payload SHA-256 equality. If a public/source literal exists, its
   length and digest are recomputed before the comparison.
3. Exact monotonic-time equality only when both records carry the same
   authenticated clock-domain identity and describe the same event.
4. A threshold-free common-clock timing attack sums absolute signed deltas for
   symmetric event pairs. A uniquely smaller distance removes the farther
   hypothesis. Equal or zero distance retains both.
5. When clock domains differ, only relative order within each source is used.
   Distinct ranks must agree exactly. Ties are ambiguous, not a match.
6. Failed attempts, aborts, retries, and non-empty partial-tail length/digest
   constraints are intersected with all complete-attempt constraints.

Each raw field is `CONSTANT_PUBLIC`, `CONSTRAINT_MODELED`,
`NOT_PRESENT_IN_CAPTURE`, or `UNMODELED`. `CONSTRAINT_MODELED` requires every
observed occurrence to participate in a symmetric, source-bound comparison.
Counts of positive, mismatching, and ambiguous comparisons are retained per
field. A mismatch removes only that structural candidate; zero, tied, or
ambiguous evidence keeps both. Missing coverage or a missing required clock
identity makes the whole receipt
`UNQUALIFIED_MISSING_WITHIN_RUN_CONSTRAINT`.

If coverage is complete, the possible non-claim statuses are:

- `DETERMINISTIC_UNIQUE_CANDIDATE`: one structural mapping survives;
- `DETERMINISTIC_AMBIGUOUS_CANDIDATES`: both survive; or
- `UNQUALIFIED_NO_STRUCTURAL_CANDIDATE`: the source artifacts disagree.

Neither deterministic status is a privacy pass. A later isolated truth scorer
may evaluate the pre-truth prediction, but truth may never enter extraction,
plan construction, joins, thresholds, or candidate pruning.

## Optional classifier study

The 24-train plus 24-holdout samples per assignment classifier is separate and
optional. `synthetic_clear_signal_calibration_rows()` deliberately fabricates
differences in payload length, direction, peer, fork, and timing. It tests only
classifier mechanics and is tagged `SYNTHETIC_UNIT_TEST`.

Classifier models and scores always carry `optional_study_only: true` and
`gate_authorizing: false`. They cannot satisfy an acceptance-ledger row. A
future study would require prospective, whole-trial captures from the exact
selected full runtime, with trial-level train/holdout separation and no reuse
of actual trials. If that corpus is unaffordable, the study is omitted; the
actual gate does not require 96 additional financial proofs.

## Stop rules

Stop and retain the failed identity when any of these occurs:

- a retry/partial leaf or attempt-history row is absent;
- frame integrity, retry lineage, time containment, END, or EOF disagrees;
- the producer-spool authority or ten-stream source closure is absent;
- an event is caller-derived rather than capsule-derived;
- an event names the P1 source/root or lacks sealed source provenance;
- candidate joins are asymmetric or contain a truth marker;
- a mapping edge has no join or disagrees with its event identity;
- exact time is requested across different clock domains;
- source ranks are missing, duplicated, or cross-source;
- any observed field lacks complete symmetric coverage; zero or tied evidence
  retains candidates, while mismatches prune only the affected candidate;
- the plan, source manifest, model/query manifest, capture, or receipt digest
  disagrees; or
- actual truth reaches any pre-truth stage.

Do not retune and reuse an identity. An operational retry needs a fresh
identity and every failed/partial capture remains in its attempt sequence.

## Current evidence and remaining blockers

Focused controls cover exact observations; constant/integrity refusal;
multichunk consistency; all retry leaves and partial tails; exact metadata and
payload literal/digest joins; common-clock timing-distance pruning; cross-clock
rank pruning; cross-source and structural-edge binding; self-join/copy-root and
cosmetic-mapping refusal; missing-field fail closure; and non-authorizing
classifier labeling. C03 v9 controls also parse and constrain HELLO model,
query-store and scalar-manifest identities; semantic-17 kind/site/count; and
projection-seal, fork-binding, End, and every footer v9 counter/bitmap byte.
Negative controls cover a single changed counter, maximum-u64 counter,
permuted lanes, noncanonical footer width, wrong projection seal, bad or reused
fork identity, malformed End, and HELLO/attempt mismatch. These are source
controls, not an empirical result.
The fixed reducer additionally checks the exact receipt and field catalogs,
rank/timing schemas and arithmetic, symmetric edge provenance, retained-set
recomputation, and a 64-edge bound. It hardcodes source-assumption coverage,
the exhaustive four-view bridge, and gate authorization to false.

The observer is not bridged to `ProducerSpoolAuthority`, so no actual event
plan exists. The v9 wire/parser controls are not yet bound to typed results
derived inside the consumed ten-leaf spool capsule. The standalone two-way
result is not bridged across the frozen four-view/two-round candidate lattice,
so it cannot close the acceptance gate even after a source-proven event plan
exists. The source-assumption registry remains empty.
Query/MSM correspondence, mixed-protocol implications, and every nonliteral
Query/MSM worker/point temporaries are not directly captured, and the
public-stage callback timing remains explicitly unmodeled. Active
malicious-server and arbitrary-host privacy remain unqualified and block all
general or production claims.
