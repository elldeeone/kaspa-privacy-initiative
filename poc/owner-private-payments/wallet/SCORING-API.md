# Frozen owner-local scoring exception

Additive diagnostics for frozen `PRIVACY-EXPERIMENT-01.md`, SHA256
`625f57369497b198d87e57d554e1d4976d4efa47b6b8f9a8ad94e936e7275803`.
The executed financial `worker.py` and `run_owner.py` are unchanged. Only this
fixed count-only exception may inspect the owning records after authorization.
There is no financial retry, reveal, decryption-result or per-row query API.

The trusted supervisor launches these operations; the public coordinator has
no request interface, Docker socket, owner paths or diagnostic result access.
All source/public inputs pass old8 plus complete NEW3 metadata/inode guards.
The only private observer export is a restricted leaf, not foreign authority.
No actual diagnostic owner execution is authorized by these source controls.

## Common selector and public verification

```text
python3 -B run_score.py observe|score|aggregate
  --experiment-sha256 625f57369497b198d87e57d554e1d4976d4efa47b6b8f9a8ad94e936e7275803
  --exclude-old-trial OLD_LOCAL --exclude-old-trial OLD_LIVE
  --exclude-new-private-directory PARTY0
  --exclude-new-private-directory PARTY1
  --exclude-new-private-directory PARTY2
  --output FRESH_PRIVATE_CONTROLLER_RUN [--execute]
```

Default stages a private operational plan only. For observe and score, also
select `--owner-directory PARTY/owner --attempt 000001 --assets FILE
--assets-sha256 SHA --session FILE --session-sha256 SHA --projection FILE
--projection-sha256 SHA`. The exact common SESSION and final genuine projection
must be selected before prediction sealing. The worker verifies all nine
genuine G16s, direct CV balance and public native/root effects with the already
selected relation/profile/wire. No PK is read, hashed, copied or mounted. The
supervisor separately requires the real outer/native gate; this diagnostic
verification alone does not claim outer proof or chain acceptance.

## One permitted colluder observation

`observe --registry FILE --registry-sha256 SHA` receives only that colluder's
own owner directory and read-only MPC directory, selected public software and
public artifacts. It reserves durable `owner/diagnostics/OBSERVER-CLOSED`
before its private view is read, and refuses every repeat.

The fixed strategy checks its two contributed rows, local value openings and
beta, then independently decrypts all final CFs using its own seed. It uses
legitimate incoming values and public admission-minus-fee priors to reject
infeasible two-output honest creator partitions; a fixed public hash breaks
ties. Decrypted receipt indices1..3 are compared with the colluder's own actual
private issuance records and identify the assigned sender under the honest
selected-worker behavior in this experiment. Those already-known creator facts
are excluded as well as its own two contributed rows. This is not cryptographic
sender authentication: stolen/shared invoices or malicious creators are a
separate boundary. Plaintext values alone do not establish creator identity.
The strategy seals candidate-assignment count1..6, label-invariant partition
count1..3, whether a hash tie-break was needed and whether constraints uniquely
identified a grouping BEFORE any truth comparison. This is one bounded strategy,
not an exhaustive privacy attack.

Public `FRESH_RUN/public/PUBLIC.json` contains only common experiment/session/
projection/strategy pins, a capsule seal, bounded excluded/unknown creator counts
and the presealed ambiguity fields. It contains no colluder-output identifiers.

Private `owner/diagnostics/OBSERVER-CAPSULE.bin`, mode0400, is exactly176bytes:
`tag8|experiment32|session32|projectionSHA32|strategy32|salt32|colluder1|mask1|guesses6`.
The fresh secret salt prevents dictionary recovery of the small ownership
mask from its public seal. No host opens, hashes or copies this capsule. Each
scorer receives only the original read-only leaf. Neither the capsule nor its
salt/mask/guesses is a publication artifact.

## One presealed query, two views

The coordinator's already-sealed public prediction file has exact fields:

```json
{"schema":"kpx7-public-creator-prediction/v1","experiment_sha256":"FIXED",
"session_sha256":"SELECTED","projection_sha256":"SELECTED",
"strategy_sha256":"FROZEN_OBSERVER_SOURCE","guesses_creator_index":[0,0,1,1,2,2]}
```

The six indices are guesses in final mixed-pool order. Each roster creator is
guessed exactly twice. This is an observer prediction, not ownership truth.
The trusted controller seals one public bundle with exact fields `schema`
(`kpx7-owner-privacy-prediction-bundle/v1`), `experiment_sha256`,
`session_sha256`, `projection_sha256`, `coordinator_predictions_sha256`,
`colluder_observer_receipt_sha256`, `colluder_capsule_seal_sha256`. Both views
must be sealed before any scorer runs; feedback never reaches an observer
before its predictions are sealed.

Invoke `score --predictions FILE --predictions-sha256 SHA --observer-receipt
FILE --observer-receipt-sha256 SHA --bundle FILE --bundle-sha256 SHA --capsule
OPAQUE_ORIGINAL_LEAF` once per owner. Under the existing exclusive OWNER-LOCK,
the worker creates durable `owner/diagnostics/SCORING-CLOSED` before reading
the private capsule or its own TRUTH. There is one such record per owner,
independent of caller experiment ID, attempt or bundle; identical and different
repeat requests both fail. An interruption after reservation is INCOMPLETE.

The worker joins only its own two tuple hashes to the fixed genuine final
pool, joins its own original financial authorization to the final effects,
compares both guesses and checks actual creator eligibility. Known incoming
creator exclusions must agree with its own payment recipient/kind records.
It writes only private `owner/diagnostics/COUNTS.bin`, mode0400,142bytes: common
tag/experiment/session/projection/bundle plus six bounded count bytes (eligible,
exact-label matches and label-invariant grouping matches). Swapped honest
creator labels cannot hide a recovered grouping. It emits no per-owner
counts, identifier, matched location, CM/tuple, private path or record hash.

## Global output only

`aggregate --count-file ORIGINAL_LEAF` repeated three times takes the three
distinct original count leaves beneath the selected three party parents,
plus `--session-sha256 SHA --projection-sha256 SHA --bundle FILE
--bundle-sha256 SHA --observer-receipt FILE --observer-receipt-sha256 SHA`.
Its clean namespace mounts only those142byte leaves, presealed public ambiguity
records and fixed public code;
it mounts no owner/MPC directory, keys, truth, executable asset or PK. The host
checks metadata only and never reads/hashes a count leaf. The worker verifies
all three contexts/ranges and exactly one colluder exclusion, then exports
only global eligible/matched/grouping counts for coordinator-only and
one-colluder views, together with the already-sealed ambiguity fields.
Private counts, filenames and argv are never publication artifacts.

A missing colluder view, missing owner count or impossible realistic inference
remains INCOMPLETE. Global counts describe this frozen finite exercise; no
accuracy percentage, statistical anonymity score or production privacy claim
is emitted from six outputs. A correct tie-break guess among multiple admissible
partitions is not by itself evidence of recovered leakage. Constraint-derived
unique grouping and chance predictions remain distinct, without retuning the
frozen failure rule after scores. Same-host trusted administration is a premise.
