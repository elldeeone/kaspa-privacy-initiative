# Public-transcript privacy calibration

**Method 04 completed:** 48 output/horizon queries across two arithmetic profiles,
with exact CP-SAT extrema and independent Z3 endpoint/outside-bound checks.
See [its result](attempts/method-04/observer-infer/result.json) and
[completion record](attempts/method-04/completion.json).
This is an offline calibration on an already published M2 wallet history,
not a held-out trial, an owner-anonymity measurement, a privacy pass or evidence
of cryptographic security. Funding ancestry is synthetic and chain acceptance
was not verified. No new proofs, funds or broadcasts were used for this analysis.

## Attempt index

| Attempt | Method change | Outcome |
| --- | --- | --- |
| [01](attempts/method-01/) | Original single-worker CP-SAT search | Incomplete; interrupted after 04 completed |
| [02](attempts/method-02/) | Per-query runtime diagnostics only | Search stalled at a maximum query; interrupted after 04 completed |
| [03](attempts/method-03/) | Added a nonbinding objective-value search hint | Search stalled at a different minimum query; interrupted after 04 completed |
| [04](attempts/method-04/) | Removed the hint and used eight CP-SAT workers | Completed both profiles and all 48 queries |

All four attempts used identical public inputs, frozen specification, domains,
constraints and metrics. Each passed 20 controls: five native rejection cases,
six projection checks and nine arithmetic controls containing 454 exact
feasible-value comparisons against an independent exhaustive oracle.
The interrupted attempts carry `interruption.json` and original logs; they yield
no privacy verdict. Parallel search can change model witnesses and runtime,
while the reported extrema still require exact certification and cross-checks.
Each completed profile used 73 CP-SAT and 121 Z3 queries.

## Evidence and observer boundary

Every attempt preserves its exact `code/` snapshots, `freeze.json`, four public
`inputs/`, full `public-input.json`, native replay, projection pins, controls,
isolation records and process logs. Native mutation diagnostics are retained;
the deterministic mutation code reproduces their omitted input copies.
Executables and dependency copies are excluded from this export. The original
method-01 export note is retained in that attempt's `README.md`.
The frozen specification is named `code/EARLY-PRIVACY-SPEC.md.txt` in this
export so its original relative links are not interpreted from the archive
directory. Its bytes are unchanged; this filename maps to the
`EARLY-PRIVACY-SPEC.md` source key in `freeze.json`.

The observer received only the four public inputs, their byte-derived projection,
frozen observer code and public dependencies. It did not receive wallet backups,
note openings, actions, scans, receive envelopes, participant labels, the earlier
report or proof timings. Published truth remains known to the authors, so process
isolation does not make this a blinded study. OS/runtime and author-written code
remain trusted.

The native records contain genuine existing proofs. Authorization and ciphertext
mutations failed canonical transaction-ID checks; the proof mutation reached
native ZK execution and failed serialization. These are not alternative valid
proofs. Removing an interior transaction failed ancestry checks; removing only a
terminal transaction may leave a valid prefix. Complete-history identity is
pinned separately.

The profiles are the broad v6 relation and a documented current-wallet shape;
the latter omits common input ownership. Solver endpoint witnesses are
alternative satisfying assignments computed from public data, **not recovered
actual private choices**. Bounds are integer extrema, not a continuous range,
probability or anonymity count. Equal commitments retain distinct positions.
Equal funding-parent IDs do not establish a common user. No timestamps were
observed. See the [frozen specification](attempts/method-04/code/EARLY-PRIVACY-SPEC.md.txt).

## Reproduction and identity

Run from `poc/shared-pool` on Linux with Bubblewrap, locked Rust dependencies and
Rust 1.95.0. The observer environment used `ortools==9.15.6755` and
`z3-solver==4.15.4.0`; all 3,422 installed dependency file identities, plus Python
and Bubblewrap executable hashes, are in each `freeze.json`. The sandbox uses an
empty temporary Python cache prefix to avoid importing unpinned existing caches.

Before reproducing method 04, compare repository source/spec bytes with its
`code/` snapshots and the source M2 inputs with its `inputs/`. Build the replay
binary only if needed, then use a **fresh** output directory:

```sh
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-replay
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py prepare /tmp/kpi-early-privacy-reproduction
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py controls /tmp/kpi-early-privacy-reproduction
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py run /tmp/kpi-early-privacy-reproduction
```

The original attempts used `/tmp/kpi-early-privacy-20261020-method-NN` as their
output directories and the existing native replay executable; it was not rebuilt
during calibration. `prepare` accepts `--binary /absolute/path/to/replay` and
`--venv /absolute/path/to/environment`. A different build or dependency tree is a
new recorded environment. This public export omits the executable and is not a
resumable runner workspace. Preserve all original attempts.

Shared SHA-256 identities:

- Specification: `1b21810517d21d1221364e4c63f258710022100c8942dcc795c200266142e96e`
- Public projection: `b49e2d9dbfd153b609dc782376fc20663b9518826deb97b06c03e9a326bdea63`
- Native replay executable: `442ba78bf089f85c16184b9072da4a1c5de7d7a136f5c0aeb9b00bf604e7bbb2`
- Method-04 result: `9942d6a9d5cc5c5537c468d65027f9126e40c3610ef7c9a66484c64cdc2f78ac`
