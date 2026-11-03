# Public-transcript privacy calibration

This is an offline amount-inference calibration on the already published M2
wallet history. It is not a held-out privacy trial, an owner-anonymity
measurement, a privacy pass, or evidence of cryptographic security. The native
transactions carry genuine existing proofs, but funding ancestry is synthetic
and chain acceptance was not verified. No new proofs, funds or broadcasts were
used for this analysis.

The observer received only the four public inputs under `inputs/`, their
byte-derived projection, frozen observer code and public dependencies. It did
not receive wallet backups, note openings, actions, scans, receive envelopes,
participant labels, the earlier report or proof timings. Published truth remains
known to the authors, so process isolation does not make this a blinded study.

## Contents and limits

- `code/` preserves the exact predeclared specification and four source files.
  `freeze.json` pins these, the four inputs, native replay executable, Python
  executable, Bubblewrap and 3,422 installed dependency files. Executables and
  dependency copies are excluded from this public export.
- `public-input.json` retains all raw public transaction bytes and the decoded
  surface. `native-replay.json` records native validation;
  `projection-pins.json` identifies the projection and complete history endpoint.
- `controls.json`, `observer-controls/` and the five native-control diagnostic
  files preserve the controls. Mutated native input copies are omitted; their
  exact deterministic mutations are in the frozen runner.
- `observer-infer/result.json` and `completion.json`, when both present, record
  inference completion. Their absence means inference is pending; a file whose
  `complete` field is false is an incomplete result, not evidence of privacy.

Controls passed: five native rejection cases, six projection checks, and nine
tiny arithmetic controls with 454 exact feasible-value comparisons against an
independent exhaustive oracle. Authorization and ciphertext mutations failed
canonical transaction-ID checks; the proof mutation reached native ZK execution
and failed serialization. These are not alternative valid proofs. Removing an
interior transaction failed ancestry checks; removing only a terminal transaction
may leave a valid prefix. Complete-history identity is pinned separately.

The two arithmetic profiles are the broad v6 relation and a documented
current-wallet shape. The latter does not model common input ownership. Solver
endpoint witnesses are alternative satisfying assignments computed from public
data, **not recovered actual private choices**. Bounds are integer extrema, not
a continuous range, probability or anonymity count. Equal commitments retain
distinct positions; equal funding-parent IDs do not establish a common user.
There are no timestamp observations. See the frozen specification for scope.

## Reproduction

Run from `poc/shared-pool` on Linux with Bubblewrap, the repository's locked Rust
dependencies and Rust 1.95.0. The original observer environment used
`ortools==9.15.6755` and `z3-solver==4.15.4.0`; the full installed-file identities
are in `freeze.json`. OS/runtime and author-written code remain trusted.
The sandbox uses an empty temporary Python cache prefix so unpinned existing
bytecode caches are not imported.

These were the preparation, control and inference commands (the output directory
must be fresh for reproduction):

```sh
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-replay
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py prepare /tmp/kpi-early-privacy-20261020-method-01
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py controls /tmp/kpi-early-privacy-20261020-method-01
PYTHONDONTWRITEBYTECODE=1 python3 early_privacy_surface.py run /tmp/kpi-early-privacy-20261020-method-01
```

The recorded attempt used the existing replay executable, without rebuilding it
during this calibration. Its SHA-256 is
`442ba78bf089f85c16184b9072da4a1c5de7d7a136f5c0aeb9b00bf604e7bbb2`.
Before reproducing, compare source/spec bytes with `code/` and public inputs with
`inputs/`. `prepare` accepts `--binary /absolute/path/to/replay` and
`--venv /absolute/path/to/environment`. A different build or dependency tree
creates a new recorded attempt; do not describe it as the identical environment.
The exported directory intentionally omits the executable and is not itself a
resumable runner workspace. Preserve the original attempt and use another fresh
output path for reruns.
