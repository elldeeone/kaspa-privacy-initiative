# Admitted local prefix reuse

ADR 0067 permits a bounded local optimization. The original caller, launcher,
Source57, financial parameters and downloaded recovery package remain unchanged.
The sibling caller retains the same private PLAN, STATE, six invoices and
consumed-action rule. It does not migrate, reset or export their contents.

`launch_cached_campaign.py runtime --output ABS` authenticates every original
Source57 member and adds the nine cached chain siblings plus the new caller and
launcher. It writes the exact public runtime selector; it cannot replace an old
source path with a new source hash.

`admission --activation ABS --activation-sha256 HEX --initial-handoff ABS
--initial-handoff-sha256 HEX --runtime-source ABS --runtime-source-sha256 HEX
--output ABS` admits only the Root-selected full first-payment handoff `73ee…ba5`.
This is an explicit trusted-controller-local-state assumption. A downloaded or
discovered public cache receipt grants no admission.

The new `proposal` operation takes the original activation arguments and adds
`--cache-admission ABS --cache-admission-sha256 HEX --runtime-source ABS
--runtime-source-sha256 HEX`. The selection must contain exactly
`cache_policy = {admission: {path,sha256}, runtime_source: {path,sha256}}`.
Materialization continues to authenticate the same actual downloaded cold package.

For each submit and confirmation, the new caller supplies the current
`STATE.head['fetch.json']` and optional `STATE.head['CACHE.json']`. It never chooses
a baseline by scanning a public directory or reverting to the activation fetch.
Only a successful selected confirmation can replace the head and retain a new
cache selector. The chain modules authenticate the selected admission and source
closure and enforce the ADR's retained-page, delta, reorg and live-UTXO checks.
All selected pool transactions still undergo complete native Full and financial
history replay.

Use the original launch arguments with a fresh unit name and `--resume`. A
consumed action enters confirmation only; it does not rebuild, reprove, request
owner authority or call submit again. Public launch receipts are named
`CACHED-RESUME-LAUNCH-<unit>.json` and must be absent before service creation.

Actual activation requires Root release after independent controls and the
genuine cached/full comparison. Final independent accounting fully verifies the
retained ledger. This optimization does not qualify consensus, privacy, or the
unchanged fee target.
