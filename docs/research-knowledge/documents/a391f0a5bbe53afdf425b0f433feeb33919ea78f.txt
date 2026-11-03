# Common-size partial withdrawal test

Status: offline execution in progress. Amount and criteria frozen in `71d2aca`.
No privacy result is claimed before the twenty blinded observations finish.

The [frozen scope](COMMON-PAYOUT-SPEC.md) adds one 2-tKAS cashout per wallet,
retains private change and then drains all remaining claims. Original deposits,
six private payments and two earlier partial withdrawals stay unchanged.
The [source review](../../research/common-payout-sources-2026-10-20.md) and
[ADR-0025](../../docs/adr/0025-common-payout-offline-screen.md) explain why this
is a client-policy experiment on unchanged v6, without a new protocol.

## Execution boundary

Four synthetic amount/schedule cases; one chain-only observer and four separate
participant disclosures per case. All know the declared client rules. The
participant observer retains H16's complete own records/ownership assumptions.
No RPC/network metadata or pooled participant records.

Compare original-source candidates after the four equal payouts and after
every final drain. Repeated Q-change outputs inherit their input's origin in
each inferred graph. Claims remain the original seven per case, even when
split into two payouts. Secret leg matching is used only by the scorer; it
does not intersect observer candidate sets.

Native calibration uses one case with genuine Groth16 proofs and synthetic
native UTXOs. The other three cases are arithmetic models. Reuse the existing
parameters, circuit and covenant. Check the saved old full exit before each
optional partial, both mutually exclusive winner orders, and all seven saved
change/unaffected-note exits after further activity. Fresh drainage is a
separate branch; the primary privacy measurements use fresh exits.

## Frozen cost

| Per case | Baseline | Common partials plus final drainage |
| --- | ---: | ---: |
| Pool transactions | 19 | 23 |
| Fees, sompi | 760,000,000 | 920,000,000 |
| Fees, test KAS | 7.6 | 9.2 |
| Additional fee per wallet | — | 40,000,000 sompi / 0.4 tKAS |
| Added complete-cashout delay | — | 40 synthetic minutes |

Fee increase is 21.05%, within the existing 25% screen. The ten-minute
inter-event schedule exceeds the existing 30-minute p95 completion-delay
screen. Neither is an observed chain fee-market quote or actual waiting time.
No test KAS or real funds are spent offline.

## Reproduction

Use the frozen original private H14 run and the existing v6 parameters outside
Git. The observer controller checks their hashes before preparation. Raw
participant records and unused fallback capabilities remain private.

```sh
cd poc/shared-pool
# Python environment: privacy-study-requirements.txt
python common-payout.py prepare "$KPI_H17_PRIVATE" "$KPI_H14_PRIVATE"
python common-payout.py run "$KPI_H17_PRIVATE" --workers 6

CARGO_TARGET_DIR="$KPI_BUILD" cargo build --release --locked --offline --bin kpi-two-input
RAYON_NUM_THREADS=4 "$KPI_BUILD/release/kpi-two-input" common-study \
  "$KPI_PARAMS" "$KPI_H17_PRIVATE/a0-s0/plan.json" "$KPI_H17_PRIVATE/native"
```

The measured wrapper copies the executable into the private run directory and
records binary/source/parameter/plan hashes plus process resource usage before
running it. `common_payout_calibration.py check` then revalidates both selected
native histories using isolated public-body-only verification and compares
their normalized public fields with the model. The controller's `export` and
the calibration export retain only allowlisted evidence after those checks.

Eight targeted controls include an independent tiny integer/provenance oracle,
known-client conditionality, floor/oversize rejection, view-prefix boundaries,
all fees and original-prefix identity. The existing protocol pins remain
unchanged. The [author's second pass](COMMON-PAYOUT-REVIEW.md) is not an
independent cryptographic audit.
