# Corrected assessment of the completed native withdrawal run

**Scope:** offline reassessment of the existing successful attempt 06 only.
No new transaction, wallet proof, trial, funding or protocol change.

The original native payout and accounting evidence stands. The original privacy
report's stronger-observer reconstruction claim is **withdrawn for this run**.
Its supplied fact selected the wrong payment history.

## What the corrected result says

All five native owner payouts completed. The retained final checkpoint has zero
reserve principal, private liability, pending deposits, unpaid exits and
outstanding permission rent. The separate state covenant retains 100,000,000
sompi (1 test KAS) as state rent. This accounts for successful attempt 06; it
does not close or recover balances from the earlier halted attempts.

Under the retained finite-grid/contact-graph model, with payout owners known,
the public deposit and private-exit amount evidence still admits two materially
different gross payment histories. The recorded executed history is retained.

| Payment fact | What the reduced model reveals after all withdrawals |
| --- | --- |
| A pays merchant M | Relationship known; amount is 0.3 or 0.4 test KAS |
| B pays merchant M | Relationship and 0.2-test-KAS amount known |
| Supplier S receives 0.1 test KAS | Payer is either A or M |

Thus some earlier payment facts remain ambiguous **within this model**. Public
withdrawal amounts and destinations, known owner mappings and net balances are
not hidden. This is neither an ordinary-user anonymity measurement nor a claim
that all native metadata preserves the two alternatives.

## The scoring error

The retained original scorer conditioned the stronger view on `M -> S`. The
executed driver instead used A-to-M 0.3, A-to-S 0.1 and B-to-M 0.2 test KAS.
The saved private execution metadata agrees and executes from the observed
deposits to the observed terminal owner notes.

The original `M -> S` view returns one candidate, but excludes the executed
history. A unique wrong prediction is not successful reconstruction. The
correction retains this view as a false-external-evidence negative control.

The correction also evaluates each possible contact edge as a hypothetical
additional-information sensitivity, before execution-truth validation:

- Knowing `A -> S` is true selects the actual complete gross history uniquely.
- Knowing only `A -> M` or `B -> M` leaves both histories compatible.
- Assuming `M -> S` selects the wrong history for this run and is flagged as
  contradictory evidence, not a privacy success or a correct privacy attack.

The `A -> S` result is a **new, explicitly post-hoc conditional sensitivity**.
The experiment did not measure how a real outside observer would acquire that
fact. It does show why the surviving ambiguity is fragile under truthful
additional knowledge. It must not be relabelled as the original frozen attack.

## Evidence and inference boundary

The corrected input projection derives credit amounts/owners, terminal note
amounts/owners and transfer count from the retained public wallet statements and
known-owner mappings. It checks credits against accepted native deposit outputs,
principal conservation and 24 retained transaction-confirmation records,
including all seven settlements. Their hashes are bound into the predictions.
Native recipient outputs can include permission-rent refunds; private exit
principal and native output totals must not be silently treated as equal.

The inference still assumes opaque commitments, ciphertexts and nullifiers,
the original 10-million-sompi grid and the four-edge possible-contact graph.
It enumerates complete compatible histories and does not count hidden labels,
commitment assignments or event permutations as separate payment histories.

The old scorer logged timing, payload sizes, sponsor linkage and other native
metadata, but did not use those fields to discriminate histories or estimate
likelihoods. The new report makes that limitation explicit. The service view
had no independently implemented IP/RPC attribution attack. Recording a field
does not demonstrate that its privacy implications were tested. In particular,
two model-compatible histories do not establish computational indistinguishability
of the complete actual blockchain transcript or equal posterior probability.

## Reproduction and preservation

Use the separate corrected entry point. The original scorer remains unchanged
for reproduction of the historical erroneous result; it is not the corrected
assessment entry point.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 score_live_correction.py predict PRIVATE_RUN NEW_CORRECTION_DIR
PYTHONDONTWRITEBYTECODE=1 python3 score_live_correction.py validate PRIVATE_RUN NEW_CORRECTION_DIR
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s . -p test_score_live_correction.py -v
```

Run those commands from this directory. The `predict` phase reads public
evidence only, seals every conditional prediction and refuses existing outputs.
The separate `validate` phase rechecks the seal/public inputs, then reads only
the existing private execution metadata. It publishes validation flags rather
than the metadata, wallet keys, witnesses or backups. Its truth check relies on
retained execution metadata and checks the coupled note-consumption history; it
does not re-prove private witnesses independently.

Results are in `run/live-correction-v2/PREDICTIONS.json` and `VALIDATION.json`.
Eleven regression controls cover unique-wrong predictions, both workload worlds,
contradictory evidence, coupled versus marginal truth retention, redundant
knowledge, label invariance, changed public amounts, JSON round trips, integer
boundaries and invalid reuse of consumed inputs. All eleven passed.

The original seven result files and their manifest were rechecked unchanged.
Their parent manifest SHA-256 remains
`1259c42cb7cde08fac0b9da29176e46cc20dddc963682c680a19958eefd5b88c`.
The correction has its own manifest binding code, report and results.

## Adversarial second pass

- No circuit, ledger, native script, reserve rule or proof-verification path
  changed; the correction cannot authorize spending, minting or withdrawal.
- A unique result now requires complete execution-truth retention before it can
  count as successful reconstruction. Contradictory side information cannot
  become a privacy claim. Marginal fact coverage alone is insufficient.
- Public records and the prediction seal are rechecked before truth validation;
  changed records or inconsistent original manifest entries reject the run.
- No wallet key, sponsor key, backup or private witness is an inference input.
  Explicit private-metadata validation is separate from public-only predictions.
- Reorg, availability and broader service-loss guarantees were not retested.
  Retained confirmations describe the historical run, not a fresh live RPC audit.
- The observed service-loss record only states wallet workers stopped before
  exit proving. It is not evidence that every operator or public data dependency
  disappeared, or that users were independently administered.
- Residual model ambiguity is not promoted to a protocol repair. The complete
  metadata attack surface and practical independence remain unqualified.

MPC remains paused. No forced delay, retained user balance, paid compute,
network mutation, commit, push or public posting was involved in this correction.
