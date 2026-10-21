# Working-balance screen: prefreeze review

Reviewed 2026-10-21 by a separate agent within the author team. This is an
adversarial source and public-control review, not an independent security audit.
No held-out seed, retained private attempt, wallet backup or prior private
history was opened during this review.

**Finding:** no remaining source-level blocker for the bounded arithmetic
screen in [the specification](WORKING-BALANCE-PRIVACY-SPEC.md). The current
68 public unittest cases pass. The complete known-public-seed sandbox rehearsal
also passed: 1,528 observer jobs were sealed before scoring, all eight accounting
bundles validated, and public export completed. This checks the experiment path;
it is not a held-out privacy result or native implementation test.

## Reviewed identity

These are the reviewed source bytes. The execution manifest must match them
before fresh sampling; a later source change needs an explicit delta review.

| File | SHA-256 |
| --- | --- |
| `WORKING-BALANCE-PRIVACY-SPEC.md` | `16f9c5669e68731db787c84e28857fef3024601daacff86ed2c1a625a76c87d6` |
| `working_balance_model.py` | `a1a8c3989d85f2309dcd726cd2d076c77c4ea77e407a7dfbd8c05f975dafbe00` |
| `working_balance_model_tests.py` | `d4c6a36f18909d46f6bdd8a0ab4efcc32c951460f4815ba4d4dd02b58caa9ab5` |
| `working_balance_observer.py` | `b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495` |
| `working_balance_observer_tests.py` | `0f2ac35622e23dfafa960e8877b743118500c3530015eaa9b59b49c208d38147` |
| `working_balance_trial.py` | `d8c73c52929743641c7180565f6e3af4abcfc8f55e53ce0902de8235eec0aa65` |
| `working_balance_trial_tests.py` | `ea56a131495832d1e0aa7f4bad221a971ba8204d5f2f627165dd78e195ab0130` |
| `working_balance_validate.py` | `407c1abeebc913b8112754d70705eae41a36f86cf954aa946dfa565abef3eb14` |
| `working_balance_validator_tests.py` | `833b7082a67a0ce0f9e98e94f896d64cb5eb6b0bfddc7882485a8f7320c13218` |

The review also read `AGENTS.md`, `SECURITY-INVARIANTS.md`, RFC-0012,
[RFC-0016](../../docs/rfc/0016-working-balance-withdrawals.md) and
[ADR-0031](../../docs/adr/0031-arithmetic-working-balance-screen.md).

## Checks and prefreeze corrections

The following command passed on the listed files, from `poc/shared-pool`:

```sh
python3 -B -m unittest working_balance_model_tests working_balance_observer_tests working_balance_trial_tests working_balance_validator_tests
```

The 68 cases comprise 21 model cases, one observer case running 28 named
controls, 42 controller cases, and four independent-validator cases. The
validator accepts all eight public development bundles and rejects corruptions
covering inflation, wrong ownership, duplicate/future/spent inputs, replayed
native sources, stale anchors, missing cash/urgent obligations and altered
aggregates. Public fixtures use an explicitly known development seed.

Before freezing, review and integration work corrected or made explicit:

- Reserved cash and external surplus are disjoint; re-entry preserves earlier
  cash obligations. Independent requests use every role once, tiny shortages
  respect the payout floor, and overpayment remains owned native value.
- Dummy outputs accept no recipient identity; disclosed self-merges have a
  defined prior; the public first-four sender/tag policy is used. Partial-tail
  subtraction permits a known co-input introduced at a later included leg.
- Prefixes include only permitted public and participant records. Target lists
  come from public modes and payout horizons, including self-merges, rather
  than the hidden honest-payment subset. Selected-row optimization preserves
  the public first-four mapping and discards only payouts preceding all queried
  targets. The separate eight-support split bound is explicitly part of the
  attack; it is not described as an equivalent optimization.
- Complete prediction rosters, exact prefix/input hashes, isolation receipts,
  chronology and unchanged C+D strategies inside the pooled profile are
  checked before scoring. Private path substitutions fail before private reads.
  The scorer receives an exact file allowlist without the seed. Its private
  view reconstruction checks the disclosures after the complete seal barrier.
- The real sandbox probe caught and corrected `bwrap --args` program-argument
  placement. A later read-only guard binds generation's input manifest to the
  committed seed hash without opening the seed; its targeted tests pass.
  The complete rehearsal also encountered bwrap's 9,000-argument limit while
  mounting score inputs. After the full seal barrier, the runner now creates a
  new 0700 directory containing hardlinks to exactly the verified public files
  and eight truth files, then mounts that directory read-only. It never mounts
  the attempt root. Controls reject an existing staging directory, exclude the
  seed and unrelated root files, and reject a missing seal before staging.
- Final guard review binds each truth bundle to its declared cell and arm.
  Export storage verification requires the complete logical file roster and
  distinguishes byte/roster checks from the separate semantic seal audit.
- Fees divided by overfunded initial capital cannot qualify RFC-0012's
  lifecycle target. The reported ordinary fee is a lower bound where extra
  merge/re-entry costs apply; the low-value fee failure is retained.

The public rehearsal audit completed at `2026-10-21T05:52:36.160251+00:00`.
It records 1,528 sealed predictions, successful isolated scoring, eight valid
accounting bundles, and 13,819 exported files totaling 78,873,536 stored bytes.
Its SHA-256 is
`df33b6ebfb352fbe36bf0a83f171f68d0ba20871eb7847f08aaadf274a8b4fb8`.
The audit's current-source hashes match the table above. It uses the explicitly
public `bytes(range(32))` input, with no fresh entropy. No development accuracy
or directional outcome was read or used for this review.

The final guards and mount repair were applied after the rehearsal's observer
snapshot. All original predictions were preserved; current stricter verification
passed and the current scorer's aggregate output matched the original exactly.
No observer rerun or attack/criterion change was needed for these operational
and verification changes. The final source review therefore finds no blocker
to freezing these bytes and starting the fresh arithmetic screen.

## Adversarial questions

| Question | Assessment and remaining boundary |
| --- | --- |
| Can value be minted? | Model transitions enforce integer ranges and conservation. Independent replay reconstructs reserve liabilities, native coins and all modeled fees. This is arithmetic evidence, not proof-system soundness. |
| Can a note or native source be spent twice? | Owned live inputs must be unique; replay tracks consumed notes and actual bridge sources. Opaque nullifiers are synthetic labels, so no cryptographic nullifier claim follows. |
| Can reserve value leave without authorization? | Every modeled payout consumes the specified owner's live notes and charges its fee. No native transaction is submitted, and no signature/proof authorization is exercised. |
| Can a policy prevent an independent exit? | Urgent requests drain all of the owner's remaining notes immediately; final drainage leaves zero private reserve. No timer, other participant or operator permission gates the arithmetic path. Actual inclusion and backup recovery remain untested. |
| Can hidden truth improve the attacker? | Observer mounts contain only the public prefix, directory, allowed participant view and public target list. All predictions are sealed before the scorer opens truth. The generator necessarily holds the complete synthetic history. |
| What if a dependency disappears? | Stage failure or missing predictions invalidates the experiment rather than counting as privacy. This does not test loss of a real prover, wallet service or chain-data source. |
| What about stale state, replay or reorgs? | Replay checks serial event/anchor ordering, note consumption and native-source reuse. The model has no forks, real roots, proofs or competing authorizations; it establishes no reorg or cross-state cryptographic safety. |
| What hidden trust or inference assumption remains? | This is an author-operated, same-host experiment with isolation and hash receipts, not independent execution attestation. Bounded amount/ownership hypotheses remain hypotheses; family maxima select aggregate strategies, never a correct guess separately for each target. |

## Interpretation limits

Four paired ledgers can reject this frozen policy but cannot establish
repeatability, population anonymity or cryptographic security. Sparse and
overlapping cells are independently sampled, so their difference is not a
controlled measurement of timing alone. Opaque ideal-hiding labels omit native
byte, ciphertext, network and operational leakage.

The split attacks retain eight ranked supports per amount on each side;
subset reconstruction uses at most three payouts and one known co-input.
These finite attacks can miss valid deductions. A pass would require further
native and recovery work, not acceptance of a privacy guarantee.

Amount truths and the fixed 45-tKAS prior are matched across each pair. Role
tie-breaks hash arm-specific opaque event IDs, so differences in sender or
recipient accuracy can reflect guess variation. A prospective identity-count
gate failure alone does not prove a new causal relationship disclosure.

Cash requests earmark native liquidity rather than spend it with external
merchants. Their independence from invoices is a primary-workload assumption;
receipt-correlated stress outcomes must remain visible. The unchanged absolute
privacy and fee requirements remain separate from directional continuation.
