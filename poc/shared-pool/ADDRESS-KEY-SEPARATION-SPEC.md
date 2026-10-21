# Offline funding/exit key-separation retest

Date: 2026-10-20 UTC. Base checkpoint:
`b62cfd1910d77f9962882b1088d6cc718e7df1b2`.

Prospective specification for the owner-authorized change in
[ADR-0030](../../docs/adr/0030-separate-funding-and-exit-keys.md).
The tested revision is this checkpoint **plus the exact frozen source manifest
and tracked patch**, not the checkpoint alone. Freeze this specification,
executable sources, binaries and observer dependencies before fresh wallets.
Preserve outcomes and failed attempts; do not retune criteria after a result.

The [original finding](ADDRESS-REUSE.md), [original specification](ADDRESS-REUSE-SPEC.md),
observer and historical evidence remain unchanged. This is an offline
constructed regression test using synthetic native funding parents. No real
funds, broadcasts or chain acceptance are involved.

## Change and question

Fresh v2 backups use `KPI/funding-key/v1\0` for native funding and the unchanged
`KPI/payout-key/v2\0` for exits. The rest of the existing HMAC message, scalar
rejection, domain/index encoding and exit-index rule stay unchanged. Original
v1 backups retain their exact old derivation for both uses; they are not relabeled
or migrated. The source review and ADR delimit the derivation assumptions.

Does this remove the observed same-index funding/payout alias for fresh v2
wallets, while original backups still recover spendable funds and genuine v1
backups retain compatibility? The unchanged observer must continue to detect
the known legacy positive example. Ambiguity after removing the alias means
only that this particular conditional attack no longer resolves the payment.
It is not a privacy qualification or a claim about other observations.

## Frozen identities and preparation

The following retained identities are fixed before execution:

| Item | SHA-256 or exact identity |
| --- | --- |
| Historical wallet executable | `1b95101d84434d2f8598d6bdd4c2a15964f7fa25fb54da313344dd5cf0d514ed` |
| Unchanged `address_reuse_observer.py` | `e157540aef57153909dd2558c853b8381a2bb1260d9e7fdc3ba613618a05a9a9` |
| Retained proving key | `6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593`, 962,197,520 bytes |
| Retained verification key | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |
| Historical public positive control | `evidence/2026-10-20-address-reuse/native/matched` at the base checkpoint |

Prepare the new evaluator first. It freezes the new scripts/specification, all
unchanged observer modules, replay executable and dependency bytes; it copies
and hashes only the historical matched arm's public inputs. Its isolated seven
development control groups and historical native replay/observer positive
control must pass before it writes `preparation.json`.

The native driver requires that preparation, checks its hash and source identity,
and freezes all new/old wallet-helper binaries, Rust sources, lifecycle utility,
ADR/RFC/source review, and a tracked source patch before creating keys. New
untracked files are covered by the complete manifest rather than `git diff`.
Record the exact new binary/spec/source hashes in the attempt evidence, then
recheck all pinned bytes after execution. Use the retained parameter bytes;
generate no setup and load no previous experiment's wallet secrets.

## Native schedule: ten proofs, three isolated observer cases

Create a fresh v2 founder A and a fresh v2 B. Create a separate fresh v1 B using
the frozen historical wallet's actual `create` command, not by editing a v2
backup's metadata. Use one descriptor and a shared A self-bootstrap. The v2
counterfactual arms reuse their fresh B keys; the v1 arm has its own fresh B keys.
Each observer sees only one arm.

| Arm | B backup | Funding derivation index | EXIT derivation index | Expected selected funding/payout script equality |
| --- | --- | ---: | ---: | --- |
| `v2-same-index` | Fresh v2 | 3 | 3 | False |
| `v2-different-index` | Same fresh v2 | 0 | 3 | False |
| `legacy-v1-same-index` | Fresh v1 created by old CLI | 3 | 3 | True |

All admission, payment, recovery and exit operations use the new wallet binary.
For v1, derive funding information with both old and new binaries from the same
newly generated backup; require exact equality before admitting the funding.
This checks actual legacy signing/spending compatibility, not only parsing.

The economic schedule is unchanged from the original diagnostic:

1. A funds 2,000,000,000 sompi and self-bootstraps a 1,960,000,000 note with zero
   change. This one proof is shared by all three arms.
2. B admits 1,200,000,000, receiving 1,160,000,000 at position 3. Stop its worker.
3. A spends its bootstrap note, paying B 1,920,000,000 at position 5 with zero
   change. Stop A's worker before B's recovery.
4. In a fresh process, recover B from its unchanged original pre-admission backup
   and supplied public history. Require owned unspent positions 3 and 5 and total
   3,080,000,000. In a fresh proving process, exit both for 3,040,000,000.
5. Stop that worker. In another process, use the same original backup to sign an
   ordinary native spend of the resulting payout and validate it locally.

There are three proofs per arm plus the shared bootstrap: ten total. Each arm
must independently reconcile 3,200,000,000 entering = 3,040,000,000 payout +
160,000,000 pool fees, with zero reserve after EXIT. Ordinary-parent/founding
fees and the later payout-spend fee are separate. Use canonical integer sompi.
Every proof, resulting native transaction and full lineage replay must validate.

Keep hashes of A's and each B's original backups unchanged throughout. Recovery
processes may access only their own backup, public history/descriptor/parameters,
supplied expected head and fresh local output directory. No original worker,
mutable note cache, saved proof or other wallet's secrets are needed to exit.
Known public history and its freshness remain external assumptions. Native
payout spending receives the known index 3; automatic native UTXO/index discovery
is not tested or claimed.

## Controls and observer separation

Wrong funding indices and an EXIT index other than the lowest selected note
position must reject without a new proof. For each v2 arm, a separate synthetic
parent addressed to the wallet's actual EXIT-purpose script must fail ADMIT at
the same index. Use a fork from the earlier valid public state for this control;
it does not enter the measured history. Compare the founder's actual funding
script as a wrong-owner script control in every arm.

The historical matched arm remains a positive control: its existing complete
native history must replay, and the unchanged observer must again force sender
0, recipient 1 and amount 1,920,000,000 only in the final linked profile. This
uses published inputs and known prior conclusions, not old private truth or a
fresh held-out sample.

For the three new arms, use the exact original observer and encodings with its
creation/final and equality-ignored/equality-enabled profiles. The observer
receives only that arm's native lineage/parents, descriptor, verification key
and funding-owner directory. Neither backup version, private derivation index,
selected note positions, other arm, operation labels, receiving envelope nor
plaintext truth is mounted. Native validation runs separately. Isolate the
observer from host home and external network.

The declared owner directory and known A self-bootstrap remain assumptions of
the frozen model. They are not inferred from different scripts. Generic PAY
does not enforce self-bootstrap; dropping it removes the full sender-uniqueness
claim. Self-payments and an unfunded `Other` recipient remain allowed where the
model permits them. Arithmetic alternatives are not alternate openings/proofs
for the actual commitments and carry no probability weights.

Seal **all three new prediction files and their batch manifest before any new
private scorer**. Then check each complete concrete history against both
original CP-SAT and integer-Z3 encodings, and compare predictions to its pinned
truth. Candidate feasibility and alternative feasibility/infeasibility must
agree in both encodings. Recheck saved hypothetical witnesses in the final
independent review; public ambiguity never substitutes for native verification.

## Success, failure and evidence limits

The bounded retest succeeds only if all of the following hold:

- Both v2 arms have unequal actual selected funding/payout scripts. All three
  private fields remain ambiguous in every unchanged observer profile.
- Genuine v1 funding matches across old/new software and matches its native
  EXIT script. Only its final linked profile forces the original sender,
  recipient and amount; the historical public positive control also still works.
- All ten proofs and every replay/accounting check pass. Every original backup
  is unchanged; fresh-process recovery and the signed native payout spend pass
  for all arms. Rejection, source-integrity, isolation and truth checks pass.

Any failed native/proof/accounting/recovery check, inconsistent truth,
solver unknown/disagreement, failed control or observer contamination blocks
the corresponding success claim. Preserve the attempt and report the cause;
do not rewrite the expected outcome or resample to hide it. Export only an
explicit public allowlist with hashes, omitting private backups/truth and
role-revealing operational logs. Combined arm publication is not an isolated
observer view because counterfactuals share keys.

The result cannot establish real-world anonymity, cryptographic security,
reuse frequency, general backward compatibility, native UTXO discovery,
current chain/relay behavior or the RFC-0012 32-role privacy thresholds. Legacy
v1 keeps its old privacy weakness by design. Fresh-key separation removes one
deterministic alias; it does not fix timing, amounts or other owner information.

## Execution order

Use the base checkout with the exact prospective patch/files and compiled new
wallet/lifecycle/replay binaries present. The old wallet is an independently
retained executable matching the hash above. Choose unused output directories.

```sh
cd /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool
KPI_KEYSEP_PYTHON=/home/luke/.local/share/kpi-shared-pool-tools/bin/python
KPI_KEYSEP_EVAL=/tmp/kpi-key-separation-eval-fresh
KPI_KEYSEP_PARAMS=/absolute/path/to/retained-v6-parameters
KPI_KEYSEP_LEGACY=/absolute/path/to/frozen-old-wallet
PYTHONDONTWRITEBYTECODE=1 "$KPI_KEYSEP_PYTHON" native_key_separation_evaluate.py prepare "$KPI_KEYSEP_EVAL"
PYTHONDONTWRITEBYTECODE=1 "$KPI_KEYSEP_PYTHON" native_key_separation_trial.py --evaluation "$KPI_KEYSEP_EVAL" --params "$KPI_KEYSEP_PARAMS" --legacy-wallet-binary "$KPI_KEYSEP_LEGACY"
```

After the native phase completes, set the newly printed private experiment
directory and run the prepared evaluator:

```sh
KPI_KEYSEP_NATIVE=/absolute/path/printed/by/the/native-driver
PYTHONDONTWRITEBYTECODE=1 "$KPI_KEYSEP_PYTHON" native_key_separation_evaluate.py run "$KPI_KEYSEP_EVAL" "$KPI_KEYSEP_NATIVE"
```
