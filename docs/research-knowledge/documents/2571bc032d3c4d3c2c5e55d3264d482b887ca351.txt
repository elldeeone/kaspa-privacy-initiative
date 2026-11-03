# Native funding/exit script reuse

Date: 2026-10-20 UTC. Candidate: `dbf4dace0fe6d992c9add46e6b4cd8a8f8b7309b`.

**Status: native script reuse and a conditional internal-payment disclosure
demonstrated.** Seven fresh proofs and both full native replays passed. In the
matching arm, the reused script identifies A paying B exactly 19.2 tKAS under
the declared funding-owner and self-bootstrap assumptions. At payment creation,
with that link removed, and throughout the different-index control, the tested
fields remain ambiguous. This is a sparse-case finding, not a 32-role verdict.

The prospective
[specification](ADDRESS-REUSE-SPEC.md), executable sources and dependencies were
frozen before fresh wallet generation. All seven development control groups
passed in the isolated evaluator. [Public evidence](evidence/2026-10-20-address-reuse/README.md)
retains native bytes, sealed predictions, scores and source identities.

This is a constructed offline diagnostic using synthetic native funding parents.
It uses no real funds and performs no network broadcast. It cannot pass the
32-role privacy gate or establish current chain acceptance.

## Question and source basis

Can a selected native funding output reuse the script of a later withdrawal?
If it does, can the resulting association resolve an otherwise ambiguous
internal payment in a small complete history?

The current [wallet](src/two_input/wallet.rs) derives both funding and EXIT keys
through `Backup::native_key`. The [key derivation](src/protocol.rs) uses the same
`KPI/payout-key/v2` namespace, pool domain and index. EXIT requires the index to
equal the lowest selected note position; funding accepts an explicit index.
The experiment exercises an allowed caller choice. It does not establish that
reuse is a default, common or attacker-forced behavior.

Matching scripts establish reuse of a native spending condition. Identifying an
internal sender, recipient or amount requires additional assumptions and a
separate inference. Funding outpoint indices are public transaction coordinates;
they are not the wallet's private derivation indices.

## Paired construction and conditional inference

One bootstrap is shared by two offline counterfactual histories. The two arms
use the same fresh wallets and pool domain, with different B funding indices.
Neither history is submitted to a chain.

| Operation | Observed native/wallet behavior, in tKAS |
| --- | --- |
| Bootstrap | A funds 20; a 0.4 fee leaves A's 19.6 note. |
| Admission | B funds 12; a 0.4 fee leaves B's 11.6 note at position 3. |
| PAY | A spends 19.6, pays B 19.2 at position 5 and leaves zero change. |
| EXIT | B consumes positions 3 and 5, pays a 0.4 fee and withdraws 30.4; reserve becomes zero. |

Amounts are represented as integer sompi in execution and inference. Each arm
reconciles 32 entering = 30.4 payout + 1.6 pool fees; ordinary-parent and
founding transaction fees are separate. The completed proof count is seven:
one shared bootstrap, then admission, payment and exit for each arm.

The matching arm funds B at derivation index 3; the different-index control uses
index 0. Both exits use the wallet-mandated index 3. Private indices and selected
note positions are excluded from observer inputs. The observer compares the
actual selected funding output's script with the actual payout script, including
the founder's script as a wrong-owner comparison.

The conditional ownership model assumes an explicit directory associates the
two selected funding outpoints with two distinct wallet-owner pseudonyms A and
B. It also assumes the published fixture's known self-bootstrap schedule:
A retains the 19.6 bootstrap output with zero change. Generic wallet PAY does
not enforce a self-bootstrap. B's admission is assumed to credit B, and an
EXIT's native controller is assumed to own its selected shielded inputs under
the current wallet policy. These are side-information and wallet assumptions,
not facts proved by distinct public keys or general guarantees of the v6 circuit.
The model retains self-payments and an additional, initially unfunded `Other`
role; the labels do not represent verified human identities.

Without using a funding/payout owner link, the following arithmetic/ownership
histories are both feasible in the controls and the native-derived analysis:

| Internal payment | Terminal same-owner notes | Native payout |
| --- | --- | ---: |
| A pays B 19.2 | B's 11.6 admission + B's 19.2 receipt | 30.4 to B |
| B pays A 11.2 | A's 19.6 bootstrap + A's 11.2 receipt | 30.4 to A |

Both alternatives pay the same four pool fees. A link from B's funding script to
the terminal payout removes the second alternative and forces
A-to-B payment of 19.2 under the declared model. Both encodings find a
satisfying assignment for each reported field and reject every different value.
The alternative histories are models under assumed cryptographic hiding;
they are not alternative openings or proofs for the actual commitments, and
their existence gives no probability or anonymity guarantee.

The observer analyzes the PAY at creation and after complete drainage. At each
horizon it compares the same public history with and without the equality-derived
owner constraint. Prefix construction removes future observations. The
different-index arm tests a valid execution without the equality; its absence
would not itself prove payment privacy.

## Evidence separation and controls

Each isolated observer receives only one arm's native lineage, ordinary parent
transactions, descriptor, verification key and explicit funding-owner directory.
It receives neither the other arm nor private backups, receiving envelopes,
action files, plaintext notes or derivation indices. The observer process has
no host home or external network. A combined later publication of both arms
would not be a valid isolated control view because the arms share fresh keys.

Both predictions were sealed before either scorer received private truth.
The separate scorer checked the actual values, ownership and input selections
against both complete arithmetic encodings before interpreting a forced fact.
Every claimed uniqueness required a feasible candidate and an impossible
alternative in both CP-SAT and integer Z3. Independent native replay remains a
separate prerequisite; the arithmetic observer does not verify Groth16 proofs.

The seven passed development control groups cover alternative histories,
genuine two-input terminal exits, prefix isolation with self-payments and an
unfunded recipient, owner-label permutation, additional activity that leaves an
amount ambiguous, current sompi values, and exact selected-outpoint/directory
validation. Missing or ambiguous owner associations cannot justify a conditional
identity claim. Passing these controls is not cryptographic security evidence.

## Frozen identities

Evaluation freeze created at `2026-10-20T22:34:26.231220+00:00` in the author-local
directory `/tmp/kpi-address-reuse-eval-20261020-01`.

| Artifact | SHA-256 |
| --- | --- |
| Evaluation `freeze.json` | `6e298fc389cae3c9e1150ccc02fe0b28029194b842b8e587593f8c15739b3b20` |
| `ADDRESS-REUSE-SPEC.md` | `8473c5602595adea088d050e9ff2c5eb2a4df49fc6105afe2e7a322b2c378e97` |
| `address_reuse_trial.py` | `685d8608126f25f92f193348432eb7090a569f2e3faf925e41292c5cb3a4ccf9` |
| `address_reuse_observer.py` | `e157540aef57153909dd2558c853b8381a2bb1260d9e7fdc3ba613618a05a9a9` |
| `address_reuse_evaluate.py` | `e9f16f485379c26b97f5e7b90b3e3696e511ecce08cec4bfea9de416c667a4e4` |
| Native replay executable | `442ba78bf089f85c16184b9072da4a1c5de7d7a136f5c0aeb9b00bf604e7bbb2` |
| Isolated control result | `7dc4984bd23b848712a812aa6f3b458ee474ffd22087d4f3929f68dbcf345eb4` |

The complete freeze records inherited model/decoder sources, Python packages
and runtime dependency identities. The native driver separately pins wallet and
lifecycle binaries, Rust sources and retained proving/verification parameters.
All 72 native-driver source/binary hashes matched before and after execution;
the evaluator also rechecked its frozen dependency/source/input/prediction bytes.
The public export passed field screening and comparison against seven secret
values from the two fresh backups. Backups, full truth and operational wallet
logs remain outside the repository. This is an explicit export check, not a
general secret-detection guarantee.

## Result record

| Required observation | Status |
| --- | --- |
| Seven fresh proofs; complete native replay in both arms | Passed; each arm has five native lineage transactions, including foundation. |
| Exact native accounting and terminal zero reserve | Passed in both arms: 32 = 30.4 + 1.6 tKAS. |
| Matching-arm equality; different-index and wrong-owner inequality | Exactly one funding/payout script match in the matching arm; none in the control; founder comparison differs in both. |
| Unlinked and linked inference at creation/final horizons | Only matching-arm final history with the link forces sender A, recipient B and 19.2 tKAS; all other seven profiles leave all three fields ambiguous. |
| Both prediction seals precede private scoring | Batch sealed at 22:49:27.271189 UTC; first scorer started at 22:49:27.339036 UTC. |
| Actual truth satisfies both complete arithmetic encodings | CP-SAT and Z3 SAT in both arms. |
| Public evidence allowlist and hashes | Passed; native operational result is exported only as a redacted derivative summary. |

Four incorrect admission/exit-index requests were rejected. All 20 native
process-isolation guards passed; both observers and scorers had separate allowed
mounts. Native execution took 825.15 seconds on this host, including cold loads.
This is not a target-device latency qualification. An author-team adversarial
review covered source behavior, assumptions and observer isolation. Its final
public-only pass independently checked 90 saved hypothetical assignments,
native bytes/replay identities, anchors 5 and 7 and both-before-scoring seals.
It found no blocker; it is not an independent cryptographic audit.

Prediction-batch SHA-256:
`ec3bffeaea88b3e400be2f49533f075b0b52be0e5e985aa7a41afcb802c18ffc`.
The creation/final comparison and same-transcript removal of the owner link
isolate the extra inference supplied by address reuse. The different-index
control confirms a genuine valid execution can avoid this equality; it does
not establish privacy against other attacks.

## Reproduction

Use a checkout at the candidate commit with the frozen diagnostic files present.
The driver deliberately rejects a different Git HEAD. The retained parameter
directory must contain the exact `pk.bin` and `vk.bin` pinned by the lifecycle
helper; do not substitute a fresh setup. These instructions generate new keys
and proofs rather than reusing the private wallet state of this run.

Build the unchanged wallet, lifecycle helper and replay binaries if needed:

```sh
cd /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-wallet --bin kpi-two-input-lifecycle --bin kpi-two-input-replay
```

Prepare the evaluator and pass its isolated controls **before** generating
fresh wallets. Choose an unused evaluation directory and set the retained
parameter path locally:

```sh
KPI_REUSE_PYTHON=/home/luke/.local/share/kpi-shared-pool-tools/bin/python
KPI_REUSE_EVAL=/tmp/kpi-address-reuse-eval-fresh
KPI_REUSE_PARAMS=/absolute/path/to/retained-v6-parameters
PYTHONDONTWRITEBYTECODE=1 "$KPI_REUSE_PYTHON" address_reuse_evaluate.py prepare "$KPI_REUSE_EVAL"
PYTHONDONTWRITEBYTECODE=1 "$KPI_REUSE_PYTHON" address_reuse_trial.py --params "$KPI_REUSE_PARAMS"
```

The native driver prints a newly created private experiment directory. Only
after its native phase completes, use that exact directory in the evaluator:

```sh
KPI_REUSE_NATIVE=/absolute/path/printed/by/the/native-driver
PYTHONDONTWRITEBYTECODE=1 "$KPI_REUSE_PYTHON" address_reuse_evaluate.py run "$KPI_REUSE_EVAL" "$KPI_REUSE_NATIVE"
```

The evaluator independently replays each arm, mounts one arm at a time, seals
both predictions, and then runs separate truth scorers. Keep private wallets,
truth and role-revealing operational logs out of the public evidence allowlist.
Do not present a direct observer invocation with both arms or operational
metadata visible as reproduction of the isolated observation.

## Limits

This two-funded-owner construction is not a 32-role rate measurement or a test
of typical wallet behavior. It cannot qualify the persistent-payment claim,
real-world anonymity, cryptographic security, relay policy or chain acceptance.
Native transaction validation uses synthetic parent UTXOs and supplied offline
heads. Zero reserve in this trace does not establish general recovery or
permissionless-exit guarantees.

This conditional disclosure justifies reviewing funding/exit key
separation and its recovery consequences before expanding the candidate. No key
derivation or backup format was changed in this experiment. Removing a repeated script would
remove this particular observation, not the independent timing, amount or
ownership inferences. Any redesign and its tests are separate work.

In particular, remove the known self-bootstrap assumption and another arithmetic
history becomes possible: A's bootstrap pays 19.6 to B, then B self-pays 19.2
and makes the same terminal exit. The ordinary payment's sender is no longer
unique. The conditional finding must not be presented as following from native
bytes and generic wallet PAY behavior alone.

## Additional reasoning: recipient without known self-bootstrap

There is a narrower analytic argument that does not require A to own the
bootstrap output. Let `R` be the reserve immediately before the terminal exit,
and `S` its selected input total. The observed payout plus fee exhausts `R`, so
conservation requires `S = R`. The immediately preceding PAY's positive
recipient note, of value `v > 0`, has had no intervening opportunity to be spent.
If the exit excludes it, the selected inputs and that note imply accounted
unspent positive-note value of at least `S + v > R`, contradicting the backing
bound from valid genesis, conservation and single spending. Count inaccessible
notes too: malformed delivery does not erase committed value.
It must therefore be one of the selected notes. Under the common-owner input
rule, own-key EXIT policy and equality-derived B association, its recipient
is B, including when the payment is a self-payment.

This reasoning assumes sound backing, conservation and single spending, a positive recipient
output under the current PAY convention, complete ordered history, and the
declared funding/native-controller ownership bindings. It is not a completed
relaxed-bootstrap solver test. The frozen observer retains known self-bootstrap;
its measured full sender/recipient/amount uniqueness result must remain scoped
to that stronger model.
