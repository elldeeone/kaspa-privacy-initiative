# Next privacy blocker: whole-claim wallet semantics

**Next work: owner-controlled partial private cashout, fresh private change,
subsequent private spending and seed-only change recovery under the existing
Auth528 relation. Then compare that wallet policy blindly with full-claim
cashout. Keep the current live trial unchanged.** A successful recovery/payment
trace does not qualify financial privacy.

Read-only assessment, 2026-10-23, HEAD `2ee3e085` plus the current worktree.
Inspected `private_action.py` SHA256
`8d952270956fa9815a9c73bab4db540d81800afcce4c2b4d3e23a77e28343c8f`.
This memo adds no implementation, trial, observer run, proof, build or RPC call.

## The exact leak and its boundary

Auth528 and native outputs expose `P`, destination, fee `f`, reserve movement,
roots/counts and activity. Hashing Auth528 as the proof statement does not hide
its public wire bytes. The relation enforces:

```text
sum(private inputs) − sum(private outputs) = P + f = R − R'
```

The current [owner wallet](../../../../poc/private-cashout-wallet/private_action.py#L137)
goes further: it selects **one real claim plus one dummy**, sets `R'=R−claimV`
and `P=claimV−f`, and creates no positive private output
([construction](../../../../poc/private-cashout-wallet/private_action.py#L169)).
Therefore **a source-informed observer assuming this selected wallet policy
learns that consumed claim's exact value as `P+f`, regardless of pool size**.
If that claim is a direct payment receipt, this is its amount. It does not alone
identify which historical CM was consumed, who controls it, or the amount of
every earlier payment in a mixed history.

| Observation | What follows; what requires additional information |
| --- | --- |
| Public native cashout | Its amount and destination are transparent native-KAS boundary disclosures. A destination is not a human identity without a mapping. |
| Generic continuing Auth528 | Only net private decrease `P+f` is forced. Hidden positive change and two real inputs are legal, so the current wallet's whole-note equation is not a universal circuit fact. |
| Terminal zero reserve/zero outputs/no append | The consumed input sum equals remaining reserve `P+f`. A single remaining candidate can be exposed; a multi-note sum need not determine individual prior payments. Two NF/CM slots are not two real notes or people. |
| Known values, P/A records, timing or sparse activity | These can turn the exposed amount into a unique note/owner link. The two controlled 60M receipts are an especially narrow mechanics case, not a representative anonymity population. |

These distinctions are enforced in the [same relation](../../../../poc/private-cashout-prover/src/circuit.rs#L292)
and [private conservation equation](../../../../poc/private-cashout-prover/src/circuit.rs#L404).

## What is already fixed, and what remains unmeasured

The old revealing-exit canary exactly joined both historical notes to their
payouts and values; private EXIT removes that explicit Note/CM/position/k
opening. The frozen [72-case population comparison](../../privacy-recovery/observer/POPULATION-RESULTS-01.md)
reported 203/290 directly opened primary amounts for REVEAL, versus 0/290 for
both P0-rerandomize→REVEAL and private EXIT at rate 100. It **did not demonstrate
additional privacy over rerandomization**. Its private-EXIT model already allowed
partial requests/change, and its four attacks used local opening/residual/time
guesses, not complete global ownership/value inference. Zero direct openings
is not proof of ambiguity. The repaired result is
`abdf6a256d92913e6d188d610f50dfc536f2317f9adf5d13d0a5394c1156b877`;
do not rerun, replace or reinterpret the frozen results as a new policy test.

The [old dummy-prefix leak](../../privacy-recovery/observer/PADDING-RESULTS.md)
flagged 129/256 raw pads. Genuine sealed dummy generation flagged 0/256, as did
real ciphertexts. This closes that classifier only. Terminal zero ciphertext
intentionally reveals an already-public terminal mode.

Backup recovery adds no publicly computable CM→destination map: payout derivation
uses the private seed ([code](../../../../poc/private-cashout-wallet/private_action.py#L66)).
V2's stable delivery key is in invoices, not Note168; directory observers can
link invoices by it, and a compromised seed exposes its recovery history.
Those are distinct P/E-profile boundaries, not evidence that chain ciphertexts
contain a stable recipient identifier. Fetch queries the discovered public
history's scripts before local ownership filtering
([query construction](../../../../poc/private-network-recovery/fetch.mjs#L330));
local proving protects witnesses but does not qualify RPC/IP/broadcast privacy.

## Smallest substantive extension after this run closes

1. **Extend the owner wallet, not the proof system.** The existing
   [partial-exit fixture](../../../../poc/private-exit-lifecycle/assemble.py#L500)
   already creates positive change with the same Auth528 layout and passed
   [genuine proof/native Full](../../privacy-recovery/lifecycle/RESULTS.md).
   Adapt that capability to independently reconstructed owner state: requested
   `P`, exact quoted `f`, `change=sumIn−P−f`, followed by a genuine private payment
   from change and a second clean restore. The backup must predate change;
   no operator receipt/index map or saved exit may enter recovery. V2 already
   decrypts an embedded invoice index and rederives its fields without lookahead
   ([receiver](../../../../poc/future-recipient/v2/recipient.py#L231)). Specify fresh
   change-index issuance/reuse and orphan/outstanding-invoice assumptions; copying
   a fixture's fixed index is not a general recovery design.
2. **Avoid a new public change marker.** Do not promote the fixture's fixed
   change-first/dummy-second ordering into a general privacy policy. Freeze
   private slot allocation/permutation and fresh receive fields, test duplicate
   invoice handling, and keep correct sealed padding. Preserve optional immediate
   full exit: no privacy timer, required balance, other-owner witness or delayed
   cooperation may become an exit condition. A 60M sole claim cannot leave legal
   60M change after any positive payout and fee; use the adopted normal payment
   range for the next workload, retaining this small-claim failure region.
3. **Freeze a blinded policy comparison with a stronger observer.** Keep the same
   economic obligations, initial capital, cash requests, public fee/timing model,
   legitimate C/P/pooled-A records, urgent full exits and final drainage. Compare
   known full-claim policy with optional partial change/repeated private spending;
   retain rerandomize→REVEAL as the functionally equivalent exact-cash baseline.
   Unsupported full-claim partial requests stay failures. Add a global integer
   conservation/ownership observer over hidden selections, reuse/spentness,
   public ingress and all later exits. Report forced amount, CM→payout and owner
   links separately from guesses; multiple arithmetic solutions do not prove
   alternative cryptographic witnesses or equal probabilities. Use singleton and
   all-but-one-adversarial controls alongside many-note underdetermined cases.
   Published ledgers are development data; a new evaluation needs fresh blinded
   held-out ledgers and sealed predictions, not retuned old scores.

## Established lever and hard limits

This follows the already inspected Orchard/RAILGUN public-value-balance join-split
pattern and the accepted repeated-shielded-spending use case, with local scanning
and fresh receive fields; see [pinned comparisons](../../privacy-recovery/SOURCES.md)
and [RFC-0012](../../../../docs/rfc/0012-useful-privacy-requirements.md).
It changes wallet behavior within an existing relation; it inherits no mature
protocol's security result. General amount privacy and sender/receiver ambiguity
still need the declared observations and workload to support them.

The fixed price prior remains `21103/100025 = 21.0977%`, above the unchanged 20%
amount cap. Partial change cannot erase prior knowledge. The current three-check
payment/two-independent-exit floor is **22,125,000 sompi per 10-KAS recipient** at
rate 100, above the 20,000,000 complete-lifecycle cap before other costs. Extra
split/rerandomization and later exit operations must all be charged. Faster
proving does not reduce this native fee. A separate
[compact-policy fee screen](../../privacy-recovery/fee-feasibility/FEE-FEASIBILITY-01.md)
is necessary: simply widening the present unrolled Merkle policy already fails
an optimistic 2.099209% bound. Neither more nominal participants nor a fee
optimization is itself a privacy fix.
