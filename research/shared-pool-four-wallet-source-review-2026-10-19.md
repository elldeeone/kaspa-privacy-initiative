# Four-wallet shared native-KAS pool: source and observer review

Reviewed 2026-10-19. This is a source review for the owner-authorized TN10
experiment, not a result of that experiment. No node, wallet secret, or prover
was accessed for this review. The original self-funded trial remains separate.

## Recommendation and the decision

Keep the direct Groth16/P2SH reserve architecture for this bounded test. Add
authenticated deposits, repeated one-note spends and withdrawal with private
change. Keep a single shared reserve and a small fixed commitment/nullifier
capacity. Do not add a service, token, vProgs runtime, new cryptographic primitive
or consensus change to answer this question.

The useful question is **whether retaining private change reduces payment/exit
linkage at an explicit observation horizon, and whether the benefit survives
subsequent withdrawals**. Existing research already predicts amount/timing
leakage. The new information is which links this concrete Kaspa encoding leaks,
whether recipients can actually re-spend and exit without another key, and the
measured extra cost of keeping change private. This is an integration and wallet
policy decision, not a claim to discover a new anonymity technique.

Falsifiable hypothesis: with identical deposits and private-payment choices,
partial withdrawals leave fewer exits with a unique feasible source commitment
than whole-note withdrawals at the first-payout horizon. Report the same metric
after all residual notes exit. If the advantage disappears on full drainage,
the conclusion is delayed disclosure under this workload, not lasting
unlinkability. No numerical success threshold is assumed before the traffic
and scoring rules are fixed.

## Verified current Kaspa surface

The live GitHub API returned these heads on 2026-10-19. A source head is not the
identity of a running node binary.

| Repository | Current reviewed head | Meaning for this test |
| --- | --- | --- |
| Rusty Kaspa | `f7d7877363fb97c2ec6871be0e8cbc351d44df10` | Six commits after the existing `01b532e8b553523216471682649693af92f0fd16` v2.1.0 experiment pin |
| vProgs | `f9b84a863a7c7c20586a9cf947550475e894f72e` | Unchanged; README still describes early/prototype infrastructure |
| Kaspa research | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | Unchanged; vProgs document is architectural research |
| KIPs | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | Unchanged; KIPs 16/17/20/21 marked active |

Sources: [Rusty Kaspa comparison][Kdiff], [vProgs README][Vreadme],
[research draft][Rdraft], [KIP head][Khead]. The reviewed native Groth16 dispatch
and implementation, transaction isolation/UTXO-context validators, and mempool
standardness/limit files are byte-identical between `01b532e` and `f7d7877`.
The opcode diff is debug formatting only. The mass implementation adds public
helper visibility, no-std gating and arithmetic helpers without changing the
reviewed mass formula. The current branch also changes wallet generation and
UTXO-index interfaces; do not silently replace the pinned SDK or builder.

| Requirement | Implemented source evidence | Application obligation |
| --- | --- | --- |
| Multiple ordinary inputs | TN10 permits up to 1,000 inputs and outputs; indexed input amount, SPK, outpoint and count introspection exist. [Parameters][Kparams], [opcodes][Kops] | Fix the accepted deposit shape and bind every relevant real input/output. Input presence alone does not prove correctly credited private value. |
| Continuing P2SH reserve | Actual output SPKs and payload bytes are inspectable. vProgs extracts the executed redeem suffix and hashes the reconstructed next script. [Opcodes][Kops], [suffix pattern][Vsuffix] | Preserve verifier/domain/rules byte-for-byte, preserve old liabilities, and bind the new state. An address or covenant ID alone is insufficient. |
| Native proof verification | `OpZkPrecompile` dispatches BN254 Groth16 at tag `0x20`; compressed point/proof/key validation and public-input arity are checked. [Tags][Ktags], [Groth16][Kg16] | Bind the intended relation, actual native values/destination, predecessor, domain, state and payload. Native verification does not certify a sound circuit. |
| Resource limits | TN10 block limits are compute 500,000, storage 500,000 and transient 1,000,000; signature-script limit 250,000 bytes, output-script limit 10,000 bytes. [Parameters][Kparams] | Measure the complete actual transaction, including expanded state, ciphertext and script. These are ceilings, not privacy-transaction throughput. |
| Default relay | Standard P2SH is admitted subject to classic sigop limits and mass/fee rules. Floor uses maximum of compute and normalized transient mass at the configured relay rate. [Policy][Kpolicy], [limits][Klimits] | Local consensus acceptance, default relay admission and confirmed payout are separate evidence. Re-read the node quote; do not infer current fees from a source constant. |

No reviewed L1 primitive blocks a reserve-plus-deposit-input transition or
partial withdrawal. This is source feasibility, not funded execution evidence.
Use the existing pinned native engine for the test and record the actual node
version and receipts. [The prior trial](../poc/self-funded/README.md) already
provides one-node execution evidence for the single-input reserve spend, not
the new deposit/partial-change relation.

## Accounting and bootstrap obligations

For the simplest deposit shape, input 0 is the current reserve and input 1 is an
ordinary signed deposit UTXO; the sole native output is the next reserve.
If the new input is `d`, deposit fee is `f`, and old reserve is `R`, constrain
`new_note = d - f > 0` and `new_reserve = R + d - f`, while preserving every old
commitment and nullifier. This charges the newcomer, not other holders. If
ordinary change is supported instead, it must enter both exact equations.
Existing-note transfers and withdrawals need no outside fee-paying input.

For a consumed private note `v`, private outputs `a,b`, payout `p` and fee `f`,
use bounded nonnegative integer sompi with the applicable exact equation:

- Private transfer: `v = a + b + f`; `R' = R - f`.
- Whole-note exit: `v = p + f`; `R' = R - p - f`.
- Partial exit: `v = p + change + f`; `R' = R - p - f`.

Require positive real outputs; do not treat public zero padding as a private
note. Preserve membership, owner authorization, unique deterministic economic
nullifier, old-state retention and exact native payout binding. Terminal close
must establish no remaining unpaid liability and must exhaust the reserve
without an admin key. [Security invariants](../SECURITY-INVARIANTS.md).

The old circuit's bootstrap shortcut (`nf_count == 0` implies one commitment
whose opening equals the reserve) cannot simply be generalized to four opaque
commitments. A joining wallet must validate initial backing without receiving
another holder's secret. Explicitly prove and authenticate genesis liabilities,
or retain a clearly documented initial-holder bootstrap step before accepting
independent deposits. Merely matching the VK/script does not authenticate an
arbitrary preseeded state. Follow the canonical funding outpoint and accepted
descendants, rather than arbitrary outputs with a matching address.

Sequential access to the single reserve prevents conflicting state updates
from both settling. It also creates contention: an otherwise valid independent
exit may need a fresh proof after somebody else spends the reserve. Therefore
“independent” means no other participant's key/signature/service is required
given current public data, not guaranteed immediate settlement under contention.
Retain public parameters, authenticated history and ciphertexts; chain UTXOs
alone do not reconstruct every spend witness. [Kaspa pruning review](kaspa-toccata-vprogs.md).

## Observer boundary and hidden ground truth

The chain-only input must be a separately exported dataset reconstructed from
actual transactions and accepted order. Give the observer the public protocol
format/code, genesis/pool identity, predecessor references, input/output amounts
and SPKs, payloads, proofs, redeem scripts, all commitments/nullifiers, fees,
transaction sizes, public state counts and chain acceptance timing/order.
Historical input amounts require the predecessor transactions or authenticated
UTXO data; a bare transaction JSON is not always sufficient. The current P2SH
successor reveals its full redeem state when spent, while public payloads can
already reveal the next state.

Exclude wallet keys, decrypted notes/openings, recipient address-book entries,
the private payment schedule, per-wallet process labels, wallet filenames,
prover logs and the harness's private ordering plan. Scoring may read ground
truth only after attacks emit predictions. A label such as `bob-exit.json` is
ground-truth leakage, not a chain observation. Public payout SPKs are observable;
mapping them to Alice/Bob/Carol/Dave is not automatic.

Deposit amounts and addresses, public withdrawal values/destinations, reserve
lineage and aggregate native movements remain visible. Ciphertexts hide note
openings; nullifiers do not directly identify which prior commitment was spent.
Public mode/count/shape differences can disclose transfer versus full/partial
exit. Fixed output order can identify which hidden output is change if the
protocol specifies it. Interpret those facts from the final implemented codec,
not from assumptions about generic zero knowledge.

RPC/network observations are a separate optional threat model: queried
addresses, queried history, submitter IP, mempool arrival, server logs and remote
prover witnesses are excluded here. Hosting all wallets on one machine and
using one node does not test network privacy. Four separately keyed synthetic
wallets funded from one public source are not four independent human users.
The shared funding fan-out and reserve chain remain linkable test activity.
Cross-run analysis can also link deliberately matched experiments; an observer
restricted to one arm is an explicit experimental restriction.

## Workloads, attacks and controls

Use two fresh pool domains with the same four starting balances and same private
transfer schedule. Include Alice to Bob to Carol without an intervening native
exit, unrelated activity from Dave, and a quiet interval with only one active
holder. Change only the withdrawal policy: consume the whole note versus make
a specified partial payout and retain private change. A fixed partial amount
shared by several withdrawals is a declared wallet-policy assumption, not a
discovered natural traffic distribution. Record actual confirmation intervals;
proof-building time is not evidence of human payment timing.

Score at first withdrawals and after eventual complete independent drainage.
Report every extra transaction/fee needed to withdraw residual change. A larger
candidate count bought by leaving value indefinitely locked is not a free win.

| Attack/control | Exact information used | Output and limit |
| --- | --- | --- |
| Structural baseline | Earlier commitments, public event order, append/spend counts | All chronologically possible source commitments; counts commitments, not people. |
| Integer conservation | Public deposit credits, fees, full/partial payouts and shapes; one hidden consumed note per event | Enumerate or solve feasible histories of unique consumption and positive integer note values. Full exit fixes `v = p + f`; partial exit fixes `v = p + f + hidden_change`. Include later drainage constraints. |
| Timing heuristic | Chain event order/timestamps only | Rank recent eligible source-creation events; mark it a guess, report tie handling, errors and abstentions. “Only active wallet” must not be supplied from the private schedule. |
| Combined attack | Feasible amount candidates, then timing rank | Separate forced unique links from heuristic top-choice predictions; do not call all predictions deductions. |
| Ground-truth control | Private schedule/notes, scorer only | Check the true consumed note is never eliminated by an allegedly exact feasible-history model; verify conservation and scorer labels. |
| Quiet-activity control | One spendable note/one compatible earlier source in a separately labelled prefix or trace | Expect a unique structural candidate; failure to recover it diagnoses the observer implementation. |
| Ambiguity/false-link control | Two or more equally feasible earlier sources; deliberately old note spent after a newer eligible one | Verify amount analysis preserves alternatives and newest-first can fail. Timing shuffles may be an offline sensitivity check, labelled synthetic. |

A feasible-history implementation must track spentness per hypothetical history;
it cannot remove a commitment just because an unrelated public nullifier exists.
With opaque values, simple exact-amount matching is only a heuristic. If a solver
omits ownership/change-owner constraints, its candidates are an upper bound;
if it searches a restricted private-amount grid or known schedule, it is a
stronger-knowledge workload model, not a general chain-only result. Name those
limitations explicitly. Empty candidate sets indicate either a bad model or
invalid data, not perfect privacy.

Report counts and denominators: correctly forced links, incorrect forced links,
top-choice correct/incorrect predictions, abstention/coverage, candidate-set size
per exit, and true-source inclusion. Also report unknown versus exactly recovered
note values, distinguish exit-to-creation links from deposit ancestry, and record
proof/loading time, confirmation delay, bytes/mass, and total/per-operation fees.
Do not assign entropy or an “anonymity score” from candidate count without a
justified probability distribution. Four synthetic wallets do not support a
population-level success percentage.

## Established designs inspected; reused and rejected

This refresh re-read the repository's mature-protocol notes and selected pinned
primary sources, not every current release of each system.

| Source | Reuse/adaptation for this experiment | Not imported or inferred |
| --- | --- | --- |
| Orchard [ZIP 224][Orchard] | Private membership, deterministic spentness, explicit conservation and keeping change/value inside the shielded domain; public exits reveal value | Halo2/Orchard cryptography, production security, or guaranteed anonymity from a shared pool |
| Aztec [privacy guidance][Aztec] | Treat public boundary calls, wallet behavior and off-chain access as separate leakage channels | PXE/sequencer/runtime or a new fee asset |
| RAILGUN [wallet contract][Railgun], [broadcasters][Broadcasters] | Separate proof/output binding and relay transport; fees can be paid from protected value | Restricted circuit source, broadcaster/list approval as an exit requirement, admin upgrade model |
| Monero [RingCT source][Monero], [historical traceability research][MoneroPaper] | Public fee conservation, clearly separated view/spend roles, and tests of effective rather than nominal candidates | Ring signatures or historical attack percentages as current Kaspa/Monero privacy claims |
| MWEB [kernel specification][Mweb] | Public fees and peg-out values remain part of hidden-value conservation | Native extension-block consensus, cut-through as protection against an observer who retained history |
| Zcash empirical research [Kappos et al.][ZcashPaper] | Amount/timing and usage-pattern attacks, explicit false-positive concerns and public-boundary analysis | Historical rates applied to this new tiny workload |

The two established behaviors under study are continued shielded re-spending
and withdrawal with private change. Neither needs a new L1 feature. Arbitrary
delay without other plausible activity does not create new candidates; no
cover-traffic service is included in this test.

## Completion and reasons to stop

Completion requires real TN10 deposits into the shared pool, repeated private
payments, actual partial-change re-spending, and full withdrawal by each of four
wallets using only its own secrets and public data. Validate all old liabilities
through deposits; reject duplicate spends, stale/domain-substituted proofs,
modified payouts and unauthorized state changes. Confirm every payout and the
terminal zero-liability/no-reserve condition. Keep local negatives, relay
rejections and confirmed positives distinct.

Stop expanding the experiment if the only result is the known fact that a lone
note has no plausible alternative source, or if partial withdrawal simply
postpones the same exact linkage until the remainder exits. Record that negative
finding and its cost. If fees, proving-key loading or state growth dominate the
four-wallet lifecycle, that is a usability blocker to prioritize before wallet
polish. None of those failures justifies weakening conservation or proposing an
L1 change without first examining simpler existing-L1 designs.

Upstream [P13][P13] remains a broader leakage-analysis task. [Issue 23][P23]
concerns production exit liveness under changing fees; this fixed TN10 workload
does not close it. Upstream KPI main was `cde2b88de3a16af401a2046bd90a124aa105418a`
when checked. Its current work does not dictate this independent experiment.

[Kdiff]: https://github.com/kaspanet/rusty-kaspa/compare/01b532e8b553523216471682649693af92f0fd16...f7d7877363fb97c2ec6871be0e8cbc351d44df10
[Kparams]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/params.rs#L650
[Kops]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L968
[Ktags]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs
[Kg16]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs
[Kpolicy]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs
[Klimits]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_limits.rs
[Khead]: https://github.com/kaspanet/kips/commit/e4ae2332117b5cb68bd6188e065ef885b6d17939
[Vreadme]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[Vsuffix]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs#L512
[Rdraft]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[Orchard]: https://zips.z.cash/zip-0224#security-and-privacy-considerations
[Aztec]: https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[Railgun]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol
[Broadcasters]: https://docs.railgun.org/developer-guide/wallet/broadcasters
[Monero]: https://github.com/monero-project/monero/blob/7778a369afdb788af245ba5ac4d5b17d5a2cc4c5/src/ringct/rctSigs.cpp
[MoneroPaper]: https://arxiv.org/abs/1704.04299
[Mweb]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md
[ZcashPaper]: https://arxiv.org/html/1805.03180v1
[P13]: https://github.com/olafweller/kaspa-privacy-initiative/issues/13
[P23]: https://github.com/olafweller/kaspa-privacy-initiative/issues/23
