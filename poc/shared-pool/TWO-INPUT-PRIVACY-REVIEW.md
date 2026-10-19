# Two-input candidate: chain-observer and adversarial design review

**2026-10-20 (Australia/Sydney). Specification review only.** Applies to
[RFC-0011](../../docs/rfc/0011-two-input-private-payments.md), not the current
compact executable. Inspected branch baseline: `228e5d0`. No code, experiments
or new privacy measurements accompany this review.

**Assessment:** two inputs and private change remove avoidable application
restrictions and make varied private payments possible in principle. They do
not establish strong relationship privacy. The observable native boundary,
historical eligibility and whole-history value constraints remain. Preserve
independent exits even when taking one leaks information.

## Observer information

The baseline observer receives every accepted transaction in the designated
pool's native lineage, its spent UTXOs, accepted-chain order/times and public
protocol rules/descriptor. They can inspect the ordinary funding and payout
ancestry in the surrounding chain. Read-only RPC can supply those chain bytes;
it does not give the observer the users' RPC logs.

| Visible in the proposal | Consequence |
| --- | --- |
| Reserve outpoints, code/domain/VK, state roots and counts | Pool membership and operation order are public; this is one serialized reserve, not hidden native transfers. |
| Admission UTXO, its amount/script and signature; reserve credit and fee | Entry value and source address/cluster are visible. Ordinary funding preparation is visible too. |
| Mode, optional native payout and destination, exact native fee | Deposit, internal spend, withdrawal and no-append `DRAIN` are distinguishable. A withdrawal amount is public. |
| Historical root/count shared by the private inputs | Inputs must precede that accepted prefix. Later commitments cannot be candidates for an old fallback. |
| Two NFs in a spend and their public insertion paths | Current spentness is verifiable. Paths identify NF-tree positions/predecessors, not the secret commitment membership positions. Repeated real NFs link disclosed alternative authorizations. |
| Two CMs and ciphertexts for a normal spend/admission | Output positions and creating transaction are visible. Which slots contain positive value, their amounts, owners and the recipient/change distinction are not explicit fields. |
| Proof bytes, fixed envelope, canonical state-update paths | Cryptographic checks are public. Fixed length alone does not prove indistinguishability or rule out implementation fingerprints. |
| Subsequent deposits, payments, withdrawals and final drain | Inference can improve retrospectively. Privacy measured only at first withdrawal is incomplete. |

Unavailable to this baseline: real input positions, ownership/viewing keys,
note plaintexts and values, real/dummy flags, payment intentions, hidden
generator labels and unpublished fallback bundles. Treating cryptographic
bytes as hiding those fields is an assumption requiring soundness, zero
knowledge, proper randomness, commitment binding/hiding and suitable encryption.
This review does not prove those properties for the proposed composition.

RPC query histories, IP addresses, packet timing, mempool-only/rejected
transactions, frontend/prover logs, exchanged invoices, viewing keys and
recipient collusion belong to **separate, explicitly augmented observers**.
Self-funded fees remove a required fee sponsor; they do not hide broadcast
origin. A remote prover given private witnesses learns those witnesses.

## What changes, and what still leaks

| Inference | Effect of this proposal |
| --- | --- |
| “Payout plus fee equals the consumed note.” | No longer generally true for normal partial withdrawal: it equals input sum minus hidden output sum. It remains true of a one-real-input `DRAIN`; two-real-input `DRAIN` reveals the sum. |
| “Every child has exactly one funding ancestor.” | Invalid after a merge. Two notes may combine receipts from distinct deposits. Track possible ancestry sets and joint value constraints instead of forcing a unique deposit label. |
| “The transaction explicitly used one input and made change.” | Hidden flags remove those explicit disclosures on the normal path. Public amount bounds can still force an input count or prove that some output must be positive. Padding is not a guarantee that every shape is feasible. |
| “The withdrawal can come from any note ever created.” | False. Its historical anchor excludes later notes, known spentness excludes consumed candidates, and joint amount constraints can exclude others. |
| “More commitments mean more private users.” | False. Commitments include change, self-payments and zero notes. Two NFs may represent one real spend plus padding. Counts are neither people nor anonymity estimates. |
| “Private change makes a distinctive withdrawal anonymous.” | False. Public amount/timing, insufficient alternative funds, address reuse or later drains can still determine the relationship. |

For a normal spend the observer knows `sum(inputs)-sum(outputs)=W+F`.
For admission they know `sum(outputs)=D-F`. For `DRAIN` they know
`sum(inputs)=W+F`. These are exact constraints, not heuristics. A particular
candidate assignment must satisfy them jointly, each positive note's floor,
the zero-padding rules, historical membership, one spend per real note and all
later observed events. A public balance too small to support an alternative
can defeat apparent ambiguity without breaking encryption.

When only one funded source exists, there is no uncertainty about that funding
source. Merging notes within it does not create another independent participant.
A singleton source transaction can likewise remain identifiable. No amount of
waiting adds eligible notes to an unchanged anchor. Fresh normal authorization
may enlarge its eligible prefix when compatible activity actually exists;
it does not make that activity independent or the candidates equally likely.

The wallet normally keeps value and change inside the pool, uses fresh receipt
randomness and payout addresses, and keeps saved fallbacks private. These are
policies, not forced waiting, an admission allowlist or a privacy promise. The
underlying principles are consistent with [ZIP 224](https://zips.z.cash/zip-0224)
and [ZIP 315](https://zips.z.cash/zip-0315); the proposed Kaspa construction does
not inherit Orchard's security properties or traffic population.

A fallback is deliberately distinguishable: it creates no new commitments,
reveals the whole consumed value or sum, and may expose a very early anchor.
Capacity exhaustion may force that path. If a private fallback is disclosed
alongside a normal proof, their shared real NF can reveal which normal input
it authorizes and recover the fallback's old eligibility restriction. Keeping
fallbacks out of logs/public evidence matters. An observer seeing both versions
has more information than the accepted-chain-only baseline.

## Correct future measurement targets

No population study is specified or executed here. Before one is authorized,
freeze its workload, observer inputs, attack rules and decision thresholds.
Use ordinary varied receipts/payments, partial withdrawals and interleaved
admissions; include a singleton, thin activity, distinctive amounts, early exits,
fallback disclosure and complete drainage. Do not add invented background users
to manufacture an anonymity score.

The old observer assumes one real input, two positive outputs and a unique
funding parent. Reusing it would exclude legitimate histories and overstate
inference. A new public-only model must permit one/two real inputs, zero/one/two
real outputs where allowed, common historical anchors, two consumed public NFs,
positive floors, independent deposits and the distinct fallback path.

Keep hidden ground truth outside the observer: selected real note positions,
owning wallet, note values, recipient/change/dummy labels, and intended economic
payments. Score only after the observer returns results. Funding ancestry after
merging is a set of contributing ancestors; fungible conservation alone does
not assign a unique source sompi from an input to a particular output. Do not
invent that allocation and call it ground truth.

Report the following separately, at withdrawal and after later activity/drain:

- Exact input-note and creating-transaction candidate sets, with feasible
  **joint** input combinations; verify that the real assignment survives.
- Correct top guesses and coverage, including abstentions and ties; distinguish
  unique logical identification from heuristic ranking. Compare random/public
  priors, anchor eligibility, timing, amounts and joint-history constraints.
- Recipient/change identification and amount ranges, and funding-ancestor
  set inference under an explicit definition. A chain-only model without
  address-to-person labels cannot measure identification of real people.
- Actual user delay, proof work, native fees and additional merge/change-exit
  operations through drainage; count failures and capacity/fee fallbacks.

Separate shape/privacy improvements from workload changes: compare matched
economic intentions and funding opportunities, accounting for the fact that
the old relation may need extra transactions or cannot express an operation.
Raw transaction-count equality is not an adequate control. H11/H12 scores and
four-wallet TN10 acceptance are not real-world anonymity percentages.

## Adversarial second pass on the design

This is the author's design review, not independent cryptographic review.
The following obligations are part of the specification, not passed checks.

| Failure attempt | Required defense / remaining limit |
| --- | --- |
| Inflate by disabling a real slot or using field wrap | Boolean real flags, zero dummy values, positive real-note bounds, checked aggregate sums and exact economic equations; all paths constrain the same statement digest. |
| Spend the same note in both slots or via normal/fallback proofs | Real NF independent of slot/anchor/mode, distinct real positions, unequal public NFs, and current NF nonmembership. Both alternative proof winner orders need later qualification. |
| Insert a victim's pending NF through a dummy slot | Dummy NF must be derived in-circuit from a separate tagged HMAC preimage. Arbitrary public dummy NFs are forbidden. This unreviewed composition and fresh-randomness assumption are explicit review gates. |
| Apply both NF updates against the old root | Sequential predecessor rewrite/append with NF 1 checked against NF 0's successor. Preserve every prior NF and compare full 256-bit values. |
| Credit a deposit without paying or redirect a payout | Bind real funding outpoint/value/script; require native funding signature and exact reserve successor; constrain exact payout destination/value and actual fee. Reject foreign inputs/outputs. |
| Use padding counts to declare the pool empty | Terminal native balance is zero only after full authorized debit; backing/conservation induction establishes no positive liability. Never substitute `C-N` for money owed. |
| Fill state so an honest note cannot leave | Wider NF tree and no-append `DRAIN`, with the capacity bound in the RFC. New payment/admission capacity is finite; an attacker can still exhaust it and worsen privacy/liveness by paying for valid activity. |
| Substitute genesis, VK, domain or an old branch's state | Pinned descriptor and independent accepted-lineage validation; canonical bootstrap; native code continuity and historical membership; correct current UTXO view. |
| Forge claims with compromised setup material | New Groth16 setup remains a soundness assumption. Parameter hashes cannot establish an honest ceremony or trapdoor erasure; experimental setup is not production assurance. |
| Deliver an apparently funded but unspendable payment | Recipient validates decrypted opening, ownership and floor before accepting, then accepted membership/spentness. Cipher hash binding is not proof of correct encryption. |
| Steal through public rebuilding | Authorization fixes payout, output commitments, ciphertext hash and fee. Rebuilder updates only authenticated current settlement. There is no fee redirection or administrative withdrawal branch. |
| Remove the operator or raise fees | Own keys plus available authenticated public data/software suffice in the model; saved proofs avoid private re-proving only while their fee remains adequate. Data loss, fee spikes and contention can still block timely settlement. |
| Exploit reorgs or leak fallback material | Rebuild from one accepted lineage and roll back orphaned state; never merge incompatible roots. Keep alternative authorizations private. Broader reorg/network policies remain open. |

The proposal's extra constraints, setup and script work have no new measured
cost. Its padded arity and private change are **privacy mechanisms to evaluate**,
not evidence of an achieved privacy level. If independent review rejects the
dummy construction, capacity argument or exit semantics, redesign the RFC
before implementation. If later permitted measurements show that usable varied
payments remain reconstructable or uneconomic, report that result and reconsider
the design rather than relabeling candidate counts as strong privacy.
