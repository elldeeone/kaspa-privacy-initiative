# Private cashout and independent recovery

Research/testnet results from baseline `63f494053b743ac9bfbd2d1842f69e0f806ef8e3`.
Native KAS remains the only backing asset. These experiments do not establish
cryptographic correctness, general financial privacy or production readiness.

## Private cashout: complete supplied-context prototype

The separate, explicitly unfunded Auth528 program executes deposit, admission,
private payment, partial native payout with private change, a continuing payout
and terminal withdrawal. Seven linked native Full operations reconcile a
4,000,000,000-sompi source to ordinary change, payouts and fees, ending with zero
reserve and no recognized positive liabilities. The public development fixture must
never be funded. [Lifecycle results](lifecycle/RESULTS.md).

Five genuine proofs verify under one new VK: four mainline actions and one
valid-ownership statement used in the competing-spend controls. Both private
spend/REVEAL orderings reject the already occupied current nullifier. The circuit
has 49 full constraint-system controls: eight satisfiable and 41 unsatisfiable.
Native controls reuse four byte-identical accepted positives and execute 76
additional rejection cases. [Proof results](proof/RESULTS.md),
[native results](native/PRIVATE-NATIVE-RESULTS-01.md).

One setup took 13.316 seconds; five individual 14-worker proofs took
7.989–8.293 seconds each. Those are individual samples, not warm-latency, complete
wallet-resource or p95 qualification. The new proof service stopped with zero
swap. The historical proof/cache and funded programs remain unchanged.

## Independent recovery

Two newly contacted TN10 endpoints independently returned the previous completed
pool's five accepted reserve transactions. Descriptor-only sandboxes received no
transaction list, snapshots, payment amounts, payer files, seed or proving key.
Headers were expanded and rehashed; local replay checked signatures/Groth16 using
the public VK. Separate Bob and Charlie backup-only processes recovered their
spent receipts and actual current native payouts. [Fetch](fetch/RESULTS.md),
[replay](replay/RESULTS.md), [wallet](wallet/RESULTS.md).

The separate fresh unspent trial now confirms the stronger service-loss path.
After its ordinary funding merge, deposit, admission and private payment, the
prover stopped. Bob discovered his unspent note using only fresh network data
and his own backup, then newly quoted and signed an exit. After that payout
confirmed, Charlie repeated from a new chain view and built the terminal exit.
Both payouts are confirmed under the strict greater-than-20 blue-score-depth
policy: Bob 55,026,200 and Charlie 55,036,800 sompi, observed at depths 185/188.
These are consented revealing fallback exits on old KPX2, not proof-private
cashouts. [Public service-loss packet](live/service-loss-02/EXTRACTION.json),
[trial preparation](live/README.md).

The complete 174,874,900-sompi ordinary source reconciles to those 110,063,000
sompi of payouts, 24,398,700 of ordinary change and 40,413,200 in fees including
the ordinary merge. Each 60M claim is a small liveness pilot, not fee/privacy
qualification. No operator archive, amount map, payer export, proving key,
prover or precomputed exit entered either cold recipient process. A final
descriptor-only terminal refetch and public native replay check all five pool
transactions, reconstruct CM4/NF5 with zero reserve/no pool head, and query both
payouts unspent. No further seed is read for this final check.
[Terminal result](wallet/unspent-terminal-01/RESULTS.json).

These network clients support the old Auth484/KPX2 program. The new Auth528
program's network recovery and independently owned private proving/signing are
not integrated. A separate ADR-0052 public-replay adapter now reconstructs the
new program's CM8/NF9/zero reserve and passes 40 rejection controls. It reuses
seven prior native results by entire body/witness/context identity, with no new
VM or proof run. Its output explicitly remains `complete:false` and
`accepted_chain_backing:false`. [Compatibility result](compatibility/RESULTS.md).

The historical scan fetched about 801–808 MB of decoded JSON per endpoint for
five relevant pool bodies (about 107–108 MB compressed retained pages). These
are semantic/disk sizes, not wire measurements. A separate 10,000-operation
synthetic replay took 10.702 seconds; its unproved data cannot establish wallet,
chain or availability performance. Data retention and validating-node assertions
remain assumptions; two endpoints do not establish independent consensus.

## Privacy and fee blockers remain

The chain-only diagnostic links both old revealing exits to their historical
private output notes and exact values. The proof-private design hides those note
openings but still exposes native payout amounts, timing, fees and terminal
drainage. The previous 21.0977% common-price amount prior still fails the 20%
gate. [Disclosure canary](observer/RESULTS.md).

A separate frozen ciphertext-only control identified a dummy-padding format
leak: 129/256 old random-byte dummies had an impossible real sealed-box prefix.
The assembler now produces dummy ciphertexts with the genuine sealed-box format;
the same classifier flagged zero of 256 corrected samples and zero of 256 real
samples. This closes that specific measured channel, without proving general
indistinguishability. [Padding result](observer/PADDING-RESULTS.md).

Actual emitted-body costs put even one private payment plus two independent
private exits at 56,916,200 sompi at reference rate 100: at least 2.84581% per
10-KAS recipient before ingress. The seven-operation example with an additional
partial payout costs 84,658,300 sompi, averaging 4.232915% per useful recipient.
Both fail the unchanged 2% complete-lifecycle target. Faster proving cannot fix
that native verification floor. [Fee measurements](native/PRIVATE-FEES-01.md).

A separate source-only screen rules out chaining more payments with the current
two-output statement, and also rules out simply widening its existing unrolled
Merkle code: the latter has an optimistic minimum of 2.099209% across batch
sizes, already over target. This does not exclude redesigned compact policies.
The next decisive fee experiment is a source-derived wider wire/code/budget/
storage screen before another circuit or setup.
[Fee feasibility](fee-feasibility/FEE-FEASIBILITY-01.md).

One frozen 32-role arithmetic comparison now completes 72 cases across eight
independent ledgers, three policies and three fee rates. It does not demonstrate
additional privacy over P0 rerandomization followed by REVEAL. At rate 100,
direct REVEAL opens 203/290 primary payment amounts by drainage; both other
policies open 0/290 through that specific channel. Neither zero establishes
general privacy. The private-exit model costs about 12.63% less than
rerandomize-then-reveal while meeting the same cash requests, but the prior and
fee gates still fail. At rate 500, seven revealing fallbacks remain on the
private-exit path. [Population comparison](observer/POPULATION-RESULTS-01.md).

All predictions were sealed before separate truth scoring. A duplicate metadata
field broke the original final summary after all 72 scores had been saved. A
separately reviewed aggregation-only repair uses those exact scores and the
original aggregate function; no generation, attack or truth scoring is repeated.
Original failures, frozen packets and all evidence identities are retained.
