# Shared pool: protocol dust floor and independent conflict recovery

Source review, 2026-10-19. This note scopes the owner-authorized follow-on to
[ADR-0016](../docs/adr/0016-four-wallet-shared-pool-trial.md) and
[RFC-0004](../docs/rfc/0004-four-wallet-shared-pool.md). It does not claim that
the new circuit or contention trial has run. No node, wallet secret, transaction
submission or implementation was used for this review.

## Recommendation

Make the existing conservative wallet minimum an immutable circuit rule in a
fresh pool version, then run two independent wallet controllers that prepare
against the same reserve and submit once each. The losing wallet must discover
the accepted spend from ordinary chain RPC, validate it, rescan its own notes
and generate a fresh proof. Do not give it the winning transaction ID or a
coordinator's next-state plan.

For the existing fixed transaction layout and 100 sompi/gram assumption, a
simple choice is a **10,000,000-sompi native payout floor** and a
**26,713,000-sompi private-note floor**. These are 0.1 and 0.26713 tKAS. The
second value is the larger full-exit fee plus the payout floor. Recompute the
fee bound for the final new layout before fixing the constants; changing the
relation requires new experimental parameters/VK and a distinct pool version.

This addresses tiny liabilities and one stale-proof recovery. It does not
guarantee liveness against arbitrary fee rises, missing public data, lost keys
or an adversary who continually wins the serialized reserve. Assume the
configured fee rate remains adequate and the recovering wallet eventually
gets one uninterrupted opportunity to prove and settle.

## Current source status

Rusty Kaspa master was rechecked at
`f7d7877363fb97c2ec6871be0e8cbc351d44df10`; the experimental native/SDK pin remains
`01b532e8b553523216471682649693af92f0fd16`. The storage formula and reviewed relay
and resource-limit behavior agree with the earlier [source refresh](shared-pool-four-wallet-source-review-2026-10-19.md).
Current source does not require a consensus change for either the application
floor or public-chain resynchronization. The historical prose in KIP-9 mentions
older standard-mass limits; use the actual pinned TN10 parameters and mempool
code for today's limits. [Current comparison][Diff], [KIP-9][K9],
[native parameters][Params], [limits][Limits].

## Exact native accounting and storage mass

All values below are integer sompi, with every division rounded down separately.
The pinned storage parameter is `C = 10^12`. The TN10 storage limit is
`L = 500,000`. The current P2SH reserve and P2PK payout each have storage
plurality one: their native SPKs fit within the 100-byte UTXO storage unit,
including the 63-byte fixed portion, and this design uses no covenant metadata.
The 4,096-byte redeem script is in the spending witness, not the UTXO SPK.
Adding covenant metadata or enlarging native SPKs can change plurality and
requires recalculation. [Constants][Constants], [storage implementation][Mass].

For a continuing exit with one reserve input `R`, next reserve `S`, payout `P`
and fee `F`, exact native conservation is `R = S + P + F` and:

```text
storage = max(0, floor(C / S) + floor(C / P) - floor(C / R))
```

For a terminal exit, `S = 0`, the only output is `P = R - F`, and:

```text
storage = max(0, floor(C / P) - floor(C / R))
```

Both formulas require strictly positive real native outputs. An omitted reserve
is not a zero-valued output. This one-input case uses the relaxed KIP-9 formula.
There is **no context-free native dust amount**: the input credit and other
output matter. A transaction above the storage limit cannot buy admission by
paying more fee. [Storage implementation][Mass], [resource checks][Limits].

There are two separate fee conditions. Default relay charges the maximum of
compute and normalized transient mass. Mining feerate uses the maximum including
storage mass. Consequently, passing the compute-based relay floor does not mean
a storage-heavy transaction pays the node's quoted rate per mining-mass gram.
[Relay policy][Policy], [calculated mining feerate][Feerate].

The prior measured layout has continuing-exit compute mass 167,130 and terminal
mass 166,707. At 100 sompi/gram their compute-based fees are `Fc = 16,713,000`
and `Ft = 16,670,700`. The following are exact integer source calculations,
not new native execution measurements. “Two equal notes” means reserve `2n`,
first payout `n-Fc`, and successor reserve `n`.

| Context and criterion | Note/reserve value | Payout | Storage at boundary | Storage with note value one sompi lower |
| --- | ---: | ---: | ---: | ---: |
| Terminal, storage ceiling only | 18,475,341 | 1,804,641 | 500,000 | 500,001 |
| Two equal notes, first full exit, storage ceiling only | 18,825,196 each | 2,112,196 | 500,000 | 500,001 |
| Terminal, storage no greater than compute | 21,353,708 | 4,683,008 | 166,707 | 166,708 |
| Two equal notes, first full exit, storage no greater than compute | 23,566,352 each | 6,853,352 | 167,130 | 167,131 |

The first two rows are admission boundaries at those fixed fees. They pay only
about 33 sompi per mining-mass gram, not the assumed 100. The last two avoid
that discrepancy for their specified contexts. These are not universal optimal
floor claims for arbitrary fees, shapes or participant balances.

The proposed conservative constants have a simpler bound. If `P >= 10,000,000`
and every continuing reserve `S >= 26,713,000`, then even before subtracting the
input credit:

```text
continuing storage <= floor(10^12 / 10,000,000)
                    + floor(10^12 / 26,713,000)
                   = 137,434 < 167,130 < 500,000
terminal storage   <= floor(10^12 / 10,000,000)
                   = 100,000 < 166,707 < 500,000
```

Thus the existing compute-based exit fee also funds the assumed mining rate.
For `S = 26,713,000` specifically, the storage-ceiling-only minimum continuing
payout is 2,063,775; 2,063,774 exceeds the limit by one. The recommended 0.1-tKAS
payout is deliberately above this boundary. Native mass tests should reproduce
all boundary rows and the final-layout bounds, rather than rely on these source
calculations alone.

## Why payout protection alone is insufficient

The v2 circuit only requires positive real note values; its wallet rejects or
quarantines small notes. A modified sender can therefore create a tiny hidden
liability while the public reserve remains large. When another holder exits,
the required successor can be too small to satisfy native storage mass. The
tiny holder may also lack enough value to pay an exit fee. A minimum payout
protects the withdrawing user's public output, not the remaining reserve.
The version-2 report explicitly records this gap. The baseline implementation
and wallet policy are preserved at checkpoint `62c8550`; current source files
contain the subsequent version-3 fix. See the [recorded version-2 limitation](../poc/shared-pool/README.md)
and [follow-up implementation/results](../poc/shared-pool/CONTENTION.md).

Enforce the following inside the new relation, not only in wallet constructors:

1. Every active created note has value at least the immutable `NOTE_MIN`:
   deposit credit, both transfer outputs, and partial-withdrawal private change.
   Inactive padding remains exactly zero and is not appended.
2. Every real spent input satisfies the same floor, including the initial
   bootstrap note. Keep the first-spend backing equality and the rule that
   later depositors cannot join before valid bootstrap. Validate the ordinary
   genesis funding value before broadcast; arbitrary transfers into arbitrary
   unusable P2SH scripts cannot be prevented by a pool application.
3. Every native payout is at least immutable `PAYOUT_MIN`; every nonterminal
   successor reserve is at least `NOTE_MIN`. Terminal reserve remains absent.
   Bind the amounts through the actual introspected transcript as before.
4. Keep bounded-integer conservation, ownership, nullifier, state-retention,
   domain and immutable-verifier checks unchanged. Do not round a small
   recipient note up by taking another holder's backing, silently burn a
   liability, or introduce an administrator to collect dust.

The reserve floor follows inductively from this design's exact equality between
reserve and outstanding notes: bootstrap establishes equality, every transition
preserves it, and any nonempty set of notes sums to at least `NOTE_MIN`.
An explicit public reserve-floor constraint also makes the boundary easy to
audit and test. This argument assumes authenticated genesis; it cannot validate
an arbitrary imported state containing old below-floor commitments.

For the existing fixed fees, deposit input must cover `NOTE_MIN + Fdeposit`;
a two-output transfer must cover `2*NOTE_MIN + Ftransfer`; a partial exit must
cover `NOTE_MIN + PAYOUT_MIN + Fpartial`. A smaller valid note can still take a
full exit. Full exits append no commitment and must continue to work at capacity.
The floor is public protocol information and changes future observer bounds;
do not silently apply it to the already recorded v2 privacy experiment.

An immutable minimum is not an arbitrary-fee guarantee. If an adequate future
fee exceeds `NOTE_MIN - PAYOUT_MIN`, a minimum note may be unable to exit under
these rules. The bounded test assumes the stated fixed rate; it does not close
[upstream fee-liveness issue 23][Issue23]. Changing a floor/VK later requires an
explicit migration design, not an admin escape path.

## Recovering without a coordinator's winner plan

The pinned `getVirtualChainFromBlockV2` accepts a previous chain cursor and `Full`
verbosity. It returns removed/added chain blocks and transaction bodies selected
from consensus acceptance data. Full verbosity requests populated input UTXO
context as well as transaction fields. Pagination can truncate the returned
added path; use the actual last returned added block as the next cursor.
[RPC service][RPC], [acceptance conversion][Acceptance], [verbosity][Verbosity].

The existing `fetch-chain.mjs` verifies known expected transaction IDs/bodies
from a coordinator-created list. That is useful receipt checking, but it cannot
demonstrate discovery of an unknown winner. Each new wallet controller needs its
own accepted-history journal and the following loop:

1. Start with the public pool identity, pinned rules/VK/parameters and a verified
   pre-race accepted history/cursor. Load only that wallet's private file.
   Scan all subsequent accepted bodies for spends of the tracked reserve;
   do not filter by a supplied winner ID or expected sequence.
2. Canonicalize each relevant body, recompute transaction ID and full hash,
   check populated predecessor context and exact reserve lineage, then run the
   native verifier and protocol/history checks. Derive new state, ciphertexts
   and reserve SPK from the body. A relevant accepted spend that cannot be
   verified is an error, not an event to ignore.
3. Apply accepted transitions in order; process several in one page if needed.
   Independently compare the derived current outpoint, amount and SPK with the
   node's current UTXO view. A mempool success, missing old UTXO, returned address
   or valid proof alone does not identify the accepted successor.
4. Rescan own ciphertexts and test the economic nullifiers against the current
   spent set. If the peer exited a different note, the loser's original note
   and economic nullifier remain valid. Rebuild using the new predecessor and
   state, choose continuing versus terminal from current liabilities, generate
   and locally verify a fresh proof, then submit the new transaction once.

If a two-note pool loses one note in the winning full exit, the remaining wallet
must switch to the terminal transaction shape. With the prior layout, its fee
falls by 42,300 sompi and its payout rises by that amount relative to its stale
continuing-exit attempt. Reusing the stale transaction/proof or just changing
its outpoint would break the actual-state binding.

Reorg notifications must invalidate affected cached history and pending proofs;
replay from a retained accepted checkpoint, or stop safely and retain all data
if that recovery is outside the bounded implementation. An omission, pagination
gap or pruned body is not authority to invent a state. The current test can
explicitly assume a stable accepted race outcome while testing rejection of
malformed/unverifiable updates separately.

RPC provides public-chain transport, not spending authority. The configured
full node remains the source of canonical-chain status and availability; local
body/hash/proof validation is not an independently implemented Kaspa light
client or an archival-availability proof. A malicious/unavailable RPC can delay
progress. It must not authorize releasing funds to another destination. Network
privacy and submitter correlation are outside this experiment.

## Smallest useful race and controls

Use a fresh two-note state owned by two separate wallets. Both prepare valid
continuing exits against the identical accepted reserve before either submits.
A barrier releases both submission loops; the coordinator does not choose the
winner. Each original transaction is attempted once. Record both native
preflight successes, submission times/errors, and which body the chain actually
accepted. A planned losing conflict is a control, not a reason to rebroadcast
that transaction or weaken validation.

After the first accepted exit, the winner stops. The loser independently polls
public chain data, validates the unknown winner, rebuilds and proves its terminal
exit, and confirms its payout. A new proof/transaction against a new accepted
state is a new attempt; keep both attempt records. The post-race wallet must
receive no private winner files, winning-ID hint, updated operator plan or
privileged signature. Prefer two separate RPC/controller processes, each with
its own public-history cache and isolated prover using only its wallet.

Required negatives: below-floor genesis/input, deposit credit, each transfer
output and partial change; `NOTE_MIN-1/NOTE_MIN` and
`PAYOUT_MIN-1/PAYOUT_MIN`; tiny successor reserve; stale predecessor proof;
changed payload/state/VK/payout; same-note double spend; malformed and wrong-pool
RPC bodies. Require actual circuit rejection when the wallet is bypassed.
Separately check the native storage boundaries with the real mass calculator.

Completion means both payouts are accepted, the stale attempt is unaccepted,
the loser proves from discovered state, both wallets have no unspent private
claim, and no reserve remains. Charge fees only for accepted transactions. The
race adds a rejected proof/submission and one fresh proof; the rejected attempt
does not pay an L1 miner fee. Existing-layout exit fees sum to 0.333837 tKAS,
excluding bootstrap/private-payment fees; measure the final implementation.
Record warm reproof time separately from parameter loading and confirmation
observation. The previous roughly 11-second warm proof time is a reference,
not a measured timing for the changed circuit.

## Narrow lessons from established designs

Orchard separates membership anchors from nullifier spentness and supports
shielded outputs/change; Aztec also distinguishes append-only notes and spent
markers. RAILGUN retains root history and per-tree nullifier state. These inform
verified state refresh, but do not make this Kaspa transaction reusable after
its exact reserve outpoint is consumed. Removing the predecessor/state binding
to imitate old-root acceptance would require a new settlement design and must
not discard a competing winner's nullifier/state update. [Orchard tree][Orchard],
[Aztec state][Aztec], [RAILGUN commitments][Railgun].

Monero and MWEB explicitly account for public fees alongside confidential value;
their wallets/state models do not rely on this one global application reserve.
Neither provides a drop-in minimum-note number for Kaspa's storage formula.
The floor here is an application solvency condition for one-note exits, not a
new privacy primitive or a claim that those protocols forbid tiny/dummy notes.
[RingCT][Monero], [MWEB kernels][MWEB].

Do not expand this test into batching, sponsorship, queues, sequencers or new L1
rules. If one unopposed loser cannot recover, fix that path first. If it succeeds,
report that bounded liveness result and the remaining starvation/fee/availability
assumptions without calling the shared reserve generally censorship resistant.

[Diff]: https://github.com/kaspanet/rusty-kaspa/compare/01b532e8b553523216471682649693af92f0fd16...f7d7877363fb97c2ec6871be0e8cbc351d44df10
[K9]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0009.md
[Constants]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/constants.rs#L26
[Mass]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L392
[Params]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/params.rs#L650
[Limits]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_limits.rs
[Policy]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs#L71
[Feerate]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/tx.rs#L658
[RPC]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/service.rs#L1367
[Acceptance]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/converter/consensus.rs#L531
[Verbosity]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/core/src/convert/verbosity.rs#L92
[Issue23]: https://github.com/olafweller/kaspa-privacy-initiative/issues/23
[Orchard]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md
[Aztec]: https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/foundational-topics/state_management.md
[Railgun]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol
[Monero]: https://github.com/monero-project/monero/blob/7778a369afdb788af245ba5ac4d5b17d5a2cc4c5/src/ringct/rctSigs.cpp
[MWEB]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md
