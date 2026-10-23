# Testnet confirmation and ambiguous submission

Status: source review only; no keys read, signatures, funding, broadcasts, node
installation, or infrastructure changes. The adapter owner performs live probes
and execution separately. This note is a proposed evidence rule for the new
rehearsal, not evidence of an accepted payment.

Source: official `kaspanet/rusty-kaspa` release `v2.1.0`, commit
`01b532e8b553523216471682649693af92f0fd16`. The clean local source checkout
matched that tag. Exact file hashes are in `SOURCE-PINS.json`.

## Acceptance and depth

Use `getVirtualChainFromBlockV2` with an explicit recent `startHash`,
`dataVerbosityLevel: Full` (enum value 3), and `minConfirmationCount: 20`.
The implementation filters accepting chain blocks using
`sinkBlueScore - acceptingHeader.blueScore > 20`, with saturating subtraction.
The strict comparison means a returned block has at least 21 blue-score units
of depth at that RPC's consensus view. This is not 20 seconds, DAA-score depth,
selected-parent edge count, or immutable finality. Twenty is a rehearsal policy,
not a protocol security guarantee. The call rejects a transitional IBD state.
The default verbosity is Full, but stating it makes the evidence intent clear.
[Official service](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/service.rs#L1368-L1420).

`chainBlockAcceptedTransactions[i].chainBlockHeader.hash` is the **accepting
chain block**; verify it equals `addedChainBlockHashes[i]`. Each entry's
`acceptedTransactions` contains accepted transactions across that accepting
block's mergeset. A transaction's `verboseData.blockHash` is its containing
merged block, so it must not be substituted for the accepting block when
tracking depth or reorgs.
[Official converter](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/converter/consensus.rs#L531-L691).

Full supplies transaction version, ordered inputs/outputs, previous outpoints,
signature scripts, sequence and compute commitment, payload, lock time,
subnetwork ID, gas, storage mass, output covenant binding, and populated input
UTXO context. Match these to the locally frozen body and expected input context;
a transaction ID alone is insufficient evidence that the intended witness ran.
For native version-1 inputs the relevant compute field is `computeBudget`;
the optional RPC `sigOpCount` field is reported as zero for that version.
JSON may contain both `storageMass` and deprecated `mass`; the source rejects
unequal values when both are present.
[Verbosity mapping](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/core/src/convert/verbosity.rs),
[Optional transaction schema](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/core/src/model/optional/tx.rs).

## Pagination and removals

The result is a bounded chain delta, not an exhaustive one-call history query.
The service limits acceptance data by merged-block count and truncates added
hashes to returned groups. Continue from the **last returned added hash** and
retain every raw page. Empty additions mean observation is pending; do not
replace the cursor with the current sink and thereby skip an unseen interval.

Apply `removedChainBlockHashes` before additions. Invalidate acceptance evidence
whose accepting block was removed, even if a transaction is later accepted
again. Preserve an ordered cursor history so a removals-only page can roll back
to its retained common ancestor. If that ancestor cannot be recovered, rebuild
from a known retained anchor and mark the gap; do not silently advance. An old
anchor outside the node's retention-root chain can be rejected.
[Chain path and retention rule](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/consensus/mod.rs#L846-L866),
[Traversal order](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/traversal_manager.rs#L34-L59).

## Proposed completion evidence

1. Save exact Full accepted bodies for all lifecycle transactions, including both
   recipient exits, from pages satisfying the depth policy. Check the expected
   physical outpoint links and all integer-sompi amounts.
2. Query both payout addresses and locate each payout by exact `(txid,index)`,
   amount, version-0 SPK bytes, non-coinbase status, and expected absent covenant
   ID. The address RPC's ordering is unspecified. A balance aggregate or mempool
   entry does not replace this check. A payout already spent requires separately
   explained accepted spend evidence; absence alone is not success.
3. Consume the next chain delta after the payout snapshot, reconcile removals,
   and retain the server identity/network/sync/index state and observation times.
   Terminal reserve exhaustion follows from the accepted input/output chain and
   liability accounting, rather than from an empty address balance alone.

These are separate RPC views; record them as observations, not as an atomic
snapshot or permanent settlement. A single public RPC remains a trusted chain
and acceptance oracle. This review supplies no independent consensus/header
verification or acceptance-Merkle proof. A second endpoint can add corroboration
but does not remove that assumption.

## Once-only submission reconciliation

Before the send, persist a record binding trial identity, planned exact body,
expected txid, endpoint, and pre-submission retained chain cursor. Persist the
submission-attempt transition before the network call. The code must not invoke
submission again for that operation after a transport exception, disconnect,
missing response, process restart, or ambiguous timeout.

Reconcile by reading accepted Full pages from the saved cursor, the expected
transaction's mempool entry, and exact current input/output UTXOs. An exact
accepted body permits continuation under the depth/removal rules. A mempool
match means observed pending admission, not payment confirmation. Absence from
all three views, even with an unspent source, does **not** prove the request was
never received; it leaves the attempt unresolved. Retain the once-only marker
and continue observation. A generous observation deadline may return a resumable
pending status, but must not convert uncertainty to rejection or trigger a
rebroadcast. Any fresh trial uses a new identity and reconciles old liabilities
separately.

`submitTransaction` returning its txid means successful RPC/mempool admission;
the implementation does not wait for chain acceptance or payout confirmation.
`getMempoolEntry` returning not found is also not proof of rejection.
[Official submission/mempool handlers](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/service.rs#L597-L680).

## Critical version distinction

Toccata transactions use **transaction version 1**, with input compute budgets
and optional output covenant bindings. Their **script-public-key version stays
0**. `MAX_SCRIPT_PUBLIC_KEY_VERSION` is zero; the script engine accepts unknown
SPK versions without executing their scripts. Assert the SPK version explicitly
in constructor output, populated input context, accepted bodies, and payout
UTXOs. Do not infer execution from a successful validation of an SPK version 1.
[Constants](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/constants.rs#L5-L20),
[Engine behavior](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L654-L721).
