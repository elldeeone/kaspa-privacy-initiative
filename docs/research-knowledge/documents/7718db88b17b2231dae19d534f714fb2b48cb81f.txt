# Recovery availability and fault review

Status: **source/design review only** at `a6fcdf1edd904dbe1bb395285230649b6c40d44c`.
No actual PK, backup, private input, network request, native validation or proof
has been run in this lane. ADR0057 is now accepted and root has released
independent light public-only controls once the new capsule API source is stable.
The independent integration file has now passed13 public-only controls; the
execution and deferred boundaries are recorded in API-REVIEW-01.md. Earlier frozen modules and packets remain unchanged.

## Constraints for the new API

1. **Authenticate the authority separately from the capsule.** The caller's
   approved capsule-root digest, descriptor/domain and permitted policy/role
   selection must come from outside the downloaded capsule. Replacing a
   descriptor, object and inventory and recomputing all internal hashes must
   still fail against that outside selection. A capsule-provided software hash
   inventories bytes; it cannot authorize running those bytes or a new policy.
2. **Separate retained bytes, valid history and current state.** Content hashes
   authenticate archived observations. Semantic/native replay checks supplied
   transactions and contexts. Fresh acceptance/ancestry, exact spentness and
   UTXO evidence require a new selected validating-node observation. An intact
   old view, changed timestamps or `complete:true` flags cannot establish
   currentness. Missing history or an unavailable node means unavailable or
   unknown, never an empty balance or terminal reserve zero.
3. **Keep compact and wide parameter roles distinct.** A compact spend requires
   its selected exact compact PK, VK, relation/source/build identity, encoding
   and shape. It must not require the wide PK. Historical wide-proof verification
   needs the selected wide VK/program, not its PK. Recognition/recover-only must
   work with no PK/prover mounted. The full new program/role dispatch must be
   independently approved; D/VK substring matches are insufficient.
4. **Finish public checks before backup bytes.** Check source/software selection,
   outside-root authority, descriptor/policy, manifest, history and current-view
   requirements before private recognition. For a spend, authenticate the whole
   owned compact PK bytes, decode exhaustion, extracted VK and query dimensions,
   then receive the selected parameters-ready identity before any backup read.
   File metadata checks may occur earlier, but must not read backup contents.
5. **Verify objects rather than trusting mirrors.** One valid root-matching mirror
   may succeed when another fails; record which candidate was rejected. If no
   complete matching object exists, stop. Never splice a prefix from one provider
   with a suffix from another without authenticating the entire selected object.
   All archive paths stay within explicit content-addressed public roots. Reject
   traversal, symlink/hardlink backup aliases and duplicate/conflicting entries.
6. **Avoid an enduring immutability claim for mutable paths.** Return owned
   validated data or explicitly require the trusted read-only release/host
   premise. A verified pathname is not an everlasting authorization for bytes
   reopened later. Existing ADR0054 deliberately assumes release-owner and host
   immutability; this work must not imply protection from a hostile same-inode
   writer or revive the superseded executable-FD runtime.

The implemented API has fixed recognition/spend-material modes and truthful
mode-specific copied-material statuses. Both set current-state and spend
authority false. History/native results and fresh observed-current results
remain separate responsibilities; see API-REVIEW-01.md for the reviewed API.

## Verified existing dependencies

The selected wide manifests for two completed trials are each 2,500 canonical
JSON bytes. They declare the **same 1,290,878,896-byte PK length and exactly the
same constraint/query dimensions**, but different D, VK and whole-PK digests.
This directly falsifies identity-by-dimensions. Only the small public manifests
were read; no PK bytes were opened. See [SOURCE-REVIEW.json](SOURCE-REVIEW.json).

| Public manifest | D prefix | VK SHA prefix | PK SHA prefix |
| --- | --- | --- | --- |
| `private-change/prover/parameters-01` (`b440d08f…`) | `bd9a7227…` | `dade8f90…` | `95729cb3…` |
| `private-service-loss/prover/parameters-01` (`008689b8…`) | `caf85e3b…` | `a82c9491…` | `de26f5d5…` |

The existing wide public manifest has a strict fifteen-field schema and no
explicit role field. The frozen network gate requires the complete 24,417-byte
approved wide program, not arbitrary descriptor bytecode. The new capsule API needs an authenticated role binding and full approved-policy
gate. That binding may live in an externally approved role-to-manifest map; this
review does not require adding a role field to the old parameter format. Do not
mutate frozen checks to accept a new policy or unknown fields. The public-only ADR0056 emitter uses `KPX4AU01`, distinct
compact/wide VK operands and a source-defined branch selector, but is explicitly
`DO_NOT_FUND_NO_MATCHED_CIRCUIT`; its role labels are not a selected setup.

Relevant source locations:

- [Wide manifest/descriptor binding](../../../../../poc/private-network-recovery/network_replay.py#L52),
  [full approved-policy gate](../../../../../poc/private-network-recovery/fetch.mjs#L66).
- [Full owned-PK authentication and decoder](../../../../../poc/private-cashout-prover/src/parameters.rs#L277):
  selected manifest before PK access, full length/digest before unchecked decode,
  no trailing bytes, extracted VK/query comparison, then parameters-ready.
- [Owner execution order](../../../../../poc/private-change-wallet/change_wallet.py#L430):
  public identity and network replay precede backup; spending additionally waits
  for selected parameters-ready before reading the backup at line299.
- [Public-path/backup inode guard](../../../../../poc/private-change-wallet/owner_rules.py#L44)
  prevents declared public objects aliasing the one mounted backup.
- [Future compact/wide native dispatch](../../../../../poc/compact-private-policy/src/policy.rs#L355)
  remains source-only candidate work, with distinct-role requirement at line874.

## History and node availability

The current fetcher starts from a user-pinned pre-founding birth anchor, asks the
selected node for Full accepted history, follows the exact founding/input0 graph,
and queries all selected consumed inputs and created outputs. It must reach the
fixed confirmed frontier; empty/truncated/pruned/cyclic/reorganized scans fail.
It watches **all currently live queried points**, including native payouts and
ordinary change, through post-query catch-up. The current implementation therefore
depends on node retention of the required Full history, not just current UTXOs.
See [scan/current-view code](../../../../../poc/private-network-recovery/fetch.mjs#L240).

The offline SDK verifier recomputes selected transaction IDs and full header
hashes, but explicitly sets `chain_inclusion_or_pow_verified:false`.
Native Full validates supplied transactions and input contexts, not consensus
membership. Current Python coverage predicates explicitly assume an honest
installed acquisition/provider. A sparse public capsule may remove dependence
on the operator's archive for retained bytes, but cannot turn those receipts into
independent consensus, inclusion proofs or a fresh UTXO observation. A sparse
history/current-view integration must explicitly bind the history tip, accepted
ancestry and exact queried points to the fresh selected-node result.

Missing unrelated bulk pages have a different meaning from missing selected
lineage: they need not invalidate a separately specified sparse-history result,
but that result must not claim it re-executed the old complete-chain scan. Missing
a required predecessor/body/context must always produce incomplete history. The
old Full-page metadata cannot be copied into a new sparse result as if that scan
actually ran.

## Independent controls after implementation

[FAULT-MATRIX.json](FAULT-MATRIX.json) preregisters six integration families.
They test production entrypoints, not a local reimplementation of their checks.
The capsule author owns parser/unit tests; this lane owns the drafted independent
integration file `test_recovery_capsule_faults.py` under this directory. The
latest frozen13-test run passed; actual selected-loader and semantic/current-view
composition families remain unexecuted in this lane. Existing SDK/native/proof controls will not be replayed merely to
increase a test count.

Run the destructive mutations only in a fresh network-off namespace with owned
public fixture copies and a synthetic 0600 sentinel that is explicitly not a
seed/backup. Do not truncate, unlink, overwrite, hardlink or chmod the real
parameter cache, installed release, prior packets or actual backups. Observe the
sentinel's kernel `IN_OPEN` events for real client-entrypoint ordering controls;
Python-only spies do not observe arbitrary child-process file access. Create and
close the sentinel before arming the watch. Declare the watcher/negative-probe
limitations honestly; no private recovery is established by this control.

Pure capsule integrity fixtures may use small opaque public objects. That evidence
does not qualify Ark decoding, a real compact PK, native acceptance or consensus.
After root selects the compact implementation and releases execution, bind the
PK-ready/order control to the actual selected loader and public PK once, and
reuse the scheduled genuine owner rehearsal for the positive proof path rather
than run a duplicate proof. Real backups, private inputs, network requests,
parameter blobs and proof jobs remain out of scope until that release.

Record the exact frozen production/test sources, input mutations, namespace argv,
exit/error category, object bytes read, sentinel-open count and accepted result
tier. A fault must return no current-balance/spendable/terminal-zero success.
Retain failed attempts and do not weaken a predicate or reinterpret the expected
result after observing it. Operator absence, corrupted mirrors or a lost PK are
availability failures; they must never authorize an exit, reveal a seed or trigger
an automatic less-private fallback.
