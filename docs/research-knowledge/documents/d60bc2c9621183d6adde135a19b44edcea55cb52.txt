# Recoverable private change: local controller

Research/testnet software under ADR0055 and the private-change common contract.
The Auth528 relation and native program remain unchanged. Old packages and
closed evidence are read-only dependencies with exact source selections.

The selected main route is whole Alice founding, a 10 KAS private payment to
Bob, a requested 4 KAS partial cashout, recovery from Bob's original backup,
a 3 KAS private payment from that change, another original-backup recovery,
Bob's full continuing cashout and Charlie's terminal cashout. There are six
main transaction bodies and five private proofs.

`materialize.py` uses the source-selected owner wallet core, reads only this
fresh local identity, obtains official zero-proof diagnostic/actual quotes,
and retains only legal final actual witnesses. Each recognition creates a new
receiver from the unchanged original backup. Real/dummy slots are privately
shuffled by the shared wallet core. Change receives a fresh uniform-u64 V2
index, with historical collision checks and no saved issuance counter.

The default ordinary source is explicitly **synthetic, unbacked, and 11 KAS**.
Its six-body check does not establish actual-source or testnet trial readiness.
An actual source needs its own signed founding body, new outpoint-bound P0
proof and actual-context validation before any once-only root submission.
The root alone funds/submits; this package's local controllers have no RPC or
submission interface. `adapter.mjs` preserves the existing strict transport
checks and dispatches six neutral once-only stages for the root.

`phase.py` authenticates the new authority/identity and existing closed helpers.
`wallet_core.py` executes exact archived wallet source bytes with a canonical
logical resource path. It does not follow mutable later cold-client selections.
Local and cold clients use the same V2 module/crypto types, avoiding mixed
receiver/error classes. Project modules are loaded from authenticated source
bytes rather than bytecode caches.

`run_local.py` accepts only selected public-type statement/proof files in a
private input projection. It reads no profile, backup, witness, PK or setup
session. Six resident proofs are substituted into their exact actual quotes;
the main six bodies plus independent C0 control pass seven native Full/input
engine checks and seven SDK roundtrips. The main route ends CM9/NF11/reserve0.

The extra C0 payment control uses an independent
**PUBLIC_SYNTHETIC_DO_NOT_FUND** owner, recipient, note, state and fake outpoint
under the same fresh VK. Both NFs and all its CMs are checked disjoint from the
main trace. Its complete body/proof can be public. It is not another canonical
trial spend or a terminal drain.

Unbroadcast main/retry Auth, NF pairs, ciphertext, bodies and raw proof bundles
remain private even after a future live exit: two preparations for the same
note can expose the real NF by pair intersection. Publish only selected scoped
outcomes, integer accounting and allowed opaque final proof/Auth hashes. Never
publish witness/input hashes or paths, private receipt/index maps, or unselected
sizing/candidate digests. `publish_local.py` enforces the bounded export.

The frozen six-negative runner executed once. All six mutations were rejected,
but its two G16-error-name predictions were wrong; the historical result is
**4/6 exact predictions and exit1**. `interpret_negatives.py` only reads those
existing reports and pinned consensus sources: failed genuine-proof rebindings
return `ZkIntegrity("Groth16 verification failed")`, rather than `VerifyError`.
Do not rerun the matrix or rewrite the original prediction result. Four early
public-check errors matched. No additional current-rebased occupied-NF proof
was generated or claimed.

Public results live in `research/next-session/private-change/lifecycle/`.
The accepted publication clarification is `EVIDENCE-PUBLICATION-01.md` in the
parent phase folder. The main fee target, financial privacy, independent cold
network recovery, durable parameter/data availability and production safety
are not qualified by this local evidence.
