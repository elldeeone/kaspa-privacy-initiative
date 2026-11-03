# H14 adversarial review

This is the implementing agent's second pass, not independent security review.
The experiment changes the observer and adds an offline driver; it does not
change v6's circuit, covenant, keys, setup or protocol invariants.

## What could give a false privacy result?

- **Using the old relation.** H11 assumes one input and a unique deposit ancestor.
  H14 permits one or two positive inputs and zero output slots; it measures
  unordered joint input sets and distinct sets of creating transactions.
  Slot permutations and padding never become additional participants.
- **Excluding the real answer.** The isolated observer writes its complete
  predictions before the scorer opens truth. Every true input/source set must
  survive every baseline and every exact prefix. A contradiction aborts scoring.
- **Missing global constraints.** Inputs consume notes at most once; all note
  values are shared across the whole prefix. Terminal zero native backing
  forces every positive note to have been spent. `commitment_count ==
  nullifier_count` is not a valid terminal rule for v6.
- **Assuming hidden wallet policy.** The solver does not learn owners, number of
  real inputs, private splits, which output is change, or that a drain actually
  used one note. It also does not assign a single depositor to a merged note.
- **Guessing uniformly from candidates.** Candidate counts are logical
  alternatives. The recency prediction is fixed without truth. Correctness,
  singleton coverage and candidate counts are separate; no anonymity percentage
  or posterior probability is inferred.
- **Timing and identity shortcuts.** Funding groups and payout-script equality
  are public. Times are an explicitly imposed ten-minute schedule. Four unrelated
  funding sources are a favorable assumption; a common funder leaves one funding
  cluster. Wallet count is not evidence of independent people. Source-set
  inference identifies transaction relationships, not natural-person identities.
- **Reading the answer.** Each observer sandbox mounts only its public trace,
  observer/solver code, installed libraries and its own output directory.
  Workload manifest, controller, generator, keys and truth are absent. Network
  namespace has only loopback. Pins contain hashes, not truth. This is technical
  blinding of the process; the implementing researcher knows the study design.
- **Dropping difficult results.** Workloads were committed as `1bf14d0` before
  generation. CP-SAT and pure integer SMT searches were interrupted for
  performance; later attempts refined repeated horizon work, fixed-graph integer presolve and the
  order of solver queries. Seven incomplete observer batches remain retained.
  The final run uses byte-identical public inputs and truth. Unknown status is an error. No economic case is replaced or counted as ambiguous merely
  because it is slow. Exact solver agreement with independent tiny enumeration
  checks zero slots, one/two inputs and the drained history. The final engine
  searches rational-valued graphs but accepts a positive result only after the
  original integer CP-SAT relation validates that entire graph. If validation
  rejects it, the graph is blocked and search continues. A rational UNSAT is
  also integer UNSAT; a rational SAT alone is never counted. No amount rounding
  or scaling is used in the final analysis.
- **Order of computation.** The final engine evaluates complete drainage first,
  then earlier observation points. A later valid history remains a possible
  earlier prefix, so its feasible input sets can be reused. Every other set is
  tested against only the prefix being reported. This changes runtime, not the
  information used to exclude a candidate or the fixed ranking. A separate
  control compares each reported prefix with a newly constructed integer model.

## Value-bound checks

The forward bounds use only funding, anchors and conservation. Backward bounds
use the fact that a positive note must later be consumed or remain in the
reserve. Its value cannot exceed its consuming transaction's total input value,
or the remaining reserve if it is unspent. Future output bounds are available
because notes are consumed strictly after creation.

A sibling pair can be consumed by at most two future transactions, or remain in
the reserve. Its total is therefore at most the sum of the two largest eligible
future input budgets, including the remaining reserve as one shared bucket.
Historical commitment counts include complete output pairs. A transaction's
budget includes all its other inputs too, so this is an overestimate, never an
assumption that the two notes funded that transaction. Explicit reserve identities
at each prefix follow by summing the per-transaction conservation equations and
using at-most-once consumption. These redundant constraints accelerate search;
they add no wallet policy, hidden amount or new economic restriction. Tiny
exhaustive enumeration and the original integer encoding check the results.

## Scope of the relation

Commitments, ciphertexts, Groth16 proofs and HMAC nullifiers are assumed hiding
except for public equality/framing. This study does not establish those
properties or setup integrity. Actual native transactions are separately
validated by the existing Rust consensus/policy harness. The Python decoder
checks its consumed public fields and continuity, not Groth16 proofs or all
Merkle witness bytes. A changed opaque nonzero nullifier requires cryptographic
verification; expecting the framing decoder alone to reject it was a test error,
corrected without weakening the native validator. Reused nullifiers are rejected.

For these frozen amounts, all funded value is far below MAX_SOMPI, every fee is
below the positive-note floor, and ordinary SPEND without payout necessarily has
a positive output. Thus the value/range/positive-output conditions of v6 follow
from the encoded equations and bounds. This is a bounded study relation, not a
general consensus replacement. Tiny oracle fixtures use scaled integer units to
make exhaustive enumeration possible; they do not change the main workloads.

## Native safety and liveness checks

The driver uses synthetic native UTXOs and the existing experimental proving
parameters. Native validation checks proof verification, backing, output binding,
fees, state roots and current spentness. Existing mutation controls are retained.
Saved proofs are created at note receipt, then used byte-for-byte after later
operations. Fresh exits share the same real nullifier and exact payout with the
saved fallback. Both winner orders update spentness and reject the other proof;
the terminal state is checked too. Four wallets must have positive final payouts
and the reserve must reach zero in both branches.

Exit adapters run separately with public state plus their authorization bundle;
no wallet secret, proving key, host home directory or network is mounted.
The experiment supplies public state to these offline adapters. This is not a
new demonstration of remote discovery, pruned-history recovery, concurrency,
reorg handling, hardware usability or general liveness. Partial-withdrawal
scripts are fresh synthetic destinations; the privacy experiment does not
exercise later ordinary spending from them. No real or testnet funds are used.

## What the result cannot settle

Surviving source sets can still have unequal probabilities under realistic
behavior. Additional auxiliary knowledge, exposed fallback bundles, common
funding, address reuse, small activity, withdrawals, or RPC/network observation
may improve inference. More candidate source transactions are not more users.
Even a passing frozen screen leaves Stage 2's strong-privacy question open.
