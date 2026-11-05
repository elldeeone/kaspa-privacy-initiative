# Joint-withdrawal feasibility gate

Date: 5 November 2026 (Australia/Sydney).
Base: `00018b9898ae2f09c9bca59ede632aee54c940ec`.

The owner authorizes checking whether optional joint withdrawals can conceal
payout ownership using current L1 rules, followed by an offline comparison only
if a concrete candidate passes feasibility. No consensus change, new token,
custody, privileged withdrawal key, mandatory withdrawal wait, funding,
broadcast, provider work or restart of paused MPC is authorized by this gate.

## Hypothesis and scope

The proposed small change is cooperative output registration/assembly around the
existing wallet-local EXIT and native permission path. It must conceal a
request-to-payout assignment without changing what the observer already knows.
Do not equate this with the much broader proposition that all application
redesigns on current Kaspa are impossible.

Check three constructions separately:

1. Existing EXIT statements/permissions with batched or shuffled payout outputs.
2. Existing exits followed by an ordinary jointly signed transaction (CoinJoin).
3. A replacement application authorizing a complete common payout set without
   publishing each request's selected destination. This is a possible design
   seam, not an implementation supplied by existing proof hooks alone.

## Evidence and observers

Use only already-published, hash-bound attempt-06 records and source code. Decode
the actual public operation payload, intent ID, native recipient key, permission
outpoint and payout output. Verify the complete retained archive manifest first.
Do not read wallet backups, secrets or private execution truth. These records
and their conclusions were already inspected; this is a forensic feasibility
audit, not a new blinded or prospectively sampled privacy experiment.

Separate two observations:

- Public chain: request-to-output/key linkage, with no assumed human identity.
- Supplied owner information: the same public records plus the retained explicit
  destination-to-owner mapping. That mapping is auxiliary experimental knowledge,
  not a fact inferred from an address, amount or transaction position.

A service that receives the same unblinded requests also receives their public
destination fields. Its human-identity knowledge and network visibility must be
specified separately; do not invent an authenticated-origin or IP observation.

## Deterministic gate and stop rule

- Reject the bolt-on if the earlier public request/permission path identifies
  the eventual recipient independently of output order. Exhausting permutations
  is an exposure-only negative control, not a valid native transaction or a
  privacy comparison of an implemented joint-withdrawal protocol.
- Reject post-exit mixing as a remedy for information already disclosed by the
  original exits. Downstream output unlinkability is a different possible
  benefit; do not score it as erasing earlier payment facts.
- A replacement requires an explicit authorized output-set binding, native
  conservation/current-spentness enforcement, a registration transcript that
  does not reveal the targeted map, and an independent fallback. Existing proof
  opcodes alone do not pass those obligations. Do not run a candidate model
  that simply deletes public destination fields or assumes protected service
  registration exists.
- If no construction passes, retain the negative result and stop before the
  conditional complete-lifecycle comparison. Report unsupported redesigns as
  unresolved, not as either proven feasible or consensus-impossible.

The unchanged known-owner/full-drainage and prior-only qualification failures
remain in scope. No historical observer, invariant or threshold is weakened.
