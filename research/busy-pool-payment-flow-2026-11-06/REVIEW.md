# Adversarial second pass

Scope: the new scheduling/actor harness against the unchanged ADR-0111 program,
full wallet relation and native adapter. This is a source/experiment review, not
an independent audit or a cryptographic correctness claim.

- **Inflation/reserve release:** the queue cannot authorize any native spend.
  Every accepted step runs the complete wallet/guest/native checks. All amounts
  use integer sompi and checked reserve/fee subtraction. Both histories must
  drain exactly 40 KAS of principal, keep fees in the separate allowance, and end
  at zero principal/liability. Funding is an explicitly supplied synthetic UTXO.
- **Double spends/current state:** a pending child cannot become settled state
  before its parent. The parent native outpoint must be current. Historical
  membership never overrides current economic nullifiers. Duplicate pending
  spends and already-spent cohort claims are rejected at their intended guards.
- **Stale receipts:** a genuine other transaction advances the bank while the
  original proof is running. Reusing that transaction fails current-outpoint
  admission; installing its proof on the new transition must fail the actual
  native ZK verifier. Neither an old valid receipt nor a queue ticket is authority
  for a different current transition.
- **Consent:** the cohort approves once. A retry uses identical proof bytes and
  the same complete intent; receiver, pool/root, cohort, fee-cap and spent-claim
  mutations retain explicit refusal checks. The actual current outer receipt is
  always new. Released conditional consent still permits delayed execution;
  deleting a local request does not revoke it. ADR-0111's timing limitation stays.
- **Privacy:** local wallet requests in this experiment are identified. Preserve
  their actual transcripts and report the ownership link. The earlier anonymous
  registration result remains separate. One host/process controller is not an
  independent-user privacy trial. Known contact roles plus known-owner public
  cashouts can expose earlier amounts even when a separate registration test
  retains multiple fresh-address assignments.
- **Operator loss:** the queue schedules this cooperating service only. It
  installs no administrator lock, consensus reservation or privileged exit key.
  Losing the coordinator/process may delay work and require resubmission; it
  cannot weaken the bank predicate. No durable production queue or complete
  all-service-loss recovery qualification is claimed. Independent contenders
  can still force repeated reproving.
- **Recovery:** each wallet stores only its own seed/view key/native keys in its
  own private directory. Actor processes are restarted before payout-spend
  controls. Replay must connect every signed spend to a real output of the main
  local history and reject duplicated supplied payout entries. The public
  parameters, encrypted history and software remain necessary dependencies.
- **Reorgs:** the experiment covers a locally accepted competing bank transition,
  not live chain reorganization. Projected/queued state is never called chain
  accepted. A live implementation still needs authenticated chain state/undo.
- **Evidence:** copy the executable before self-spawning; preserve failed
  preflights. Freeze executed source/image before proving. Authenticate exact
  input, image, complete journal and actual native effects during public replay.
  Publish a finite reviewed selection; scan it against excluded private key
  material. The receipt/manifest cannot independently authenticate itself.

The unchanged depth-four/16-leaf profile bounds the workload. One competing
update and three incoming payments cannot establish unbounded throughput,
independent users, complete financial privacy or commercial affordability.
