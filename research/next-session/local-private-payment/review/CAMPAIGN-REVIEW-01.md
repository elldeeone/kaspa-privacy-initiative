# Matched21 campaign caller review

2026-10-25 UTC. Source reviewed at
`70ee8827f9eac31a05d58a74b8bf789776f642f55f9dd47b5d205e0c0b79d8b4`.
No actual private plan, original backup, invoice, witness or worker log was read
or hashed by reviewer. No campaign, funding or network operation was executed.

Source GO: no confirmed financial authorization blocker found. The actual cold
receipt, artifact inventory and final campaign selection still need to match
the frozen producer output before an execution release.

- The private plan fixes six useful payments totalling 2,100,000,000 sompi and
  nine exits. Per-round owner order, recipient-cycle direction and exit order
  use `SystemRandom`; the plan and its hash are not public exports. The caller
  validates the exact amounts, one owner/recipient per round, selection policy
  and three exits per original.
- All six recipient-produced private invoices are prepared before the first
  payment. A later payment requires only its payer's seed and already
  authenticated invoice. The caller passes the exact read-only invoice leaf
  through private IPC and never reads/hashes its bytes. The trusted local IPC
  binding is the stated authentication channel, rather than encryption itself.
- Owner namespaces receive finite authenticated public source/parameter leaves,
  one original backup leaf, one private request and at most one invoice leaf.
  Seed restoration and received/change classification use public history;
  convenience labels are reconstructed from owned historical NFs, not a role
  index convention or private recovery journal. Exact native fee checks and
  private owner fee caps precede Spend/Exit proofs.
- Cold owner/proof and native-case construction use downloaded source/parameters.
  The final native namespace permits exactly seven downloaded verifier/engine
  leaves and no proving key, outer prover, live owner or MPC service. Source
  review identified an unbound download-receipt flag; the author now validates
  receipt schema, actual archive/selected Exit-PK artifacts, exact unpacked
  inventory and membership of every cold mount.
- Caller state is durably marked consumed before invoking the separately
  once-only submitter. Unknown or interrupted submission resumes confirmation
  only. Complete accepted-CASE equality, exact current head, Full and payout
  checks remain in the chain layer. Public progress contains ordinal/txid only.
- Completion requires fifteen confirmed actions, zero terminal reserve and a
  final downloaded-software scan of each original. Ordinary preparation fees
  and confirmed-history fees are added once; change is not useful demand and
  the old fee/privacy verdicts remain unchanged.

`CAMPAIGN-TOY-CONTROLS-01.json` records five independently rerun public controls.
The separate known-public owner API result reports genuine Spend plus two
Output proofs through original-seed restoration/private invoice IPC, while
explicitly withholding outer/native/chain claims. These checks do not constitute
an actual campaign, actual cold download execution, independent administration,
off-host recovery or confirmed payouts.
