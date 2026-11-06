# Adversarial second pass

This is a source review of the isolated offline experiment, not a security audit
or production approval. Positive/negative execution belongs in the final run
artifacts; this document states the reasons for the checks and the limits.

- **Inflation / fees:** the old ledger invariant accounts for pending deposits,
  private liabilities and unpaid exits. The adapter checks the actual input,
  bounded integer output sum and fee. Native fees consume only the explicit
  allowance; successor value covers the complete remaining principal. Terminal
  unused allowance returns separately. Count that refund and ordinary funding
  change in cash-flow reconciliation, never as paid fees or useful payments.
- **Repeated spending:** all economic nullifiers, deposit statuses, note tree and
  accepted anchors survive reconciliation. Only paid exit bookkeeping disappears.
  The next root commits the retained NF set. The native current outpoint prevents
  a previously valid entire transition from being applied twice. Test an actual
  old, still cryptographically valid wallet exit against the later NF set, as
  well as replaying native transactions.
- **Unauthorized payout:** the complete native effect set includes the previous
  outpoint/index, input value, output count and every output value/script. Native
  scripts fix all other header fields and prohibit output covenant metadata.
  The outer receipt separately binds the complete public operation payload.
  Every owner checks that its exact key receives its entire note value before
  making a whole-set authorization. Named batches still check every individual
  destination. No registration, executor or admin key has a spend branch.
- **Meaning of positions:** common-set exits do not commit a recipient key per
  NF. The reconciliation loop checks equal amounts and records the whole effect
  context with each authorization. Its position does not certify ownership of
  an output key. It never records an NF-to-output-index association. The named
  comparison intentionally does commit and check that association.
- **Successors:** the native policy reconstructs output zero with the new root
  and the exact current immutable suffix. A guest cannot change its verifier,
  image or spend policy while continuing the bank. Zero new-root is possible
  only after the guest has reconciled all native principal effects.
- **Dependency loss:** proof, credential or SDK failure halts that path. An
  incomplete group cannot be partially applied. Restored owners can use the
  solo branch without issuer/peers, given their keys and required public state,
  parameters and fee allowance. This is not an all-infrastructure-loss recovery
  test. Proving parameters are public data, although this test retains them in
  ignored local storage. Later fee top-ups and arbitrary new deposits are outside
  this finite adapter.
- **Stale state / reorganizations:** native outpoint and committed prior root are
  both bound. Public replay checks the complete linked local history. The source
  UTXO is supplied, not observed on-chain; this does not test accepted DAG history,
  a real reorganization, confirmation policy or relay inclusion.
- **Privacy:** assume the established proof zero knowledge, encryption, SHA256
  and RFC9474 blindness. Only equal denominations and fresh independent payout
  keys are measured. Retain native fee refunds, payloads, all public state and
  public prover inputs. One participant disclosure leaves two assignments;
  all-but-one knowledge, known prior destinations or network/origin disclosure
  removes the benefit. Independent honest people, anonymous transport, malicious
  cohort selection, later co-spending and unequal-balance decomposition remain
  unqualified. Three wallets on one host cannot establish these properties.
- **Costs / reliability:** include eligibility proofs, native deposit and every
  settlement, solo/refund paths, withheld-round work and retry. Preserve backend
  failures; do not count their outputs as valid proofs. Explicitly hypothetical
  prover tariffs do not establish a commercial quote. Local provider charges of
  zero do not establish zero electricity, depreciation, service fees or latency.

The application adapter introduces no consensus or underlying wallet-circuit
change. Its local experimental setup and the reused cryptography remain
unreviewed for production. A favorable bounded ownership/cost comparison cannot
by itself select a better complete architecture than upstream.

Two implementation limits matter for the decision. Whole-effect authorizations
include the exact bank root/outpoint, so another accepted state transition can
make approvals stale even when some participants' notes remain unspent. The
experiment checks refusal, not the cost/frequency of races in an active pool.
Its three claimants exhaust the isolated pool, so it is a quiet, serialized
fixture. The finite adapter also has a prepaid allowance, not a tested top-up
mechanism; permissionless exits are conditional on sufficient fee funding.
Neither issue justifies an admin withdrawal shortcut.

There is an existing implementation optimization to assess before extending
another proving subsystem: `poc/private-note-chain/common/src/lib.rs` already
uses checked-before-pinning immutable wallet parameters. This experiment checks
the authenticated dynamic wallet verification key inside every outer proof.
The cycle stages show substantial fixed preparation work, but no timed pinned-key
variant is included, and no saving is priced as measured. Keeping proof/state
bindings while reusing that established path requires a separately frozen test.
