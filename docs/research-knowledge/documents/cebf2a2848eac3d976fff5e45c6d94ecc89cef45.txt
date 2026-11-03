# Funding source second pass — 2026-10-28

Self-review of the new GEN3/funding/activation sources. This is not an
independent execution review or permission to start mining. No actual private
funding signature, node query, funding or broadcast was executed.

The original legacy sign/fund workers cannot parse this backup or derive this
wallet. The new worker calls only the strict new-version backup loader and
`wallet_profile.Receiver`; it reuses generic SDK/native tools for transaction
serialization, quotes and signatures. The consolidation SDK is deliberately
different from GEN3's three-ordinary-input SDK. That concrete source mismatch
was found during review and corrected before execution.

- **Inflation and unauthorized reserve release:** each initial Output must prove
  the same public `Commit(20KAS,0)` liability; three distinct CMs imply exactly
  sixty KAS. The public CASE parser checks every owner's contribution, change
  and fee allocation. The isolated owner then reopens its own exact note, checks
  its designated funding key and signs the whole CASE with ALL. Actual
  NativeFull is rerun after combining all signatures. A shape/report Boolean
  never replaces those signature/native checks.
- **Double spends and replays:** input points/keys are distinct; actual node
  confirmation compares the entire accepted CASE and current output. Durable
  one-use network submission intents precede an RPC write. Uncertain writes
  are queried, never automatically resubmitted. The private service's persistent
  admission history remains a separate live-prover prerequisite; funding code
  cannot reset or resolve it.
- **Privacy:** no Original, native secret, honest truth or MPC share is mounted
  in the public network namespace. Each signer sees one Original. Public
  signatures/funding keys/deposit amounts are intentionally transparent; this
  source supplies no funding anonymity claim. Fixed route metadata and the
  legitimate colluder's incoming knowledge remain in the frozen observer view.
- **Dependency failure:** missing SDK/native/proof/source pins or failed
  verification refuses before publication. Independent wallet scans/Exits do
  not require the owner-auxiliary generator, Output PK or a live MPC service.
  They still require their public recovery data and selected verification/
  proving software. The network wrapper mounts only admitted public wheels,
  Node/SDK and certificates.
- **Reorg/stale state:** a supplied-context native rehearsal is not accepted
  history or currentness. Activation requires fresh Full-prefix exact-CASE
  acquisition plus a fresh current-output read. Subsequent R1/R2/Exits require
  their own current head and fresh owner authorization; GEN3 activation alone
  cannot authorize them or clear the private-history lock.
- **Hidden trust:** selected source/binaries and the local routing/namespace
  controller are trusted; this is no hostile-host guarantee. Node acquisition
  retains its explicit node/Tor/currentness assumptions. Single-party trusted
  setup and new cryptographic composition remain research assumptions. Passing
  parser/namespace/native tests does not establish cryptographic correctness.

Current evidence: eleven wallet-boundary controls, eight GEN3 public CASE
controls, four new funding-observation controls, three projection/witness
controls against retained genuine public Exit CASEs, and independent actual
public Output/CV controls. The public network child separately runs mocked
boundary and actual network-off import probes. Actual complete funding,
accepted wallet history, private payment lifecycle and terminal testnet payout
qualification remain pending. Do not promote these source checks into readiness.
