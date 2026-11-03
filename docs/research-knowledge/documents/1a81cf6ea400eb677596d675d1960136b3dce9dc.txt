**The new native private action passed its offline lifecycle and ordinary
negative controls.** Four genuine positive actions were accepted in the
separate lifecycle packet: private transfer, partial private cashout, remaining
owner cashout and terminal reserve consumption. Their exact body/context/proof
bytes match this packet's four bases; their existing Full and every-input
ScriptEngine reports were reused without repeating those native runs.

The one additional native run executed **76 negative cases; all 76 matched**:

- 68 failed before the Groth16 charge, covering actual outpoint/reserve binding,
  context/frame constraints, exact output amounts/topology, complete native
  destination script, immutable successor code/VK/domain, covenant metadata,
  both sequential nullifier witnesses, capacity bounds and terminal zero fields.
- Seven native-consistent original-proof replays reached Groth16 and failed
  with exact integrity errors in both Full and the input engine. They changed
  the destination, payout, fee, outpoint, ciphertext or unsigned amount encoding.
- A separate zero128 malformed proof reached the precompile and failed with
  the typed ARK serialization error.

The two negative-zero cases preserve a material boundary: the native script's
sign-magnitude decoder can read u64 `0x8000000000000000` as zero. The circuit
interprets authorization amounts as unsigned integers. Both altered statements
failed their original genuine proof, as required. This is not a claim that the
native decoder independently enforces the circuit's unsigned semantics.

The run took 0.42 seconds under the selected binary in a network-isolated
namespace, with public source and executable mounted read-only and no proving
key or prover mount. An active cgroup sample confirmed two CPU cores, 2 GiB
memory and zero swap allowance. The owned unit is inactive, its captured PID
has exited and its cgroup is gone. No workload was repeated after success.

Evidence:

- [Selected source02](private-native-source-02/SOURCE-FREEZE.json), union
  24,417 bytes, Auth528, payload4400, existing private budget1600.
- [Control source02](private-controls-source-02/SOURCE-FREEZE.json).
- [Exact reviewed run freeze](private-controls-preparation-01/PRE-RUN-FREEZE-02.json),
  SHA256 `092cfa8a07a49738dfbac15efb6df7d51fbe5ee4bae8c9ae7e4bee06b19e6688`.
- [Four positive report reuses](private-controls-preparation-01/BASELINE-REUSE.json).
- [76-case typed outcomes](private-controls-execution-02/cases/RESULTS.json),
  [artifact closure](private-controls-execution-02/RESULTS.json) and
  [owned-unit cleanup](private-controls-execution-02/CLEANUP.json).
- [Generic emergency REVEAL helper](RECOVERY-HELPER-RESULTS-02.md): 12/12
  component methods, including authorized signing and Full under the new
  source-approved program, without a proving key.
- [Actual quoted fees](PRIVATE-FEES-01.md). The unchanged 2% complete lifecycle
  target at 10 KAS still fails.

The original 80-case prospective packet remains preserved. Its four positive
cases were removed only from the new execution list after their bytes and
already accepted reports matched. Genuine current-root occupied-nullifier
private/REVEAL competing spends are owned by the separate lifecycle packet;
ordinary path-corruption cases here do not substitute for those races.

Measured private-engine usage ranges from 14,846,698 to 14,961,272 script units
under the unchanged 16,009,999 allowance. A future budget reduction requires a
source-derived worst-case bound before selection. No budget, matrices, proof,
authorization or fee was changed to improve this result, and such a reduction
would not remove the retained verifier-floor economic failure.

This is finite supplied-context implementation evidence. It establishes no
accepted chain backing, testnet confirmation, privacy qualification,
cryptographic correctness proof, security audit or production readiness.
