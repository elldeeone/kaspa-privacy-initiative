# Independent one-shot consensus-helper source review

Reviewed standalone `research/poc/public-state-consensus-check/src/main.rs`
SHA256 `6c33f1b270770b2b8e925be6c4e236bf10cc199c9e301210277f3a5d19ab6414`
against official native pin `01b532e8b553523216471682649693af92f0fd16`.
No reviewer build, native execution or proving. No source blocker found within
the exact NONFUNDABLE one-shot scope.

The helper depends directly on pinned Kaspa consensus/core/txscript, not an SDK,
prover or shared-pool implementation. Its lock contains no risc0-zkvm/build or
shared-pool crate. Thirteen helper/upstream identities are retained in
`state-consensus-source-identities.json`.

## Trusted input and body preservation

Exact sizes and independently fixed SHA256 values for body2910, prior redeem1383
and J336 are checked before generic Borsh decoding. Consequently untrusted vector
length prefixes cannot reach decoding. `borsh::from_slice` consumes the complete
body; reserialization must match every original byte. Cached V1 ID and actual
full hash are checked against fixed identities, and finalizing a clone must not
change the decoded transaction. The original positive transaction is not rebuilt,
resigned, assigned a new storage commitment or otherwise changed. Only separately
labelled negative clones are mutated/finalized.

Declared UTXO amount/SPK are derived from exact J and the pinned prior redeem;
the exact outpoint, canonical witness tail, one input/output, output amount and
budget1600 are checked. The helper deliberately supplies UTXO DAA0/noncoinbase,
POV DAA1,000,000,000 and block DAA2,000,000,000,000. These are synthetic inputs,
not database evidence that the outpoint exists, is unspent or was accepted.

## Native checks and negative stages

The validator uses the real constructor with TESTNET_PARAMS and real mass/sigop
parameters, not `new_for_tests`. It explicitly invokes isolation, followed by
`validate_populated_transaction_and_get_fee(..., TxValidationFlags::Full, None,
None)`. The latter checks maturity, input/output values, storage commitment,
sequence, covenant context and scripts with the input's actual committed budget.
The positive requires the exact80M fee. Actual stage plus typed TxRuleError must
equal the source-constructed expectation; arbitrary I/O, process or resource
errors cannot count as a semantic rejection.

All ten negative expectations match the pinned ordering:

- Four isolation failures: missing/duplicate input and zero/over-MAX output.
- Six Full failures: outputs exceed input, over-MAX input, wrong storage mass,
  changed P reaching native pairing failure, immature coinbase and unmet sequence.

Wrong storage mass specifically detects SkipMassCheck substitution; changed P
specifically detects SkipScriptChecks substitution. Maturity and sequence errors
are correctly expected before script execution. Full API entry is not a claim
that every later check ran after an earlier failure.

Header/finality validation is a separate private upstream API and is explicitly
not invoked. The unchanged baseline lock_time0 is trivially finalized; the
helper does not qualify arbitrary header/HF contexts. Missing UTXO lookup,
selected-chain state, conflict/RBF and block insertion remain untested.

## Policy boundary

The four policy cases are explicitly source-adapted predicates, not calls to
crate-private Mempool admission. Output/input script classes, P2SH sigop ceiling15,
and integer relay-floor rounding match the pinned mining source. Relay fee uses
normalized noncontextual compute/transient mass, excluding storage. The block
dimension comparison is separately identified; Full's storage-commitment check
does not itself enforce all block dimensions.

Default source-adapted policy, max-budget dimension failure, nonstandard output
and fixed80M fee failure at500sompi/gram have the expected distinct meanings.
No mempool capacity/conflict/RBF, P2P relay or actual chain acceptance follows.

## Independent stdlib byte/arithmetic check

`state_native_body_recount.py` independently decodes the entire fixed Borsh body,
consumes exactly2910bytes and reconstructs the native full-hash serialization:
`056636101fadbf4eb400104e59031fec9499615028713a85c5f3ae078d6af2ed`.
The cached ID matches its pin; Python does not independently recompute BLAKE3 V1
ID, which the helper's finalized-clone check separately covers.

The native proof/redeem bytes are preserved. Independently reconstructed output
P2SH matches BLAKE2b256(successor redeem); old/new1383-byte redeems differ only in
state105. The same immutable suffix retains the literal old-outpoint guard, so
the successor is intentionally noncontinuing.

Independent size/mass arithmetic gives estimator2920 (not Borsh/P2P wire size),
compute163290, transient11680, storage29 and fee80M. Default100/gram relay floor
is16,329,000;500/gram requires81,645,000, preserving the1,645,000 deficit. Results
are retained in `state-native-body-independent-recount.json`.

Even an eventual Full pass strengthens only validation of this exact supplied
one-shot context. It does not establish initial backing, accepted lineage,
continuing pool policy, owner exits, durable parameters, privacy or readiness to
fund. Continuing S7 lifecycle work remains a separate source/design decision.
