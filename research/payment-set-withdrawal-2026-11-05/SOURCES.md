# Reuse and source checkpoint for actual-wallet integration

The [current-L1 primary review](../common-set-withdrawal-2026-11-05/SOURCES.md)
and [mature-protocol review](../native-kas-shielded-value-sources-2026-11-03.md)
are the same-day source checkpoint. Reuse RFC9474 registration; established
SHA256/HMAC, Groth16 and encrypted recipient discovery. Orchard/RAILGUN effects
binding and conservation remain useful; their native/EVM formats are excluded.
Aztec's separate network metadata obligations remain. Monero/MWEB confidential
native outputs and all consensus changes are excluded. No new crypto primitive.

Actual code reused unchanged: `poc/private-note-wallet/src/{protocol,circuit,
wallet,ledger}.rs`, local depth-four profile. This is the system behind the
[executed lifecycle](../full-drainage-executed-lifecycle-2026-11-01/RESULT.md), not
the separate consensus-native Orchard research or the paused MPC prototype.
The new isolated circuit copies the full old relation and changes only public
packing to a canonical statement SHA256 digest. The transformation is executable
and checked against the original source. Both old/new genuine proofs and kernels
are exercised. New VK binding prevents old proofs being accepted as new ones.

The original native destination is `SHA256(0x00 || x-only-key)`, as defined by
`poc/private-note-chain/common/src/lib.rs::destination` and used by
`research/full-drainage-executed-lifecycle-2026-11-01/run.py`. The matched direct
control must prove that actual commitment, not raw key bytes. Its observer
reconstructs the commitment for every actual output. The old native operation
parser requires this destination binding, so it cannot accept the common-set
digest unchanged. This diagnostic replaces that finite withdrawal boundary;
it does not upgrade the original outer guest or claim a drop-in native adapter.

Native policy and registration reuse the finite common-set experiment. Their
exact adaptation and all source/dependency hashes are frozen per run. Native
Groth16 can verify the serialized Arkworks 0.5 proof; actual engine execution
must establish compatibility with its pinned 0.6 verifier, not a host assertion.

Pinned Kaspa: `4863866fce8439d0305b410fc4d802e7261d54d0`.
Native Groth16 charges base 14,000,000 script units plus 250,000 per VK gamma-ABC
element (public-input count plus one), before script overhead. The current
source paths are `crypto/txscript/src/zk_precompiles/{tags.rs,groth16/mod.rs}`
and `consensus/core/src/{mass/mod.rs,config/params.rs}`. Public outputs remain
ordinary values/scripts. Mass units, component block limits and actual fees
are distinct. The 100 sompi/mass price is the historical comparison, not a
prediction of current inclusion. Read actual locked source constants in checks.

A finite supplied native predecessor authenticates no accepted deposit/history.
The real wallet kernel is executed locally; no new complete outer state-transition
receipt or production consensus path is claimed. Fee-floor failure alone is
enough to reject cheapness for the frozen route, without building that larger
settlement system or changing privacy requirements.
