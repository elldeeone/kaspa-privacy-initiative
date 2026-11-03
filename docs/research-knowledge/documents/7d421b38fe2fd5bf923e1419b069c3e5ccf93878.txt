# Independent constraint-control and setup review

**ACK for fresh development role parameters and role-manifest installation.**
The next gate is cold, full-PK authentication and the exact role-selection READY
boundary before any owner backup read. This review used source and public
reports only; the reviewer did not open a PK, backup or witness, or run setup,
proving, a native VM or network operation. Date: 2026-10-23 UTC.

## Frozen source and actual controls

The B04 source freeze is
`7d32163e89e8ad2dfefeb8ed2d536546ad1fde5743349055b0a9e2887de0096a`.
Its build identity is
`8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a`.
The four relation modules retain the exact hashes recorded in
`RELATION-SOURCE-REVIEW-01.md`. The final runtime delta constructs the selected
local Rayon pool and executes the command inside `pool.install`, before CS
construction. Shape/check use one worker; setup/prove retain fourteen. No
constraint, authentication or private-input ordering check was removed.

`prover/final-controls-04/SUMMARY.json` SHA256:
`715772bef18e275948fbc2cf03e321ee83fee3d27fc930c03f7c15e91341f518`.
The valid compact case is SAT and has the previous finalized matrix. All thirteen
predicted direct-constraint negative cases are UNSAT; the deliberate continuing
next-CM-root mutation is SAT in the private relation and requires native rejection.
Parser/host rejection was not counted as constraint rejection. The latter control
preserves the boundary between private knowledge and the public native transition.

The stronger separate overflow control is also direct-CS UNSAT at the frozen
wide shape. Its 32 individually legal outputs sum to `2^64 + 1,000,000,000`,
while the real input/reserve is `1,000,001,000`, fee `1000`, payout zero and new
reserve `1,000,000,000`. Coherent membership, NFs and output/list/tree hashes
isolate exact private conservation; wrapping u64 arithmetic would accept it.
Public report `prover/overflow-isolation-05/result/report.json` SHA256:
`4e97db4b206bd5fcfb5d9b35be1aa8d62cdf71beae16940b11aaa99bff0179d7`.

Compact terminal/continuing and wide positive SAT evidence is retained in
`prover/shapes-02/SUMMARY.json` SHA256:
`f8fcca64c592d9baf4a04d73f9d4a19b3fc91789f390cb1c28bf5828e0e80a10`.
The earlier wide performance-stop attempt remains incomplete, not an UNSAT or
proving-infeasibility result. B04 compact SAT checking fell from roughly 59.36s
to 1.995s while retaining the identical finalized matrix; this measures a
diagnostic scheduling improvement, not a payment/proving or fee result.

## Fresh setup metadata

| Field | compact2 | wide32 |
| --- | --- | --- |
| Constraints | 3,284,767 | 7,448,842 |
| Witness variables | 3,248,304 | 7,361,092 |
| Instances including one | 3 | 3 |
| FFT domain | 4,194,304 | 8,388,608 |
| Matrix SHA256 | `98c92c77b48028768456068b950ea65c019bf72931cab1b6174b9545fad6514a` | `be86280d0ad0ede51e9fea23b3962765543e4a30c85d8e6a1d63b877d6aee9be` |
| PK bytes | 1,307,894,256 | 2,892,421,872 |
| PK SHA256 reported by setup | `c8d72c6eae9d03ce22e350bb9d0c616fc8e1d2a8b4f2b0d748cc0336726b11a4` | `05639b54302e9f568dbdbfb68bc7e6c5760bea5d96ffe09d087b1f836447f83d` |
| VK SHA256 | `bf033abd75237c3f04f4b8ca19ef93c115b192d04eb8360b8d5060ccdb9bed78` | `a1be8ead145bd5fa65702f7eb3d2246dea307138f2915e5847a03813d70373fb` |
| Setup report SHA256 | `d63ea7ffee84810a63f9ec45f643a8981a858ce73fa8efd8cda62f996acadc35` | `0153d7e2320fd8255178b2d7c860e475878261fada1e04b483ec599579de24bd` |

Both reports bind the same frozen source/build identity, D, testnet genesis,
trial, correct role/arity and official arkworks uncompressed serialization.
Every a/b query count is witness plus instances, l is witness and h is FFT minus
one. Actual setup pool is fourteen. Setup metadata records OsRng, fsynced
serialization/readback and exited workers. Cleanup observations report no
resident operator. The two-role summary SHA256 is
`7f907df02d4616dbb0a5a276071380df2d04860ac99c5655e27d5057edce2f27`.

The later canonical role manifests were independently hashed and compared to
both reports. `prover/parameters-compact2-01/public-parameters.json` SHA256 is
`f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043`;
the wide32 counterpart is
`b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149`.
They preserve all fields above and exact source freeze/setup-report/executable
provenance, so installing those two role pins and rebuilding the selected owner
ELF is ACKed. Pin installation must leave the frozen relation/build identity
unchanged; selected binary hashes are measured separately.

Reported PK hashes have not been recomputed by this reviewer from their bytes.
The independently selected runtime must authenticate them in full, then check
owned decoding, exhaustion, canonical VK and all query dimensions. Unselected
before-witness controls are useful fail-closed evidence, but do not substitute
for selected, actual cold role-PK reloads and READY-before-backup controls.

## Eight-risk second pass and remaining boundaries

Exact bounded conservation and isolated overflow rejection address tested
inflation paths. Shared real NFs across roles plus native absence/update and
competing-spend checks remain necessary for double spends. Native context,
fee/SPK/code and tree transitions remain necessary for reserve release; private
SAT alone does not authorize them. Public mode, timing, fee and amount linkage
still require the separately frozen privacy measurement. Role availability and
public recovery must survive loss of the original source/cache; a hash alone
does not provide availability. Fresh accepted node context/UTXO evidence is
still needed for stale/reorg safety. Fresh single-party development setup and
selected software/host remain explicit trust assumptions, not an audited or
distributed ceremony. Every recipient must independently decrypt/rederive its
own receipt/CM/NF and demonstrate spending; correct ciphertext hashes alone do
not establish delivery. Full-capacity permissionless exits remain open.

No owner proof, native financial acceptance, funded testnet lifecycle, confirmed
payout, privacy qualification, production safety or cryptographic correctness
is established by this parameter/control ACK.
