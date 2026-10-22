# Independent retained compressed-receipt verification

Verified the saved 581-byte Groth16 receipt without running a guest, building or
proving. Receipt SHA256
`7ace0642e77fadacf9bc704e7500a97f2c8ea6a0b81a043ae5049eefbd1b97ff`;
unmodified source Succinct receipt SHA256
`51a2f69e9986179696141ef106401109a3c7bf58fe87c8b0a645e29c49c4a3ec`.

Reviewed the additive verification-only CLI source and invoked the existing
`proof-target/release/verify_compressed`, SHA256
`f77d63678f0025c9007c96ec9e884a5c731ae128d6a2b764b99d064e12dc60f3`,
against our own new output directory. It contains no prover API. RISC0_DEV_MODE
was absent, dev mode explicitly false in SDK context, thread environment2,
address-space limit2GiB. Exit0, elapsed about0.029s. Retained ten exact
executable/source/pin/artifact identities before/after, all unchanged.

The actual SDK verifies the Groth16 receipt under selected image
`50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832`,
with exact J42/public P consistency and no unresolved assumptions. Claim digest
is the pinned source claim
`7e5bed968ae55ede2c88edb1021b5bb718d8785061d8df761050badd2210b2e3`.
Output P1088/J42 hashes match the independent byte oracle. Real SDK calls reject
wrong image, changed journal bytes at offsets0/8/10/41 and corrupted seal; the
application boundary also rejects a fake receipt variant. These are seven
negative cases, with the fake case explicitly a type/profile rejection rather
than a claimed native or pairing-level failure.

Separately inspected the researcher's retained actual-native0x20 report: all
eight cases match expected exact native errors, including four validly encoded
pairing failures and three canonical-framing failures. Source reviewed earlier;
I did not rerun that native harness. Its fixed five public inputs contain the
same claim digest, with the expected official control-root and BN254 identity;
VK424/proof128 are the outer wrapper, not the inner v6 VK328.

Independent live cleanup check at13:18:51UTC confirmed compression unit inactive/
dead, MainPID0, result success/status0, empty ControlGroup. All four recorded
PID/start-time identities were absent. No GPU compute process; instantaneous
global snapshot1MiB/0%. Producer monitor recorded sampled matching GPU peak
5332MiB, cgroup memory peak1,783,631,872bytes and success in5.06s (samples may miss
brief peaks). No reviewer process termination occurred.

Evidence is in `compressed-receipt-independent-01/` and its adjacent log.
This verifies a compressed public development pair statement. It does not
establish authenticated state/backing, current spentness, covenant/transaction
acceptance, owner exits, old-instance compatibility, privacy or production
safety. The official Groth16 wrapper adds its established setup trust.
