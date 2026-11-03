# Generic owner REVEAL helper, selected version 2

**12/12 frozen methods pass**, including an authorized native Full fallback
exit under the new private-balance union. Version1 and its immutable executable,
source snapshot, test freeze and results remain unchanged.

Version2 adds exactly one source-approved whole-program template: the new
24,417-byte unified private-balance program, alongside the original22,388-byte
program. One shared official opcode parser permits only the exact State112
prefix, ten literal domain operands and one VK328 operand to vary. Every other
opcode/data byte must match the independently reviewed source-derived template.
The selected template's source hash is reported correctly. Quote/sign/value/
consent/ALL/current-SPK and native Full behavior is otherwise unchanged.

The new-program positive uses a coherent **unfunded public synthetic** singleton,
60M reserve, 10M fee and 50M payout. Its seed/native signing key is deliberately
public DO_NOT_FUND data. Its unused private VK is deliberately invalid zero328;
the Groth16 branch is not executed by this revealing test. It demonstrates the
approved emergency branch's public checks and genuine native signature/Full,
not a private proof, accepted backing, chain payout or independent recovery.
The other controls include a public historical quote under the real fresh
42fab9-domain accepted body without reading any fresh signing secret.

Selected immutable local-only executable:
`/home/luke/projects/kpi-intensive-2026-10-22/recovery-native-target/selected-02/kpi-independent-recovery-native`

SHA256 `a43d07bbff53aba74be6ac966ead53fb72670b22aa19e974e51e61f986512280`.
Only independently selected/pinned software may receive the wallet's owner key.
No caller-selected expected executable digest is authority.

The compiled Rust/TOML/lock bytes are exact [source04](recovery-helper-source-04/SOURCE-FREEZE.json).
An external Python test addendum adds the separately frozen new-program
authorized-sign case after compilation; it does not change the executable.
[Pre-run freeze](recovery-helper-tests-02/PRE-RUN-FREEZE.json) binds15 inputs,
software and source/test identities. All remain unchanged after the run.
[Raw tests](recovery-helper-tests-02/tests.log) report12/12 in0.098s;
[result](recovery-helper-tests-02/RESULTS.json) and
[cleanup](recovery-helper-tests-02/CLEANUP.json) record the successful stopped
unit, PID0 and empty cgroup. The accepted launch requested2CPU/2GiB/swap0/network isolation and
readonly public repository/software mounts. No fresh live trial key, PK,
prover, network interface or broadcaster was available. This subsecond unit was
collected before active cgroup properties were sampled; its later infinity
limit properties are unloaded-unit defaults, not measurements. The executed command
and resources are retained; a separate prospective runtime-script digest was
not created and is not claimed.

This is software/component conformance under supplied contexts. It does not
replace the independent fetch/replay/current-head/old-backup integration or
authorize automatic privacy-degrading fallback.
