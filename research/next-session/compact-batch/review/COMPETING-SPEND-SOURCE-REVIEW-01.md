# Additive same-note competing-spend source review

**Source ACK for root-released PUBLIC proof/native controls; actual results are
still separate.** Reviewed2026-10-23 UTC. The closed main17 files, Rust circuits,
parameter pins and previous publication artifacts remain unchanged. Only
`poc/compact-batch-lifecycle/competition.py` is added, SHA256
`f7ad57cf3289c1fdae388566e1c52322f168e22a9b6289242228e46a49915ba2`.
The main reviewer and a fresh independent reviewer read source/public helpers;
the relation peer confirmed the scoped private-SAT/native-NF boundary. None used
PKs, main histories/backups/witnesses, runtime jobs or network operations.

The anchor authenticates the exact previously selected public wide Native Full
case/report and its payload against the deterministic public construction. Both
real inputs are existing physical positions32/33, each1B, with native public key
corresponding to the explicitly public signing scalar1. The shared original
HMAC real NFs are independent of role. Compact and wide alternatives consume the
same two real NFs and produce the same resulting NF root, with different valid
CM updates. Reserve32B, sumIn2B, fee1000 and all outputs at least60M exclude
reserve/floor confounds. This exercises two-real-input relation support; it is
not hidden aggregation of actual owners' witnesses or another32-human payment.

The authorized REVEAL alternative uses the same original note0/NF0, current
physical CM path, scalar1 SIGHASH_ALL and exact current context/output programs.
Its successful branch would leave reserve31B and unchanged CM membership.
After either private winner, signed REVEAL duplicate controls recompute current
CM paths and authenticate an occupied current NF predecessor. Its value equals
the requested real NF, so the retained native strict pv<NF guard must reject.

The raw negative builder is isolated in this new public file. It explicitly
constructs a counterfactual duplicate NF row list, verifies the predecessor path
against the actual current root and computes its claimed next tree, while never
passing the invalid duplicate rows through Snapshot.verify/replay. The production
insert API remains unchanged and selftest requires it to reject an occupied NF.
This is construction of a negative native witness, not acceptance of bad state.

The third fresh compact statement is built after the successful public REVEAL,
with its actual outpoint/current state, correct unchanged input CM membership,
sumIn2B, reserve31B, n64→66 and m4→6. The private relation does not own NF absence,
so it should be SAT and obtain a genuine new selected proof. The native layer
must reject its authenticated occupied predecessor equality before the G16
charge. This is stronger than reusing an old proof against a changed statement.
Two additional old-proof/Auth rebases are explicitly labelled stale Auth only;
they must not be counted as isolated duplicate-NF or fresh-proof evidence.

Planned execution is two genuine role proofs/seven Native calls, then the fresh
current-state compact proof/one Native finish. Reports must retain actual counts,
selected role/statement proof identities and pre-G16 units for the final guard.
Fee1000 is intentionally below reference-rate100 relay fees. These are synthetic
interoperability/guard controls, not an accepted-chain race, actual testnet
backing/currentness, economic fee result, privacy or live readiness.

New source/results require a separate finite additive publication selection;
they do not alter the prior89-path lifecycle or295-path prover publication ACKs.
