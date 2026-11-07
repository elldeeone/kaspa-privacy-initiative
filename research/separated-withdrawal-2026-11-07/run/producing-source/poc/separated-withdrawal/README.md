# Wallet/service separation and payout-owner attacks

Owner-directed offline test of the existing private payment system. No consensus
changes, new primitives, native proof images, network broadcasts or real funds.
Read the [frozen selection](../../research/separated-withdrawal-2026-11-07/SELECTION.md).

Four wallets and the registration service run as unprivileged containers with
separate PID/network namespaces and writable volumes. Each has its own actual Tor
process. The service never mounts wallet files or public proving parameters. The
observer runs without networking, with only service/public data. Owner truth is
read for scoring after the observer's prediction file has been sealed.

This separates roles on one host. Host root can still inspect everything.
It does not simulate independent people, machines, a global network adversary or
production custody. The direct arm deliberately uses wallet-specific socket
origins as a positive linkage control. Honest and adversarial arms use onions.

The new Rust executable imports the existing wallet actor, RFC9474 client/server,
proof engine, native adapter and economic kernel directly by source path. It
adds small public state/intent utilities and an **adversarial test issuer**.
The issuer tests a different round ID for each genuine claimant, while retaining
one issuer key, public bank, denomination, real blind signatures and real wallet
proofs. This deliberately violates the RFC's common-configuration rule to check
whether current client approval enforces that rule. It changes no fund authority.

`run.py NEW_PRIVATE_RUN` executes the three selected arms. It expects the prior
qualified local TN10-profile public parameters/program path in private
`.local/cached-approval-verification/COMBINED.json` and locally available Docker,
Tor and Rust worker assets. Secrets, Tor state and owner truth remain private.
The Docker image contains only tooling and shared libraries; each run records its
exact image identity. Source epochs are retained when replay-only code is added.
No funded trial is created or submitted.

`host ... replay PUBLIC_VIEW NEW_REPORT` verifies all genuine eligibility proofs,
blind credentials and actual intent sets using public data only. `check` verifies
the complete economic/native-effect input with the unchanged kernel. That is
host execution, not a new outer receipt, native Full validation or chain
acceptance. The existing prior TN10 acceptance result remains separately scoped.

The observer derives source links or configuration tags from real wire fields.
It never receives owner-key truth. Six compatible allocations are a conditional
three-role count, not statistical population anonymity; a timing guess is not an
equality constraint. Published scored counts depend on the retained private
owner-local truth; public replay verifies the protocol and conditional inference,
not a new public cryptographic proof of human identities.
