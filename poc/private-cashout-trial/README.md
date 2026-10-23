# Fresh Auth528 private-cashout trial

Source package for ADR0053 with the ordinary trusted-release execution amendment
in ADR0054. A fresh unfunded identity and private setup shape have been created;
their exact original sources and public-only controls are archived separately.
Actual four-body preparation, proofs/Full validation and funding remain gated
by their own source/fixture checks.

The selected route is direct whole Alice founding → private Bob60M/Charlie60M
claims → Bob's independent private full cashout → Charlie's terminal private
cashout. Actual complete-body fee fixed points decide every amount. No funding
prep/admission action is required for this research question.
The actual two-recipient slot order is selected once with OS randomness and
retained only in the private action recipe. Each owner locates its claim through
recipient recognition; no public role-to-position map is an input or export.

The controller will have no RPC or broadcast interface. Root owns the ordinary
funding merge and publication. Complete local terminal rehearsal precedes funding;
only founding/P0 are operator publication inputs. Each cold client must fetch
again and build/prove its own new exit without operator precomputed exit mounts.

See the [prospective design](../../research/next-session/private-service-loss/trial/DESIGN.md)
for source/parameter matching, exact-source planning, shutdown and cold boundaries.
Runtime binaries use SHA-checked0500 copies in private0700 release directories,
ordinary execution, a clean environment and read-only sandbox mounts. Trusted
host/release immutability is an explicit assumption; hostile inode writers are
outside this trial's threat model.
