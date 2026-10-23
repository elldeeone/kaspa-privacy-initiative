# ADR-0054: Ordinary execution from trusted read-only releases

**Status:** Accepted execution-only amendment to ADR-0053.
**Date:** 2026-10-23 UTC.

## Reason

The initial execution design used authenticated sealed executable snapshots.
Host namespace restrictions complicated that path, and automated screening
stopped a parallel worker while it prepared execution checks. No new trial
funding or private-cashout broadcast had occurred. Do not work around that
screening or change host security policy.

The research already trusts the host OS, installed runtime and protection of
owner backups. Select the simpler ordinary executable workflow under that same
explicit host-trust boundary.

## Decision

Supersede only ADR-0053/common-contract executable-launch requirements. Use
ordinary reviewed executables copied to dedicated private release directories.
Set directory permissions0700 and selected executable permissions0500. Verify
the complete file SHA256 against trusted software selection before each launch.
Mount releases read-only into owner/network sandboxes, use a fixed clean
environment and invoke the selected normal executable path. An RPC response,
descriptor or parameter manifest must never choose the executable or arguments.

Trust the host and release owner not to mutate, replace or change permissions on
selected release files during operations. This does not defend against a
malicious host/inode writer; neither does the backup/seed threat model. Keep
that limitation explicit instead of claiming race-proof content immutability.
Do not use special executable-FD/system-loader launch paths or change any system
security setting for this experiment.

All protocol and confidentiality boundaries remain: authenticate descriptor,
manifest, public parameters and software before backup access; the local prover
signals parameter readiness before reading the private witness pipe; fixed
errors and public output allowlists exclude private material. Value conservation,
current roots/nullifiers, exact native body/context/fee binding, native Full and
durable once-only transport checks are unchanged.

Earlier source snapshots, public runtime controls and failed/unexecuted launch
attempts remain historical evidence. New active runtime/selection/control freezes
must identify this amendment. The already created unfunded domain and source
relation are unchanged; no old funded instance or closed packet is modified.
