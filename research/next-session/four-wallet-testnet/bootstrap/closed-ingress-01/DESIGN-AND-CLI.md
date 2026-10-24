# Additive closed GN2 entry launchers

The original frozen `run_signer.py` obtains `owner-init.json` from an original private owner directory. A launcher that excludes all eight original owner directories cannot use that host ingress. The original public `entry_cli.py` also defaults to a fixed host SDK cache. These new launchers close those two ingress paths without changing a frozen financial validator, worker, transaction format or fee rule.

`poc/four-wallet-bootstrap/run_closed_signer.py` is a trusted stdlib-only host launcher. It inventories both original four-owner trial trees using metadata only. All eight files must be distinct regular, single-link files with mode0600, outside Git and outside mounted system trees. Every selected source/runtime/SDK/public input is checked against all eight original inode identities and complete owner directories before the first selected public byte is read. Each read checks the opened descriptor before its first byte and verifies stable metadata plus its expected public SHA256.

Only public source, ELF, SDK, profile, proposal and constructor-export bytes are copied. The source closure reuses exactly the eleven already frozen bootstrap/reference members; the executables and SDK files retain their original exact pins. The original backup is never opened, copied or hashed by the host. A single bwrap namespace mounts that one original file read-only at `/owner/backup.json` and the copied, externally pinned constructor public export with mode0400 at `/owner/owner-init.json`. No original owner directory is mounted. The unchanged `gn2_owner.py sign-entry` repeats exact profile, trial, body, quote, own-note/CF and original receipt/key rederivation before its ordinary input ALL signature.

`poc/four-wallet-bootstrap/run_closed_entry.py` reuses the new launcher's host staging helpers and adds the frozen `entry_cli.py` preimage. It has zero backup mounts. Its `prepare` and `combine` operations provide only pinned staged SDK files at both `/runtime/sdk` and the historical fixed SDK pathname expected by the frozen Runtime. Neither the host home directory nor the mutable host SDK cache is mounted. All financial and native checks remain in the unchanged entry worker.

Both scripts default to staging only. `--execute` is required to launch their namespaces. The current evidence is source-only: no bwrap, SDK, signer, Native, prover, private backup read, network call or transaction submission was executed. A prepared plan does not establish financial validity, successful execution, chain acceptance or trial readiness. This retains the existing trusted-host assumption; it does not resist a malicious host changing mount sources at launch.

## Exact CLI

All paths below are externally selected. `SOFTWARE` has `runtime-source/<repo-relative-path>`, `runtime/{crypto,node,native-validator}` and `runtime-sdk/{kaspa.js,kaspa_bg.wasm,package.json}`. `run_closed_signer.SOURCES` is the exact eleven-member source map; public entry additionally needs `runtime-source/poc/four-wallet-bootstrap/entry_cli.py`. The two exclusion roots are distinct LOCAL and LIVE four-owner trial roots. The sole backup handle must be the original selected role's `owners/A/backup.json` or `owners/C/backup.json` in one of them. The copied public constructor export must be outside every original owner directory.

```text
python3 -B poc/four-wallet-bootstrap/run_closed_signer.py
  --software-root SOFTWARE
  --backup ORIGINAL_BACKUP --role A
  --owner-public COPIED_CONSTRUCTOR_EXPORT --owner-public-sha256 OWNER_SHA
  --profile PROFILE --profile-sha256 PROFILE_SHA
  --case PROPOSAL --case-sha256 CASE_SHA --trial-id UUID
  --exclude-trial-directory LOCAL --exclude-trial-directory LIVE
  --output FRESH_CONTROLLER [--execute]

python3 -B poc/four-wallet-bootstrap/run_closed_entry.py prepare
  --software-root SOFTWARE --profile PROFILE --profile-sha256 PROFILE_SHA
  --trial-id UUID --owners PUBLIC_A PUBLIC_C --owners-sha256 SHA_A SHA_C
  --sources SOURCES --sources-sha256 SOURCES_SHA
  --exclude-trial-directory LOCAL --exclude-trial-directory LIVE
  --output FRESH_CONTROLLER [--execute]

python3 -B poc/four-wallet-bootstrap/run_closed_entry.py combine
  --software-root SOFTWARE --profile PROFILE --profile-sha256 PROFILE_SHA
  --trial-id UUID --case PROPOSAL --case-sha256 CASE_SHA
  --approvals APPROVAL_A APPROVAL_C --approvals-sha256 SHA_A SHA_C
  --exclude-trial-directory LOCAL --exclude-trial-directory LIVE
  --output FRESH_CONTROLLER [--execute]
```

Reference fee rate is fixed at100 sompi/mass. There is no historical-budget or fee-relaxation flag. New proposal/sign/combine retain10/10 budgets, two independently generated ordinary ALL approvals, exact per-owner fee allocation and the final NativeFull/all-engine checks. These launchers do not acquire accepted-chain authority or submit any transaction.

Signer staging writes a mode0600 `PRIVATE-PLAN.json` containing the opaque original backup handle. Do not publish or hash it. Only `client/run/APPROVAL.json` is the signature export. Public entry writes `PLAN.json`, and executed public operations export `client/run/{proposed-case,selected-case}.json`. A public `RESULTS.json` distinguishes staged from executed operations; staging reports neither an approval nor an executed Native check.

## Bounded controls

Nine meaningful control groups use freshly created `PUBLIC_SENTINEL_NOT_A_KEY` files outside Git and fake nonexecutable source/ELF/SDK sentinels. Their selected pins are replaced inside the tests only; no such bytes are a fundable runtime. They cover one-backup mount shape, zero-backup entry plans and the fixed SDK mounts, all eight forbidden owner directories, all eight private-inode aliases, a last-SDK-file alias before any source hash/copy, a hardlink swap rejected before descriptor reads, both public-operation ingress guards, context/original metadata/fresh-output guards, and actual unchanged frozen source preimages. The same nine groups passing again is independent reproduction, not nine additional tests.
