# Generic owner REVEAL helper, selected version 1

The source-reviewed immutable helper passes **10/10** frozen public-input tests.
It quotes and prepares an owner-authorized continuing and terminal native exit
from the actual authenticated redeem, without a PK, prover, per-domain build,
RPC or operator archive. Signing tests use only explicitly public historical
DO_NOT_FUND keys. A separate positive quote uses the actual fresh-domain TN10
public exit body and no fresh signing key.

The quote checks the complete source-approved opcode template, patching only
State112, exactly ten parsed literal domain operands and the unique VK328
operand. A caller's own tail digest is not authority. It checks the actual P2SH,
domain, bounded values, real CM/NF paths and reaches only the expected final
Schnorr failure with a dummy signature. Quote returns no revealing transaction,
note/k payload or signing key. Sign requires the explicit disclosure consent,
the unchanged quoted version1 transaction ID and the matching owner native key.
It uses official Schnorr ALL, computes full native mass and requires actual
Full/all-input script success before returning the authorized public body.

Controls reject missing/automatic consent, a signing key in quote mode, a
self-hashed modified policy, wrong domain/current SPK, stale NF root, amount/fee
and canonical integer/hex failures, changed quoted body, wrong signing key and
a caller sighash override. No key/request is echoed. Public-context validation
is not current-chain authentication; independent replay/fetch must supply that.

Selected local-only executable:
`/home/luke/projects/kpi-intensive-2026-10-22/recovery-native-target/selected-01/kpi-independent-recovery-native`

SHA256 `a4c5da2c94691ba39ca9f5be1279b3243a0328481f9ba795e812483c770e1186`.
The wallet must independently select this software identity before any owner
secret enters its stdin; an adjacent caller-supplied digest is not sufficient.

Exact executed source is [source03](recovery-helper-source-03/SOURCE-FREEZE.json).
[The test freeze](recovery-helper-tests-01/PRE-RUN-FREEZE.json) pins 12 source,
binary and original public-input files. [Tests](recovery-helper-tests-01/tests.log)
complete in 0.084 seconds inside a network-isolated sandbox, with CPU quota2,
2 GiB operational memory allowance and no swap. The unit is inactive/dead,
MainPID0, successful, empty cgroup. This is not a wallet latency or p95 result.

This version approves the original three-branch KPX2 program with runtime D/VK;
it deliberately rejects the new unified-private-exit program until its approved
template is separately added and reviewed. It does not grant an old funded pool
new authority or turn revealing fallback into a private exit.

The first host-path compile was stopped before native execution after identifying
dependency-cache path drift. The isolated first full build repopulated the cache
in 3m56s. Subsequent reviewed snapshot builds take approximately 5.5s. All build
logs and immutable source stages are retained; no failed semantic result was
overwritten and no funded/recovery trial was attempted by this helper lane.
