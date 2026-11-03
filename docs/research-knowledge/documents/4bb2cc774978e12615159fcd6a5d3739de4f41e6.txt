# Public future-exit native feasibility result

**Bounded result:** a new public, current-root, hash/HMAC/Schnorr exit checker
can pay a60M-sompi claim with no external input at the500-sompi/mass scenario
for the frozen terminal and sufficiently funded continuing layouts. The same
small claim still fails for the tested20M/10M reserve remainders, and the
49,152-byte envelope fails at the frozen budget200. These are conditional
layout results, not a complete native KAS private payment lifecycle.

All60 positive signed bodies passed official isolation, official Full and the
underlying ScriptEngine. All39 negative controls rejected with exactly VM
`VerifyError` and Full `SignatureInvalid(VerifyError)`. This excludes storage,
resource and malformed-signature failures as substitutes for the intended
negative checks. The45 separate fee-agility cases contain36 economic passes
and9 economic failures; consensus acceptance does not erase those failures.
[Machine verdict](VERDICT.json), [native output](execution-01/output.log).

## Frozen identity and validation boundary

Native source commit `01b532e8b553523216471682649693af92f0fd16`; standalone
source SHA256 `29f4d40c0e9457fb541411ad5b92beed3b357c2e0e8e9b4de8816686a3691bf8`.
[Source snapshot03](source-03/src/main.rs), [standalone package](../../../../poc/future-exit-feasibility/README.md).
No wallet, private key restoration, owner CLI, replay, DRAIN, proving, PK,
funding, broadcast or GPU execution was used. All fixture credentials are
public. Native wire contains k and the opening, not s or the signing secret.
There is no implemented private proof/branch or private/native combined policy.

The complete public wires, authentic supplied current-root contexts, scripts,
actual signed transaction bodies, amounts, fees and expected controls were
prepared before VM/Full execution. Freeze02 SHA256
`1c8d432425ced73fc4f7e9a0d74cf992c86d0ad41dc3001504cd1998ba4a3983`
retains freeze01 and adds independent Python wire checks and99 supplied UTXO
contexts. The parent obtained independent adversarial/source/economic ACKs
before authorizing the one native run. The native source implements direct raw
official APIs and adapts only the existing native helper seam; it imports no
old private relation. Runtime deterministically reconstructed the bodies from the exact frozen
binary, rather than parsing the prepared JSON. All99 final transaction JSON
files are byte-identical to their prepared copies. [Comparison](execution-01/frozen-body-comparison.json).

An independent standard-library SHA256/HMAC/Merkle/indexed-set/accounting oracle
checked all60 positive prepared wires and the CURRENT spent-NF equality control.
Those checks are separate from native Full. [Oracle result](preflight-01/independent-wire-check.json),
[supplied contexts](preflight-01/fixtures/supplied-contexts.json).
The current NF predecessor membership authenticates before strict ordering;
the same path/index updates its leaf. Empty append authenticates the resulting
intermediate root, followed by the one new real NF leaf. No two independently
chosen old/new paths are accepted.

## Actual fee agility at500

All amounts below are integer sompi. Every note principal is60,000,000. The
unchanged payout floor is10,000,000, fee cap50,000,000, one input and no subsidy.
Minimal actual redeem is5979 bytes. Padded sizes are explicit NOP feasibility
envelopes, not a private proof branch or a security argument.

| Fixture | Redeem bytes | Actual signed fee | Native payout | Full mining mass |500 economics |
| --- | ---: | ---: | ---: | ---: | --- |
| Terminal singleton |5979|14,318,500|45,681,500|28,637|PASS|
| Terminal singleton |32,768|35,066,000|24,934,000|70,132|PASS|
| Continuing, reserve remainder60M |5979|15,369,000|44,631,000|30,738|PASS|
| Continuing, reserve remainder60M |32,768|35,119,000|24,881,000|70,238|PASS|
| High NF append65536, reserve remainder60M |5979|15,369,000|44,631,000|30,738|PASS|
| High NF append65536, reserve remainder60M |32,768|35,119,000|24,881,000|70,238|PASS|
| Continuing, reserve remainder20M |5979|45,647,500|14,352,500|107,174|FAIL; next required53,587,000|
| Continuing, reserve remainder20M |32,768|47,135,500|12,864,500|115,233|FAIL; next required57,616,500|
| Continuing, reserve remainder10M |5979 or32,768|0|60,000,000|102,381|FAIL at first step; next51,190,500|
| All49,152-byte envelopes |49,152|0|60,000,000|102,900 terminal /103,006 continuing|FAIL at first step; next fee exceeds50M|

For a failed row, the displayed body is the **last prepared supported body**,
not an affordable relay candidate: its fee does not cover its quote. A zero-fee
Full acceptance is a consensus/script result, not relay readiness or free
withdrawal. All30 profiles at100/200 passed their separately computed economic
gate. At500 there were6 passes and9 failures. Full45-case results, each with
compute/storage/transient/relay/mining mass, actual fees and complete iteration
histories: [fee agility](execution-01/results/fee-agility-results.json).

The pre-frozen monotone algorithm starts fee0, rebuilds and owner-signs each
actual payout-dependent body, computes full mining mass, and increases the fee
to `rate * mass` until it covers that body or the next fee breaches50M. It does
not transplant a quote from a different payout. Small reserve remainders create
a KIP9 storage-mass feedback loop: raising the fee shrinks the payout, which
can raise storage mass and require another fee increase.

The original15 fixed-fee/P10M/F50M bodies remain intact. At500 only terminal
minimal and32,768-byte passed:2 economic passes,13 failures. Paying the maximum
fee can make storage mass worse; all15 were consensus-valid. This is why the
independently frozen fee-agility experiment matters. [Fixed-cap cases](execution-01/results/positive-results.json).

## Exclusion, authority and boundary evidence

New domain/tags/state only. The RFC exact `K=SHA256(KEY_TAG||D||k)` is used.
CM includes O, incoming, value, rho, K and native PK. The reference private
predicate requires both s and k; copied public k plus a wrong s is rejected.
The deliberately unsafe k-only reference accepts copied k and is retained as a
failing design reference. Neither is a SNARK or actual private spend.

The reveal authenticates CM against the CURRENT immutable root and count,
computes the exact positioned HMAC NF, and authenticates current NF absence and
insertion. Canonical P2PK payout uses the CM-bound key; exact SIG_HASH_ALL binds
the actual predecessor/body/fee-bearing outputs. The weak-type control uses a
**valid actual SIG_HASH_NONE signature**, independently Schnorr-verified, and
is rejected by the exact-ALL guard. Opening/key/domain/payout/fee/successor,
wrong/stale roots, malformed counts, wrong predecessor/path/append, private
branch selection, extra input and trailing payload all reject precisely.
[39 controls](execution-01/results/negative-results.json).

Replay after ideal reference private consumption is tested with both the old
stale witness and a genuinely current-root authenticated spent NF supplied as
an equal predecessor. The latter successfully authenticates membership and
then fails strict ordering. This is public state-relation evidence, not a
private proof or accepted private transaction.

CMdepth16 and NFdepth17 are distinct. Active reveal requires m<=n, with m
including the sentinel and prior real NFs; successor m+1<=n+1 is serialized.
The near-capacity case has n65536, position65535, current m65536 and exact
append index65536. All65535 prior public note openings and their actual derived
NFs are constructed and sorted into a valid indexed set. This is constructible
synthetic supplied state, not accepted chain/proof history. It contains one
remaining60M liability and60M donation surplus. After exit the surplus is still
locked in a zero-liability successor; no privileged withdrawal was added.

Terminal R=V creates one positive payout with no zero reserve, conditional on
valid prior I1 over COMPLETE unpaid liabilities L: current unspent V implies
V<=L<=R, so R=V forces L=V and whole-note consumption leaves L'=R'=0. A root does
not establish that prior backing. The R=V-plus-another-positive-liability
countercontext is explicitly unsupported/underbacked, not silently erased.
[Countercontext](preflight-01/fixtures/unsupported-underbacked-terminal-context.json).

## Resources, preparation failures and remaining work

One native run, no retries:353ms service wall,352ms CPU,30.8MiB reported peak,
swap0;6CPU/10GiB/swap0 hard caps and network-unshared bwrap. This is whole test
harness resource use, not user wallet/exit latency. Largest observed script
use was425,140 units at the high-index49,152-byte envelope. Frozen budget200
allows2,009,999 units. This source is not a global worst-case budget proof and
no budget reduction was applied in this run. [Cleanup](execution-01/cleanup.json)
confirms all task units inactive/dead, no MainPID and empty cgroups.

Preparation failures are retained: copied lock needed pruning; all-target
offline metadata wanted an uncached Android-only dependency; Linux-filtered
locked metadata succeeded with all428 external identities unchanged. Build01
caught a JSON macro expression syntax issue; build02 caught two hash-array
borrows and an ambiguous integer type. Build03 succeeded. No VM/Full execution
preceded these fixes or the second adversarial pass; source01/02/03 and build
logs remain. Nothing was repaired by changing the principal, payout floor,
fee cap, failed economic labels or authenticity checks.

Remaining: source-bound universal metering, actual future private circuit and
combined immutable branch, recipient backup/descriptor validation and reuse,
accepted backing/authorization, data survival, independent recovery, contention
and reorg operation, accepted testnet payout and complete lifecycle cost/latency.
Financial-privacy targets and prior negative privacy evidence remain unchanged.
The current successful seam removes one particular fresh-Groth16 fee assumption
for a new conditional format; it does not qualify existing notes or production
security.
