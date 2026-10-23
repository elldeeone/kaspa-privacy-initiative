# Fresh unfunded identity constructor

The new [TN10-only constructor](../../../poc/future-testnet/README.md) creates
an unfunded private identity in one network-free command. The first measured
successful invocation took0.129s; the root's separately created actual trial
took0.133s. These times include supported key derivation and official SDK address
conversion, not matching build/setup or proof generation.

```sh
python3 -B poc/future-testnet/trial.py new --network testnet-10 /absolute/new/private-trial
```

It uses fresh OS randomness for payer/recipient seed backups, funding secret and
trial nonce. The compiled-instance domain is SHA256 of the exact tag
`KPX2/TN10/TRIAL/v1` followed by a NUL, fixed TN10 genesis32, then nonce32.
Profiles/backups remain0600 under0700 outside every Git worktree; no private
sample is stored here. Public output excludes private values. No old wallet,
DO_NOT_FUND seed, proving key or selected-development key pin is read/copied.

An explicit source materialization step copies only allowlisted current source,
locks and compile-time published known answers into the private trial. Only two
DOMAIN declarations change. Original/generated SHA256 values remain in its
manifest. A matching new circuit/VK/setup is mandatory. The lifecycle agent owns
the separately automated build/setup and finite new-format transport; this
constructor does no funding, RPC, broadcast, native execution, setup or proving.

Thirteen finite offline controls pass: independent identity/seeds/domains,
backup/profile permissions, exact TN10 address/SPK, secret exclusion, refusals
for existing destinations, repositories including ignored directories, symlinks,
mainnet, wrong genesis/domain/class/profile permissions, changed SDK and an
alternate JS module beside the genuine pinned SDK files. Source-copy checks
verify exact two-array substitution and unchanged originals. Tests use removable
private OS temporary directories outside Git.

The independent source reviewer found the alternate-SDK-path issue: sibling
files were pinned but a supplied alternate JS path could execute different
code. The fix verifies the actual resolved JS bytes too; the dedicated negative
control passes. Root's actual trial used the canonical pinned JS and is
unaffected. The test suite's brief failure after an overbroad `.git` directory
check was corrected by using Git's read-only worktree query; a non-repository
`/tmp/.git` directory does not classify all temporary files as repository files.

These checks establish constructor behavior only. No accepted testnet funding,
current head, relay acceptance or terminal payout is established here. The
existing offline evidence, privacy failures and fee/resource limitations remain
unchanged. A retry uses a new identity after any actual used trial.
