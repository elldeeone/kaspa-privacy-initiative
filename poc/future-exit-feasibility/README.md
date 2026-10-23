# Public future-exit feasibility probe

Standalone, offline, DO_NOT_FUND. [ADR0040](../../docs/adr/0040-public-revealing-exit-feasibility.md)
and [RFC0019 candidate C](../../docs/rfc/0019-fees-and-independent-exit-obligations.md).
All credentials and contexts are deliberately public synthetic fixtures.

This measures a new hash/HMAC/Schnorr/current-root indexed-NF seam using official
native isolation/Full and separate ScriptEngine execution. It does not import
wallets, owner CLI, replay, DRAIN, proving or private material. There is no
implemented private branch/SNARK, chain funding, accepted lineage or migration.
Current historical instances stay unchanged. The reference private predicate
requires both s and k; its result is a host reference, never a proof result.
The wire reveals k and opening, never s or the native signing secret.

`freeze OUTPUT` deterministically prepares signed native bodies, public scripts,
amounts, current CM/NF contexts and complete native mass calculations without
calling ScriptEngine or Full. `run OUTPUT` additionally validates the prepared
bodies and enforces39 exact typed negative rejections. The frozen packet and
second adversarial pass precede first native execution; do not overwrite them.

The Python `verify-prepared.py OUTPUT/fixtures` is an independent standard-library
oracle for canonical wire, SHA256/HMAC, full Merkle paths, same-path indexed-set
update, successor covenant, whole-note accounting and the current spent-NF
membership/equality control. It exports supplied UTXO contexts. It does not run
Kaspa consensus or establish accepted backing.

The15 fixed-cap bodies retain V60M/P10M/F50M. Another45 bodies measure a frozen
monotone actual-body fee fixed point at100/200/500 with the same50M fee cap and
10M payout floor, changing payout-dependent storage mass on every iteration.
Report economic failure separately from script acceptance. The32768/49152-byte
NOP envelopes measure conditional future combined-script footprint only; they
are not private branch implementations or security arguments.

Terminal R=V is conditional on valid prior I1 including ALL unpaid liabilities:
V<=L<=R then L=V, and whole-note consumption permits no reserve output. A state
with R=V plus another unpaid liability violates that assumption. Authenticating
a supplied CM/NF root does not prove its whole prior reserve history. Positive
surplus may remain locked after all liabilities are gone; no admin release is
added. Public-data availability, recipient backup/descriptor validation, actual
private relation, reveal privacy, contention/reorg behavior, accepted funding,
complete lifecycle cost/latency and independent recovery remain open.

Reproduction uses exact Cargo.lock and native commit
`01b532e8b553523216471682649693af92f0fd16`; retained build launchers use offline,
network-unshared6CPU/10GiB/swap0 Forge jobs and a private target outside Git.
[Plan and evidence](../../research/next-session/exit-fee/future-exit/PLAN.md).
Passing tests do not prove cryptographic correctness or production safety.
