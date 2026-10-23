# New wallet implementation boundary

The accepted [common contract](../CONTRACT.md) is the authority. Current code is
under `poc/private-change-wallet`; the earlier `private-cashout-wallet` and all
closed packets remain byte-for-byte unchanged.

The deep action seam owns one recognized real input, its current membership,
private NF-slot allocation, current ordered NF updates and fee-dependent output
construction. `Intent` fixes user-requested value. `ActionTemplate` fixes one
prepare's private randomness; each `actual(fee)` rebuilds receipts, fresh seals,
CM paths/root, State112 and Auth528 together. It returns an `ActualCandidate`.
The separate payment-only `sizing(fee)` returns a `PublicSizingCandidate` with
public effects only and no private witness API. This boundary makes it possible
to size a legal C0 payment without first encoding an illegal subfloor note.

`change_wallet.quote_action` obtains checked native fees and actual body/context
identity. It returns only the final actual candidate and actual quote. The
already-authenticated local prover remains on an empty data pipe until this
function succeeds. No witness is serialized for sizing, subfloor/negative
change, an obsolete fee candidate or a readiness mismatch. Native verification
then substitutes only proof128 and checks exact actual quote identity/effects.

New owner metadata checks precede any caller-selected public read/hash. They
reject own-backup inode aliases and symlinks, and stat-check the public invoice
width before reading it once. They do not claim to identify arbitrary copied
secrets: one-backup namespaces, immutable readonly source/releases and trusted
host/system libraries remain the authority.

Self-change uses unchanged V2 encrypted-index discovery. Uniform OSu64 indices
and both private slot permutations are selected locally; known historical own
indices/receive tuples and current recipient tuple are excluded. No child seed,
new crypto, counter, map, operator service or recipient secret is introduced.
Historical default-native-payout recovery reuses KPX3PAY derivation from each
recognized receipt, including spent ones. Duplicate-positive ownership and
privacy-contamination behavior remain unchanged.

Source provenance is recorded separately. Public controls use deterministic,
explicitly unfunded fixtures, the existing selected established-crypto bridge,
an independent public tree decoder and mocked native/prover orchestration.
They are not genuine G16/native/chain execution. Actual component and live
rehearsal remain root-scheduled follow-up work with fresh identity/parameters.

Risk boundaries remain the [source findings](../SOURCES.md), ADR0053/0054 and the
common contract: authenticated recipient descriptor/encryption behavior,
selected-node accepted history/current UTXOs, retained ciphertext, probabilistic
index freshness and local parameter availability. A single-owner intermediate
reserve reveals a total, public payouts/fees/timing remain, and more actions
cost more. No measured privacy or full-lifecycle fee target is qualified here.
