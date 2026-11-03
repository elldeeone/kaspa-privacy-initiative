# Seed-only recovery wallet boundary

The new wallet reads one receiver's seed-only backup, a user-authenticated public
pool descriptor and freshly fetched public chain data. It calls the separate
public replay itself. It does not accept an operator snapshot, expected-payment
map, full private controller profile, precomputed exit, prover or proving key.
It never broadcasts.

The selected work reuses the current V2 receiver's established SHA256/HMAC
derivation, supported sealed-box/libsecp bridge, exact note rederivation,
positioned nullifier and current Merkle witness construction. The source
comparison in `../SOURCES.md` and the prior private-integration primary-source
review cover Orchard/RAILGUN local note checking, Monero recovery-height/key
roles and MWEB's warning against server-side viewing-key scanning. Their
cryptography, addressing, consensus or retention guarantees are not imported.

## Inputs and authority

`wallet.py` takes one stdin request:

```text
op: recover | prepare-reveal
backup_path, descriptor_path, expected_descriptor_sha256, fetch_path, crypto_path
```

The descriptor is `kpx2-recovery-descriptor/v1`, with exactly the public network,
genesis, domain, selected founding outpoint, pre-founding scan anchor, initial
redeem, immutable-policy hash and VK fields specified by replay. Its recursively sorted compact UTF-8
JSON SHA256 is carried into the result. User selection of that descriptor remains
an explicit instance-identity assumption; a self-supplied hash is not authority.
The required expected digest comes from the caller's separately authenticated
wallet profile/descriptor selection, never automatically from the fetched node
or descriptor file. The client checks it before reading a seed. This verifies
the user's selection; it does not prove how the caller obtained that selection.

The backup is exactly `kpx2-tn10-seed-backup/v1` with network, genesis, domain and
32-byte root seed. It must be a regular0600 file outside Git, with no symlink
component. The bridge's complete bytes and immutable V2 Python source must match
software-compiled trusted pins **before** reading the backup. A node/descriptor
cannot choose an executable or its expected hash. Root seeds and private
ownership secrets stay in the wallet process. Only the required derived delivery
or native keys enter the narrow trusted helpers on stdin. Root seeds, private
ownership secrets and native signing keys are never printed, logged or written
by this client. The
explicitly consented REVEAL body intentionally contains note-local k; it is
written only to fresh0600 files before any owner-controlled broadcast. Separate
network-offline one-owner processes enforce the intended run boundary.

## Reconstructed state and recognition

The wallet invokes `replay(descriptor, fetched)` on public inputs. It verifies the
result's descriptor/network/domain and complete current view, parses all ordered
deliveries and physical indexed-NF records, recomputes both roots and compares
State112 and exact current reserve/P2SH/immutable tail. A missing/incomplete
history or current head fails; it is never converted into an empty balance.

Only then does the wallet scan locally using its root seed. A successful decrypt
is followed by exact invoice/key/CM rederivation and current positioned-NF
checking. The report counts recognized valid receipts, their current unspent
principal, duplicate/contaminated positions and native payouts matched by exact
CM/position/opening/native key. It distinguishes historical payout amounts from
freshly queried still-unspent payout UTXOs. It does not trust actor labels or an
operator's intended amount.

**Residual delivery boundary:** the current relation binds ciphertext bytes but
does not prove correct receiver encryption. Failed decryption can mean foreign
data or a maliciously undeliverable note. The wallet therefore reports
`recognized_valid_receipts_only`; it does not prove that every conceivable owned
liability was discovered in an ongoing pool. No-recognized-receipt is not a
universal zero-balance claim. A validated terminal reserve of zero is a separate
public all-pool-liabilities condition. Earlier owned claims remain actionable
when later duplicate invoices contaminate privacy.

## Revealing fallback

`prepare-reveal` additionally requires an exact explicit disclosure-consent
string, selected recognized unspent position, positive fee rate and fresh private
output directory. Without that consent it must stop before creating/exporting a
revealing payload or invoking a native helper. It never silently chooses this
fallback when ordinary private proving/data is unavailable.

After consent, construct the unchanged2029-byte revealing payload from the
current witnesses. A separately pinned generic native helper uses the actual
current redeem, preserving its immutable tail and replacing only State112 for a
continuing successor. Official native Schnorr `ALL`, actual mass calculation and
Full validation protect its exact payout. No compile-time-domain factory or PK
is used. Quoting is monotone integer-sompi fixed-point iteration; explicit native
Full success is mandatory before returning a signed body path. The output is
still unbroadcast, and its reveals are private local files until the owner sends
them.

Network acceptance still assumes the selected validating-node acquisition and
available public history. This is independence from the preferred operator
archive, not independent consensus, durable DA, reorg finality, financial privacy
or production safety.
