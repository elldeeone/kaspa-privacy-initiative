# Fresh private service-loss integration contract

Authority: ADR-0053 SHA256
`dd77b305df860011ae6608e312eb09396f2c6585fa17225646bdb8f181fa9b58`.
Prior closed checkpoint: `2ee3e0850a277f2d4a2f512da67683540be01958`.

## Identity and public inputs

- Public trial schema: `kpx3-tn10-private-trial/v1`.
- Classification: `PRIVATE_TN10_TEST_KAS_ONLY`.
- Program label: `AUTH528_PRIVATE_CASHOUT/v1`.
- Domain: SHA256 of exact `KPX3/TN10/PRIVATE-RECOVERY/v1\0`, then the pinned
  TN10 genesis raw32, then a fresh OS nonce32. Reject AA and all used identities.
- Seed-only backups retain `kpx2-tn10-seed-backup/v1` and V2 derivation; that
  version names the backup format, not the native program.
- Descriptor schema: `kpx3-private-network-descriptor/v1`, exactly
  schema/network_id/genesis_hash_hex/domain_hex32/founding_outpoint/
  birth_start_hash/initial_redeem_hex/vk_hex328/immutable_policy_sha256/
  public_params_manifest_sha256. Canonical sorted compact JSON determines its
  separately authenticated SHA256.
- Public parameter schema: `kpx3-public-proving-parameters/v1`; its reviewed
  prover-owned exact contract must include ADR network/genesis, D/VK, complete
  uncompressed cache hash/length, core/source/build/lock/toolchain identity,
  measured fresh constraint/query counts and setup provenance. Store canonical
  compact JSON without a newline, so raw and canonical SHA256 agree.
- Fetch/replay receive only public descriptor, small public parameter manifest
  and public software. They never read the parameter blob or any backup.

## Payout derivation

Use **exactly ADR-0053's tag**, not an alternative existing derivation prefix:
`KPX3PAY\0` (hex `4b50583350415900`). HMAC-SHA256 key is owner seed32; message is
tag8 || D32 || founding(txid raw32,index u32LE) || owned CM32 || position u32LE
|| retry u32LE. Reject non-scalars, zero and any x-only key equal to a real
consumed note's emergency native key; do not reduce modulo the curve order.
The fresh payout secret stays only in the wallet. Recover using the same public
instance/owned-note context. Default full-claim exits are the selected scope.

## Proof and native interfaces

- Strict private witness: `kpx3-private-action-witness/v1`, auth_hex528,
  inputs[2], outputs[2] using the existing detailed typed field names. A new
  parser constructs the same relation and rejects unknown fields. No public
  synthetic classification or private witness hash/path is emitted.
- Fresh setup uses a private fresh-D source clone, never old/AA keys. The public
  template is unselected and cannot set up or accept witnesses. Measure actual
  new-D constraint shape; prior AA counts are reference observations, not a
  reason to reject a correctly reviewed fresh constant-domain circuit.
- Resident rehearsal labels: spend, bob-full, charlie-terminal.
- Cold `prove PUBLIC_PK WITNESS_FD NEW_PRIVATE_OUT`: authenticate public manifest,
  core/build and the entire owned cache before unchecked trusted decoding;
  require exhaustion and checked extracted-VK equality. Emit parameters-ready
  with manifestSHA/domain/VKSHA/buildidentitySHA before reading the empty witness
  pipe. The wallet checks these before backup/seed access. One local load, one
  owner witness, verified proof, then stop. No hosted prover.
- Native public helper schema: `kpx3-public-native-action/v1`, quote|verify,
  exact current redeem/outpoint and actual supplied UTXO, Auth528/cipher528/
  public_witness3344/VK328/proof128, fee_rate_sompi_per_mass. Quote uses zero128
  only and must reach the declared Groth16 seam. `expected_quote_id` binds the
  entire normalized zero-proof body, all contexts and fee rate. Final verify
  substitutes only proof128 and requires Full/all engines. It has no key inputs.
- Launch authenticated immutable sealed ELF snapshots. This host's bwrap blocks
  direct memfd exec; a separately SHA-pinned read-only system ld-linux can load
  the same sealed FD with clean fixed environment. Loader/shared libraries are
  explicit trusted public runtime inputs. Do not weaken host policy. The child
  /proc/self/exe can name the loader; it is not the payload identity authority.

## Minimal trial and source context

One directly funded whole Alice note creates P0 two60M receipts; Bob full private
exit continues, Charlie full private exit terminates. Actual native quote/mass
fixed points determine all amounts. Three genuine proofs, four native Full/all
engine passes, links/SDK roundtrips and zero terminal accounting precede funding.
Publish only founding and P0, stop operator prover, then fresh independently
rebuilt private owner exits with confirmed payouts. No precomputed exit enters
either cold process; REVEAL is absent.

Bind the local founding input to the exact planned ordinary merge outpoint,
amount, SPK, noncoinbase flag and no covenant. Every source input has u64MAX
sequence (relative locks disabled); policy has no DAA introspection. Future
blockDAA cannot be predetermined: replace only that metadata with freshly
accepted actual context and revalidate Full before publishing. Do not change
signed body, Auth, proof, fee or source fields. Pinned upstream sighash and mass
omit DAA; maturity/relative-lock preconditions are explicit.

Root alone funds/submits, using fresh identities and durable once-only intents.
Missing dependencies safely halt; no automatic disclosure. All fees, change,
failed attempts and public-evidence trust boundaries remain visible. Existing
privacy/fee failures and all prior frozen packets remain unchanged.
