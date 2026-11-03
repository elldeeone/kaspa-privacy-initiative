# Public verifier and native adapter (ADR-0063 prototype)

This is an unfunded research interface. It does not authorize using the old
financial profile, old owner backups, real UTXOs, submission, or funding. A host
predicate, CPU execution, genuine receipt and native VM acceptance are separate
evidence levels. Native acceptance with supplied UTXO contexts is not accepted
backing or current chain state.

## Relation and authorization

The batch has exactly three Spend proofs and six shuffled Output tuples. No
public action number, output subset, per-owner balance, individual blinding sum,
authorization public key, authorization signature, or BindingSig is included.
A genuine Spend proof made after owner checks is financial authorization. Its
witness/proof representation may change while the financial effects remain the
same. Nullifiers are stable per note and domain, independent of session/retry.

All tags below are eight ASCII bytes. D is the new ADR-0063 domain; it is never
the profile-41c child or wrapper domain.

* Spend statement (200 bytes): `KPX7SP01 | D32 | oldCMroot32 | NF32 | CV64 |
  effectsDigest32`.
* Output statement (168 bytes): `KPX7OU01 | D32 | CM32 | CV64 | CFH32`.
* Each statement is SHA-256 hashed inside its R1CS relation. The public vector is
  the first and second 16 digest bytes interpreted as two exact little-endian
  128-bit Fr integers. There is no reduction of arbitrary 256-bit digests.
* Output tuple (520 bytes): `CM32 | CV64 | CF264 | CFH32 | OutputProof128`.
  `CFH = SHA256(CF264)` is checked again publicly. Correct ciphertext delivery is
  also checked by the intended recipient before the spender authorizes effects;
  a public ciphertext hash alone is not a proof of correct encryption.

CV is canonical affine x32LE followed by y32LE on the selected normalized
BabyJubjub curve over BN254 Fr. Coordinates must be canonical field elements;
curve membership, prime subgroup and nonidentity are checked. Delta is a
canonical scalar below that curve's prime subgroup order. Selected independent
value/blinding generators come from the circuit author's reviewed parameters.

The guest checks `sum(CVin) - sum(CVout) - fee*V = Delta*R` for this P0 prototype.
Every note value is range-constrained by its genuine component proof. The
profile records an integer absolute value-coefficient bound strictly below the
subgroup order, so a nonzero integer balance cannot wrap to zero. No publicDelta
is treated as ownership authority. DLP binding and component setup soundness are
explicit assumptions.

## Fixed P0 body, 10,780 bytes

The prototype uses one reserve input and one same-template successor output.
Native payouts are exactly zero. It does not implement a new independent exit.
The complete native header, actual input point/amount/SPK, successor amount/SPK,
fee and output count are checked; adding a payout or changing a destination is a
rejection, not an ignored field.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | `KPX7PB01` |
| 8 | 8 | u16LE version=1, Spend count=3, Output count=6, mode=0 |
| 16 | 32 | D |
| 48 | 32 | session |
| 80 | 32 | roster digest |
| 112 | 36 | actual previous txid32 + output index u32LE |
| 148 | 112 | old state |
| 260 | 8 | old reserve sompi u64LE |
| 268 | 112 | successor state |
| 380 | 8 | successor reserve sompi u64LE |
| 388 | 8 | fee sompi u64LE |
| 396 | 8 | payout sompi u64LE = 0 |
| 404 | 32 | aggregate Delta |
| 436 | 288 | three `NF32 | CVin64` records |
| 724 | 3120 | six complete mixed Output tuples |
| 3844 | 3480 | three indexed NF insertion witnesses, 1160 bytes each |
| 7324 | 3072 | six sequential CM append paths, 512 bytes each |
| 10396 | 384 | three Spend proofs, 128 bytes each |

The state layout reuses the 112-byte CM/NF root-and-count representation under
new state magic `KPX7ST01` and D. It has no ciphertext root. The public statement
and CF hashes bind delivery bytes. NF insertion uses the established indexed
17-level tree witness. CM append uses the established 16-level tree and empty
leaf, with six consecutive append positions. Three distinct nonzero NFs are
inserted against the actual prior root; no initial synthetic NF root may replace
it. Spend membership is against the old CM root, with note position kept private.

## Native projection, hashes and no self reference

The 193-byte native prefix reuses the existing financial projection encoding
with magic `KPX7FX01`: version u16=1, input count u16=1, actual point36,
sequence u64=max, input value u64, input SPK length u16=37 and SPK37, output
count u16=1, output value u64, output SPK length u16=37 and SPK37, absent
covenant byte0, locktime u64=0, native subnetwork20=0, gas u64=0, body length
u32=10780. All integers are little-endian. Full projection is prefix plus body.

`effectsDigest = SHA256(KPX7EF01 | nativePrefix193 | body[0:10396])`.
It binds session, roster, native effects and current state, all three ordered
input NF/CVs and all six full output tuples including their genuine Output
proofs. It excludes all Spend proofs. It is computed, never stored in the body.
Thus Output proofs are generated before mixing and Spend proofs after checking
final mixed effects; there is no proof-hash cycle.

The 104-byte journal is `KPX7JR01 | D32 | componentProfileSHA32 |
SHA256(fullProjection)32`. The component profile pins two new VKs, curve,
generators and relation limits before guest compilation. It does not contain the
guest's own image ID or actual trial/body/state. The native template is emitted
after image derivation and pins that new image. The native script reconstructs
the actual projection and independently binds old state/reserve/current point,
exact same-tail successor state/SPK/amount and fee. The R0 outer proof lives in
the input witness and is excluded from the projected body; no self reference is
introduced by the journal or proof slot.

## Reuse and execution gates

* `poc/accelerated-bn254/common/src/lib.rs`, SHA
  `ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e`:
  checked Arkworks proof decoding, canonical re-encoding, nonidentity checks and
  the standard four-pair Groth16 equation through established substrate-bn.
  Adapt its thin standard-equation backend into the new module with coherent
  Arkworks 0.6 checked decoding; leave the old crate unchanged. Genuine proofs
  must also pass the relation crate's independent Arkworks 0.6 verifier.
* `poc/four-wallet-profile/proof/common/src/lib.rs`, SHA
  `af8e286fb40d5ac5878e0d239cd56ddfb84d9f01c4926bd98adb855567d7b353`:
  adapt indexed NF insertion and CM path checks. Its old fixed two-child
  predicate, profile identity, old state assumptions and old image are rejected.
* `poc/four-wallet-profile/proof/host/src/native_proof.rs`, SHA
  `53da4c819fa0a1801c0f00ef76e0a15acf98dc6ec348c16ea4cab889dcc0ce7b`:
  reuse standard genuine R0 Groth16 seal conversion only after receipt/image/
  journal/no-assumption checks. No fake receipts or proof-acceptance flags.
* Existing RISC Zero 3.0.3 and matching pinned component graph, standard outer VK
  and native077 engine are reused. A new common predicate, guest program/image
  and native covenant emitter are required. No consensus change is expected;
  actual Native Full validation remains a required experiment.

The prior genuine two-proof LIVE CPU execution was 108,385,504 cycles in
2.052 seconds (`profile/live-outer-public-01/execute/report.json`, SHA
`57ef5760ed2f54734853840f9c3da37950cda4ba9c0f712bab58342cf9a447b5`).
Nine verifications alone project about 488M cycles. Declare a generous 2B-cycle
operational session allowance and segment limit 2^19 before measurement. First
run the real nine-proof CPU guest and record actual cycles. Only then schedule
GPU succinct proving/compression. This allowance does not change any financial,
proof, subgroup, root, count, range, fee or authorization check.

Required controls include genuine positive nine-proof evaluation, malformed and
wrong-key proofs, modified output tuple/proof/CF hash, duplicate/stale NF, stale
CM membership/state/point, cross-domain/session/roster effects, wrong fee or
successor, noncanonical fields/scalars/points, subgroup and identity points,
integer antiwrap boundaries, and native malformed-proof/body/header mutations.
A host-only pass cannot be labelled native acceptance.
