# Two-v6 binding and native receipt boundary: cross-review

**Ruling: coherent binding-only specification with explicit unmet gates.** The two reports agree on what the proposed guest would assert and what the existing native receipt verifier can bind. No contradiction or unacknowledged state/settlement/exit obligation was found that prevents specifying this strictly nonsettling statement. There is still no implemented two-v6 guest, independently expected wrapped image, qualified Arkworks bridge, or accepted outer receipt. This review authorizes none of that work.

## Scope, time and frozen identities

- Source-only review on Forge; owner `/root/architecture_options`.
- Actual start: **2026-10-22 10:41:21.564793 UTC** / 21:41:21 AEDT.
- Deadline: **2026-10-22 11:11:21.564793 UTC** / 22:11:21 AEDT.
- Source inspection stopped: **2026-10-22 10:42:54.164636 UTC**. The ruling was settled; subsequent work only records it.
- Report finished: **2026-10-22T10:44:32.761700+00:00**.
- Read applicable `AGENTS.md` and `SECURITY-INVARIANTS.md`. No implementation, executable-package import, build, setup, proof, runtime test, new fixture, benchmark, GPU allocation, private evaluation access, parked-job reconstruction, staging, commit or publication occurred. Only this report was written.

| Compared document | Exact SHA-256 |
|---|---|
| [C: desired two-v6-bundle contract](../roadmap/TWO-V6-BUNDLE-BINDING-CONTRACT.md) | `d16ec7b288cc93473cbeffd8af0c0071a06f575552522572f6ccd64b97a03e44` |
| [N: native receipt constraints](../native/OUTER-RECEIPT-SOURCE-CONSTRAINTS.md) | `7d3cfb438f398edf5fed9018f13808098f24692f3065631ee8fa2674b3fb4e6c` |

Both hashes were checked before inspection and immediately before this report was written. Neither input was edited. Line references below identify these frozen versions. This is their cross-review, not another backend search or a repeated dependency inventory.

## Cross-boundary ruling

| Obligation | Agreement and remaining gate |
|---|---|
| Exact public statement | C lines 60–110 accounts for every byte of each 377-byte authorization. Its restricted mode-1/zero-payout profile excludes admission, bootstrap, DRAIN and native payout effects. Fixed domain/VK, exact little-endian digest limbs, individual checked fees and original ordered ciphertext hashes are coherent with the inspected v6 sources. These are required guest checks, not existing guest behavior. |
| Complete public projection | C 112–186 requires four distinct nonzero NFs and four complete CM/ciphertext records, preserving multiplicity and original pairing through two private bijections. Complete `P` includes profile/count, domain, VK digest and checked aggregate fee. It contains no per-operation proof, authorization hash, fee or anchor handle. Cross-bundle duplicate records are not deduplicated. Nothing in N requires disclosing those hidden per-operation fields. |
| Journal versus aggregate digest | C 147–197 defines 1,088-byte `P`, `H = SHA256(P)`, and exactly 42 journal bytes `J = "KPI2V6J1" || u16le(1) || H`. N 24–43 binds the digest of actual journal bytes. Therefore the native journal argument must be **`SHA256(J)`, not `H`**, a serialized receipt, or the two inner field limbs. The native boundary does not prescribe the historical 352-byte application journal; a proposed 42-byte journal is not a length contradiction. Exact guest emission remains unimplemented. |
| Trusted program and final claim | N 37–43, 51–70 requires an independently expected image and a compatible final control identity, with successful `Halted(0)`, zero input digest and zero assumptions in the final claim. The contract's private guest input is not authenticated by the claim's input digest; the expected program must enforce all input checks and commit their public result through `J`. C 49–50, 98–108 and 230–234 require that program to pin the actual v6 key/domain, not echo a prover-selected key. No guest image or final control selection exists. |
| Current v6 integration | C 199–216 and N 55–57 agree: the existing v6 covenant expects one direct Groth16 proof under tag `0x20`, not this `0x21` receipt or four-record layout. Receipt integrity does not replace the covenant, change the embedded VK, or authorize migration. |

The byte totals are mutually consistent: `P` has `8+2+2+32+32+16+4×32+4×217 = 1,088` bytes; `J` has `8+2+32 = 42`; the proposed input has `1,088+2×(377+128+185+185)+8 = 2,846`. This is a specification check, not serialization execution.

## Binding is not settlement

The coherent implication is conditional: **if the new guest correctly implements this contract and the inner and outer verification boundaries are sound, an accepted public `P` has a witness consisting of two valid, profile-conforming, same-anchor inner authorizations whose NFs and paired output records exactly cover `P`.** It is an existential partition, not authenticated submission order or proof that particular wallets supplied it. C 137–145 makes that distinction explicitly.

The exclusions in C 201–216 are necessary and are not silently supplied by N's generic verifier:

- **State and single spending:** equality of hidden anchors/counts does not establish accepted-history membership. Four distinct NFs only exclude collisions inside this pair. There is no authenticated prior spent set, freshness/sequence condition or successor transition. Re-presenting the same binding receipt would still assert the same verification fact; it must never mean another valid spend.
- **Native backing and no inflation:** inner value conservation is about the notes represented in the proofs. Without authenticated accepted state and actual reserve/output binding, it cannot show those claims were backed or that aggregate fee `F` is affordable. No reserve KAS may be released from this receipt alone. Fixed domain and VK do not substitute for accepted state.
- **Delivery and independent exits:** pairing ciphertext bytes with CMs and checking their digest does not establish correct encryption. Sorted records alone provide neither accepted positions/history nor an exit witness, independent scanner or available authentic data. Publishing a digest without its matching `P` also fails the stated publication contract. Existing holders acquire no new collector permission requirement.

In particular, hiding the common anchor means a future covenant cannot simply read it from `P` and perform the omitted history check. A full composition must add verifiable accepted-state binding at an appropriate boundary, then bind spentness, successor state, actual native amounts and exits. That is a separate reviewed relation/integration obligation, not an innocuous use of the existing binding-only receipt. This preserves I-1, I-2, I-4, I-6, I-7, I-10 and I-14; none is waived because the smaller statement is coherent.

## First unmet prerequisite and smallest separable obligation

**Stop here:** the implemented guest and independently expected wrapped image are absent (C 184, 230–234; N 68, 84–86). Consequently this source review cannot promote the contract to a verified receipt or native application. The exact effective dependency graph and Arkworks 0.6-to-0.5 checked VK/proof/input boundary are also unqualified (C 98–108; N 70–80). Equal control roots or matching source assertions do not establish interoperability, canonical acceptance equivalence or proof performance.

The smallest separately testable prerequisite is **checked v6 public-bundle verification compatibility across those exact inner-verifier implementations**. It needs an independently identified retained public rehearsal bundle, the pinned 328-byte v6 VK, exact 128-byte proof, 377-byte authorization and its two ordered ciphertexts, the two independently derived 128-bit inputs, and the effective dependency identities. The required claim is canonical byte/field agreement and verification of that same bound statement, not merely acceptance of a different built-in key. No compatible two-bundle pair was selected by C, and one-bundle compatibility would not supply one or close the guest/image/native gates. Build/runtime resource needs and future guest/proof costs are unmeasured. This names an obligation only: it provides no command, runnable fixture, execution release or resource allocation.

## Direct primary-source anchors checked

Project source was read with `git show` at **`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`**:

- `poc/shared-pool/src/two_input/mod.rs:24–112,158–178`: exact authorization framing, two hash limbs, and separate domain/reserve/ciphertext binding.
- `poc/shared-pool/src/two_input/circuit.rs:109–145,158–218,223–278`: private ownership/membership, real/dummy NFs, output constraints, bounded conservation and authorization-digest inputs.
- `poc/shared-pool/src/two_input/covenant.rs:597–634`: ordered ciphertext hash, two native field inputs, embedded VK, `0x20`, and 128-byte proof requirement.
- `poc/accelerated-bn254/common/src/lib.rs:66–128`: old built-in key versus caller-validated program key; checked canonical proof/arity checks. The constructor itself does not validate a new v6 key.

Native source was read at **`01b532e8b553523216471682649693af92f0fd16`**:

- `crypto/txscript/src/zk_precompiles/risc0/mod.rs:83–136` and `rcpt.rs:98–156`: exact stack fields, Poseidon2 restriction, receipt integrity/control checks and claim binding call.
- `crypto/txscript/src/zk_precompiles/risc0/receipt_claim.rs:50–100`: expected image/journal, success and empty-assumption claim.
- `crypto/txscript/zk-sdk/src/zk_to_script/builder/commit/succinct.rs:14–34` and `builder/proof/succinct.rs:12–42`: image/control commitment and caller-owned versus fixed journal digest.
- Cached `risc0-zkvm-3.0.3/src/receipt.rs:272–293`, SHA-256 `5b7b75d7f17eae46517f78129e1235145f204a7b4d73104f922da4d1b542b1a6`: digest of raw journal bytes. This file was read as data only.

The checked files' hashes matched C/N's source identities. This narrow agreement is not a new audit of those proof systems, a native acceptance result, privacy evidence, or an endorsement of a complete batch-pool design.
