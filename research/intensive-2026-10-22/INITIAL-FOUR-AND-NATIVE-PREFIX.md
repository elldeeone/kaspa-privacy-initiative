# Initial four proofs and native prefix: closed evidence

**Result:** four fresh, genuine v6 inner proofs and the generated founding → bootstrap → ADMIT native prefix passed their stated checks. The final native prefix is `(CM count, NF count, reserve) = (5, 2, 1,660,000,000 sompi)`. This is a **DO_NOT_FUND offline fixture under supplied synthetic seed UTXOs**, with `accepted_chain=false`.

This packet closes only the initial producer and native prefix. The paired guest/proof/native transaction has separate owners and evidence. The owner CLI/public replay job was rejected by automatic tool-safety review and remains parked. No owner DRAIN proofs, restored-key proof, independent exit workflow, funding, broadcast or completed owner lifecycle are claimed.

The adjacent [manifest index](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/research/intensive-2026-10-22/INITIAL-FOUR-AND-NATIVE-PREFIX.manifest.json) records exact paths, sizes, SHA-256 values, historical source resolution and this closure's checks. It indexes files in place; it does not duplicate the proving key or build caches.

## Instance and source identity

Base: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`, branch `work/s7-owner-lifecycle-20261022`; design: [ADR-0037](/home/luke/projects/kpi-intensive-2026-10-22/integration/docs/adr/0037-offline-continuing-s7-owner-lifecycle.md). The unchanged v6 relation is `KPICU06`, two SHA-256 digest limbs, with a fresh untrusted single-party OsRng setup. Public deterministic wallet labels are test identities; note randomness, ciphertext randomness and setup/proof randomness are fresh. Toxic setup scalars and RNG state were not serialized.

| Fixed identity | Value |
| --- | --- |
| Inner domain | `94e85656f6425a159b459c3d4e15979db396889e44ba09ef1061aa44eb1bfea7` |
| Separate pool ID | `c25ff361ac94fee2316b1d50eccae08e5a2af78db6d1407233e255775a7362af` |
| Inner VK, 328 bytes, SHA-256 | `28ae722b8a01773a8abdef4825b32af1b03c1ee9498b75b9516419a947010e28` |
| Selected new state guest image | `e21ab79e3aebdaba0355680d6a17bf0142bf0b3b5bbb687a6f2726499282a0d3` |
| Initial producer `fixture.rs` SHA-256 | `32f2044f22a3df0ddc315dbdcefd480779f6907c038faf2aa61bef6a0df061f7` |
| Initial selected binary SHA-256 | `469234cbd26ae0ffb1411e61dce9420a243a990c95d6af478b5f5bc96be2ca7c` |
| Additive finalizer `fixture.rs` SHA-256 | `3ee0ec70777ba940cceea71578742b57d445b54876bf1706949be60b374759c1` |
| Finalizer selected binary SHA-256 | `0a829a28aa082c9f6fafa959fe0b3dd0d043cec858e3ee2a5011b3bf7176d961` |

The initial default-off producer was frozen, built and run before the native finalizer was appended. Both exact source versions survive in their stage `source-snapshot/` trees; both binaries survive as `selected-producer` / `selected-finalizer`. The live build-target binary and live source paths were subsequently superseded intentionally. Historic manifests resolve to the retained snapshots, rather than pretending those live paths still contain the initial version. The finalizer enables `s7-native-policy`; its only new dependency edge names the already-transitive `kaspa-txscript-errors` at the existing pinned Kaspa commit `01b532e8b553523216471682649693af92f0fd16`.

## Four genuine authorizations

All amounts below are integer sompi. Every proof has **4,372,824 constraints**, passed circuit satisfaction and fresh Arkworks 0.6 proof verification, and was saved as Bundle JSON plus exact `A377 || Q128 || ciphertext-pair370 = 875` bytes.

| Statement | Real inputs | Intended outputs | Fee |
| --- | --- | --- | ---: |
| Bootstrap | Alice 800,000,000; one padding slot | Alice 400,000,000 + Alice 360,000,000 | 40,000,000 |
| ADMIT | Bob external deposit 940,000,000 | Bob 450,000,000 + Bob 450,000,000 | 40,000,000 |
| Pair bundle 0 | Alice 400,000,000 + 360,000,000 | Bob 400,000,000 + Alice 320,000,000 | 40,000,000 |
| Pair bundle 1 | Bob 450,000,000 + 450,000,000 | Alice 500,000,000 + Bob 360,000,000 | 40,000,000 |

Both paired SPENDs use the genuine common count-5 anchor and four distinct active nullifiers. Eight recipient-delivery checks used the known intended fixture recipient to decrypt each generated ciphertext and compare its exact plaintext and commitment: `AA / BB / BA / AB`. These checks ran before preparation was frozen and again before setup; they are output consistency checks, not a wallet scanner or privacy result.

The [public proof manifest](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/initial-four-public-fixture-20261022T1415/public/initial-proofs-manifest.json) has SHA-256 `c1b6f41fe0d8fc554cb19d89ba58a0c035bb37a2e90bfb0fabeeea618d62df33`. The independent stdlib [public oracle report](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/research/intensive-2026-10-22/lifecycle-oracle/public-initial-four-check/oracle-result.json) re-derived framing, roots, permutations and next-state bytes from its fixed public allowlist. It did not read openings, wallets or the PK, or verify Groth16/native validity. It preserves raw-lex public ordering, numeric little-endian indexed-NF ordering and complete-record multiplicity. Its count-7 root is a committed CM prefix, not a separately accepted native state or a qualified owner anchor.

The public PK remains at [proving-key.bin](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/initial-four-public-fixture-20261022T1415/public/proving-key.bin): **962,197,520 bytes**, SHA-256 `9a10b69c6354d72ed39b2f4f65375701dda52508eeb21bafcbc3b1f9ae032102`. It was streamed through a buffered writer, flushed/fsynced and hashed in a bounded-memory read. The root's [stored-file check](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/research/intensive-2026-10-22/root-stored-public-pk-integrity.json) also matched its serialized VK prefix. The four proofs used the in-memory setup key; **no complete PK reload or proof from the restored file has run**.

## Actual native prefix and accounting

Two explicit supplied synthetic seeds begin the fixture: Alice 1,000,000,000 and Bob 1,040,000,000 sompi. Bob's actual signed ordinary funding parent produces the independent 940,000,000 admission output; it does not depend on the reserve/image. The synthetic seed outpoints have no claimed accepted ancestry. Founding creates an 800,000,000 reserve and initial commitment; bootstrap authenticates that initial liability against the actual declared reserve input before ADMIT. The prefix is `(1,0,800M) → (3,2,760M) → (5,2,1660M)`. Thus pool inputs `800M + 940M = 1660M reserve + 80M pool fees`; ordinary founding/Bob funding fees are separate.

Every body passed exact JSON roundtrip/ID comparison, official pinned Kaspa isolation and `TxValidationFlags::Full` against its supplied UTXOs, all-input VM metering, and the helper's explicit standard-script/block-mass/default-fee checks. This is not an actual Mempool or chain-acceptance test.

| Body | All-input script units | Estimated bytes | Compute / storage / transient mass | Mining mass | Actual fee |
| --- | ---: | ---: | --- | ---: | ---: |
| Bob funding | 100,001 | 318 | 2,038 / 10,205 / 1,272 | 10,205 | 1,020,500 |
| Founding | 100,001 | 319 | 2,049 / 5,263 / 1,276 | 5,263 | 526,300 |
| Bootstrap | 14,972,602 | 30,141 | 200,511 / 65 / 120,564 | 200,511 | 40,000,000 |
| ADMIT | 15,029,161 | 30,261 | 201,631 / 0 / 121,044 | 201,631 | 40,000,000 |

The new native reserve profile uses budget 1700 and a measured 17,810-byte emitted body padded to 24,576; canonical scriptSig is 24,709 bytes. Passing these bootstrap/ADMIT bodies does not qualify its unexecuted DRAIN branch. Default rate 100 passes. Arithmetic quotes at rate 200 require 40,102,200 / 40,326,200 sompi for bootstrap / ADMIT, so **both 40M fees fail**; rate 500 also fails. These retained fee negatives were not repaired by changing amounts or checks.

The [native-prefix manifest](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-native-20261022T1431/public/initial-native-manifest.json), SHA-256 `ba312b9040f8b546ebf63ad4b67cdb2761d6224b86da3deb7c8a09256cd7e544`, links all bodies, spent UTXOs and validation records. The exact prior `S7[105]` hash is `c282d73547faa9e31d92e8f40fb7537898e81cf1146b9fc1eddbc30545d6e2b0`. ADMIT's actual raw outpoint is:

```text
c2fb1044efc0afd7c5d5c820813f67234b2734e497196424f9995876ecf6f0d700000000
```

It is `admit.id().as_bytes() || u32le(0)`, with no reversal. The [provenance record](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-native-20261022T1431/public/admit-outpoint-provenance.json) retains display/raw equality, canonical body hash, payload hash and exact V1-rest preimage. The [two-field oracle tuple](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-native-20261022T1431/public/oracle-pair-context.json) binds that raw36 to reserve `1660000000`; it is input to the separately owned paired-state assertion work.

## Runtime and retained failure

| Stage | Wall seconds | CPU seconds | Peak RAM bytes | Bound: CPU / RAM |
| --- | ---: | ---: | ---: | --- |
| Stopped wrong-cache build | about 120.07 | 238.484 | 2,061,377,536 | 2 / 3 GiB |
| Correct warm build + prepare | 30.205 | 53.636 | 986,415,104 | 2 / 3 GiB |
| Fresh setup + four proofs | 364.414 | 2,330.398 | 8,235,835,392 | 8 / 12 GiB |
| Finalizer source build | 19.696 | 58.223 | 1,079,488,512 | 4 / 5 GiB |
| Native prefix execution | 0.0646 | 0.0598 | 9,990,144 | 2 / 3 GiB |

There was **one** stopped producer build attempt, retained at [producer-source-build-20261022T1415](/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/producer-source-build-20261022T1415/stopped-for-correct-warm-cache.json). Rust 1.97/host-path fingerprints invalidated a copied Rust 1.95 `/src`/`/cargo`/`/target` cache, triggering dependency/C++ rebuilding. It was stopped before producing a binary, preparation, setup or proof. Its launch, source identities and logs remain intact. The replacement used the correct Rust 1.95 mounts and passed; there is no second failed producer attempt in this packet.

All executed stages used owned bounded units, zero swap and offline builds or an unshared-network runtime. Setup and native-prefix selected inputs were rehashed before and after execution, with identical results. The native finalizer mounted only its 17 named immutable public inputs/binary/policy files; no PK, producer plan or wallet artifact was mounted. All five owned units are now inactive/dead, PID 0, with empty cgroups. Closure only rehashed retained files and wrote this report/index; it ran no additional proof, test or native transaction.

The broader symbolic `1740M = 1500M payouts + 240M pool fees` lifecycle remains a design/accounting statement. The parked owner workflow and absent post-pair owner DRAIN proofs prevent a completed lifecycle, collector-independent exit, secrecy or fundability claim.
