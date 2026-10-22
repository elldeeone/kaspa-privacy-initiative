# Historical state assertion results

One genuine historical n5→9 assertion was proved on the local RTX 3070, compressed
without re-execution, independently verified in software, and accepted by a
separate pinned native full-input-script checker in a synthetic transaction
context. **This is NONFUNDABLE, one-shot local evidence.** The successor cannot
continue the fixture's designated-predecessor policy; accepted lineage, backing,
direct owner exits, durable proving parameters and chain acceptance remain open.

## What was checked

The unchanged two-v6 gate verifies the same two genuine public development
proofs and P1088. The separate state core adds authenticated historical anchor
membership, four sequential current indexed-NF insertions, four ordered CM
appends, two odd-prefix history appends and checked integer-sompi reserve
subtraction. Fixed 11,219-byte input and J336 were independently reconstructed before
compilation. Both current n3→7 and historical n5→9 contexts match every expected
prior/next-state and journal byte. No new inner setup or proof was needed.

Fourteen core tests and four wrapper tests passed using the host's pinned
dependency graph. Real guest execution passed both positives, 16 specific
semantic rejection cases and two valid context changes producing exact changed
journals. The independent authenticated already-spent NF fixture specifically
rejects `NullifierOrder(0)`. Nonuniform txid/index bytes test journal byte order.
Valid reserve/outpoint declarations are not presented as guest authentication of
actual native context.

| Measured stage | Result |
| --- | --- |
| Current guest execution | 77,648,566 user cycles; 170 segments; 1.482 s |
| Historical guest execution | 77,648,328 user cycles; 170 segments; 1.480 s |
| Historical Succinct proof | 303.363 s; 223,898-byte receipt |
| Same-receipt Groth16 compression | 4.361 s; 1,169-byte receipt; 256-byte SDK seal |
| Proof hardware evidence | Matching worker PID 1701019 / start ticks 36920424; sampled 6,096 MiB VRAM; cgroup511,438,848B RAM; zero swap |
| Compression hardware evidence | Matching worker PID 1730123 / start ticks 36984741; sampled 5,300 MiB VRAM; cgroup1,783,369,728B RAM; zero swap |

The state additions cost 518,530 user cycles over the 77,129,798-cycle J42 pair
guest, about 0.67%. This is one implementation/input comparison, not a general
proving-cost bound. VRAM was sampled every 0.5 s and can miss brief peaks. RAM
figures are the owned cgroup's charge, not total machine memory or all cached
asset pages. Both owned GPU units terminated successfully; recorded PID/start
identities disappeared, cgroups emptied and an independent snapshot found no
GPU compute applications.

## Exact identities

- Selected image:
  `e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9`.
- Historical input SHA256:
  `544219aaba5b4738a546691eed6cc7b93a4cda6f2c3b158ef51fbf8c4bcbf462`.
- Historical J336 SHA256:
  `457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3`.
- Succinct receipt SHA256:
  `8ab05861de29305c8f1288a2159896da52be3d0185246ac6595ae048debdbce4`.
- Compressed receipt SHA256:
  `e01de2650193181f96f40a985f6d321bc21bae7eb01805194b40fb022b983a3b`.
- Unchanged successful source/output claim:
  `2450e2c7e083e367887ec53f3449cd4d5d62b1575b94119479997cec8ff5aaf4`.

SDK 3.0.3, official Rust 1.97 guest toolchain, bigint2 and the retained SDK 3.0.3
sm86 CUDA worker are pinned in build manifests. Exact immutable inner VK bytes
were fully host-checked before guest compilation; all submitted proof checks
remain. The established official Groth16 wrapper assets were authenticated and
mounted read-only. Both inner development setup and official wrapper setup
retain their stated trust assumptions. Compression preserves the complete
selected claim/J336; it has no executor or guest-proving entry.

The separate reviewer reran the saved Succinct receipt against selected
image/J336/P/JOIN and 21 crypto/field controls. The separately invoked compressed
verifier checked exact successful claim/J336, Groth16 profile, no unresolved
assumptions, dev mode false and 14 negative controls. Source, executable,
receipt and expected-context identities matched before/after.

## Separate native context result

The native checker at 01b532e8 used its immutable selected binary 3de6727d…63db0a4
and the genuine compressed proof, reconstructing J336 from its synthetic input,
output and P context. It accepted one positive and rejected 22 exact controls;
coherent state/P/reserve changes reached native Groth16 verification failure.
This is stronger than a bare receipt callback and remains a declared synthetic
predecessor, with no network or funds.

The report measured compute/relay/mining mass 163,290, transient 11,680 and
storage 29, within its pinned block dimensions. Native estimated serialized size
is 2,920 bytes; its 2,910-byte Borsh artifact is not P2P/RPC wire size. The actual
authorized fee remains 80,000,000 sompi. A hypothetical 100 sompi/gram quote requires
16,329,000 sompi; 500 requires81,645,000 sompi and exceeds the unchanged fee. Neither
quote lowers the actual fee or qualifies a 1% privacy/economics target.

The native report is separately owned by `poc/public-state-native-check`.
The final packet records its exact path/hash and the independent review paths.
All original J42 source, image, receipts and baseline evidence remain separate.
Passing controls is not proof of cryptographic correctness, anonymity,
production safety, permissionless exits or readiness for a funded trial.
