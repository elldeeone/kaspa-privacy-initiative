# Exact-SHA circuit cost reduction

**The first frozen full synthesis passed:** 3,497,893 constraints, down
1,152,640 (**24.79%**) from 4,650,533. The required Groth16 FFT domain falls
from `2^23` to `2^22`; including the three instance variables leaves 696,408
constraints of headroom below the boundary.

| Observation | Baseline | Isolated candidate |
| --- | ---: | ---: |
| Constraints | 4,650,533 | 3,497,893 |
| Witness variables | 4,612,281 | 3,459,641 |
| Instance variables including one | 3 | 3 |
| Complete sizing relation satisfied | yes | yes |
| Required FFT domain | 8,388,608 | 4,194,304 |
| Synthesis wall time | 42.27 s | 33.25 s |
| Synthesis peak process RSS | 1,080,448 KiB | 957,832 KiB |
| CPU quota | 4 | 2 |

The differing CPU quotas and this synthesis workload do not establish a proof
speedup or wallet RAM result. **No setup, key loading or proof was run here.**
The prospective pass criteria, source review and immutable binary/runtime were
frozen before the single full synthesis. Both owned units exited successfully
and are inactive with PID zero; networking and swap were disabled.

## What changed

The isolated `poc/exact-sha-cost-probe` copies the existing private transfer
relation and adapts the pinned Arkworks SHA-256 gadget. Only choice and majority
inside the SHA rounds change to equivalent Boolean selection expressions:

```text
Ch(e,f,g)  = e.select(f,g)
Maj(a,b,c) = (a XOR b).select(c,a)
```

For three variable bits the combined cost falls from eight constraints to
three. Majority uses the original expression on constant operands, preserving
constant folding. Schedule expansion, additions, streaming, SHA padding and
feed-forward remain byte-identical to the pinned source. The independent
[source review](sha-source-analysis.md) mechanically checked that difference.

Ten cheap tests passed, including 64 Boolean value/allocation combinations and
15 SHA message lengths covering padding boundaries and every circuit hash size.
The [known-answer scope](KNOWN-ANSWERS.md) and [build result](build-01/RESULT.json)
retain those checks. The [full synthesis result](measurement-01/RESULT.json)
uses the unchanged public sizing witness, with transcript-bound placeholder
NF/next-CM roots. It is a complete private-relation synthesis, not an actual
native or chain state trace.

Ownership, s+k authorization, positioned HMACs, dummy-slot behavior, raw-CM
membership, integer bounds, conservation and transcript binding are unchanged.
No HMAC merge, domain/format change, alternate primitive or active-trial edit
was included. The old production sources and all existing keys remain unchanged.

## Implication and remaining check

The smaller domain directly reduces FFT vector and H-query dimensions, making
this a useful next prover experiment. Actual proof latency and total prover RAM
must be measured; neither a sub-4-GiB wallet nor a ten-second warm proof is
claimed from synthesis.

The R1CS matrices changed, so **a fresh setup and matching verification key are
mandatory before proving or native use**. Before adoption, run the existing
17 authority/padding/binding/integer negative controls against this isolated
circuit, then one fresh matching setup, proof and native validation. Preserve
current testnet trial evidence and its immutable policy/key. Passing these
checks would still not constitute cryptographic review or establish privacy.
