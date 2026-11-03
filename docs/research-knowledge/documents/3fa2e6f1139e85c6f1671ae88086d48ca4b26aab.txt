# Two fresh public owner proofs

Both new compact2/P0 child proofs passed local genuine Groth16 verification for
the selected capacity-fresh domain/profile. Each owner ran separately with the
network unavailable, the original controller/backup paths absent, one own
witness FD and exact whole-PK READY before deriving its known-public unsafe
seed. The selected public outputs are under `public-components-01/`; its
26-file manifest is SHA256
`07e32656d86f4e81a8a0dcba96d4c65765d01bc7da277d49f90ab5decb2b4ec4`.
The nine reviewed producer files remain at source freeze02
`352a4add90fd970e4f60a1243822889c1f773eba13e68340cfc2c745534610b5`.

| Quantity | Owner0 | Owner1 |
| --- | ---: | ---: |
| Net requested invoice, sompi | 1,000,000,000 | 1,000,000,000 |
| Explicit recipient exit credit, sompi | 18,023,200 | 18,023,200 |
| Recipient gross note, sompi | 1,018,023,200 | 1,018,023,200 |
| Allocated outer fee, sompi | 9,254,000 | 9,254,000 |
| Sender positive change, sompi | 972,722,800 | 972,722,800 |
| Namespace wall time, seconds | 12.357 | 12.051 |
| Prove + local checked verification, seconds | 8.826 | 8.577 |
| Reported Rayon workers | 14 | 14 |
| Systemd scope CPU, seconds | 67.371039 | 65.446481 |
| Systemd scope peak memory, bytes | 5,473,562,624 | 4,334,661,632 |

The constructed R0 is 4,000,000,000 sompi; after two children R is
3,981,492,000, exactly R0 minus F0 minus F1. No deposit/backing or accepted
chain history is claimed. Each proof spends only its actor's original own2B
note; owner1 also recognizes owner0's incoming invoice from the public prefix,
without spending it. Each payment has exactly one invoice and positive sender
change, using existing serial compact semantics. This is not a privacy redesign.

The fixed F=18,508,000 and exit credit were selected from the actual-image
public sizing skeleton, reference SHA256
`de7d9d545a81b1eab52a22cbec2dab3b84fd7a999786399448afd4ef05778103`.
The settlement lane subsequently checked both genuine proofs and full public
component semantics, then normalized the actual W body: F=18,508,000,
mining mass185080 and storage mass1 exactly matched the provisional selection.
No fee/credit reprepare was needed. Its separate result is recorded under
`../settlement/native-body-codec-01/RESULTS.json`, SHA256
`1f9fcf7ad1819f7910019aca6eadb60d3eb7e027905baa6fc414eac73f9253dd`.
All remaining wrapper
authority/currentness/NF obligations and the outer proof/native check remain
the settlement lane's responsibility.
Changed effects or fees require new authorizations/proofs. The individual
virtual bodies explicitly fail the standalone reference fee; they are proposed
new-wrapper components, not transactions that acquire old-policy spend
authority on their own. The supplied `RESULTS.json` retains that failure.

This phase adds no outer/native/chain acceptance or permissionless-exit result.
The recovery lane separately receives one original backup per unsafe setup
actor, with no actor label in the exact existing backup schema, to recover all
incoming and change claims from public history. The additive setup helper's
canonical path correction is recorded in `SOURCE-ADDON-04.json`; its two
pre-seed negative controls and independent source review passed. No backup,
seed, witness, discarded preparation or global output-purpose map is in the
published component manifest. Both owner processes have closed. Systemd scope
records supply the reported CPU/memory figures; launcher-only `time` rusage is
not presented as prover usage.

Both actors know their crosspayments. An attacker experiment involving only
these two participants can have zero unknown third-party economic targets;
successful mechanics cannot turn that denominator into privacy evidence.
