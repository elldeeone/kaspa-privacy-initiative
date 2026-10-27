# Native verification: about 99.5% is the upstream schedule

**2026-10-25 UTC. The measured mixed path spends 15.5 million SU on scheduled Groth16
verification and only 62,777 SU on everything else. Direct Exit spends 14.75 million SU
on that schedule and 79,859 SU elsewhere. Script micro-optimization cannot remove
the fixed 14-million-SU base.** These are selected-VM/source findings, not an attestation
of every public node's deployed consensus configuration.

No source, case, parameter, proof, selected budget or live state changed. No new
VM runs were needed; the analysis uses retained public fixtures/results.

## Exact source schedule

The selected generic engine is SHA256
`077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061`, with
rusty-kaspa dependency pin `01b532e8b553523216471682649693af92f0fd16`.
Both branches call **`OpZkPrecompile` 0xa6 with Groth16 tag 0x20**. There is no
dedicated `OpCheckGroth16` opcode in this path.

For n public inputs, the accepted-proof charge is:

`U_Groth16(n) = 14,000,000 + 250,000*(n+1) SU`.

The base is `Gram(1000*140)` converted at 100 SU/gram. The surcharge counts every
VK `gamma_abc_g1` element, including its constant element; arity is checked before
that charge. [Tag cost](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L24-L34),
[VK surcharge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L49),
[dispatch charge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L758-L770).

The R0 [fragment](../../../../poc/local-private-payment/verification/native/src/r0_fragment.rs)
supplies five inputs and a 424-byte VK (six gamma elements). Direct
[Exit](../../../../poc/local-private-payment/verification/native/src/policy.rs#L551-L584)
supplies two digest limbs and a 328-byte VK (three elements).

| Metered component | Mixed R0 | Continuing direct Exit |
| --- | ---: | ---: |
| Fixed Groth16 tag | 14,000,000 | 14,000,000 |
| VK arity surcharge | 1,500,000 | 750,000 |
| **Crypto-schedule subtotal** | **15,500,000** | **14,750,000** |
| Other measured Script work | 62,777 | 79,859 |
| **Measured total SU** | **15,562,777** | **14,829,859** |
| Crypto-schedule share | 99.5966% | 99.4615% |

The tag charge covers a verification cost estimate; it is **not a measurement of
pairing-only CPU time**. Deserialization/subgroup checks, VK preparation, public
input preparation and final pairing verification have no separate meter
partition here. [Actual verifier calls](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L66-L118).

Official HEAD checked in this session,
`4edcbbccb449f84832afb1ca157904b35f37d006`, has byte-identical `tags.rs` and
`groth16/mod.rs`: SHA256 `b3288d447e0ea09447e6564c921389bd6d5668d6d302c8d409ded7895919ef03`
and `cb9fa14115d445c727cb8639ba384bde37d9a01f6c6f7fd1c92f77861f8a388d`.
[Current tag file](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs),
[current surcharge file](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs).

## Finite accounting of our overhead

SHA256 charges 1 SU/input byte; Blake2b charges 2. Newly produced/copied runtime
stack bytes cost 1 SU/byte. There is **no universal per-opcode SU charge**: the 1
in an opcode declaration is encoded length. Literal pushes and pure moves are
unmetered in SU, although their serialized bytes still contribute transaction
mass. [Hash pricing](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L54-L72),
[new-byte meter](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/runtime_resource_meter.rs#L47-L50),
[execution accounting](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L577-L595).

Both retained cases have a 7696-byte redeem script and a continuing output.
P2SH checks its redeem hash; `same_tail_successor` hashes the reconstructed next
redeem. Their combined Blake2b input charge is `2 hashes*7696 bytes*2`=30,784 SU.

| Non-precompile work | Mixed | Continuing Exit |
| --- | ---: | ---: |
| SHA256 input-byte charges | 4,449 | 7,156 |
| Two redeem Blake2b input-byte charges | 30,784 | 30,784 |
| Remaining runtime pushed-byte charge, inferred by subtraction | 27,544 | 41,919 |
| **Total outside precompile schedule** | **62,777** | **79,859** |

Mixed SHA preimages are 4077+104+98+170 bytes: projection, journal, R0 Output and
ReceiptClaim. Mixed NF/CM path verification runs inside R0, not native Script.
Exit hashes four depth 17 NF walks (`68*72`), three 76-byte leaves, an 1880-byte
effects preimage and its 152-byte statement. Hash result pushes belong in the
last row, not twice in the hash-input rows. The inferred push charge is
conditional on these source-identified executed paths. This is static path
attribution plus a metered-total residual, **not an opcode-by-opcode runtime trace**. Terminal
exits and other values/branches can have different residuals; the arity charge
is unchanged. [Policy helpers/branches](../../../../poc/local-private-payment/verification/native/src/policy.rs#L110-L192).

## Budget padding and wall time are separate

The retained B1557 probe allowed 15,579,999 SU, used 15,562,777 and passed with 17,222
SU headroom. B1800 allows 18,009,999, leaving 2,447,222 SU for that case. Exit B1500
allows 15,009,999, leaving 180,140 SU. Budgets buy 10,000 SU each plus the per-input
9999-SU allowance. [Conversion and covering rule](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L23),
[covering calculation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L77-L101).

The probe kept the actual 19,228,400-sompi fee unchanged. Its B1557 quote of
16,798,400 is potential pricing, not realized savings or a newly selected budget.
Current live B1800/1500 settings remain selected. Their actual chain acceptance
is a separate confirmation gate.

Retained whole-engine calls took about 0.019–0.026 seconds, including Native Full
and a separate per-input ScriptEngine recheck. This does not time one pairing,
and SU are neither CPU cycles nor seconds. R0 proving's minutes/cycles are a
different workload. No per-operation wall-time partition was measured.

## What can move the cost

| Change | Defensible effect |
| --- | --- |
| Script hash/copy/encoding optimization | Cannot save more than the entire 0.40–0.54% residual above; real safe savings are smaller. Preserve every state/effects check. |
| Faster pairing library, VK preparation cache or hardware | May reduce wall time; scheduled SU stay unchanged unless upstream pricing/runtime rules change. |
| Direct combined proof with two public limbs | Saves the 750,000-SU five-to-two-input surcharge before new native path/codec overhead; retains the 14m base. Requires the reviewed new profile described in the direct-proof memo. |
| Payment/Exit aggregation or changed verification schedule | Can amortize or change a fixed charge, but requires separate authorization/architecture or upstream protocol review and actual network support. |

Dropping digest inputs or financial binding is not an optimization. The existing
R0-succinct tag has a 25m-SU base, so switching tags is not a cheaper source-backed
escape. Local custom metering would not establish public-node acceptance.

At100 sompi/gram, the crypto-only floor is 0.1475 KAS per two-input Exit and 0.155
KAS per current R0 verification, before bytes/policy/padding. Nine independent
exits alone imply at least 1.3275 KAS (6.321% of 21 KAS) under that selected policy.
Two R0 payment batches plus those exits imply 1.6375 KAS (7.798%) before extras.
This sharpens, without invalidating or editing, the earlier coarse 1.54-KAS bound.
The 21-KAS denominator, current paid-fee record and **2% FAIL remain unchanged**.

Public evidence: `/var/tmp/kpi-local-private-payment-01/results/public/native-budget-probe-01/public-output/RESULT.json`
(SHA256 `95a568fee0665a6c828c9f8f80220d45fe8c1de9dc38d5512f2d3ab261d8cc97`),
and `native-underfee-exit-calibration-01/public-output/RESULT.json` under the same
public results root (SHA256 `db4fcedd99dcbe4d58f03dacfa7ffa82647d14f858121a45134cde5e5a9b47f0`).
The latter establishes supplied-context VM behavior, not relay/chain admission.
