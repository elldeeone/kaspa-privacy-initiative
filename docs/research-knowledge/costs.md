# Cost and performance lessons

[Knowledge guide](README.md) · [Proof evidence](proofs.md)

## Keep profiles and denominators together

| Retained result | What it says | What it does not say |
| --- | --- | --- |
| [matched lifecycle checkpoint](documents/fdfd544f40bd93450cab30c7bda64dcab3ec69fa.txt) | Six payments/nine payouts paid 264,166,000 sompi on 2,100,000,000 useful sompi: 12.5793%, failing 2%. | Faster payment proving alone cannot repair the measured fee gap: other costs alone remain 148,795,600 sompi, above 42,000,000. |
| [two-recipient offline layout](documents/e26b3bf00641382ebabf9b4b577cc31ee1c27d7d.txt) | The separate offline supplied-UTXO layout with two useful 10-KAS recipients calculated approximately 1.85% per payment. | It was not broadcast, is not the same benchmark, and one useful recipient plus change failed. |
| [authenticated cache measurement](documents/90a8571364109e2cb5f360b33e966fedd0ca7308.txt) | Parameter loading fell from 156.38 seconds to roughly six seconds; one genuine load/prove/verify run took 30.87 seconds. | About 5.39 GiB and missed warm-proof/memory targets remain; cache/CPU conditions prevent a universal speedup claim. |
| [selected HMAC sizing](documents/7eb487100c8e69f48abe417e7bcd98c681b24e3b.txt) | The selected synthesis reduced constraints by 31.20%. | That sizing packet did not complete setup, proving, native validation and the full negative suite. |
| [independent RTX 3070 reproduction](documents/b3ed0a758e9200456318a9e26b8342db78d5c327.txt) | Four retained outer receipts completed in 627.3 seconds on RTX 3070 under the documented adaptation. | Do not extrapolate another curve, proof profile or GPU from that timing. |
| [compression qualification note](documents/4b69b4e8de333d2e96ec10eb2ddc82474a7e4ee6.txt) | A selected compression run measured sampled VRAM and process memory separately. | A setup file's size is not a VRAM formula; sampling may miss peaks, and an upstream benchmark row with RAM=0 means unmeasured. |

Compute mass, storage mass, transient/overall mass, committed script budget,
units consumed and paid transaction fees are different quantities. Use final
SDK-decoded transaction bytes and the actually selected policy for quotes;
separate quotes, local Full validation, relay policy and paid chain evidence.
A cheaper bare verifier is not a cheaper complete lifecycle.

## Carry into the next measurement

Use integer sompi end to end. Include deposits, funding, private transfers,
change, all exits, rent, pool/sponsor fees and useful-recipient value under the
same declared accounting scope. Report remaining principal, liabilities and
state rent independently. The successful depth-four attempt's zero user
principal does not recover earlier halted attempts' retained test-KAS reserves.

Current tool/process repairs improve reproducibility; they establish no new
GPU benchmark, cryptographic performance result or paid-fee result. A useful
optimization is a candidate to assess when its component is needed, not a reason
to restart an unrelated proving campaign.
