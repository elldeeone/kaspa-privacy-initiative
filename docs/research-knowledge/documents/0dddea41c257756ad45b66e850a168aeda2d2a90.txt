# Independent recipient recovery and spending: component result

**The separate extension passes with actual recipient-created public addresses.** Two recipient processes generated and retained their own private scan/spend keys. Senders received only66-byte public StealthAddress files. Both recipients later recovered exactly one of four aggregate outputs and spent it with their own derived authorization key; fresh public verifier processes accepted both spends.

This addresses the original test-helper limitation at the component/API level. The original helper run, its source/plan/results and [scope correction](../CLAIM-CORRECTION-01.json) remain retained. The extension has a separate [design](DESIGN.md), [pre-run source freeze](SOURCE-FREEZE.json) and fresh generated data. Neither run establishes financial privacy, accepted funding, native KAS compatibility or production security.

## Actual actor flow

1. RecipientsR1/R2 ran in separate processes and each published one public address. Their scan/spend secrets stayed resident until their process exited; no key files, private coin/opening exports or hashes were produced.
2. SenderA generated and recovered its own local declared funding fixture25, then used the **production** `::TxBuilder::BuildTx` to payR1 amount10, create own change14 and pay fee1. SenderB independently did40→20+19+1. Neither sender received a recipient's private keys.
3. Another process loaded only the public sender transaction bytes and called existing upstream aggregation/validation. A fresh process verified the result: two inputs, four outputs, two kernels.
4. Each recipient validated that public aggregate, scanned all four outputs and accepted exactly one. It checked the view tag, its own receiver address, unmasked amount/nonce, reconstructed commitment, sender consistency (`Ke`) and derived private spend key matching the received public authorization key (`Ko`). The other three outputs were not accepted as its own.
5. The recipients used the production builder to spend their actual received outputs:10→9+fee1 and20→19+fee1. Separate fresh verifier processes accepted both resulting signed/range-proved/balanced transactions. Their input IDs exactly match the recovered output IDs; the two recovered IDs are distinct.

R1's actual received output ID is `ec7911b3ae224ca5ba5ce7fa8dec160736d82d3fa798e8de6f991d5ddce17704`.

R2's actual received output ID is `8ffed90397fc629e9c615414696851af8534c23aa3b50a9d69cc3684a6a6124d`.

All amounts are integer unfunded MWEB library test units. The funding fixtures declare local peg-ins solely to exercise the library; there was no canonical peg-in, chain UTXO validation, node/daemon, broadcast, real money or KAS transaction.

## Reused code and exact boundary

All consensus/cryptographic builders and validators remain upstream-unmodified at Litecoin commit`ec1b6489a900d09cf5991e220dce089c77a232a2`. The sender and recipient spend use the actual production [TxBuilder.cpp](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/wallet/TxBuilder.cpp).

The production [Keychain::RewindOutput](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/wallet/Keychain.cpp) depends on wallet metadata/LegacyScriptPubKeyMan. This test does **not** run that DB-backed keychain. Its one-known-address adapter follows that exact recovery/check sequence and the official [Test_Keychain restoration example](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/test/tests/wallet/Test_Keychain.cpp), calling existing unmodified OutputMask/Hasher/SecretKeys/PublicKey APIs. The local address registry consists of the independently generated recipient's one known address. No new primitive, production wallet metadata implementation or weakened acceptance check was introduced.

The existing documented OpenSSL RAND_bytes fixture entropy bridge remains. Process isolation assumes an honest host; this is not protection from a root debugger reading resident memory. The senders normally know their sent amounts and output construction data; no stronger sender-knowledge claim is made. No malicious-sender exhaustive analysis, wallet seed/index scanning, cold recovery, long-term key/history retention or independent provider availability is established by this one-address test.

## Evidence and resources

[run-01/RESULTS.json](run-01/RESULTS.json) contains the two actual recipient observations, aggregate/fresh verification, both fresh spend verifications, distinct process IDs and pre-exit cgroup resource observation. The recipient source is frozen before any new draw; the original component source and workload were not changed or retuned.

The eight-process extension completed in1.513s with1.538cgroup CPU seconds and formatted38.7M peak, swap0. The exact pre-exit snapshot records40,656,896bytes memory peak, zero swap/OOM events and1,532,167CPU microseconds; final service counters are later. At capture only the controller and its timing parent remained, and the service completed inactive/dead/MainPID0. These are tiny feasibility cases, not throughput or p95 benchmarks.

## What this does and does not advance

This supplies a concrete established-component example of recipient-only private spend authority across owner-local construction and public aggregation. It strengthens the actual receiver-spendability evidence beyond the original marker-only fixture.

Public consumed output IDs remain visible. A coordinator or network observer retaining pre-aggregation components can still associate their original inputs/outputs/kernels. Singleton/early-funding timing and amount-information failures remain. No C1 anonymity/guessing threshold was tested, and possession of an actual receipt/opening is not itself an anonymity guarantee. Current SHA-note/hidden-membership/native-KAS relations and their parameters are not compatible merely because this MWEB component works. A future adaptation remains a separately reviewed architecture decision.
