# MWEB recipient extension: independent source/result review

**ACK for the narrow recipient-separation component boundary, with one fresh-verifier caveat below.** This review inspected public source and retained public results only. It did not execute a builder, verifier or experiment, inspect binaries, or read private material or original work directories.

## Exact reviewed identities

- Extension freeze: `425bd8c5947e29db8d3aa20333b761603ce9611d1656a6d1126e980398a95e00`, at `privacy-components/recipient-extension/SOURCE-FREEZE.json`.
- `poc/mweb-component-screen/recipient/recipient.cpp`: `5213a65b538cacb4f4a92c4af24446bc4eb7c34e01ac38ec2eb4481fa9f24cd8`.
- `poc/mweb-component-screen/recipient/run_recipients.py`: `fab801228bf703678ee341b0573efbc46279903991c8d968cefd62611c3764ce`.
- Extension design: `780e9cd7546c260a26ba7ec875d6877ae99ca8ce76674457f10fa8706c77df5e`.
- Upstream source commit: Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2`. The retained result names recipient binary `b93af9810a91f8a21843c70355f5259331a9257247be096c017b304ca7a506dc`; this review did not independently reproduce its build or hash the binary.

## Source findings

`recipient.cpp:54` accepts only a canonical, valid 66-byte public recipient address. Recipient scan/spend keys originate inside `recipient()` at line 74; the process exports its public address and public observations, without a private key or coin file. `run_recipients.py:45` starts two separate recipient processes before the independent senders and passes public filenames/amounts over stdin. This closes the original test-helper's sender-generated-recipient-key gap for this honest-host component test.

The known-address rewind at `recipient.cpp:32` follows the pinned production [Keychain::RewindOutput and CalculateOutputKey](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/wallet/Keychain.cpp) and [Test_Keychain restoration example](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/test/tests/wallet/Test_Keychain.cpp): standard fields and valid Ke/Ko, view tag, recovered B/A ownership, OutputMask amount/nonce and switch commitment, Ke consistency, then the recipient-derived spend key matching Ko. It uses existing OutputMask, Hasher, SecretKeys and PublicKey APIs. It replaces the wallet metadata lookup with one already-known address; it does not run the production DB-backed keychain.

`recipient.cpp:80` validates the aggregate before scanning. Lines 85–89 require one owned output of the expected amount, use its recovered Coin in production `::TxBuilder::BuildTx`, validate the spend, and bind its input ID to the recovered output. The source derives the input commitment and authorization key from the checked received output rather than constructing an unrelated input.

## Retained public result and caveat

`privacy-components/recipient-extension/run-01/RESULTS.json` records two distinct recipient PIDs, four scanned outputs per recipient, exactly one recognition each, amounts 10 and 20, and spends 9+1 and 19+1. Sender expected output IDs, recipient recovered IDs and fresh spend-verifier input IDs agree. The source/design hashes match the freeze; the result names that exact freeze and binary identity.

**The fresh public verifier is a standalone transaction validator, not an aggregate-UTXO lookup.** `run_recipients.py:74` invokes generic `verify` and then compares input IDs/counts; `screen.cpp`'s `fresh_verify` calls `tx.Validate()` without the aggregate as context. It does not independently compare the spend input's commitment and output authorization key against the aggregate output. Those checks are present in the recipient source. Claims that the fresh process itself independently confirms all three received-output fields exceed this exact check. Such a claim needs an additional public comparison of ID, commitment and authorization key, or must retain this source-checked honest-recipient boundary.

No financial privacy threshold, native KAS compatibility, accepted funding/chain state, hostile-host isolation, malicious-sender coverage, seed/index scanning, cold backup recovery or production-security conclusion follows. Public spent IDs and coordinator/grouping, amount and sparse-timing limitations remain.
