# Independent recipient public-address extension

Status: separate fresh experiment and source freeze, before implementation or data generation. The original component run/source/plan and its C1-label scope correction remain unchanged. No statistical privacy thresholds or old workloads are retuned.

## Problem and established APIs

The default upstream test helper generates recipient keys inside the sender process. Test actual recipient separation instead: two recipient processes each create a StealthAddress with their own private scan/spend keys, publish only its66-byte serialized public address, and retain secrets in memory while waiting. Each sender sees only the corresponding public address and declared amount, plus its own independently generated local fixture input.

Use the actual production `::TxBuilder::BuildTx` and unmodified underlying Output/Signature/Bulletproof/balance code. The production `mw::Keychain::RewindOutput` requires wallet metadata/LegacyScriptPubKeyMan and DB infrastructure; do not introduce a fake DB or claim that whole wallet ran. For one registered address, reproduce the exact public-address recovery sequence in official `Test_Keychain.cpp` using existing `OutputMask`, `Hasher`, `SecretKeys` and PublicKey APIs: view tag, receiver B ownership, masked amount/nonce, reconstructed commitment, Ke sender consistency, and recipient-derived spend key. This is a known-address component adapter to the established algorithm, not a new primitive or full wallet implementation.

## Fixed workload and process boundaries

RecipientsR1/R2 are independent live processes. SenderA declares local synthetic owned input25, paysR1 amount10, keeps change14 and fee1. SenderB declares input40, paysR2 amount20, keeps change19 and fee1. Funding is an unfunded locally declared peg-in fixture, never a canonical or accepted-chain claim. Input amounts and every sum use integer test units.

The aggregator receives only public serialized sender components. A fresh verifier validates the aggregate. Each recipient then receives the same public aggregate, validates it and scans every output; require exactly one recoverable owned output of the requested amount and a derived spend key matching the output authorization key. Sender-generated change and the other recipient's output must not be accepted as this recipient's own. Each recipient signs a fresh spend using the production TxBuilder, paying fee1 and creating an output of amount9/19 to its own address. A fresh public verifier validates both spends and their actual input references/commitments/authorization keys match the aggregate's received outputs.

Recipient private keys remain in their original live process; there are no private key/coin files, hashes, export to senders/aggregator or main-project key reads. The controller sends public filenames over stdin and receives public address/readiness and successful amount/output-ID observations only. This is process isolation under an honest host, not defense against a hostile shared-memory debugger/root or a claim that senders cannot know output values/blinds.

## Required observations and retained failures

Require upstream signature/range-proof/kernel/stealth balance validation, proper recipient-origin public address, recipient recovery/private spend authority and exact input-output matching. Record producer stdout source and process IDs to distinguish actual recipients from fixture metadata. No operator-held shared spend key, custom crypto, rule weakening or network/chain operation is introduced.

The final format, public spent IDs, original kernel/offset features, known pre-aggregation grouping and singleton/timing failures remain visible. C1's actual own receipt/opening knowledge is stronger than the original known-output JSON marker; do not manufacture an anonymity score or transfer this component behavior into the KAS policy. Any KAS hidden-membership/value-binding adaptation remains a separate reviewed architecture.

Bounded compile<=4CPU/6GiB; yield to the root's R0 proving window. If existing APIs require unavailable node/DB environment beyond this known-address adapter, retain that limitation rather than implementing new cryptographic logic or installing unrelated infrastructure.
