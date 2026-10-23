# Publication boundary for repeated-spend controls

This additive clarification preserves the accepted ADR-0055/common-contract
bytes and the six-local-proof count. It changes no circuit, native check,
privacy threshold, old experiment or genuine live workload.

## Finding

Alternative preparations spending the same positioned note keep its original
real NF while resampling the dummy NF. Publishing both pairs reveals their
intersection and identifies the real NF/slot. This does not alone identify the
historical CM, but defeats that padding ambiguity. A new founding outpoint alone
does not fix it: the original NF binds domain, note CM and position.

## Selected evidence handling

- Keep all unbroadcast main/retry body, Auth, NF, ciphertext and raw proof bundles
  private when they could share real claims with live actions. This remains true
  after the live cashout confirms. Actual accepted-chain bodies are already public.
- Publish source, scoped native/proof outcomes, integer reconciliation, measured
  resources and opaque hashes of the selected final local proof/Auth when needed
  to establish distinct statements. Publish no private witness/input hash/path,
  receipt/index/owner map, or unselected sizing/quote candidate digest.
- The sixth local proof uses an independent **PUBLIC_SYNTHETIC_DO_NOT_FUND**
  owner/recipient/note/state and fake outpoint under the same fresh VK. Privately
  assert that both NFs and every CM are disjoint from the main trace, and export
  only the disjointness boolean. Its complete public test body can be retained;
  it is not another canonical trial or simultaneous accepted spend.

The original same-first-change C0 fork proposal remains a retained design
proposal, superseded before execution/publication. It was not silently scored
as a privacy result. No previous closed files are altered. General retry,
mempool and orphan-disclosure privacy remain separate questions.
