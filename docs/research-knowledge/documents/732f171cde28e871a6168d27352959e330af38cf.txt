# Actual ordinary TN10 mining

**46.62340004 free test KAS in exact fresh-wallet coinbase UTXOs was observed.**
The released run submitted 16 unique blocks, received 16 RPC success reports, and
finished in 154.449 seconds. The observed UTXOs, rather than the submission
reports, establish this bounded reward result.

- The exact reviewed miner, SDK and public receipt were used. No private key,
  backup, wallet signing, transaction spending, mainnet endpoint, new daemon or
  GPU software was involved.
- Every submitted hash had one durable intent and one response. All 16 retained
  body hashes were recomputed successfully. No hash was submitted twice; no
  response was unknown or rejected. Raw block journals and detailed per-block
  status remain outside Git.
- Fourteen workers used 1,715.988801 CPU seconds, 752,730,112 bytes peak memory,
  and zero swap. All workers exited successfully; the owned unit was stopped
  and verified `inactive/dead`, `MainPID=0`, with launcher status 0.
- At the final mining observation, current DAA was 604885932 and 17.48114106 KAS
  was already mature. The remaining coins still required the 1,000-DAA maturity
  check. A separate reviewed collector must obtain actual current outpoints,
  amounts and maturity before any ordinary consolidation.

This is free testnet funding evidence. Ordinary 21 KAS A / 21 KAS C funding,
privacy-protocol deposits, settlement, exits and confirmed privacy payouts remain
separate operations. The selected public validating node and its network,
template and UTXO responses remain trust assumptions.

Machine-readable evidence: [MINING-RESULTS-01.json](MINING-RESULTS-01.json), SHA256
`4fc17c89ec4d4d5e293355b432c8b6003d8584793a650c84e5c848ff8b916a06`.
Root review SHA256:
`93c1d917e7e49ec4de58565554d5a7e7bf455fac2b54ea3d289205ff59213af0`.
