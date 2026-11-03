# Unfunded private-exit lifecycle result

The complete seven-transaction supplied-context lifecycle passed native Full
validation, using four genuine proofs under one fresh VK. Both original-nullifier
competing-spend orders also behaved as predicted. No testnet transaction was sent.

| Main stage | Actual fee, sompi | Native payout, sompi | Reserve afterward, sompi |
|---|---:|---:|---:|
| Ordinary funding preparation | 911,400 | 0 | — |
| Coherent founding | 2,574,600 | 0 | 60,000,000 |
| Admission | 5,256,200 | 0 | 2,018,958,700 |
| Private payment to Bob and Charlie | 18,958,700 | 0 | 2,000,000,000 |
| Bob partial private exit with private change | 18,999,900 | 200,000,000 | 1,781,000,100 |
| Bob full claim private exit | 18,999,900 | 762,000,200 | 1,000,000,000 |
| Charlie terminal private exit | 18,957,600 | 981,042,400 | 0 |

All seven actual predecessor links, every input ScriptEngine and exact fees
passed. The terminal has one native payout, no successor reserve, no commitment
append and no recognized positive liability for Alice, Bob or Charlie. Final
counts are CM8/NF9. The complete 4,000,000,000-sompi source reconciles exactly:
1,914,873,700 ordinary source change + 57,425,400 founding change + 1,943,042,600
native payouts + 84,658,300 fees.

Full attributable fees are 51,850,250 sompi for Bob and 32,808,050 for Charlie,
splitting the common ingress/payment fees equally and counting each 1B-sompi
useful payment once. These are 5.185025% and 3.280805%; their weighted mean is
4.232915%. The unchanged 2% lifecycle fee target fails. These are actual complete
body fees at rate100, not the verifier-only lower bound or a rate200/500 acceptance.

The separately accounted race branches passed all three expectations:

1. Bob's original valid REVEAL accepts from the actual private-payment output.
2. A correctly signed old REVEAL against the actual post-private-partial state
   rejects its authentic, currently occupied original NF at 62,365 units.
3. A fifth genuine ownership proof against the actual post-REVEAL current state
   rejects its authentic occupied original NF at 171,845 units.

Both negatives return Full `SignatureInvalid(VerifyError)` and engine
`VerifyError`, below the 14,750,000-unit Groth16 floor. The losing private body
differs from its reviewed body only by insertion of the exact genuine proof128.
All three current-output links were checked; fork payouts are excluded from
mainline accounting. Independent review closed both actual result packets.

Before any actual body/proof fixture, raw random dummy padding was replaced by
the existing cryptobox seal of random216 plaintext to a one-shot delivery key.
The old source and zero-runtime boundary are retained. This removes the identified
X25519-prefix discriminator; it establishes neither general indistinguishability
nor device-memory erasure. The original two-real-output setup shape was unchanged.

All secrets/witnesses are public synthetic fixtures marked **DO NOT FUND**.
Native validation uses supplied funding/current-history/archive context and the
selected source-adapted native fixture; it is not accepted-chain or unmodified
testnet relay evidence. Five resident proofs took 7.989–8.293 seconds each,
including parse and checked verification; this is not a p95 qualification.
Financial privacy, independent network recovery, durable public data, confirmed
testnet payouts and production safety remain outside this result.

Exact main result: `main-execution-01/RESULTS.json`, SHA256
`e288a32d10428415742a5c44a408bfb3f2368bd42fa86de63b6d1763ee2ce6c9`.
Exact race result: `race-execution-01/RESULTS.json`, SHA256
`f40ce9ebfcfc88399ff9aa939930c5630e5e0fd1dc472e033cf63633f98b067a`.
