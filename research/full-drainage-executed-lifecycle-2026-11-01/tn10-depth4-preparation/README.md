# Depth-four TN10 preparation evidence

**Date:** 2026-11-01  
**Boundary:** exact local wallet/native/guest evidence; no TN10 funding,
broadcast, confirmation or privacy claim.

## Exact profile

- domain: `5228579a04c43c288ae4f715a497e6b1704d18764b62f1785b21f261cfc22bc1`
- verifier: `97ef3a85e5d03956150f9802d42697a8dcbb338a32a30efc811d1b3898157e32`
- guest image: `b80aa1fa8b9553b2021be9987647046ff8c15aa77206a4db858f13bf9c9a8688`
- raw guest ELF SHA-256:
  `b9f5cb8399f47b3c804ed1ca978dcdd99096db16aeeaf66343c08c00dd1b9a13`
- wrapped guest program SHA-256:
  `f03e520e76f4fd8d756b7659da6dd7d8075fbf7ecc675dbbd41d15e8c8f8e5bc`
- experimental proving parameters SHA-256:
  `5c43a6e2d5b8206c227aa7a4158f2c4d97c2d60c14134d8fe854123d500ee907`
  (180,236,176 bytes; parameters and toxic waste are excluded from Git)

`wallet-public/` contains both fresh alternative-world transcripts. The
selected native fixture is `trial-a23e64a6a381f127`; aliases and all wallet,
native-payout and truth secrets remain outside Git in `0700`/`0600` storage.
The public audit checked eight 64-byte wallet stores against 121 public files
and found no secret half or hexadecimal encoding. The frozen public-only score
retained two known-owner gross histories and the one-history strong-observer
failure; no TN10 transcript has yet been scored.

## Exact native schedule

The seven local native batches consume 39 distinct synthetic inputs with no
conflict. All local scripts accepted the genuine path. Wrong domain/root,
cross-profile proofs, exit replay, underpayment, wrong recipient and every
applicable reserve-diversion mutation rejected. Terminal reserve principal,
private liability, pending deposits, unpaid exits and permission rent are zero.

| Batch | User cycles | Pinned / effective po2 | Proof seconds | Peak VRAM | Receipt SHA-256 |
|---|---:|---:|---:|---:|---|
| 01 | 140,115,121 | 20 / 19 | 544.527 | 6,221 MiB | `f1a87587…e51e44c` |
| 02 | 139,735,495 | 20 / 19 | 540.168 | 6,213 MiB | `e0f1b388…2ad57b6` |
| 03 | 46,274,838 | 20 / 19 | 181.541 | 6,217 MiB | `dc1a71c6…1df49f5` |
| 04 | 46,443,318 | 20 / 19 | 182.070 | 6,229 MiB | `97dbf52c…cf0c4dc` |
| 05 | 46,599,013 | 20 / 19 | 182.851 | 6,225 MiB | `585d9df5…e61a6c2` |
| 06 | 46,934,007 | 20 / 19 | 184.449 | 6,213 MiB | `b43b35c0…897159` |
| 07 | 2,850,602 | 16 / 16 | 104.776 | not sampled | `27fc4776…e1982f` |

All CPU executions matched their exact expected journals and remained below the
160,000,000-user-cycle limit. All seven batches now have 223,930-byte genuine
Succinct receipts. Separate CPU processes verified the exact journal, image,
seal and official JOIN control for every receipt; wrong image/control, journal
mutations, seal corruption and control-inclusion corruption rejected.

The original batch-1 po2-20 attempt remains preserved: it reached complete guest
execution and failed when the 8,192 MiB RTX 3070 could not allocate another
1,728,053,248 bytes. Inspection of pinned RISC Zero 3.0.3/zkp 3.0.4 source found
the supported `segment_limit_po2` resource control. Re-running batches 1-6 at
po2 19 changed only segmentation/resource use; every final receipt still bound
the exact unchanged program image, input-derived journal and official JOIN
control. Peak sampled VRAM stayed at 6,213-6,229 MiB.

The complete receipt-backed rehearsal then rebuilt all seven native settlements,
matched every frozen transaction ID, executed every issuance and payout script,
and ended with zero reserve principal, private liability, pending deposits,
unpaid exits and permission rent. The separate 100,000,000-sompi state rent
remains excluded. This is local evidence, not TN10 acceptance.

## Source/regression checks

- default wallet profile: 9 tests passed;
- new TN10 profile accounting/circuit: 8 tests passed;
- the default persisted-proof fixture rejected under the new profile at
  `domain/version/verifier/kind`, as required rather than counted as a new test;
- default recovery-native host, unchanged recovery-TN10 driver, new host with
  and without receipt support, and the new runner all compiled;
- mutually enabled local-depth-four/TN10-depth-four profiles failed at the
  compile-time domain guard; and
- a clean rebuild regenerated all seven native fixture directories byte-for-byte.

## What remains

The actual fresh-identity TN10 funding, broadcasts, selected-chain confirmations,
service-loss recovery, five withdrawals, final reconciliation and transcript
privacy score remain unexecuted. A fresh unfunded trial identity was created
locally on 2026-11-02, and the isolated seven-stage TN10 builder passed both
profile tests and all five genuine-receipt permission/payout layouts. Live RPC
is currently blocked because this checkout has no retained trusted binding for
the gateway's current ED25519 host key; strict host-key checking correctly
refused the connection. No test KAS was funded or broadcast.

