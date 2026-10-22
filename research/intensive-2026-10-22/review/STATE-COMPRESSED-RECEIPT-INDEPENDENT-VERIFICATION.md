# Independent historical-state Groth16 receipt verification

Verified the saved1169-byte compressed historical n5→9 state receipt without
building, proving, rerunning a guest or invoking the native VM.

- Compressed receipt SHA256
  `e01de2650193181f96f40a985f6d321bc21bae7eb01805194b40fb022b983a3b`.
- Unchanged source Succinct receipt SHA256
  `8ab05861de29305c8f1288a2159896da52be3d0185246ac6595ae048debdbce4`.
- Immutable verification-only executable SHA256
  `1c2813e30eb62c9199754351fbdf91e4625f1ffe2f4212cf137b7f5a8aa0c3f2`.
- Selected image
  `e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9`;
  exact historical J336 SHA256
  `457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3`.
- Same independently computed successful claim
  `2450e2c7e083e367887ec53f3449cd4d5d62b1575b94119479997cec8ff5aaf4`.

Ran the existing verifier with two-CPU affinity, two-thread environment,2GiB
address-space limit and development mode absent/disabled. Exit0, approximately
0.05s. The real SDK verifies Groth16, exact selected image/successful claim/J336,
no unresolved assumptions and publication consistency. P1088 and both105-byte
state slices match the independently reconstructed oracle, with n5→9. Thirteen
source/artifact/executable identities are unchanged before/after; all55 selected
source pins still match. Source/output hashes and full claim digests agree with
the retained compressor report and reviewed same-source compression-only path.

All14 controls reject: wrong image; journal offsets0/8/10/42/74/106/110/215/320/
328/335 (framing, projection, pool, txid, index, both states and both amounts);
corrupted seal; fake receipt. Fake is explicitly an application profile rejection
and seal corruption is not claimed to be a canonical-point pairing failure.

Independent live cleanup13:54:32UTC confirmed the compression unit inactive/dead,
success/status0, MainPID0, empty ControlGroup; all four recorded PID/start-time
identities absent. No GPU compute app; global snapshot1MiB/0%. Producer monitor
retains about5.01s unit wall time,4.36s compression, sampled matching VRAM peak
5300MiB, memory peak1,783,369,728bytes and no swap. Samples can miss brief peaks.
No reviewer process termination occurred.

Also reviewed the researcher's new native23-case report without rerunning it:
report SHA256
`f0d182a24334bbd5cbde27e7153056cbe8b26a1d510e021d0fea882302190224`,
checker SHA256
`3de6727d554b0b5747ee9396c49550a4ddd4a7cb94ba8ddf0b213665063db0a4`.
Rehashed all eight selected native source/pin files. The one positive and22
negatives match exact typed expectations: five coherent claim/state mutations
or canonically negated-A proofs reach actual Groth16 verification failure;
seventeen context/amount/framing cases reach VerifyError. The additional amount
controls correctly cover zero/MAX, fee width and negative-zero conditions.
The1383-byte old/new redeems differ only in the105-byte state body; the immutable
prefix/suffix and literal designated-predecessor guard are identical. Payload1203
is exact P plus next state. The successor cannot continue that guarded policy.

Independently recomputed native mass quotes: mass163290 requires16,329,000 sompi
at100/gram,32,658,000 at200, and81,645,000 at500. The unchanged80M authorization
covers the first two and fails the500-rate quote by1,645,000. This negative stays
preserved. Lower mass does not reduce the actual fixed80M fee or meet the stated
1% fee target.

Evidence is closed in `state-compressed-receipt-independent-01/` and its adjacent
log. This is a NONFUNDABLE one-shot conditional state assertion. No authentic
genesis/accepted lineage, backing, continuing owner-exit policy, chain acceptance
or privacy claim follows. Official outer setup and the single-party inner
development setup remain assumptions; passing controls are bounded evidence.
