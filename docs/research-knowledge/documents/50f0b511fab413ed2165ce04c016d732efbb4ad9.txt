# Independent historical-state Succinct receipt verification

Verified the genuine saved historical n5→9 assertion, not the current-anchor
context and not the earlier J42 pair statement. No build, proving or guest/native
execution was performed by this reviewer.

- Receipt223898bytes SHA256
  `8ab05861de29305c8f1288a2159896da52be3d0185246ac6595ae048debdbce4`.
- Immutable selected verifier SHA256
  `efba3e34eaca4b42e01c27ee92389bf0a46fa3708f7e15e77a43037384d90d01`.
- Selected image
  `e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9`;
  program SHA256
  `d1336290bd4b8555edea9c5d7dd56aa4883f1d185b0a4aca9b08105b0537097a`.
- Exact historical J336 SHA256
  `457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3`;
  source input11219 SHA256
  `544219aaba5b4738a546691eed6cc7b93a4cda6f2c3b158ef51fbf8c4bcbf462`.

Ran the existing immutable host's `verify historical-anchor RECEIPT NEW_OUTPUT`
under two-CPU affinity, two-thread environment and2GiB address-space limit.
RISC0_DEV_MODE absent. Exit0. Rehashed all55 selected-source identities against
the pre-execution freeze; current image/program/key/core/host/helper/pins match.
Primary receipt and executable identities remain unchanged after verification.
Checked publication P1088, exact J336 and both105-byte state slices against the
previous independent reconstruction; n5→9 and fee/R/R' are unchanged.

The actual SDK verifies a successful, assumption-free Succinct receipt with dev
mode false. The additional official STARK callback checks decoded control equals
the independently expected JOIN and receipt control, with official allowed-root
inclusion; it does not merely compare report metadata.

Fifteen built-in cryptographic controls reject wrong image; journal offsets
0,32,64,96,128,160,192,224,256,288,320; corrupted seal; malformed control
inclusion; and a wrong expected control passed to the actual verifier callback.

Six additional serialized **outer Journal** mutations exercise exact txid/index,
prior state, next state and successor amount bytes at offsets74/106/110/215/328/
335. Their inner proved claim is unchanged. Every case returns the exact SDK
`ClaimDigestMismatch` display with independently computed old/new claim hashes;
none creates an accepted output. The binary serialization contains J twice
(inner unpruned claim and outer Journal); only the latter was changed. An initial
review-harness assumption expected `JournalDigestMismatch`; inspecting pinned
SDK source showed its successful-execution verifier uses `ClaimDigestMismatch`.
The unchanged first negative/log was retained and checked against the corrected
source-derived exact error; no receipt or test input was retuned.

Independent stdlib transcription of the pinned SDK tagged-struct hashes gives
the expected successful claim digest
`2450e2c7e083e367887ec53f3449cd4d5d62b1575b94119479997cec8ff5aaf4`.
This is also the expected claim for same-claim compression and native mapping.

Live cleanup at13:50:44UTC: producer unit inactive/dead, MainPID0, empty
ControlGroup, success/status0. All four recorded PID/start-time identities were
absent. GPU had no compute apps; instantaneous global snapshot1MiB/0%. Producer
monitor reports303.74s, sampled matching VRAM peak6096MiB, cgroup memory
peak511438848bytes and no swap (sampling can miss brief peaks). No reviewer
process termination occurred.

Full logs, six mutated public receipts, errors, exact identities, expected claim
and cleanup are retained in `state-receipt-independent-01/` and its adjacent log.
This verifies one NONFUNDABLE synthetic state assertion. Authentic predecessor
lineage, KAS backing, continuing policy, owner exits, chain acceptance, privacy
and production safety remain separate and unproved.
