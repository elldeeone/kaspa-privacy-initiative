# Run 01: preserved witness-generation failure

**FAIL_PRESERVED, 6 of 49 rows reached. No rerun or source/criteria change.**

Five positive witnesses passed the actual R1CS checker: one SHA relation with
four padding vectors, and both owners' unchanged and newly authorized records.
Both owner processes had exited. Every accepted complete-tuple digest byte,
LE128 limb and signed message matched Node's independent computation.

The first negative, `payment-npk-old-signature`, was rejected by the witness
generator at `ForceEqualIfEnabled` → `EdDSAPoseidonVerifier` → authority line
360. Its mandatory **actual R1CS rejection** could not be tested because no
complete witness was emitted. This is an evidence/harness failure: an invalid
signature was rejected, rather than an observed authorization bypass.
The remaining 43 rows, including altered-CF and subgroup/encoding negatives,
were not executed. There is no 49-row pass or general negative-coverage claim.

[Result](run-01-public/RESULT.json):
`d4f4e9ddb21e242cb3e4ac7e6e3c2f9ad5256b6b810faf67b53ba3db6ad4106b`.
[Run record](run-01-public/RUN-RECORD.json):
`2cb614ea43265c08c7ef81913b77c193121cabea695222673abf01be02cab1ef`.
[Failed public input](run-01-public/CASE-FAILURE-INPUT.json):
`4bd6adc81bf79d8f70f992a19b4a212a4c5f2e0692b3a726207510c064007218`.
The zero-byte partial negative witness and all logs/builds/positive witnesses
remain under `/dev/shm/kpi-signature-predicate-scratch-01/run-01`.
[Evidence closure](run-01-public/EVIDENCE-CLOSURE-01.json),
`0939fe86988de57d3d58a2999de3112596ac3be49d129d9c075449215b77e724`,
pins 35 primary files. Only six small public JSON copies entered the repo;
the tools symlink, logs, builds and witnesses were excluded. Tmpfs retention
is volatile across reboot/cleanup.

The authority compiler emitted 576,505 constraints; the SHA companion 222,320.
The measured preparation/compilation/check commands consumed 124.82 CPU
seconds in total. Highest reported RSS was the authority compiler's 2,909,200
KiB, below the prospectively selected 4 GiB. Primary artifacts occupied about
267 MB, below 2 GiB. No setup, proving key, Groth16 proof, GPU or native-KAS
operation occurred. These are per-command resource observations, not native
fee measurements or a hard aggregate memory sandbox.

Source diagnosis: selected Snarkjs `wtns_calculate.js` SHA256
`93750fa68c8f5509cb3b1c0c17ec1dc16d34a1f52be2fd1d349a68941d12475a`
passes the options object to the runtime builder. Runtime SHA256
`c1347b4b6f6a40a49e0715d57fb91b64a4df1d3eccb0c7ad9d7d6e9c7cc65324`
maps `sanityCheck:false` to WASM `init(0)`; object truthiness is not this cause.
The exact compiler's [WASM assertion emitter](https://github.com/iden3/circom/blob/ad44e915a12bb047b05745c2884aad9cc8326bc6/compiler/src/intermediate_representation/assert_bucket.rs#L44-L87)
emits this assertion unconditionally. Its C++ branch gates equality-derived
generator assertions at sanity level zero while retaining explicit asserts.
A separate prospective C++ harness must preserve the original R1CS byte for
byte; no changed generator or second run is authorized by this outcome.

This remains a **NON-PRIVATE authorization predicate**. Full ciphertext/output
validity, current profile/state/fees, recovery, malicious MPC and hidden
partition proving are absent. Existing 2% fee and active-retry failures, the
25-file model closure, all actual Original material and financial runtime are
unchanged. The stopped native-exit benchmark was not retried or reassigned.
