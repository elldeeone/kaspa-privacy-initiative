# Genuine private payment to independent native exits

Primary trace: **PASS on the first frozen attempt**, offline supplied UTXOs only.
All identities and source funds are public synthetic DO_NOT_FUND fixtures.
Canonical founding/current lineage and complete archive availability remain
external supplied oracles. No chain broadcast or testnet payout occurred.

The actual22,388-byte immutable native union contains PRIVATE Groth16, public
ADMIT and owner-signed REVEAL branches. The selected native executable is an
immutable copy of source04; later control helper builds do not replace it.

## Actual complete trace

1. Ordinary P2PK preparation spends a supplied4B-sompi source into a120M
   founding coin, a1,963,601,800-sompi admission coin and ordinary owner change.
2. Founding creates Alice's60M singleton reserve and ordinary change. First
   native ADMIT authenticates its exact singleton CM and sentinel NF state,
   then adds Alice's1,958,751,400-sompi note.
3. Alice consumes both actual current notes with a genuine new Groth16 proof.
   Bob and Charlie each receive1B sompi through real V2 sealed receipts. Their
   ownership/nullifier secrets are absent from Alice's output witness. There
   is no private change; reserve and all positive liabilities become2B.
4. Fresh receiver objects restore the backups saved before any invoice/receipt.
   The exit sandbox excludes both the new PK file and prover executable;
   preferred-service interfaces are absent before any exit quote/signature.
   The complete current archive/head are supplied explicitly.
5. Bob's current native reveal pays995,026,200 sompi. Charlie's subsequent
   terminal reveal pays995,036,800 sompi. Final reserve and **every** Alice,
   Bob and Charlie positive liability are zero.

All6 actual bodies pass official native isolation, Full and ScriptEngine.
All6 links compare the consumed outpoint, supplied amount and SPK to the exact
previous body's output, including preparation output1 → ADMIT input1. Every
Full fee equals actual input/output accounting and the frozen authorized fee.
The native private proof is also independently verified by the pure library.
The independent relation oracle checks actual Auth484, private witnesses,
all3,344 public-update witness bytes and exact immutable P2SH successor.

## Exact fees

Selected rate:100 sompi/mass. Integer fixed points use actual complete native
bodies, budgets, source funding/change and KIP9 mass before proof generation.
The final proof retains the same fixed128-byte width; its body is validated
separately. Quotes at other rates are observations, not cheaper actual fees.

| Operation | Actual fee, sompi |
| --- | ---: |
| Ordinary funding preparation | 911,400 |
| Coherent singleton founding | 2,574,600 |
| Native public ADMIT | 4,850,400 |
| Genuine two-recipient private SPEND | 18,751,400 |
| Bob continuing reveal | 4,973,800 |
| Charlie terminal reveal | 4,963,200 |
| **Total** | **37,024,800** |

Shared preparation/founding/admission/private fees split exactly13,543,900
sompi each. Adding each recipient's own actual exit gives Bob18,517,700 and
Charlie18,507,100 sompi. The maximum is1.85177% of its1B-sompi payment.
The private operation alone allocates9,375,700 sompi per useful payment.

This is the explicitly favorable **two distinct useful10-KAS payments, no
private change, one shared payer/prover** case. It does not qualify the full
ordinary/lifecycle workload or erase the single-payment verifier floor,
high-rate/small-tail failures, retry costs or prior privacy failure. No extra
user's principal, reserve tail or imaginary exact-size source coin is omitted.
The complete4B source reconciles to actual ordinary change, recipient payouts
and these fees.

## Proof and resources

One fresh local development setup uses the independently reviewed pure
Arkworks0.6 relation:4,650,533 constraints,4,612,281 witness variables and two
public hash limbs plus the constant instance variable. Setup uses OsRng.
The new compressed PK is1,006,401,200 bytes, stays0600 outside Git, and is
selected by an explicit new-format source/domain/VK/full-file hash contract.
Hashes do not establish trapdoor erasure or setup integrity.

| Stage | Wall | CPU | Peak RSS |
| --- | ---: | ---: | ---: |
| New setup | 22.30 s | 221.04 s | 3,930,412 KiB |
| Checked cold PK load + genuine proof | 198.12 s | 646.28 s | 5,674,112 KiB |
| Actual native ingress prefix | 0.11 s | 0.10 s | 38,144 KiB |
| Actual private body + two native reveals | 0.43 s | 0.42 s | 48,048 KiB |

Expensive runs permit14 logical CPUs/18GiB; actual utilization is measured,
not inferred from the cap. All runs have network isolation and swap0. Installed
Arkworks provides no adopted GPU backend. All primary units are stopped.

New PK SHA256:
`e95202462feaeeeed6761ae0ae137c86c9730c54612df42252d3b3c085e86bfb`.
VK328 SHA256:
`5f551fa7b0cbeb9ec89ccf0e198575b1803db4c8012919166436af625e0136bc`.
Exact actual private witness fixture:
`e59a1dd7f93c1bbe7c6176e589accc558efa97907411508a12f6cbdfbf704a06`.

## Genuine recipient private spending and both competing paths

Two separately frozen forks use the **same new key**, with genuine proofs and
fresh authorizations bound to actual primary outputs. They do not add payouts
to the mainline or change its six-body result.

| Fork/control | Actual result |
| --- | --- |
| Bob privately spends his received1B note with one canonical dummy input | Genuine proof accepted by native Full; fee18,751,400 |
| Bob's old revealing exit after that private spend | Exact `SignatureInvalid(VerifyError)` |
| Bob's fresh private authorization after his mainline native reveal | Host-verified genuine proof; native rejects the current spent NF with exact `SignatureInvalid(VerifyError)` before Groth16 |

All3 frozen native expectations match. The first authenticated NF leaf/path
uses the **current** state in both negative controls and carries Bob's same
original positioned HMAC NF. The private-after-reveal fixture intentionally
has an invalid duplicate NF update; its private ownership/value relation is
valid. It is never passed off as a positive public-update oracle case. Neither
negative depends on an old transcript/proof or a stale CM path. The revealing
negative uses the correct original native signing key.

The positive recipient spend creates500M and481,248,600-sompi notes and retains
Charlie's original1B note. Its reserve/all positive liability is1,981,248,600;
those hypothetical fork liabilities are retained in its physical snapshot.
This additional positive closes genuine recipient private spending, while the
mainline independently closes both recipients' revealing exits and zero tail.

The selected development loader authenticates the compiled metadata, source,
domain, entire new PK length/SHA256 and fixed VK before trusted-input decoding
of the same owned buffer. Untrusted VK/proof checks remain unchanged. Its
separate source review and loader-only experiment are retained in the
[loader packet](../proof-loading/evidence/MANIFEST.json). The baseline checked
198-second run remains unchanged.

| Additional proof | Wall | CPU | Peak RSS | Compressed decoding | Proving plus checked verification |
| --- | ---: | ---: | ---: | ---: | ---: |
| A: private before reveal | 184.01 s | 266.28 s | 5,644,180 KiB | 158.20 s | 24.46 s |
| B: private after reveal | 183.74 s | 267.49 s | 5,585,628 KiB | 158.40 s | 23.97 s |

These two runs execute concurrently at7CPU/9GiB each, swap0 and no network.
They still miss a4GiB wallet memory target. Compressed decoding remains the
dominant wall cost; different fixtures, concurrency and cache conditions do
not establish a causal speedup. All three genuine-proof runs and native fork
jobs are stopped. All proofs use the one fresh setup and its selected
development key.

- [Exact fork fixtures](forks-materialized-01/FORKS.json),
  [genuine proof handoff](FORK-PROOF-RESULTS-01.json),
  [native fork closure](FORK-NATIVE-RESULTS-01.json).
- [Actual three-case native results](../native/fork-runtime-01/evaluation/RESULTS.json),
  [A genuine accepted-body oracle case](fork-proof-A-01/independent-private-auth-cases-genuine.json).

The unchanged independent stdlib evaluator also passes A's one-real plus
canonical-dummy relation, every public update byte and the actual immutable
P2SH context in [oracle result03](../independent-oracle/RESULT-03.json), SHA256
`2fc6372f477476f0c08f340d46418b8dcbf35f4372d55b937f76d1f2e9e729cc`.
Its separate freeze pins both the original01 body/context aliases and the
byte-identical02 bodies actually validated by the native runner. The placeholder
case and all earlier freezes remain unchanged. B is excluded from this positive
oracle claim because its public NF update is intentionally invalid.

## Evidence and limits

- [Actual complete result](execution-01/RESULTS.json),
  [six actual body links](execution-01/actual-body-links.json),
  [ingress prefix](prefix-01/PREFIX-RESULTS.json).
- [Exact backing/accounting fixture](materialized-01/ghost-accounting.json),
  [pre-proof actual context](materialized-01/independent-private-auth-cases.json),
  [genuine native-body context](execution-01/independent-private-auth-cases-genuine.json).
- [Seed-only pre-payment backups](shape-01/PUBLIC-SYNTHETIC-backups.json),
  [exit sandbox check](execution-environment-01.json),
  [service absence before authorization](execution-01/services-absent-before-withdrawal.json).
- [Setup](setup-01/report.json), [genuine proof](proof-01/report.json),
  [runtime freeze](PRE-EXECUTION-FREEZE-01.json),
  [primary cleanup](CLEANUP-PRIMARY-01.json).

Competing-path proofs/native controls are separately frozen evidence. Their
positive/negative classifications cannot substitute for accepted chain
lineage or be concatenated into extra mainline payouts. Native Full with supplied
UTXOs does not establish accepted ancestry/backing. The retained archive oracle
does not demonstrate independent network discovery, durable public DA or reorg
recovery. This work is not a security/cryptography audit, privacy qualification,
production readiness or a confirmed testnet rehearsal.
