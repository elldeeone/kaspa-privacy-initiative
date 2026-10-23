# Live context and cold-owner artifact review

Reviewer: `/root/private_exit_review`. This addendum preserves the closed source
and local-native report `SOURCE-REVIEW-01.md`, SHA256
`03f40e9a93cffe8c05124abc9753d7317b77910a5eaedff3ebd061512ff9cfa6`.
No reviewer execution, RPC, funding, signing or broadcast is authorized here.
No actual private request, backup, seed, witness, recipe, shape or PK blob is read.
Both actual cold cashouts, their selected-node confirmations and final separate
seed-only recovery clients are artifact-closed below. This is bounded research
evidence under selected-node, setup, data/software availability and trusted-host
assumptions; it is not a financial privacy or production qualification.

## Actual DAA context refresh

The selected adapter source remains
`08b5870879c8e9ae83e54a5cf27f337c694a2fa87ad7f687a39d6aa70b7c1b23`.
Its `localCheck` requires the exact raw-body hash, transaction ID, profile hash,
positive native Full/all-input-engine results, native executable hash and every
input's outpoint, integer-string amount and DAA, full SPK, noncoinbase flag and
null covenant. Founding also needs the exact `output0_redeem_hex`; the prepared
next action's input frame contains the approved identical redeem program.

The adapter checks current queried DAA before submission and accepted Full input
DAA during observation. The actual merge output's DAA belongs in the founding
context; the actual founding output's DAA belongs in the payment context. A
context-only refresh must preserve the entire signed native body, ID, Auth,
genuine proof, fee, amount, SPK, outpoint and all other context metadata, then
obtain fresh actual-context Full/all-input-engine validation. The release pins
the new exact local-check file hash. If using the keyless helper, its quote ID
must also be regenerated: its deliberately complete context binding includes
DAA. There is no requirement to regenerate an unchanged Auth-bound proof.

Pinned upstream `01b532e8b553523216471682649693af92f0fd16` supports this narrow
context-only operation. `consensus/core/src/hashing/sighash.rs:246` hashes the
input outpoint, SPK, amount, sequence and transaction fields, without UTXO DAA.
`consensus/core/src/mass/mod.rs:137` converts an input into only amount and
plurality. The UTXO validator's `check_sequence_lock` filters out inputs with
the disabled sequence bit set; actual founding/payment sequences are u64MAX,
lockTime0, noncoinbase and without covenant. The selected private policy's
`build` enforces these values and does not introspect DAA. Auth528 has no DAA
field. These facts do not authorize changing any other input metadata.

One release has a single `native_binary_sha256` for all included stages. Both
stages can use the selected generic validator077585b8; mixed generic/helper
validation identities need separate exact per-stage releases. Each release
must pin the body ID/hash, local-check hash, public identity/trial directory,
adapter/native-safe/native executable hashes, endpoint, network and genesis.
Durable stage and transaction-ID markers remain exclusive before submission.

This is a read-only source/contract check. Current network observations and the
actual released bodies/context reports remain root and network-adversary gates.

## Prefix stage controller source

`poc/private-cashout-trial/prefix_stage.py` SHA256
`46fa38b5751f0b10717eea4fa0707fb3c6dec6457fb643fde0c30c94206ef8e4`
was independently read before preparation/actual-context validation. It pins the
closed local body packet, matches the selected trial/domain, checks a confirmed
predecessor and exact accepted-output/current-UTXO static metadata, replaces only
DAA, and writes the identical transaction bytes. Both stages use generic077585b8
for fresh Full/all-engine validation. Payment additionally receives a fresh
keyless helper zero-proof quote with exact normalized body/context comparison.
It emits the adapter's complete local-check contract. There is no key, private
witness, proving, setup or broadcast interface.

Its `STAGED.json` contains local trial/profile paths and must remain private.
Only an explicit public body/context/report/local-check allowlist can be
published. The sibling preparation public packet supplies quote D/VK; it cannot
override the helper's whole-body/domain/VK/context checks. Exact staged public
inputs and resulting actual-context reports remain a subsequent artifact gate.

## Founding actual-context closure

The prepared founding body SHA256
`e10feaf59bb56d6e46ad4ac654b6126b73df2cb1b3f31d3a2443ed077264b634`
is byte-identical to the closed local body. Context
`aca3bde4cb171be6b0fd75f3e3e70335f3f66790dce63d503404266c065392ce`
changes only input DAA to604176575; native case
`eb6185e3669ec937cca620d9bc5c4333155ffc869781d5f0a73fa27c001d9c8e`
binds that exact body and static input metadata. Runtime source freeze
`daad940cac5c3e03709fe64466c33b8ef43aa7de85b63e7a00f5bc282ef89ef3`
uses the ordinary release/public-source pattern, network unshared and no keys,
witnesses or PK mounted. `STAGED.json` was not opened by the reviewer.

Actual native report
`5d78ea3086386302aae0ac27d3be5da7733b6aaccfecc4cd4ce106f3032eab2c`
has isolation PASS, Full/all engines accepted, fee1,411,200 sompi. Local check
`a6fc15d5489bab27cb56526f93fd238d133e2cc7d03047dfd85147fbfcfa229a`
matches the body/ID, selected profile hash, actual input context, generic
validator identity and exact approved output redeem. Validated result is
`850b8adeab9e6f6ae6c8b33699659b0ffe9e077422ade6145df84ce87d988015`.

The single-stage founding release
`fad305f2cac9a81ad662f252b6031fb9405e11839d22913d3d848552cc3c398f`
and submit request
`4cd44ed190e4c06761b5084403a1701f676570a488d0aa6739bbf27463bbb6ce`
were checked for exact body/local-check/source/executable/profile/network/
genesis/endpoint/trial binding. They authorize only the founding stage. The
request uses the matching stage, released body/check/release hashes and
canonical public identity location. The reviewer performed no submission and
opened no actual private request, backup, witness or proving-key blob.

The retained receipts distinguish a failed user-bus launch before any VM from
the successful systemd invocation around ordinary env-i/bwrap. Both successful
prefix jobs requested2CPU/4GiB/swap0; their exact issued wrapper arguments and
invocation IDs are retained, with no active cap/usage sample or resource
qualification inferred. Both jobs ended inactive/dead/PID0. Chain confirmation
is separate.

## Payment actual-context and public prefix closure

The payment body
`7004aed3e69e5ee17ff7240a18340627e23360fc7ae42d46e11d5822b7ef7221`
is byte-identical to local case1. Context
`8ccff7491c19a39096f136618c56524adfa80aaaa03b7ce1ec2793da47734102`
changes only its input DAA to604180733. Native report
`b7b6940bbb4fa9aec454c723d7e312bca8720a74073c990f5086d76877426224`
has exactly the earlier positive native semantics, all engines accepted and
fee18,958,700. Fresh zero-proof quote
`41fce747fc14d96bf176260acd1972f860d27f0ff70ff92ebf77d44529ce57c2`
matches the normalized original body and actual context, with exact Full/engine
ARK G16 failure and a changed complete-context quote ID. Local check
`7e65d18c61c6a3d705b73a4a165efc1b99c3470fc3a1c1ed3de5a054d9918e62`
matches the selected generic validator, body, profile and input metadata.

Single-stage payment release
`ebaea7fe79ddbeedc61600e3a2b38f5cbd42cac38a0bc2fbf5bfb4cc549f4293`
and request
`437ba05722ebbe35c465145aa33fa2d2c155719a8accb640ff4ce42148c4ee56`
match the exact current source/profile/endpoint/body/check/context bindings.
Runtime source freeze is
`568b5c2e3e712f2061af802d1a0710e7c490135bcec86d89155a160f68f5e16f`;
validated result is
`cb612122433526e6d1af051437cbec720db7f1de6f11143860dd7aaf7dc84d74`.
There was one positive actual-context Full operation and one fresh zero-proof
quote; no reviewer VM/proof/RPC/submission was performed.

The public prefix projection is closed at allowlist
`330d4859c2df65349c8a6089a8f6d1e964583a64fdf6706f112f75f64b97a46e`,
15 exact payloads. It preserves the reviewed two bodies/contexts/native checks
and correct sanitized authorization/runtime selections, excluding their local
filesystem paths. The ten-field public descriptor binds manifest008689b8, fresh
D/VK, exact initial24417-byte program, immutable tail hash, founding outpoint and
shared birth anchor. It includes no precomputed private exit bodies or witness
material. The explicit public projection source `prefix_packet.py` is
`443d4c5d9daa11d5997690c19b1f4379e7d191cdb03cedd5d1b8689e5565cfa5`.
Chain observations remain a separate selected-record packet.

## Ordinary funding linkage

The bounded ordinary funding packet manifest
`f09b8b0046b9c8351439f54b432c5fbcf57ce13c2b5a6aa480f8e43bd5bef2c5`
matches all 16 payloads and exporter
`cd91b53b32228cc0623508788eec3908ea98d3f34ec1a3b8ffe203dd923c9146`.
The fixed extractor reads only the individually selected public merge03 files
and selected observation; it uses the exact immutable earlier sanitizer/codec.
An initial source omission of copied case/context linkage was identified and
fixed before export. The actual native case matches its signed body and all
four input contexts; legacy four-field supplied contexts normalize an explicit
null covenant. Full/all four engines accept, with exact reconciliation
229,498,500 = funding output228,999,900 + fee498,600. All four consumed inputs
are queried spent, and the sole funding output is unspent at the selected
observation with DAA604176575, exactly matching the founding actual context.
Both durable intents, release3a197829, raw-body hash and refreshed start anchor
agree. Selected-node confirmation distance74 exceeds20, with no removals.
Only the selected acceptance records are included. Original bulk pages were not
opened by this reviewer or published; independent header/consensus/current-now
qualification remains explicitly absent.

## First cold-owner issued mount boundary

The network adversary independently inspected the issued private launcher and
published only the neutral scope report
`d86e103ec212f9eedf9fdfa1ba4b0eba683626e408ffde1648646b818ae03a74`.
This reviewer rehashed that report and checked its descriptor canonical digest
`7d8f74edc7cffc813201af8c932fb4196adffa4a2ccb5593910bc5cd82bf1a57`
against the closed public descriptor. The scope pins selected source3c6d2329,
manifest008689b8 and fresh public fetch72174443. It reports the reviewed runtime,
all14 source pins, exactly one own backup file at `/backup.json`, read-only
public parameters at `/public-params.bin`, selected own software, only neutral
private output/metadata writable, and an unshared namespace without operator
profile/tree/precomputed exits or other backups. It does not claim execution
success or a payout. Actual host paths, private request/preflight/OWNER report,
backup metadata/bytes and PK blob were not opened by this reviewer. Public
Proof/native output and confirmation were separate later gates at this mount
checkpoint; both are closed below.

## First cold private cashout closure

The actual own-prover public output is independently pinned in
`COLD-OUTPUT-REVIEW-01.json`, SHA256
`d2cd7e066da91f6200988fcf2b9a9fe2645a9e8beac70c4ad3f2755f5a95de32`,
covering exactly nine public files. Public result
`ed22cb7add0749f06a90b5640628720b0f703be8967814be33612f4124dc9923`
pins proof
`34ee0d49ad95dcb1d2fb7801eb19eea403b04fc5f493b3149afcae557a860832`
and Auth
`cae5d2cdb508c217b53f3f646cca79199482f4170c30a92cfe443d41e2206536`.
Both differ from all three operator rehearsal references. Those comparisons
were performed only by the reviewer after cold execution; the reference proofs
and private precomputations were never cold-client inputs.

The selected Auth/proof/VK/frame, prior state, actual P0 outpoint and context
DAA604181796, ciphertext hash, two output SPKs/covenants, CM5/NF5 successor and
120,000,000 = reserve60,000,000 + payout41,000,100 + fee18,999,900 were checked
from the exported body. The exact full-body/all-context Rust serde quote ID
`2b9e1915a4e8074c87deab2d6759fa4327b9296025aa3455dfe747328d83a654`
was independently reproduced after zeroing only proof128. Full and every engine
accept, using14,960,868 of16,009,999 allowed units. Mass189999 at rate100 matches
the exact fee. Prover870e61f6/nativef6139cea/manifest008689b8 match selection.

Root's staged body/context/native report match those public artifacts byte for
byte. Single continuing-stage release
`184cc57a6a09bf9ce4bb11849c1752d3ecbd8aabc8979db52fc80b02a29b82ed`
and request
`0e3182e18b6cbe1fa04995ec84b3f40c7bde28c69bc3b3a7670fa765c9546e7c`
bind their exact helper/source/profile/endpoint/trial/body/local-check/context
fields. The request uses a separately refreshed observation anchor, not the
descriptor birth anchor; that is allowed and the selected observation below
binds the actual issued anchor. No reviewer submission or new native call ran.

Confirmation packet manifest
`0fb17204649537817d54c581f40099ebabbad9d32883c42e2a65d351b8a817b5`
matches all six payloads, including exporter source snapshot
`442fb4aa48d3e95016474106b4929fd5dc63420837e0707280386cfe7461f385`.
It binds the exact public cold body71a1536f, input/current native context, fresh
fetch72174443 and issued release/request. The sole consumed P0 input is queried
spent; the60M successor and41,000,100 native payout are queried unspent at this
observation. Selected-node confirmation distance104 exceeds20, without removals,
and the post-query related-spend guard passes. Only the selected acceptance
records are exported. Private paths, actual owner-stage labels, receipt maps and
unrelated bulk pages are excluded. Independent consensus, immutable finality,
current-now and population privacy/fee qualifications are not inferred.

## Terminal cold private cashout closure

Independent public-output review `COLD-OUTPUT-REVIEW-02.json` has SHA256
`0a6b29e9bc685bb10f518558f89dbc2f9ae4d7d5ce5457f9bf088ddbc629d397`.
It covers all ten payloads in wallet packet
`7011dbd392bc217c476733c478455303b3308d7e61ba679d8c83cd796fed41c1`.
Public result is
`b832ec2b51aff49ff91a6ac7a75f9b16844f43e504cbcb89399c25a068cc7620`;
new proof
`85ba121927506baf56c734dfd4f34274829bff1b46d1d8db9004d92d23997be2`
and Auth
`b0bdfeede7010531474255c79ffffa170310ce23ff80d0e2e36031910a82cdab`
differ from all three operator references and the first actual cold cashout.
The reviewer performed those comparisons after execution; the owner client
never mounted the reference files.

The current first-cold successor outpoint, DAA604187550, prior state and SPK,
selected Auth/proof/VK/frame, and exact full-body/all-context quote ID
`ac9011676292bf5c2751f6d839852d2787ca22b37df62b4ca0b3e651f3a3740e`
were independently checked. Terminal CM64, cipher528 and both CM paths at
payload3376..4400 are zero, with the SHA256 digest of528 zero bytes. CM root and
count5 carry unchanged; both NF insertions advance count5→7 with a changed NF
root. There is one exact authorized native payout and no pool successor:
60,000,000 = payout41,042,400 + fee18,957,600, reserve0. Full/all engines accept,
using14,846,582 of16,009,999 allowed units; mass189576 at rate100 matches the fee.

The second issued mount review
`d01bf6223a57ef7ba8dee0a343842cbab4a3210ffa74fa7f12a9021d72d07d9e`
pins the same14 selected source files and new public fetch7b851dfa, with a
distinct single backup file and neutral private output/metadata, without the
operator tree or other backups. The public execution receipt reports12.711
seconds, observed active CPU limit14 cores, memory18GiB, swap0, zero swaps and
collected/inactive/dead/PID0. These are single functional samples, not cold
installation or p95 qualification. No actual private request/backup/OWNER
report/PK was read by this reviewer.

Root's staged terminal body/context/native report match the reviewed public
files byte for byte. Single terminal-stage release
`e854e46ce31954ea7a09ff03e60e86224ae155e48d7044b5f74671952ee0820b`
and request
`2d5a6fc6ca65ecb545ceead9bf785b4de05a6fe3dddbf9082a4abbb489586902`
match the exact body/check/context/helper/source/profile/endpoint/trial fields.
The current local-check hash is
`5da606cbbe2d4309e3d3624fd73040c885e0e26d36d309f9e70ac7fa3aea9ad1`.

Terminal confirmation manifest
`ebd72e58e37c442b86e0c16bf041fc8e530d0b9810e5a40e28656e18fd63ca30`
matches all six payloads and preserved source snapshot
`410ea019cf1e08dcf68845d9800653c71f75f7044b028fa4dc422d96d55a2bd4`.
Its exact prior pool input is queried spent and sole41,042,400 native payout is
queried unspent; selected-node depth75 exceeds20, with no removals and a passing
post-query related-spend guard. The issued request's refreshed anchor and
release/request identities match. The first confirmation packet stays unchanged.

Actual whole-source ledger
`6ec9bde7d27b967b2b4c2370f63af557037b318f02dcbe12abb0388c307573c4`
was independently recomputed using five actual bodies and their contexts, with
all four real predecessor links. No operator cashout body contributes:
229,498,500 = ordinary change88,630,000 + payout41,000,100 + payout41,042,400
+ actual fees58,826,000 + terminal reserve0. Final public counts are CM5/NF7.
Final fresh network/recover-only closure is recorded below.

## Final fresh state and separate recovery closure

The final fresh Electron capture SHA256 is
`4c137a71336dae9ed2dc2f613bbd9b4587010681bc08b3f3942fbb136b0794bf`.
This reviewer checked its exact seven selected current queries: the four
consumed inputs have no current entry, while the actual ordinary change and
both actual native payouts have exact amount/SPK/outpoint/noncoinbase/null-
covenant current entries. No SDK hash calculation, native execution or RPC was
repeated. Header/transaction hash verification is retained in the actual SDK
receipts; inclusion/PoW/independent consensus remain outside this evidence.

Two separately issued, unchanged `recover` clients are closed at wallet
manifests
`620a6c29d6ec8be8153107cec90130d5d2a294695b2a1528b428b61a43d7c16b`
and
`7306eb49b63a4e8810c5c5bade63afb15522849c5699378cc37536dc7ffe5671`.
All16 public payload hashes/lengths in each match. The four replay native cases
are exactly the actual founding, payment and two cold cashout bodies with their
actual contexts. Every Full/input engine accepts with the exact actual fees.
Both SDK receipts identify those same four transactions and the same canonical
bundle, and report transaction/header hashes recomputed without claiming chain
inclusion or reading the parameter blob.

Each safe recovery projection reports one recognized historical receipt, one
spent receipt, no remaining recognized claim, and one authenticated current
default-native-payout UTXO. Historical default-payout value remains current in
this trial. The public projection contains counts and booleans only; receipt
values, CM/position, native key/SPK ownership associations, private reports,
original paths and private report/witness hashes are excluded. It explicitly
does not infer universal absence from no recognized receipts, and does not
claim recovery of arbitrary external destination keys.

Each actual recovery execution used one own backup and fresh replay before seed
access, with no public PK/local prover/cashout helper mounted or blob read.
The selected source3c6d2329 remains unchanged. Runtime source freeze is
`f076a4ebdbf95dc1c59bda3b0f35decd9d62ff74a2563bc946c9ab76e9e658d7`.
The two public receipts report1.031 and1.029 seconds, observed active4CPU/8GiB/
swap0 limits, zero swaps and collected/inactive/dead/PID0. These are actual
recovery operations, not extra qualification reruns. This reviewer read no
private backup/request/OWNER report or PK and performed no execution.

The milestone establishes this selected-instance workflow: confirmed public
prefix, operator prover stopped, separate owner-local private proof generation,
confirmed native payouts, then separate backup-only payout-authority recovery.
The ordinary runtime trusts the same host and retained software installation;
the cache is not evidence of an independently durable mirror. Full-claim mode
reveals the consumed claim value as public payout plus fee. Financial privacy,
the fee target, cryptographic audit, durable availability, hostile-host defense,
independent consensus and mainnet readiness remain unqualified.
