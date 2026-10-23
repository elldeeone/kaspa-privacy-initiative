# Next testnet gate — prospective, not ready

**Recommendation:** adapt the completed finite **six-body** new-format trace to
a fresh TN10-only private identity and existing generic SDK/RPC transport.
First implement the missing network-free instance constructor. Do not fund the
current DO_NOT_FUND instance or invoke old S7 workflows. This note is source
planning only: no constructor, SDK execution, node RPC, key load, funding,
broadcast, installation or infrastructure change was performed.

Inspected continuation HEAD `0c2f4c788a4274b381c4838e05cce5e9c32e8536` plus the
current new integration sources/reports; upstream refs checked 2026-10-23
02:45 UTC. New integration source remains separate from that pushed baseline.

## What can be reused

The [offline lifecycle report](lifecycle/REPORT.md) records actual native Full
acceptance of preparation, founding, public ADMIT, one genuine private payment
and two sequential revealing payouts, with final reserve/liability zero.
It already uses real V2 encrypted delivery and pre-payment seed-only recipient
objects. Its accepted head, funding ancestry and complete archive are supplied
oracles. Its public deterministic seeds/source coins and existing bodies must
never become the live identity.

Reuse the **shape**, not those identities: one payer owns genesis60M plus the
admitted note; both are privately consumed into two distinct1B recipient notes,
then each recipient exits. This is the favorable two-useful-payments/no-change
case, not the general fee workload. The old price-prior failure and all runtime/
privacy requirements remain unchanged.

Existing [TN10 transport](../../../poc/shared-pool/runtime.mjs) preserves exact
transaction version, computeBudget, storageMass and canonical SDK roundtrips;
[`chain.mjs`](../../../poc/shared-pool/chain.mjs) supplies accepted Full-body
pagination, UTXO/output comparison and one-submission/ambiguous-outcome patterns.
Adapt those generic seams only. The v6 runner's payload5228 parser, saved-proof
capabilities and default legacy funding directory do not understand KPX2.
Do not run the old runner or import its owner/prover workflow.

## Fresh unfunded identity: one command is a missing feature

The existing v6 `two-input-run.mjs new ...` and
[A1 instance constructor](../../../poc/a1/src/bin/kpi-a1-testnet-instance.rs)
demonstrate the appropriate **no-RPC, fresh-directory, fresh-private-key** pattern.
Neither constructs this new protocol. Current
[`assemble.py`](../../../poc/future-lifecycle/assemble.py) derives public fixture
seeds; the [Rust runner](../../../poc/future-lifecycle/src/main.rs) explicitly
accepts `PUBLIC_SYNTHETIC_DO_NOT_FUND`, with check/setup/prove modes, not a live
`new` mode. Renaming that label is not a private testnet constructor.

A proposed, **not implemented**, single `new --network testnet-10 NEW_DIR`
command should create fresh payer/recipient/funding secrets from OS randomness,
write seed backups before invoices, and emit one unfunded public run manifest:
network/genesis, fresh domain/identity, selected code/VK/policy, public addresses,
invoice profile and later canonical founding locator. Secrets stay0600 under a
0700 directory outside Git, never in arguments, logs or public witness fixtures.
It must reject an existing destination and make no RPC/funding/proof request.
No manual ceremony is needed for each fresh identity. Success in minutes must
be measured for this command before claiming it exists.

**Domain decision is load-bearing.** KPX2 tags specify the protocol format;
current D is simultaneously the note/NF/derivation namespace and a compile-time
circuit constant. The circuit explicitly constrains D, and native policy/library
checks the same literal. A UUID, address prefix or manifest network label is
not another native instance binding.

The conservative current-design route is a fresh TN10 D incorporating the fixed
TN10 genesis plus a fresh nonce, corresponding suite rebuild and new development
setup. Its domain-dependent VK cannot be replaced by the old development VK.
Measured offline setup was22.30s on Forge, so a minutes-scale packaged constructor
looks feasible; build/complete-constructor time is **unmeasured**, and setup is
distinct from the later198s observed cold-load-plus-proof. Rebuilding/setup may
be staged separately before the lightweight identity step, but the chosen
instance still needs exact matching domain/key pins.

A reusable-key runtime-domain factory would require a separately reviewed
parameterization/circuit change. Alternatively, reusing one TN10 D/VK across
trials relies on fresh seeds and external canonical-genesis identity plus
Auth484 actual-outpoint/SIG_HASH_ALL binding. Invoice208/Note168 do not bind an
extra pool ID; this is an explicit replay/privacy tradeoff, not automatic
per-trial isolation. Do not silently select it merely to shorten construction.

## Smallest complete rehearsal after separately authorized preparation

1. **Close the new-instance gate.** Review domain choice and a minimal fresh
   constructor; preserve old snapshots. Produce the exact private trial profile,
   keys and immutable binaries. Reproduce its offline actual-body/recipient/
   semantic controls with real scoped secrets before any test-KAS request.
2. **Qualify transport read-only first.** Exact SDK roundtrip of all six newly
   constructed body types, then TN10 identity/genesis, version/sync/index and
   retained Full-history checks against the selected validating node. Retain a
   pre-funding checkpoint. These checks have not been run in this lane.
3. **Use only fresh trial test KAS when authorized.** Resolve the actual new
   funding UTXO/ancestry and amounts; reconstruct/reprice preparation, founding
   and ADMIT. Auth484 commits to the actual ADMIT output and exact fee, so an
   offline synthetic-outpoint proof cannot be submitted. Generate the new
   genuine private proof only after those actual body IDs/fees are fixed.
4. **Run the finite chain through both final payouts.** Submit each new body
   once, compare accepted full bytes and successor UTXOs before proceeding,
   retain public delivery/current-state records, and stop preferred services
   before recipient quote/signing. Recipients use only their own backups and
   retained authenticated public data. Observe both owned native payouts and
   final zero pool liability/reserve, then reobserve acceptance after the chosen
   confirmation horizon. A submission acknowledgement is not a payout result.

This needs a small KPX2 adapter to the existing generic transport/recorder, not
a new general wallet, network replayer or resurrection of the parked S7 job.
The bounded pilot may retain its trusted validating-node/complete-archive oracle;
it must not be called independent network recovery or durable data availability.
Ambiguous submission is reconciled read-only, never blindly rebroadcast. A failed
trial is retained and retried only under a fresh identity. Timeouts are generous;
strict checks protect state, ownership, fees and evidence.

## Exact remaining gaps and current upstream/runtime facts

| Gap | Source-grounded boundary |
| --- | --- |
| New secret instance/profile | Domain is fixed in private `lib.rs`/`circuit.rs`, native `policy.rs` and assembler. Current artifacts are deliberately public. There is no new-format private TN10 constructor or network-scoped mode. |
| Serialization/chain adapter | New payloads4356/1344/2029, common witness offset199, multiple funding inputs and actual selected VK must roundtrip unchanged. Existing v6 live adapters are format-specific. |
| Node, SDK and current funding view | Cached public SDK2.1.0 JavaScript/type declarations exist and expose computeBudget/storageMass/Full RPC APIs. File presence is not byte-pin or body-compatibility verification. No live node, secret config or funding wallet was contacted/read here. |
| Consensus versus relay | Supplied-UTXO Full passes do not establish mempool standardness, live fee sufficiency or inclusion. Quote/reprice complete actual bodies; fee changes alter private Auth/proof. Retain all rate200/500 and general-change failures. |
| Canonical instance/data | Pin actual founding outpoint and network genesis, authenticate accepted funding/current lineage and retain ciphertext/update records. Node assertions remain trusted; pruning/reorg/competing spends are not solved by a root. |
| Readiness | No new confirmed TN10 payout exists. Only a complete rehearsal including terminal payouts meets `AGENTS.md`; offline completion alone is insufficient. |

Official GitHub read-only refresh confirms latest release
[v2.1.0](https://github.com/kaspanet/rusty-kaspa/releases/tag/v2.1.0), whose tag
resolves to executed native pin `01b532e8b553523216471682649693af92f0fd16`.
Current master remains `4edcbbccb449f84832afb1ca157904b35f37d006`; it was not
substituted into validation. The official2.1.0 SDK ZIP is56,646,535 bytes with
published SHA256 `ba674e109ff5dd8bedc4dc2ee8a5ecdf4b600b1178a541d77888ec58310b6124`.
No download/install was performed. Release/source facts do not attest the
configured remote node or prove this union's relay acceptance.

Pinned TN10 genesis is
`f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370`.
Existing [`a1_trial_rpc.mjs`](../../../scripts/a1_trial_rpc.mjs) demonstrates
strict TN10/version/sync/UTXO-index checks and Full-history confirmation, while
its A1 artifact/owner schemas are unrelated. The official
[inline-ZK documentation](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx)
likewise requires exact expected proof program and successor binding; presence
of the native verifier is not an accepted state/backing oracle.

**Next concrete source task:** the scoped unfunded-instance/domain constructor
and exact six-body SDK adapter, under a fresh testnet ADR/release. This note
creates neither and authorizes no infrastructure or live action.
