# Fresh unspent recovery trial

**Current result:** the fresh `7b2e385d…` trial completed both independent cold
exits and confirmed payouts. See [RESULTS.md](RESULTS.md) for the seven-transaction
accounting, final fresh terminal check and limitations. The earlier `c0d00370…`
preparation is retained historical failure evidence.

This lane tests ADR-0049 using the unchanged KPX2 policy and Auth484. The separate
proof-private cashout prototype is not part of this trial. Testnet-10 test KAS only.

The current fresh domain and matching immutable native/prover binaries are in
`preparation-02.json`. Two recipient notes each carry 60,000,000 sompi before exit
fees. The constructor stored separate owner backups before generating invoices.
The earlier identity in `preparation.json` was abandoned while still unfunded;
`retained-local-failure-01.json` preserves its six successful native validations
and the operational failure: systemd's default PATH omitted the host Node
wrapper during SDK bookkeeping. The corrected runtime passes an explicit PATH
and checks Node before reading seeds or starting setup. No bodies were sent.

`local-rehearsal-02.json` records the corrected fresh run: six native Full checks,
six SDK roundtrips, one genuine proof, stopped prover and zero terminal reserve
and liabilities in 41.853 seconds. The separate `readiness-02/index.json` pins 44
public review files, including the exact domain source and four prefix SDK/native
receipts. Independent review ACKed the complete index and value/outpoint graph.
This operator review packet is excluded from cold client mounts; only its
nine-field descriptor is a recovery input.

`service-loss-02/PUBLIC-FILES.json` allowlists 95 public files, including the
confirmed prefix, both newly cold-signed exits, approved ordinary funding records
and the unused first merge metadata. Its separate `SHA256SUMS.json` hashes the
other 94 files. The packet totals 985,123 bytes. Seven original observations
totaling 462,309,586 bytes remain local with a 0600 hash index; publication keeps
only relevant acceptance records, headers, input contexts, confirmation depth
and current-output queries. Unrelated FullV2 transaction pages are excluded.
The adapter's headers with `parentsByLevel: {}` remain selected-node assertions;
the fresh fetcher's independently rehashed headers are separate evidence.
The coordinator owns the aggregate lifecycle result and fee reconciliation.

`poc/recovery-trial/live.py` has no RPC or broadcast interface. It reuses the
existing finite lifecycle runner, accepts only this new identity's funding key,
and rejects a used trial before opening its secrets. Its local rehearsal checks
all six bodies, then exports an operator plan containing only funding-prep,
founding, admission and private payment. The prover must already be stopped.
Local precomputed exits remain operator-side readiness evidence and are excluded
from all cold client inputs.

1. The coordinator supplies the exact ordinary-merge output as private source
   JSON, with `source_key` equal to `TRIAL_FUNDING_KEY` and integer sompi. A planned
   output is `LOCAL_SUPPLIED_CONTEXT` until independently observed on testnet.
2. After the coordinator releases CPU/memory, run `python3 -B
   poc/recovery-trial/live.py rehearse PRIVATE_TRIAL --source PRIVATE_SOURCE
   --cpus 14` inside the agreed resource-limited service, with
   `PATH=/home/luke/.local/bin:/usr/local/bin:/usr/bin:/bin`. This runs a fresh setup
   once, one genuine private proof, six native Full validations and six SDK
   roundtrips. It stops its resident prover before local exit signing.
3. The coordinator publishes only the four prefix bodies after their exact
   funding source is confirmed. It retains the pre-founding scan anchor.
4. Export the nine-field descriptor using `live.py descriptor --identity
   PUBLIC_IDENTITY --founding FOUNDING_BODY --admit ADMIT_BODY --vk VK328
   --birth-start-hash ANCHOR --output PUBLIC_DESCRIPTOR`. This verifies the
   complete approved policy, genesis payload/state/reserve and founding linkage.
5. Separate cold clients receive only this descriptor, their own seed backup,
   public network records and approved wallet/native software. Each independently
   discovers the current head and prepares a new exit with current witnesses,
   fresh quote and explicit revealing-exit consent. The second owner refetches
   after the first owner's exit. The coordinator submits each new body once and
   confirms its native test-KAS payout.

The 12 wrapper controls use retained public records and malformed inputs. An
independent second pass checked the new-funder boundary, used-identity rejection,
four-body prefix, stopped prover and minimal descriptor. These are local software
controls; they make no new network or cryptographic correctness claim.

This is a bounded R1 liveness experiment under selected validating-node, retained
data and development-setup assumptions. Revealing exits disclose their note
details. The result cannot qualify privacy, fees, independent consensus, durable
data availability or production readiness.
