# Unfunded private-action lifecycle assembler

This separate finite harness prepares exact Auth528/native bodies for the new
ADR-0050 domain. It never loads a proving key, creates a setup/proof, contacts a
node or broadcasts. All fixture seeds/secrets are deliberately public
`PUBLIC_SYNTHETIC_DO_NOT_FUND`; entropy and real sealed receipts are frozen in
the resulting fixture files. These artifacts establish no financial privacy.

Continuing dummy ciphertexts use the same existing cryptobox seal operation as
real receipts: random216 plaintext to a fresh one-shot delivery key whose secret
is discarded. Raw random264 padding disclosed some dummy slots through an
invalid X25519 prefix and was replaced before actual body/proof generation.
The old source and zero-execution boundary are retained under
`lifecycle/pre-fix-padding-01`. Terminal cipher528 remains exactly zero as required.

1. `assemble.py shape --crypto BRIDGE --output NEW_SHAPE` creates a valid-shape
   P0 fixture and seed-only backups before invoices. The proof owner creates the
   sole fresh setup and returns its VK328.
2. `assemble.py materialize --crypto BRIDGE --shape SHAPE --native NEW_NATIVE
   --vk NEW_VK --output NEW_PREPARED` freezes complete actual bodies and integer
   fee fixed points. These calls use native `*-freeze`, never VM/Full execution.
3. Source/fixture review precedes any actual Full execution or genuine proof.
   The same resident fresh key proves the four exact action fixtures: P0
   two-recipient payment, Bob partial private cashout plus private change, Bob
   full claim cashout while Charlie remains, and Charlie terminal private exit.

`execute.py prefix` runs the three native ingress bodies under an exact reviewed
source/input freeze. `execute.py execute` requires those pinned actual prefix
records, the selected setup report/core source and four already verified proofs.
It executes all four native actions and reconciles every ordinary return,
native payout and actual fee to the complete source.
`freeze.py` records the selected public files and exact hashes; `--authorize`
records the coordinator's source/artifact release. It excludes proving keys,
does not authorize funding or network access, and defaults to runtime disabled.

`assemble.py races` prepares separate branch controls: a valid Bob REVEAL first,
a correctly signed old Bob REVEAL after the main private partial spend with
CURRENT occupied-NF paths, and a new owner-valid private proof after the valid
REVEAL with a CURRENT occupied original NF. The latter is an additional genuine
proof under the same resident VK; its ownership relation may be satisfied while
the native absence predicate must reject. `execute_races.py` runs exactly those
three reviewed controls after the mainline. Alternate payouts are never counted
as extra mainline value. These are newly constructed unfunded alternatives,
not replay of a funded trial.

The 4B-sompi external source, founding/admission/change and every final payout
must reconcile. There is no token, privileged withdrawal or hidden subsidy.
Actual accepted ancestry and durable public data remain supplied-context
assumptions. Native complete-body fees necessarily fail the unchanged2%/10-KAS
target on this unamortized proof-private route; no target is weakened.
