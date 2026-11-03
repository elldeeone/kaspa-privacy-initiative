# Isolated local-wallet stages

The worker never broadcasts or uses a network. Only a new isolated owner process
may read its own backup, request, invoice or witness. The controller must not
open or hash private files. Preserve all older seeds and trial directories.

Run `python3 <stage>/wallet/worker.py OP --owner /owner --public-output /out`.
Mount one selected owner directory at `/owner`, a fresh public export directory
at `/out`, finite authenticated source files, and only needed pinned public
assets. Source closure: `wallet/{worker,payment,support}.py`,
`recovery/history.py`, selected `verification/wire.py`,
`integration/trees.py`, unchanged pinned recipient-v2 `recipient.py`. The Python
runtime and required shared libraries are separate fixed runtime dependencies;
do not mount a repository, all `/var/tmp`, private parent, old trial or home.

Every operation except `restore` needs `--assets PATH --assets-sha256 HEX32`.
`scan/pay/exit` also need exact public `--history`, `--history-sha256`,
`--context`, `--context-sha256`. Context schema
`kpxa-selected-history-context/v1` has exactly `schema`, `domain_hex32`,
`genesis_sha256`, `checkpoint`; checkpoint is `state_hex112`, integer
`reserve_sompi`, `outpoint_hex36` or null at zero terminal reserve. The genesis
digest hashes canonical compact sorted JSON for the exact genesis object.
The caller authenticates genesis backing and the exact current native
checkpoint. A supplied context must be described as supplied-context evidence.

`pay/exit` additionally require `--native-fee-policy PATH` and
`--native-fee-policy-sha256 HEX32`, plus finite sources
`integration/native_fees.py`, `verification/native_case.py`, the selected native
codec and one public template projection. The template is a quote-only shape
probe, never an authorization. The policy schema `kpxa-native-fee-policy/v1`
has exactly `schema`, `native_case` and `codec` (path/sha256 objects),
`outer_image_hex32`, `component_profile_sha256`, `payment_compute_budget`,
`exit_compute_budget`, `fee_rate_sompi_per_mass`, `template_projection`
(path/sha256 object). Fee policy is pinned externally. The owner request must
approve the exact native fee fixed point before actual payment/change creation;
the completed projection is independently reconstructed and re-quoted before
generating Spend or Exit proof authority. A mismatch refuses the operation;
fees are never changed after authorization. Initial selected research budgets
are 1800/payment and 1500/exit, with 100 sompi per mining-mass unit; a quote is not
native VM acceptance or a fee-feasibility pass.

1. `init --admission-sompi 2000000000` creates original `BACKUP.json` mode0600
   under `/owner`, generates and genuinely verifies an encrypted Output520,
   with public CV(value,0), and writes `/out/PUBLIC.json` with exactly `schema=kpxa-initial-public/v1`,
   `domain_hex32`, `output_hex520`, integer `admission_sompi`,
   `funding_spk_hex36`. No receipt plaintext/index/owner/invoice PK is exported.
2. `restore --backup /backup/BACKUP.json` imports only the selected own original
   backup into a fresh runtime; its status explicitly does not claim recovery
   until `scan` succeeds. No original seed contents/hash enter controller logs.
3. `invoice` writes `/owner/INVOICE208.bin` for authenticated confidential
   counterparty delivery. The public status contains no invoice or index.
4. `pay --request /owner/REQUEST.json` consumes exact private fields `schema`
   (`kpxa-private-payment-request/v1`), `payment_sompi`, `fee_sompi`,
   `invoice_path`, `invoice_sha256`, `position` (u32 or null). Invoice path is
   own-local or the single private mount `/invoice/INVOICE208.bin`. The exact
   digest must be authenticated by the owner out of band; encryption is
   insufficient. Completed role-free `/out/PROJECTION.bin` contains genuine
   Spend+two Output proofs. Fresh secret output order/indices stay local.
5. `scan` restores every own receipt from complete authenticated public history
   and derives ordinary Spend/Exit authority without lookahead, role labels,
   roster or saved plan. At least one historical receipt must match the seed;
   a wrong seed cannot report a successful empty scan. All-spent genuine wallets
   retain historical matched receipts and can reconcile terminal payouts.
6. `exit --request /owner/REQUEST.json` accepts exactly `schema`
   (`kpxa-private-exit-request/v1`), `fee_sompi`, `position` (u32 or null), and
   emits `/out/PROJECTION.bin` plus `/out/EXIT-PROOF.bin`. It uses only the direct
   Exit152 relation, its selected PK and the original seed; no shared outer
   prover or other live owner is needed. Native Full/confirmation is subsequent.

The assets JSON schema `kpxa-local-wallet-assets/v1` has exactly `schema`,
`domain_hex32`, `relation`, `crypto`, `recipient`, `wire`, `trees`, `spend`,
`output`, `exit`, `native_tail_hex`. Program/source objects have exactly `path`,
`sha256`. Role objects have exactly `manifest`, `manifest_sha256`, `pk`,
`pk_sha256`. All identities are externally pinned by the whole assets digest.
Programs must be selected ELF files mode0500; role PKs are fully authenticated
before secret input. The unchanged recipient source and crypto adapter retain
their existing exact SHA256 pins. Derivation uses fresh financial D; proofs use
the new relation binary and fresh Spend/Output/Exit setup artifacts.

History schema `kpxa-local-private-history/v1` has exactly `schema`,
`domain_hex32`, `genesis`, `transitions`, `head`. Genesis has exactly
`state_hex112`, `reserve_sompi`, `outpoint_hex36`, `outputs_hex520`,
`deposit_sompi`; every initial CV must equal recomputed CV(deposit_sompi,0),
and the reserve must equal deposit_sompi times the output count. Each output
is genuinely proved and contains only CM/CV/encrypted receipt/CFhash/proof.
Payment transitions have exactly `kind=payment`, `projection_hex`,
`successor_outpoint_hex36`. Exit transitions additionally have `proof_hex128`
and `kind=exit`. Zero reserve requires null successor. Replay checks complete
proofs, exact current head/policy, state updates, public group balance and
duplicate actions; reorg recovery replays the newly selected complete history.

These are research source controls. A component-complete export is not native
acceptance, testnet confirmation, network anonymity or cryptographic review.

`campaign-pay` takes exactly private request `schema`
(`kpxa-private-campaign-payment-request/v1`), integer `payment_sompi`, integer
`fee_cap_sompi`, and `selection_kind` (`any`, `received`, `change`, or
`received-preferred`). A selected isolated recipient worker creates the exact
invoice, and the private caller binds that single immutable leaf at
`/invoice/INVOICE208.bin`. This authenticated local IPC binding supplies exact
recipient authentication; the caller never opens or hashes the invoice. The
sender worker computes its exact digest locally, quotes the fee privately,
enforces the approved cap, and uses the same complete consent/proof path.
The labels are reconstructed locally from original-seed-owned historical NFs
and accepted transaction output positions. They do not use public scan-index
conventions, output roles or private attempt journals and do not change authority.

`recovery-exit` takes exactly private request `schema`
(`kpxa-private-recovery-exit-request/v1`) and integer `fee_cap_sompi`. It restores
the original seed, scans complete accepted public history, selects an owned
unspent claim locally, computes the exact continuing/terminal fee, enforces the
cap and emits the existing direct Exit projection/proof. No claim, scan index,
note role, payout derivation index or quote-readiness row is exported. This
removes the need for a cold controller to know a private claim's exact exit fee.
