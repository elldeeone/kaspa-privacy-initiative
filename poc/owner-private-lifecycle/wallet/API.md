# Owner-local lifecycle wallet

ADR0064 research/testnet client. All secret-bearing work runs in a network-off
owner namespace. A trusted same-host launcher and administrator remain explicit
assumptions. These interfaces do not establish independent operators, chain
consensus or general privacy.

## Layout and launcher

The entire `/var/tmp/kpi-owner-private-lifecycle-01/private` parent is mandatory
in the exclusion list. All owner/MPC/controller directories are below it.
An owner's `BACKUP.json` has only schema, fixed domain, public participant ID and
32-byte root seed. Funding derives through the existing recipient key API at
reserved invoice index `0xffffffff`; initial notes use index zero.

Every call uses:

```text
python3 -B run_owner.py OPERATION
  --owner-directory PRIVATE/OWNER/owner
  --mpc-directory PRIVATE/OWNER/mpc
  --private-run-directory PRIVATE/controller/FRESH_GENERIC_NAME
  --output PUBLIC/FRESH_GENERIC_NAME
  --exclude-old-trial OLD_LOCAL --exclude-old-trial OLD_LIVE
  --exclude-new-private-directory /var/tmp/kpi-owner-private-lifecycle-01/private
  [--execute]
```

`--output` contains only the selected `PUBLIC.json`. Public-source staging,
private command plan and raw child stdout/stderr stay in the private run
folder. The supervisor inspects original backup metadata only; restoration
mounts one original backup leaf directly into its owner child. No original
seed/backup/map contents or hash is returned.

The required runtime-source closure is `paths.py`, `support.py`, `history.py`,
`trees.py`, `worker.py`, this launcher, the pinned unchanged recipient reference,
the crypto ELF, new construction codec, new wire codec and selected relation
ELF. Selected profile plus all three role manifests/VKs are always checked.
Output PK is required for prepare, Spend PK for authorize and Exit PK for exit;
whole needed PK bytes are checked before the first seed read. Relation calls
use four Rayon threads per owner so three simultaneous owners use twelve.

## Operations

1. `init --crypto ELF --participant-id HEX32 --position 0|1|2
   --admission-sompi INTEGER` creates the fresh seed backup and a genuine encrypted
   initial receipt. Its public record contains the 496-byte initial Note/CM/CF/CFH,
   admission and funding x-only key/SPK. It neither funds nor signs a deposit.
   The separate bootstrap signer rederives its own record and funding key before
   authorizing the exact complete GN3 body with SIGHASH_ALL.

2. `restore --backup ORIGINAL/BACKUP.json` creates a fresh runtime from only that
   original leaf. It imports no former attempts, output map, receive-index map,
   creator blinding or state cache. Existing runtime backups are never replaced.

3. `invoice` authenticates the current public history and creates three fixed
   240-byte private peer envelopes for the selected fresh session. Invoice
   indices derive from `SHA256(KPX8IV01|sessionSHA|sender_u32LE|role8)[:8]` as u64LE;
   reserved zero/funding indices are rejected. Receipt encryption retains its
   embedded index, so a seed restore needs no receive-index lookahead.

4. `prepare --party 0|1|2 --note-kind initial|received|change|any|received-or-change
   [--payment-sompi INTEGER]` rescans the complete history and selects its note
   inside the owner. An exact requested payment must leave a positive bounded
   change note; it is never clipped. Without that argument the research policy
   privately selects a middle-range amount. Add three `--peer-owner-directory`
   arguments to the launcher. No foreign owner directory is mounted: only that
   sender's designated three receive envelopes cross the boundary.

5. `authorize --own-mpc-result RELATIVE/OWN-MPC-PROJECTION.json` checks the owner's
   authentic engine result, all Output proofs, exact own inclusion/openings,
   owned delivery, global balance, current note/NF, selected policy, fees and
   state. The Spend proof authorizes the complete effects. Durable directory
   and disclosure barriers precede generation of usable financial authority.

6. `scan` rederives owned notes, positions, spentness and change classification
   from the original seed and public history. Private scan results stay inside
   the owner. At terminal reserve zero it requires every owned claim spent and
   rederives every owned historical native payout key. Its public report contains
   completion/reconciliation booleans, no owned note/NF/payout correspondence.

7. `exit-ready --note-kind ...` privately selects a current unspent full note,
   then exports only its public exit NF, gross claim amount and fresh native
   payout SPK. Those fields are needed to build and quote the actual withdrawal.
   It grants no financial authorization and exports no CM/position.
   After complete public-history/checkpoint verification and seed scanning,
   an owner with no unspent claim instead returns the disjoint schema
   `kpx8-owner-no-unspent-claim/v1`, containing only participant ID, selected
   history SHA and `empty:true`. Missing/pruned/conflicting history is a refusal,
   never empty. A missing requested kind while other claims exist also refuses.

8. `exit` rescans and validates the exact native Exit projection, current NF
   update, own full note, selected fee and freshly rederived payout destination.
   It generates the genuine direct Exit152 proof without MPC or a shared outer
   prover. A prior authorized-but-unsettled mixed body does not prevent a direct
   exit against the latest selected state: current native point and same stable
   NF arbitrate which candidate settles. No timeout revokes the prior body.

For operations other than init/restore, supply `--assets/--assets-sha256`,
`--history/--history-sha256`, `--context/--context-sha256`. Invoice, prepare and
Spend authorization additionally take `--session/--session-sha256`; authorize
and exit additionally take `--projection/--projection-sha256`.

## History, checkpoints and exports

The strict `kpx8-owner-private-history/v1` snapshot contains domain, GN3 genesis
three records/initial state/reserve/point, complete batch/exit transitions, and
head state/reserve/point. Every mixed transition retains its complete public
SESSION object as well as its genuine projection. Exit records retain their
projection and direct proof. The wallet reconstructs all CM/NF roots, validates
all component proofs and conservation, and matches the separately pinned
context checkpoint. This does not itself select today's canonical chain: the
reviewed acquisition layer must supply authenticated accepted/current data.

Public READY has only participant/session/NF/CVin and fixed readiness flags.
Recovered CM, position and paths never enter that registry. Public financial
exports have exact statement/proof bytes and effects digests, never witnesses.
All amounts are integer sompi. Public native fees/payouts, funding history,
endpoints, counts, timing and selected wallet policy remain visible.

Fresh payout indices use the existing Receiver key derivation, selecting the
first u64LE from `SHA256(KPX8EP01|D32|currentPoint36|NF32|counter_u32LE)` that
is neither zero, reserved funding index, nor any own known receipt index.
The owner proves the exact effects and checks the corresponding derived SPK.
Historical recovery repeats the same prefix history and point/NF derivation.

Seed-only restoration preserves authority and stable NFs. It cannot revoke old
valid authorizations or reconstruct unpublished attempt journals; failure/retry
privacy remains part of the explicit unqualified composition assumptions.

## Verification boundary

`test_wallet.py` uses deterministic public unsafe cleartext envelopes, fake CVs
and mock proof bytes to test source/control behavior. Those fixtures are not
fundable, encrypted payments or genuine financial proofs. Real relation,
Native Full and accepted-chain evidence are retained separately by the
integrated lifecycle runner. Passing these controls is not a security audit.
