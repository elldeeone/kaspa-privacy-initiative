# One-owner private cashout client

New ADR0053 research client. It reconstructs the approved Auth528 pool from a
fresh descriptor-only network capture, recognizes one receiver's notes from one
seed-only V2 backup, and privately proves a full-claim cashout using that owner's
local prover and authenticated mirrored public proving parameters. It never
broadcasts, creates a setup, accepts an operator fixture or automatically falls
back to revealing a note.

`private_wallet.py` reads one stdin request with exact fields:

```text
schema: kpx3-private-owner-request/v1
op: recover | prepare-private-exit
backup_path, descriptor_path, expected_descriptor_sha256
public_manifest_path, fetch_path, crypto_path, output_dir
```

Preparation additionally requires `public_pk_path`, `local_prover_path`,
`native_helper_path` and positive integer `fee_rate_sompi_per_mass`. The output
must be a fresh child of an existing private directory outside Git. Private
backup bytes must be in a regular0600 file outside every Git worktree.

Paths never authorize expected hashes. `owner_selection.py` is part of the
trusted wallet installation and initially remains unselected. Root selects the
fresh canonical parameter manifest, D/VK/build identity, final local-prover/native
ELFs and new public replay source only after review. A request or RPC cannot
replace them. Incomplete public replay, unselected software or mismatched loaded
parameters halt before backup bytes are read.

Selected ELF bytes are copied/authenticated into fully sealed memfds. The fixed
SHA-pinned system loader executes those same bytes under the existing bwrap
policy and a clean environment. Python orchestration, fixed imported source,
system loader/shared libraries and the root-authenticated installation remain
separate trust assumptions; ELF sealing does not authenticate the whole OS.

For preparation, the local prover authenticates the complete selected PK and
checked VK first, then emits the exact `parameters-ready` event. Only then does
the wallet read the backup, recognize claims, quote the actual public body and
send its strict private witness over an inherited pipe. The root seed and
payout scalar are never sent to the prover/native transaction helper. The
narrow supported crypto bridge receives only the derived secret required for
its checked public-key operation. No private witness bytes/hash/path is written
or exported.

The default payout key follows the exact ADR0053 HMAC tag `KPX3PAY\0`, binding D,
founding outpoint, owned CM, position and scalar retry. It differs from the
consumed note's emergency key and can be recovered from seed + history. Spent
historical receipts still permit matching the wallet's default private native
payouts. General external destination-key recovery is not claimed.

`OWNER-RECOVERY.json` is private and never hashed/exported. Public stdout and
`RESULTS.json` use an explicit scalar-field allowlist that excludes input CM,
position, note, invoice/native-key association and private witness hashes. Failed
keyless native calls retain their public Auth/body diagnostics privately, without
the private prover witness. All output files remain0600 in0700 directories until
owner-controlled submission/export. Research publication must curate public
outputs separately; recursively copying the owner output is not supported.

Controls use only public unfunded seeds, genuine supported crypto, standalone
public system ELFs and the frozen public tree decoder. They test full-claim
updates, terminal zeros, stale/double NF rejection, key derivation, payout
recovery, private-output exclusion and before-seed gates. They do not load a PK,
run an actual private proof/native VM or establish cryptographic correctness.
The actual selected-trial local proof/Full/payout rehearsal is a separate gate.

See the [design](../../research/next-session/private-service-loss/wallet/DESIGN.md)
and [frozen common contract](../../research/next-session/private-service-loss/CONTRACT.md).
Selected-node history, correct receiver delivery, public-data/parameter retention
and development setup assumptions remain explicit. This code is not production
or privacy/fee qualification.
