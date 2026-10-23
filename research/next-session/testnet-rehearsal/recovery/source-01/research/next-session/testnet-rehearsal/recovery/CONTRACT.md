# Finite TN10 recipient recovery and payout check

This standalone checker supports only the selected six-body pilot and its
four-/five-body pre-exit prefixes. It does not discover or replay a general
public ledger, contact RPC, create signatures, load proving material or fund
anything. The native adapter supplies validating-node Full-history/UTXO
observations. That node and the complete archive remain trusted inputs.

## Inputs and secret boundary

The stdin JSON request contains paths and public pins only:

```json
{
  "oracle_stage": "TRUSTED_TN10_ACCEPTED_NODE",
  "identity_path": "/private-trial/public/identity.json",
  "backup_path": "/private-trial/backups/bob.json",
  "archive_path": "/private-trial/accepted-archive.json",
  "current_observations_path": "/private-trial/current-observations.json",
  "crypto_path": "/selected/pinned/kpi-future-recipient-crypto",
  "crypto_sha256": "selected public executable SHA256",
  "label": "bob"
}
```

Read only the public identity, the selected recipient's seed-only backup,
public accepted records/current view and the pinned crypto bridge. Never read
the full private profile, payer seed, another recipient's seed, PK or prover.
The backing identity/domain/profile are checked before receiver derivation;
the bridge's complete bytes are hashed before secrets enter its stdin.
For network checks, the public recovery identity's `runtime_pins.bridge_sha256`
must also equal the requested pin; an arbitrary executable cannot select its
own expected digest. A separate secret-free public recovery identity may carry
that pin if the original constructor export omitted runtime metadata.
No private key, seed, plaintext note or revealing k is printed or returned.

Network-stage identities require the fresh constructor's exact schema, origin,
TN10 network/genesis and nonce-derived nonlegacy D. The backup has precisely
the constructor's seed-only fields and0600 permissions outside this checkout.
These metadata checks rely on correct constructor/source provenance; they are
not a cryptographic proof that arbitrary supplied seeds were secretly generated.

## Archive and fresh view schemas

`kpx2-tn10-accepted-archive/v1` contains `oracle_stage`, `trial_id`,
`domain_hex32`, `network_id`, `genesis_hash_hex`, ordered operations, snapshots
and head. Operation kinds are exactly:

```text
fundingprep, founding, admit, private, bob-reveal, charlie-reveal
```

Each operation supplies its raw transaction ID, exact accepted-body file/hash
and observation file/hash. The four-/five-body modes require the corresponding
complete prefix. Snapshots are `founding`, `before-private`, `after-private`,
`after-bob`, `terminal`, each with ordered CM/ciphertext deliveries and physical
indexed-NF entries. The head records actual operation index, State112, reserve
amount and current outpoint, or null once the terminal output is gone.
The public `expected_payments_sompi` map states Bob/Charlie's exact selected
pilot amounts. Each decrypted positive receipt must match its amount; the
checker reports actual sompi and does not import a historical10KAS benchmark.

`kpx2-tn10-current-view/v1` carries trial/stage, a separately refreshed adapter
checkpoint and new observation records. Before exit it must show the exact
current reserve output unspent. At terminal it must independently reobserve
Bob's continuing payout and Charlie's terminal payout as owned UTXOs, plus
the consumed final reserve. Missing current outputs, changed amounts/SPKs,
retained input UTXOs or stale/removed acceptance reject.

Network records use adapter trust label
`VALIDATING_NODE_AND_PUBLIC_ARCHIVE_ORACLE`, correct TN10 genesis/network,
exact Full accepted body, its canonical digest and at least20 confirmations
under the pinned native accepting-block blue-score-distance interpretation.
Fresh observations must be no earlier than the refreshed checkpoint. Different
later sinks are normal; equal rapidly moving sink hashes are not required.
The caller must actually refresh this view. Timestamp labels/JSON cannot prove
honesty or freshness against a malicious node/archive provider.

## Independent checks

The checker compares every accepted body and prior-output link, rejects duplicate
accepted spends, and authenticates the exact immutable BLAKE2b32 P2SH policy
with current State112. It derives four ordered CM records from founding, ADMIT
and bound PRIVATE ciphertexts, verifies actual NF predecessor/intermediate
append witnesses and compares every declared snapshot with those exact updates.
Actual reveal opening/CM/NF/value, native payout key/amount and terminal lack
of a reserve successor must match. No supplied current root self-authenticates
its own history.

Only after those checks does it wrap the unchanged V2 recipient code. Its
`SYNTHETIC_ACCEPTED_STATE_AND_ARCHIVE_PIN` remains an internal mathematical
root/data check; the external node observations supply the explicitly trusted
chain-acceptance premise. Seed-only recovery must find the exact intended
recipient note and selected integer-sompi payment. Current witnesses need no payer/prover service. At terminal,
the backup must own the actual earlier revealed note and have no surviving
owned pool liability; both native payout UTXOs and zero reserve are checked.

`LOCAL_SUPPLIED_CONTEXT` is separate: immutable DO_NOT_FUND six-body evidence
can test these transformations, but verdicts always mark network confirmation
false. Mock node metadata in negative tests is not a live trial or a chain
acceptance result. No network-stage positive result exists in this packet yet.
