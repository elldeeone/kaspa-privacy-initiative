# Four-wallet ordinary funding and GN2 entry

ADR0060 research client. Native test KAS only. Existing programs, keys and
evidence remain unchanged. This package creates no W entry branch, operator
withdrawal key or new cryptographic primitive.

The new identity command completes independently of setup/proving:

```sh
python3 -B poc/four-wallet-bootstrap/new_trial.py \
  --identity research/next-session/four-wallet-testnet/PROFILE-IDENTITY.json \
  --identity-sha256 INDEPENDENTLY_SELECTED_IDENTITY_SHA \
  --destination /var/tmp/FRESH_UNUSED_TRIAL_DIRECTORY
```

Four network-isolated owner-init processes create four original compound
backups. Only A/C create initial notes; B/D supply the separate recipient
invoices. Every backup has the exact seven-field
`kpx6-four-wallet-backup/v1` format and two independent OS-random values: the
shielded seed and ordinary funding key. Only the owning process reads them.
The coordinator receives public invoices/records/addresses, never a central
dictionary of seeds, key contents or backup hashes. The original backup also
retains control of any ordinary funding change.

Identity creation is not financial-profile selection, funding, chain backing
or trial readiness. New trials reuse the reviewed financial profile with fresh
keys/outpoints/UUIDs; failed trials are not rebroadcast under a used identity.

Once the final financial profile and accepted source contexts are selected,
the public coordinator proposes an exact entry:

```sh
python3 -B poc/four-wallet-bootstrap/entry_cli.py prepare \
  --profile FINAL_PROFILE --profile-sha256 EXTERNAL_PROFILE_SHA \
  --trial-id UUID --owners PUBLIC_OWNER_A PUBLIC_OWNER_C \
  --sources PUBLIC_SOURCES_JSON --output FRESH_PROPOSAL_DIRECTORY
```

`PUBLIC_SOURCES_JSON` is a two-row array. Each row contains `outpoint`
(`transactionId`, `index`) and `entry` (`amount` integer sompi,
`scriptPublicKey`, `blockDaaScore`, `isCoinbase:false`, `covenantId:null`).
The GN2 frame is exactly 1080 bytes; both initial notes/CFs, fresh trial ID and
externally selected final financial-profile hash are signed. The state has
CM/NF roots and no CF root. CF bytes/hashes are in the signed entry payload.

Each actual original owner approves separately:

```sh
python3 -B poc/four-wallet-bootstrap/run_signer.py \
  --owner ORIGINAL_OWN_OWNER_DIRECTORY \
  --profile FINAL_PROFILE --profile-sha256 EXTERNAL_PROFILE_SHA \
  --case PROPOSED_CASE --trial-id UUID --output FRESH_OWN_CLIENT_DIRECTORY
```

This mounts only that original compound backup, immutable own initial record,
checked public proposal and selected software in a network-off namespace. The
owner independently re-quotes, checks its half/remainder entry fee, matches
the original note/CF, decrypts/rederives it and signs only its designated input
using ordinary Schnorr ALL. No PK or proof-generation worker is needed. An
approval digest is process evidence, not an additional cryptographic signature.

The coordinator combines two signature-only exports:

```sh
python3 -B poc/four-wallet-bootstrap/entry_cli.py combine \
  --profile FINAL_PROFILE --profile-sha256 EXTERNAL_PROFILE_SHA \
  --trial-id UUID --case PROPOSED_CASE \
  --approvals APPROVAL_A APPROVAL_C --output FRESH_COMBINED_DIRECTORY
```

Only the two input scripts may change. Exact body/quote/ID/storage mass and
Native Full/all input engines must pass. This package exposes no submit API.
Accepted funding/current UTXOs and all later accepted W transitions are the
separate chain adapter's responsibility.

`gn2.py` provides pure state derivation. Campaign `validate_genesis` and
`validate_proposal` require exact 10/10 budgets and signature-sized placeholders.
`validate_accepted_genesis` accepts canonical u16 budgets, because version1
ordinary signatures/txid do not cover those budgets. **The caller must first
establish actual Native Full and accepted-chain evidence.** It still checks
every financial/header/payload/source/root/allocation requirement and makes no
native-validity or currentness assertion. Historical fee is actual authorized
input-output difference, not a new reference quote after budget malleation.

Controls:

```sh
python3 -B -m unittest discover -s poc/four-wallet-bootstrap -p 'test_*.py'
```

The separately invoked `public_signature_controls.py` uses public control
scalars, nonexistent sources and an intentionally dummy OP_TRUE tail. Its
ordinary input Full success is **not actual W execution or financial-profile
validation**. It demonstrates why successful funding inputs alone do not
validate the created reserve program. Never fund its addresses or outputs.
`accepted_budget_controls.py` retains the actual same-signature/same-ID
budget 10→11 native-valid RED/GREEN and budget 0 native rejection.

No passing local result establishes accepted backing, privacy, sound setup,
independent service operators, production security or a complete fee target.
Read-only mounts and hashes retain the existing trusted-host/release premise.
