# Native confirmation boundary checked on 2026-10-28

Official `kaspanet/rusty-kaspa` `master` resolved by `git ls-remote` to
`4edcbbccb449f84832afb1ca157904b35f37d006`. This is a source check; no RPC,
submission, wallet, Original or private-state input was used.

`submitTransaction` returns a transaction ID after local submission succeeds.
That response does not establish subsequent acceptance. The existing once-only
submitter's separate read-only confirmation remains necessary.
[Official service implementation](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/service/src/service.rs#L629-L652)

`getVirtualChainFromBlock` returns removed/added chain blocks and optionally
accepted transaction IDs. It is paginated, rejects transitional IBD, and can
limit recent entries through `min_confirmation_count`. A consumer must handle
removed blocks and complete its selected prefix; an isolated transaction-ID
match does not authenticate the whole populated CASE.
[Official service](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/service/src/service.rs#L696-L742),
[request and response](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/model/message.rs#L781-L847)

`getUtxosByAddresses` requires an enabled UTXO index and rejects transitional
IBD. Its returned order need not match address order. Payout confirmation must
join exact outpoints and compare integer sompi and script bytes.
[Official service](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/service/src/service.rs#L751-L767)

The request decoder still accepts the older Borsh request version without
`min_confirmation_count`; that source fact does not qualify every compatibility
detail of the retained SDK. Keep the existing pinned SDK until actual finite
roundtrip and read-only acquisition checks establish a replacement.
[Official request decoder](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/model/message.rs#L804-L812)

## Existing implementation to reuse

- `../bootstrap/new_trial.py`: isolated original-wallet initialization without
  funding; its existing domain/key profile is not the new authorization profile.
- `../integration/campaign_cached.py:Campaign.settle`: consumes submission once
  and then performs only read-only whole-CASE reconciliation.
- `../chain/confirm_pool_borsh_shared_prefix.py:confirm`: compares accepted whole
  CASE, replays the prefix and checks actual payout UTXOs.
- `../bootstrap/gn3_runtime.py:Runtime.validate`: runs actual Native Full and all
  input ScriptEngines. Its supplied contexts remain an evidence boundary.
- `../integration/campaign_cached.py:Campaign.owner`: restores/scans one Original
  with finite downloaded public software, history and parameters.

One selected validating node and finite retained history do not establish
independent consensus, indefinite currentness or independent storage retention.
The existing 1-input/2-output financial profile, wallet derivation and Exit VK
cannot silently accept a new 3-input/6-output authorization-key-bound profile.
