# Isolated owner API

Trusted supervisor only; never invoke this launcher from the untrusted public
coordinator. Default stages an operational private plan; `--execute` runs the
closed worker. Every operation takes these private controller selectors:

```text
python3 -B run_owner.py init|prepare|authorize
  --owner-directory PARTY/owner --mpc-directory PARTY/mpc --output FRESH_RUN
  --exclude-old-trial OLD_LOCAL --exclude-old-trial OLD_LIVE
  --exclude-new-private-directory PARTY0
  --exclude-new-private-directory PARTY1
  --exclude-new-private-directory PARTY2
  --peer-owner-directory PARTY0/owner
  --peer-owner-directory PARTY1/owner
  --peer-owner-directory PARTY2/owner
  [--execute]
```

Each complete party parent is mode0700 outside Git and contains regular private
owner/MPC files. The host inspects private metadata only. Each child receives
its own owner and MPC directories; prepare additionally receives only three
designated private participant-bound invoice leaves, never foreign directories.
The fixed public export is `FRESH_RUN/public/PUBLIC.json`. Every other file in
FRESH_RUN, including source staging and PRIVATE-PLAN/log files, remains a private
controller artifact and must not be blindly collected or published.

1. `init --participant-id HEX32 --position 0|1|2 --admission-sompi INTEGER
   --crypto SELECTED_ELF` creates one fresh unfunded seed and initial note,
   plus three private fixed240byte participant/invoice envelopes. Only initial
   CM, position, admission amount, domain and public participant ID are exported.
   Init requires neither proof setup nor SESSION nor a native fee quote.
2. `prepare --party 0|1|2 --assets FILE --assets-sha256 SHA --session FILE
   --session-sha256 SHA --context FILE --context-sha256 SHA` privately creates
   two Output proofs, complete tuples and the fixed2695byte own MPC input.
   Its public export is only the session/participant/input CM/NF/CVin skeleton.
3. `authorize --assets FILE --assets-sha256 SHA --session FILE
   --session-sha256 SHA --projection FILE --projection-sha256 SHA
   --own-mpc-result mpc-private-OPAQUE/OWN-MPC-PROJECTION.json` consumes the
   authentic result directly inside that owner's MPC mount. After all checks
   it exports only a genuine Spend proof and its full-pool effects statement.

Assets are the externally SHA-selected `kpx7-wallet-assets/v1` JSON with exact
fields `schema,domain_hex32,component_profile,component_profile_sha256,relation,
crypto,spend,output,codec_sha256,wire_sha256`. Programs have `path,sha256`;
parameters have `manifest,manifest_sha256,pk,pk_sha256`. The exact selected
component profile joins both manifest VKs, hashes and compiled Pedersen/program
identities before owner-state reads. Paths are public asset selectors, not
commands. Provers receive only minimal witnesses over owner-local stdin.

The pinned premix context and session formats are in worker.py and the
construction API. The context approves integer fee shares, initial state,
current point, reserve and exact native tail. Actual SESSION and SpendAuth must
wait for the selected new native budget/rate100 quote. This API does not claim
accepted backing, fund or broadcast a transaction, or reconcile a prior auth.

After the first durable disclosure barrier the worker refuses every prepare or
authorize attempt before opening old maps. Before authorization it can privately
archive the old fixed input and create fresh session/output/CVin material while
preserving the original note and NF. There is no map/secret reveal endpoint.
