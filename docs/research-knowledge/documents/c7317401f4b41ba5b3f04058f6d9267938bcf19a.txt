# Fixed public runner

`poc/four-wallet-live/runner.py` performs public acquisition, accepted-history
reconciliation and journal inspection. It never signs, generates a proof,
reads an owner backup, or submits a transaction. All commands export only
status/counts to stdout. Public result files contain the actual transaction
and evidence digests needed for review; controller paths and owner mappings
are excluded.

The host, selected read-only software installation, ordinary operating-system
libraries and remote validating TN10 node are explicit premises. Node views
remain non-atomic. Passing these controls does not establish independent
consensus, financial privacy, production safety, or complete-trial readiness.

## Commands

1. `anchor`: capture a recent confirmed birth header using the selected fixed
   Node/SDK implementation. Output is `anchor.json`; this alone authorizes no
   funding. Recapture immediately before the fresh funded trial.
2. `fetch`: acquire the selected GN2/W accepted prefix and current exact
   outpoint observations. Output is `acquisition/fetch.json`, still
   `FETCHED_PENDING_REPLAY`.
3. `reconcile`: authenticate software and external evidence digests, exclude
   all four backup identities from every retained page before reading any
   page, copy exact pages read-only, then execute complete SDK Full-page,
   fresh NativeFull and genuine financial replay. Only that successful path
   can append an accepted correspondence receipt to an existing send intent.
4. `snapshot`: report intent, recorded acceptance and unresolved-intent counts.
5. `arithmetic`: require the complete six-stage campaign journal, four distinct
   payouts, zero final reserve and all-fee conservation. This is an independent
   arithmetic cross-check. The lifecycle ledger additionally requires actual
   original-backup owner results and final owner recovery scans.

Use `runner.py COMMAND --help` for exact arguments. Acquisition and replay
outputs must be fresh directories outside the source and private-owner trees.
The software inventory must include the complete live closure, fixed chain
`anchor.mjs` and `fetch.mjs`, the selected Node executable and all three SDK
members. Public profile, descriptor and SDK bytes are copied read-only before
Node receives their paths. Credentials and caller environment variables are
not inherited by the fixed acquisition process.

Public semantic replay uses a roundtrip-only SDK adapter and passes an explicit
fresh read-only SDK directory to the fixed Full-page verifier. It never relies
on the owner launcher's namespace remapping of the historical host SDK cache.
The adapter has no signing, key or RPC interface.

Campaign reconciliation uses `--journal` and one of `funding`, `settlement`,
`exit-01` through `exit-04`, or `fallback-01`/`fallback-02`. The actual accepted
prefix must preserve all earlier recorded financial effects and stage order.
The current fetch may include later accepted transactions; the target's
historical remaining reserve/head are derived by replaying its actual prefix.

Independent owner reconciliation uses `--owner-attempt --stage owner-exit`.
It reads that owner's existing public attempt identity and intent, and needs
no campaign journal or another owner's backup. The accepted full private exit
must spend exactly the previously observed physical head recorded in that
attempt. Recovery authority remains the verified accepted public history.

An immutable intent's exact case digest governs the one-attempt send/audit
record. A same-ID accepted budget/witness variant can reconcile only after
complete accepted bytes/context binding, fresh native acceptance and all
financial semantics pass. The accepted financial projection must match the
intent. The intent is never changed and no reconciliation command resubmits.
Historical reconciliation intentionally does not reapply a new-preparation
reference-rate fee quote to an accepted unsigned-budget variant.

## Checks run

- CLI parsing/help and all 20 current public Python controls passed.
- Five additional public synthetic orchestration controls passed: a mocked
  accepted byte variant records only after replay/native stages; replay refusal
  leaves no acceptance receipt; changed financial effects refuse; an owner
  attempt reconciles without a campaign journal; and a retained page hardlink
  to the fourth public backup sentinel refuses before replay.
- The additional controls mock SDK/native/chain work. They used only public
  synthetic sentinels and do not claim an actual accepted transaction, genuine
  proof, private-file access, network operation, or completed rehearsal.

Reproduce all 19 controls with:

```sh
python3 -B -m unittest discover -s poc/four-wallet-live -p 'test_*.py' -v
```

The five orchestration controls are retained in `test_runner.py`; their mocked
acceptance flags are synthetic test inputs, never external evidence authority.
