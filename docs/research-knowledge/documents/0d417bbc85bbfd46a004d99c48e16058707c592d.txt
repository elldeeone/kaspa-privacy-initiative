# One-attempt public submission

`poc/four-wallet-live/submit.mjs` is the fixed submission entry point. Run it
with the selected read-only Node executable and `--use-openssl-ca`. It invokes
the fixed public Python preflight, checks the selected financial profile and
SDK, queries every exact source with real DAA immediately before sending,
commits an exclusive durable intent, then makes exactly one transaction RPC.
No backup, signing key, witness or proving parameter is read.

Required options are `--stage`, `--trial-directory`, `--trial-id`,
`--financial-profile`, `--financial-sha256`, `--descriptor`,
`--descriptor-sha256`, `--case`, `--case-sha256`, `--software-root`,
`--inventory`, `--inventory-sha256`, `--output`, and `--execute`.

1. Funding uses `--stage funding --journal PRIVATE-CONTROLLER-JOURNAL`.
2. A shared settlement or campaign exit additionally needs `--fetch`,
   `--fetch-sha256`, and `--bundle-directory` from fresh accepted acquisition.
3. An independent owner exit uses `--stage owner-exit --owner-attempt
   PRIVATE-OWN-ATTEMPT` plus those fresh accepted-prefix arguments. It requires
   no coordinator journal and no other owner's backup contents.

The output directory must be fresh. The journal/owner-attempt directory stays
outside source control. Paths to owner backups are used only to exclude their
metadata identities from public reads. `--rpc` optionally selects a public WSS
endpoint without credentials; the default is the selected TN10 vector endpoint.
All own preparations retain the explicit fee-rate100 quote; the optional
`--fee-rate` compatibility argument must equal 100. Historical accepted replay
does not reapply this own-preparation quote to valid unsigned-budget variants.

`RPC_ACK_ONLY` is never confirmation. Any unknown response leaves the intent
reserved forever and returns `RECONCILE_READ_ONLY`. Use the fixed public
runner's `fetch` and `reconcile`; never repeat a used identity's broadcast or
delete its intent. A retry of a failed trial means a new trial identity.

The exact SDK body/context must equal the strict native case before intent
reservation, including budgets, witnesses and all u64 bits. Later acceptance
may have valid same-ID budget/witness variants only after full accepted-body,
native and financial replay; both complete digests are retained without
changing the original intent.

The public preflight's offline SDK adapter accepts only transaction roundtrip
requests. Its SDK members are copied from the selected public tree into a
fresh read-only directory after all four backup metadata exclusions. The
accepted Full-page verifier receives that explicit selected SDK directory.
This public path therefore does not depend on an owner namespace's remapping
of the historical host SDK-cache path.

The host, system Python, selected immutable software installation and remote
validating TN10 node remain premises. Public source/mock controls establish
neither a completed live rehearsal nor privacy or independent consensus. No
live submit was executed while implementing these sources.
