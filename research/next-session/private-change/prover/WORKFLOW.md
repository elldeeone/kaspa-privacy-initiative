# Fresh-domain Auth528 prover workflow

ADR-0055 uses the unchanged 17-file unselected template selected by
`private-service-loss/prover/TEMPLATE-SOURCE-FREEZE-01.json`
(`b207222c4f7dda52a88e8682fed5af8eec521ac1ac678ab1077128ffee74d3ec`).
Root's new reuse-selection binds that original ADR-0053 provenance to ADR-0055,
the accepted private-change contract and one fresh public identity. Nothing in
an earlier package, trial, setup or frozen evidence is rewritten.

1. Materialize the new public source workspace. Only `src/lib.rs`'s DOMAIN array
   and `trial-selection.json` differ from the unselected template. Verify its
   exact 17-file source map. Build both existing binaries with frozen offline
   dependencies; mount only the source workspace, toolchain/cache and output.
2. Run the existing setup/session executable once, after root's concrete setup
   release. It receives one caller-known private shape outside Git, measures the
   finalized generator CS, exports the fresh public VK/PK identity and retains
   that one newly generated key. No old PK/matrix is read or mounted.
3. Export a public parameter candidate using the unchanged reviewed producer.
   Root selects the exact canonical manifest; a separate cold source copy alters
   only the three public parameter pin files. Compile the existing cold client,
   verify its selected full-size loader and hand its exact identity to the new
   owner-wallet release.
4. Generate six distinct local checked proofs under the resident key: the five
   linked main-route statements plus the separate exact-zero-change payment
   fork. `expected_proofs=6` is already supported by the existing controller.
   Actual fixtures and native body gates are the lifecycle lane's responsibility.
5. Stop the operator resident process before cold recovery. The four live owner
   actions use separate owner-local cold processes, authenticated public
   parameters, original backups and fresh public replay. The operator resident
   key/session never receives those owners' live witness submissions.

The unchanged CLI is:

```text
kpi-private-cashout-setup session PRIVATE_SHAPE_JSON NEW_SETUP_DIR NEW_PUBLIC_PK
kpi-private-cashout-prover loader-only PUBLIC_PK NEW_PUBLIC_REPORT_DIR
kpi-private-cashout-prover prove PUBLIC_PK WITNESS_FD NEW_PRIVATE_OUTPUT_DIR
kpi-private-cashout-prover verify AUTH528_FILE PROOF128_FILE
```

Source builds use 8 CPU/12GiB; active setup/proving uses 14 CPU/18GiB, swap0 and
unshared network. Generous operational caps are resource bounds, not security
qualification. Public runtime plans/results omit private shape/witness paths,
contents, hashes and owner associations. Private execution records stay outside
Git. Existing ordinary 0500 release/read-only mount/trusted-host assumptions and
reviewed private path checks remain unchanged.

No build, setup or private shape read was performed by writing this workflow.
