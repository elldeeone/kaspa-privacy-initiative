# Independent live accounting

Both real payment rounds, all nine independent withdrawals and the further
three fresh original-seed terminal scans passed. **The native reserve is zero;
all historical owned claims and payout keys reconcile. The 2% fee target fails.**

```text
9,615,864,283 mined source sompi
= 3,611,321,183 ordinary GN3 change
+ 5,788,849,600 confirmed native payouts
+             0 remaining native reserve
+     3,874,200 ordinary acquisition fees
+       668,900 GN3 fee
+    39,828,200 two mixed-batch fees
+   171,322,200 nine independent-exit fees
```

The independent auditor takes externally SHA-selected public bytes only. It
does not import the financial implementation or read files, backups, seeds or
ownership maps. It checks three ordinary cases and all 33 distinct coinbase
inputs; exact GN3 input/output and fee-share arithmetic; each accepted native
body against its replay receipt; state/script/outpoint continuity; distinct
nullifiers; exact payouts and fees; complete history/checkpoint joins; and both
retained exact-output query views.

The completed audit covers twelve accepted pool transactions, nine confirmed
native payouts, zero remaining reserve, and three separately selected fresh
original-seed terminal scans bound to that exact final history. Both accepted
payment rosters identify the same exact three participants; the terminal scan
participant set equals that public cohort. The neutral report exports only the
aggregate outcome. Earlier prefixes remain explicitly incomplete.

The useful-payment denominator is frozen at **2,100,000,000 sompi (21 KAS)**:
three 5-KAS payments and three 2-KAS payments. It is declared by the workload,
not inferred by decrypting payments. The complete fee numerator includes
ordinary acquisition, GN3, both mixed batches and all nine independent exits.
The 2% target is checked by integer multiplication; it cannot be made to pass
by changing amounts, omitting exit/acquisition fees or enlarging the denominator.

Actual all-in fees are **215,693,500 sompi (2.156935 KAS)**, or
**10.2711190476%** of the frozen 21-KAS useful payment volume. The exact fee ratio
is `431387 / 4200000`. The two mixed batches cost 0.398282 KAS; acquisition,
entry and especially the nine exits determine the full lifecycle verdict.

Exact input selections, scan inputs and the complete detailed result remain
locally retained outside the shared publication set.
`PUBLIC-LIVE-TERMINAL-01.json` is the final neutral publication view, SHA256
`20171bc5474dff30a70575c5153d04bcff5824f50b675276dc3a175843436079`.
Earlier source versions and their results remain retained. Nineteen focused
malformed-evidence controls passed,
including inflated sources/notes, wrong change keys, altered current outputs,
insufficient confirmations, duplicate JSON keys, boolean amounts and an attempt
to promote the GN3 prefix into lifecycle completion. These controls use explicit
synthetic mutations and establish no additional chain authority.
Two later focused controls over the real R2 prefix also rejected a changed
second-round participant and a terminal-scan cohort different from the accepted
payment cohort. Their report exports no participant IDs or scan receipts.

The SOURCE04 arithmetic auditor is unchanged after independent review. The
separate `public_report.py` renderer uses an explicit field allowlist. Shared
reports contain aggregate amounts/counts, fee buckets, aggregate terminal-scan
booleans and neutral accepted-prefix evidence hashes. Client scan/READY receipts,
participant identifiers, original/controller selectors and owner-to-exit
associations are excluded from publication. Detailed terminal-scan selections
and the full internal terminal result must remain outside the shared set.

The shared twelve-case lifecycle packet also omits the raw acquisition ledger
and three ordinary consolidation cases. The ledger carries ordered funding
labels, and the actual consolidation payload includes a participant identifier.
Copy preflight caught the nonempty payload before creating any publication
files. Removing that metadata would change the executed transaction bytes, so
the original cases remain unchanged and locally retained. Their acquisition
fees are included in the neutral all-in ledger; independent reviewers can
retrieve those ordinary transactions using the public GN3 previous-input IDs.
Those participant identifiers already exist on TN10. Omitting repository
copies does not remove that chain-visible linkage or qualify privacy.

This is an independent arithmetic and receipt-join pass over a **recorded
observation of one selected validating node**. Native/proof verification is
supplied by separately pinned replay evidence. It is not an independent
PoW/GHOSTDAG verifier, perpetual currentness, cryptographic correctness proof,
privacy qualification, retention guarantee or separate-administrator evidence.
