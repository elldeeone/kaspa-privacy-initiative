# ADR-0050: Unified private action with native payout and private change

**Status:** Accepted for a separate unfunded research prototype; not adoption.
**Date:** 2026-10-23 UTC.

## Problem and reused design

The existing native REVEAL publishes the spent note/CM, positioned NF credential
and key. The actual chain-only canary reproduces direct historical note-value
and output-to-payout disclosure. Established shielded join-split public-value
balance designs motivate a proof-backed native payout with hidden input notes
and optional private change. Current Kaspa and mature-protocol sources are
refreshed in the accompanying source comparison. No new primitive is invented.

## Exact selected experiment

Use the [new contract](../../research/next-session/privacy-recovery/PRIVATE-EXIT-CONTRACT.md),
Auth528: old 484-byte field positions with private magic KPX3AU01, followed by
P:u64LE at484 and full canonical destination SPK36 at492. Payload is4400 bytes.
State112, Note168, V2 invoices, ADMIT/REVEAL/genesis encodings and SHA/HMAC
formulas remain unchanged; new domain, matrices, setup/VK and immutable policy
are mandatory. The public unfunded development domain is SHA256 of exact ASCII
`KPI/private-exit/DO-NOT-FUND/v1/2026-10-23` (no newline/NUL):
`aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2`.
Never fund this public fixture or modify/migrate an existing instance.

Require hidden ownership s+k and current CM membership, two real/dummy NFs,
explicit integer ranges and `sumIn=sumPrivateOut+P+f`, `R'=R-P-f`.
I-2 is explicitly extended to name authorized native payouts separately from
private outputs and fees. P must be nonnegative, bounded and bound to the exact
native amount/destination; P0 transfers retain the previous identity. I-1 backing
and I-7 withdrawal authorization are unchanged. No payout is relabeled a fee.
P0 has all-zero destination and at least one positive private output. P>0 has
P>=10M and complete version-zero P2PK SPK binding. Conditionally require its
PK32 to differ from every real input note's emergency nativePK32. This blocks
that exact equality channel; it does not prove global freshness, control,
randomness or curve validity. The wallet validates and derives fresh destinations.

Continuing R'>=60M inserts two NFs and appends two private CM slots, including
hidden dummy padding: n'=n+2,m'=m+2. Terminal R'=0 requires P>0, zero complete
output-note witnesses including rho, zero CM0/CM1, zero cipher528 and zero
CM-append witnesses1024. Its ciphertext hash is SHA256(zero528), not zero.
Enforce inactive zeros before skipping appends; n'=n and CMroot is unchanged.
Both NF updates still execute,m'=m+2. This permits terminal exit at full CM
capacity; continuing append exhaustion remains a stated limitation.

One native pool input pays exact f and optional P. Verify actual outpoint/state/
R/fee, all public updates, fixed VK, full successor code/roots and exact payout
amount/SPK/position. Continuing outputs are pool0 plus payout1 when P>0;
terminal is payout0 only. SPK versions and covenant metadata are exact. Use one
shared verifier path rather than duplicate private branches. Proofless REVEAL
retains its note-bound key/ALL signature as an explicitly consented fallback;
unavailability must never silently trigger public note disclosure.

## Limits and evidence requirements

This does not hide public payouts, fees, timing, prior distributions or aggregate
conservation. Preserve all earlier privacy failures and emergency disclosure
horizons. One payment proof plus two independent cashout proofs already costs
at least44,250,000 sompi at reference100, or2.2125% per10-KAS recipient before
other costs. This route necessarily fails that unchanged complete-fee target.
No private-witness pooling, new payer, token or admin path repairs it here.

Before setup/proofs, review exact source and positive/negative fixtures covering
ownership, malformed/padded/terminal fields, ranges, stale/wrong roots, domains,
destination/context substitution and duplicate-spend state. Valid alternate
owner statements require fresh proofs; native current-context replay must reject.
Preserve original/funded sources, old failed measurements and all new failures.
Actual native bodies/fees and prospectively frozen privacy comparisons are
required before any claim beyond the tested prototype.
