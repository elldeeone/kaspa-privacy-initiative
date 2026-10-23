# Six checked local proofs under one fresh setup

All six selected statements produced genuine Groth16 proofs and passed checked
verification under the same fresh domain, VK and compiled core/build. The five
main-route statements exercise private payment, positive-change partial cashout,
payment from recovered change, continuing full cashout and terminal cashout.
The sixth is the separately selected independent public-canary zero-change
payment control. These are unbroadcast supplied-context local results.

The [scoped summary](session-01/CHECKED-PROOFS-SUMMARY.json) contains only the
root-approved opaque selected Auth/proof hashes, counts, outcomes and timings.
Times were 8.203, 8.118, 7.972, 8.151, 7.975 and 8.041 seconds for request parsing,
proof generation and checked verification. Actual private output file widths/
hashes match their reports; six selected Auth hashes and six proof hashes are
distinct. No private witness or its hash/path is exported. Main raw Auth/NF/body/
cipher/proof bundles remain outside Git: publishing parallel unbroadcast
authorizations can expose real-NF intersections with later cold preparations.

The [session result](session-01/RESULT.json) records exactly one fresh setup,
six checked proofs and no old PK/matrix load. After the sixth event the operator
received quit once and stopped inactive/dead, PID0, exit0 and error null.
All 14 frozen runtime inputs remained unchanged. The unchanged controller's
distinct-statement checks and allowed public event schema were preserved.

The [resource summary](session-01/RESOURCE-SUMMARY.json) has 2,758 samples, a
4,951,035,904-byte observed cgroup peak and zero observed swap. Inner GNU time
reports RSS 4,222,760 KiB and 507.36 CPU seconds. Wall 23:18.14 includes resident
idle time; neither these peaks nor wall time isolate a proving phase or establish
p95. Four later cold-owner processes have separate resource and recovery gates.

Shared-VK checked proofs demonstrate compatibility across these selected modes;
no raw matrix digest, security proof or production qualification is claimed.
Lifecycle owns exact proof-only body substitution and native Full/all-engine
validation. This report establishes neither accepted-chain backing/payouts,
independent network recovery, general financial privacy nor the fee target.
