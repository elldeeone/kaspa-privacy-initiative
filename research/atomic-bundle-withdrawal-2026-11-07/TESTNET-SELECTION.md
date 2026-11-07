# Atomic bundle: frozen TN10 acceptance trial

Selected 7 November 2026 before any transaction in this trial. This is a
Testnet-10 check of the optional current-L1 design in ADR-0116. No consensus
change, mainnet transaction, real funds, or privileged withdrawal path.

## Question and fixed workload

Can one complete 3-reply bundle fit in an ordinary accepted TN10 transaction,
be read by the separated wallets through public chain connections, and allow
the existing private-payment and native-withdrawal path to finish?

The fixture uses only integer sompi: a fresh 2.7 KAS trial funding output,
2.0 KAS bank, 1.2 KAS private principal, and 0.8 KAS fee allowance. A pays B
0.6 KAS; B pays C 0.3 KAS; A pays D 0.3 KAS. A/B/C each claim a 0.3 KAS
group payout. After approval D pays A 0.06 KAS. The same proving programs,
proof checks, withdrawal kernel, wallet backup/restore, and ordinary native
payout scripts as the complete previous TN10 rehearsal are used. The source
change pays the one ordinary public bundle transaction fee.

The issuer receives three private blind issue requests, sends only unusable
`queued` acknowledgements, and writes one bundle containing all three blinded
replies. The accepted transaction must contain those exact bytes. Three
separate wallet reader processes, using the two listed independently operated
TN10 public routes, each require the exact transaction body, exact payload,
network ID, ten confirmations, and no reported reorg before writing a local
accepted-bundle file. This is same-host process separation, not proof of
independent human users or censorship resistance.

## Pass, failure, and stop rules

Pass requires all of these: the single ordinary bundle transaction accepted;
each wallet's independent reader finds the exact bytes; three wallets verify
the complete public RSA relations and their own credential; the unchanged
kernel confirms the group payout, subsequent external payment and final
drainage; all five native payout outputs are spent with restored owner keys;
reserve and liability end at zero. Record all native fees, including the
bundle and recovered-output spends. The service-only timing observer must
have no exact owner-to-payout link. Report known-owner, amount, and network
observer limits separately.

Stop and preserve evidence if any acceptance or exact-body check fails, a
reader sees a reorg, a wallet can redeem from an incomplete/invalid bundle,
the service recovers an exact link, or native conservation/authorization fails.
Do not resubmit within a used trial identity. A retry creates a fresh
unfunded identity in one command. A missing service or reader halts the trial.
Passing this bounded trial does not prove production privacy, cryptographic
soundness, or independent-user agreement.
