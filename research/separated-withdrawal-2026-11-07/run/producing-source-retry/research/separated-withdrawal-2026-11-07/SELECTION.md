# Separate wallet and withdrawal-service experiment

Selected before fresh observations, starting at `79f71e65`, 7 November 2026.
Owner authorizes separating wallets from the withdrawal service, attacking payout
ownership, and cost work only if privacy holds. No consensus or cryptographic
relation changes, broadcasts, real funds, mainnet, paid hosts or external contact.

## Question and fixed boundary

Can a withdrawal service map three known eligible claimants to their three new,
equal-value payout keys after genuine private payments and common-set approvals?
Reuse the existing wallet, Ledger, blind-RSA implementation, packed proof key,
and withdrawal kernel unchanged. A new offline harness changes deployment only.

Four wallets generate their own fresh backups in separate containers. Each has
only its own writable volume, read-only public parameters, and its own network
namespace/Tor client. The service has public state, its issuer key and full raw
service logs, but no wallet files, Docker socket, controller IPC, owner-local
schedule or scoring truth. The observer runs with service/public inputs only;
predictions are sealed before owner-local truth is collected for scoring.
Host root remains trusted: these are separate roles on ONE physical host,
not independent people, machines, a kernel-escape test or global traffic proof.

## Fixed matched workload and controls

Fresh four-wallet instances per arm. Deposit fixture: 40 synthetic KAS; genuine
credit and payments A->B 20, B->C 10, A->D 10, leaving four 10-KAS notes.
A/B/C register equal 10-KAS outputs and authorize the exact common payout set.
Service-side claim identities are admitted knowledge, not hidden-label anonymity.

1. Direct identified-source control: wallet-specific network endpoint accompanies
   both issue and redeem. It should reconstruct three correct owner/key links.
2. Honest common configuration, independent actual Tor clients: retain ALL
   service fields, lengths, timestamps, ports, proofs and blind signatures. Try
   exact fields/source joins and preselected issue-order/redemption-order matching.
   Never count a wrong unique guess as reconstruction or six permutations as a
   measured real-world anonymity guarantee.
3. Active service configuration tagging: test whether the existing wallets accept
   different service-supplied round IDs despite the same public bank/issuer/key/
   denomination. The adversarial issuer may deviate from round barriers, but
   must verify genuine eligibility and final credentials. Test whether ordinary
   whole-set approvals and the UNCHANGED withdrawal kernel reject the attack.
   This tests enforcement of the existing RFC's common-configuration requirement;
   it does not assume an authenticated common bulletin already exists.
4. Disclosed participant controls: one owner known, two owners colluding, and
   all owners disclosed. Separate these facts from the ordinary service view.
5. Actual filesystem/PID/network separation controls, and public proof replay.

## Gate and stop rule

The direct control and genuine proof/kernel checks must work. For a bounded
honest-service benefit, no observed exact service-only join may reconstruct the
honest mapping; report heuristic successes and uncertainty separately.
To progress to costs, the tested service must also fail to reconstruct the
mapping through its own configuration choices while wallets still authorize
valid payouts. If it succeeds, privacy gate FAILS: retain the narrow honest
benefit, stop cost work, document the missing client-side enforcement and the
smallest next privacy fix. Do not silently add a trusted common configuration,
change the observer, retune schedules or weaken fund/state checks.

No finite result here qualifies confidential amounts, complete financial privacy,
independent recovery or production security. Fresh native outer proving and
chain acceptance are unnecessary to demonstrate a leak already accepted by
genuine wallet authorization and the existing economic kernel; state that limit.
