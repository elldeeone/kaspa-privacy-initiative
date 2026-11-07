# Adversarial review

This is research tooling and experimental one-party parameters, not a production
security review or proof of cryptographic soundness. No consensus code changes.

| Question | Constraint / executed evidence |
| --- | --- |
| Can a cache mint value or authorize a changed payout? | It attests only existing wallet-proof validity. Every settlement still runs current Ledger application and full native backing/payout/refund/cap checks. Valid static certificates for changed consent/unknown mode are rejected by fresh economics. Zero, maximum, out-of-range, overflow, altered recipient and fee cases are checked. |
| Can it spend the same note twice? | Current accepted anchors, NFT spentness and deposit status remain in `Ledger::apply`. Static validity remains true for an old proof; spending authority does not. Native exact-current-outpoint binding and UTXO consumption provide the separate native replay boundary. |
| Can the host claim verification happened? | The pinned guest calls `env::verify` for a fixed authorization image/exact journal. The actual Proven Succinct receipt must resolve that assumption. SDK/native final claims require successful complete execution with zero assumptions. Wrong-image/journal, malformed seal, Fake and wrong receipt-kind controls refuse. The actual Claim-only test is refused by SDK3.0.3 before receipt generation; no native conditional-proof execution is claimed. |
| Can malformed points bypass validation? | Original checked submitted-proof decoding and established BN254 arithmetic are reused. Compressed/full immutable key bytes are independently fully decoded, compared and canonically re-encoded by the host build gate before guest construction. |
| Can state or native effects be reused? | Only the complete ordered packet/domain/pool/key proof-validity fact is cached. Native old/new roots, actual predecessor/value, full payload and all outputs remain fresh. Actual native proof/effect transplant controls refuse. |
| Does cancellation add authority or a bank lock? | It stops only the research controller's owned process group. The actual accepted competing update invalidates the pending settlement. Original consent/certificate survive; the replacement checks the current bank. Independent actors can still race; sustained contention is unqualified. |
| What if cache/prover/registration disappears? | Public packets and retained exact software/key identities permit certificate recreation or direct full verification under the same new bank image. No unchecked fallback/admin key exists. The finite test preserves all data locally; independent all-service-loss recovery and public parameter/history availability remain unqualified. |
| Does the cache increase anonymity? | No. Protected output registration remains a separate mechanism. The actual registration-service view retains six candidate claimant/key allocations; labelled local redemption order, all-but-one collusion or later owner disclosure collapses them to one. Whole same-host controller observations are broader than the isolated service view. Amounts remain public. |
| Are timing and cost comparisons fair? | Original cross-arm cache reuse was detected and retained. A separate empty-cache reference repeats all four post-prefix certificates and must preserve native IDs. Charge cold creation, fresh proving/compression and discarded work; report one-off setup and wallet/onion work separately. Unknown operating costs prevent a complete commercial-price claim. |

The private execution-method selector chooses two full verification methods,
never an unchecked `already verified` flag. The static journal binds purpose and
wallet domain, pool, fixed wallet-key identity and SHA-256 of the entire canonical
Packet, including original proof/delivery/intent bytes. Changing the packet needs
another certificate even when individual wallet proofs remain mathematically
valid. Fresh economics must still accept that packet.

Wallet processes keep their own blinding state and random native payout keys.
The latest full backup, including those native keys, is required for the tested
restored-key spends. This does not establish seed-only, physical-loss, independent
participant or all-service-loss recovery. The root/operator of this one machine
can inspect every role. Research signing helpers trust the controller to supply
the intended initial program/config and payment instructions; they are not a
hardened production wallet interface.

The new TN10 domain uses the existing packed wallet relation with fresh
experimental one-party parameters. These are distinct from the retained offline
key/profile and are not interchangeable. The setup/cryptographic review and
durable independent parameter distribution remain unresolved. New guest images
start new banks; no old immutable bank is upgraded.


Completed evidence: the actual fresh TN10 run confirms four receipt-backed bank
settlements, unchanged original approvals after a real update, zero bank value
and five restored-key spends. Independent public-only replay and both synchronized
RPC routes agree with the retained observations. All eleven submissions have
at least ten observed confirmations. This closes the selected chain-functional
check, without expanding the qualifications above.
