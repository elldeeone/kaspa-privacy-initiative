# Adversarial review of the wallet agreement experiment

- **Value creation / unauthorized payout:** The new cohort check only gates
  release of a client's payout key. It does not sign or verify a fund-release
  transaction. Three original wallet approvals and the unchanged economic
  kernel authorize the final set; changed-intent replay is rejected. The
  supplied predecessor and native effects are not chain evidence.
- **Double spend / replay / stale root:** Each cohort operation must have a
  distinct nullifier and independently pass the existing Ledger proof check
  against the same configured state. The read-only controls reject a duplicate
  and a wrong state. Accepted-chain reorg and spend races were not retested.
- **Sender/receiver/amount leakage:** The round-tag leak was blocked, but the
  service's selective reply release reconstructs all three claim-to-payout
  links. Native payout amounts stay visible. A repeated honest order guess
  matched 3/3 in one fresh sample; that alone is not a rate estimate.
- **Dependency failure:** A silent or offline issuer can prevent this joint
  registration from finishing. The check safely withholds payout keys but does
  not improve availability or establish independent exits in this run.
- **Hidden trust:** Wallets accept a service-delivered transcript of genuine
  proofs. Proof validity does not show that the same transcript reached every
  wallet at once. The service controls its reply schedule, and this is the
  measured privacy failure. No independent release bulletin is assumed.
- **Boundary:** No new native receipt, Testnet payout, three-host ownership
  model, production deployment, security audit or consensus change was tested.
