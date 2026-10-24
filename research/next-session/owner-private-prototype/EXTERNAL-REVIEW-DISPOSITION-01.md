# Disposition of the initial external source review

2026-10-24. The retained [review](EXTERNAL-SOURCE-REVIEW-01.md) examined an
in-progress snapshot. It is not an approval of the later implementation.

| Initial finding | Current implementation and evidence boundary |
| --- | --- |
| Financial circuits and native predicate absent | Separate Spend/Output circuits, a nine-proof guest and new native adapter now exist. Genuine component proof controls passed. Integrated guest/proof/native results must be read separately; implementation alone does not close this finding. |
| Foreign MPC domain accepted | Construction Source04 requires the fixed ADR0063 domain at session ingress. No cross-domain acceptance is permitted. |
| Variable private input lengths | Each owner now writes exactly 2,695 bytes. Decimal normalization occurs inside that party's namespace. No per-party completion times are sent to the isolated public coordinator. |
| Launcher has Docker access | This remains an explicit trusted-host boundary. The coordinator is a separate process without the socket, owner directories, host home or an execution-request API. Same-host namespaces do not establish independence from their administrator. |
| Missing integrated failure/privacy evidence | The frozen experiment records required cases and count-only truth separation. Component checks and a successful mix do not qualify anonymity or the complete native financial flow. |

The genuine six-output, three-party sorting run completed under the selected
Source04 and original resource limits. All parties agreed on the result. This
establishes neither complete financial authorization nor grouping privacy by
itself.

The initially proposed stock shuffle was also replaced after a separate source
check found that its unweighted malicious-switch check permits cancellation of
invalid switch residues. The retained counterexample is a source-level negative,
not a demonstrated network attack. The selected replacement uses the existing
malicious MPC engine's authenticated bits and fixed oblivious sorting network;
the original shuffle is not silently qualified by the replacement's result.

Selected source receipts:

- Construction `SOURCE-04.json`: `2bd9d631356bdbd90df622b2420605fd526feeb3674686200ef50236db939605`.
- Wallet `SOURCE-FREEZE-02.json`: `9ed37ba3e02f30618042a0f5d44b918af1a5fcc443048cfbb2f4f02aaf4e32ac`.
- Financial relation `SOURCE-01.json`: `b72693249a8e882d673a6d81d698983bfae9bc5bf0379600112ea3a64f319daf`.
- Public verifier `SOURCE-CODE-01.json`: `c8d6e0596b0eb6e428b39ba5d5606c4991c45ff61a0514405808ce79061a6314`.

No mainnet, accepted-chain backing, independent exit, anonymous transport,
malicious-host protection or production security claim follows from this work.
