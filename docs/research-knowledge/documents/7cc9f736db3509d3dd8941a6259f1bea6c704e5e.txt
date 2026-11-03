# Private-action proof implementation: second pass

Scope: build03 core relation and CLI. This is an implementation review of the
new, public, unfunded development profile, not a cryptographic audit.

| Attack | Enforced boundary and remaining dependency |
| --- | --- |
| Mint private value | Byte-ranged note values, bounded input total and exact input=private outputs+P+fee; exact public reserve_after=reserve-P-fee. These integer sums are far below the field modulus. Native backing and accepted ancestry still require the immutable native transition and genesis policy. |
| Spend twice | Real inputs prove original positioned HMAC NFs and CM membership; duplicate real positions and zero/duplicate public NFs reject. Current NF absence and exact consumed outpoint are native checks. An occupied-NF ownership proof may be valid and must still fail natively. |
| Release another owner's reserve | Every positive input proves separated s/k ownership and membership; at least one real input is required. Payout, fee, destination, current roots and outpoint are included in Auth528's hash. Native exact actual output/context binding remains mandatory. |
| Bypass terminal constraints | Mode flags are constrained Boolean predicates of Auth bytes. Terminal outputs are complete all-zero notes, public CMs zero, cipher hash SHA256(zero528), unchanged CM root/count and m+=2. Both original NF constraints remain unconditional. Native verifies zero actual ciphertext/CM paths before skipping append. |
| Switch setup shape by mode | Input/output allocations, SHA calls and selected-HMAC construction are fixed; terminal/P/real flags gate equalities. All 49 full-CS fixtures share dimensions. Genuine proofs under one fresh VK must additionally establish tested cross-mode compatibility; count equality alone is not a sparse-matrix identity proof. |
| Link sender or receiver | Input openings and private change remain witnesses. Conditional inequality forbids exact real-input emergency-key reuse. P, fee, count/root evolution, ciphertext and timing remain public. Global destination freshness/control, sealed-box padding distribution and traffic analysis are separate wallet/observer obligations. |
| Lose a prover or service | Existing proofless owner REVEAL is an explicit privacy-degrading fallback. This circuit adds no admin key. Obtaining current accepted data and producing an independently valid native transaction remain recovery-client obligations. |
| Replay stale or cross-profile state | New fixed D/magic/matrices/VK; Auth binds current roots/outpoint. Checked VK/proof decoding rejects wrong widths/noncanonical points/identity/arity. The caller selects the trusted VK. Native acceptance and reorg handling are separate. |

Full-CS controls deliberately call the relation directly, bypassing public host
validation. Parser failures are not counted as UNSAT. Alternate owner-chosen
canonical destinations are new statements; retaining the original proof for a
changed statement is a replay test, not an argument that every alternate
statement must be unsatisfiable.

The CLI has no PK or matrix loader. The one setup uses OsRng; its official
uncompressed PK stays outside Git and remains resident for the selected five
proofs. Public exact fixture bytes are copied once before submission, and each
proof report must match their SHA256, the source identity and the same fresh VK.
Passing these controls does not establish setup trust, production safety,
privacy qualification, accepted chain backing or a low-fee payment system.
