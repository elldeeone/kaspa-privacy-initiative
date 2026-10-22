# Conditional fee frontier

Freeze before calculation: use native source commit
`01b532e8b553523216471682649693af92f0fd16`, two public field inputs in the
existing v6 verifier, rates100/200/500, and unchanged RFC-0012 targets. Count
only necessary proof-verification costs; every omitted cost is nonnegative.
Use exact integer sompi and rational ratios. No transaction or proof is created.

Cases: one verifier per ordinary transaction; one unamortized ADMIT plus one
fresh direct verifier per complete lifecycle; one60M-sompi note with a10M
payout floor. Compare normal payment endpoints10/100/1000 tKAS and keep every
failure. These are conditional route bounds, not observed transaction quotes.
Shared/amortized admission, already authorized withdrawal vouchers and
receiver-only payment histories require separate accounting and do not inherit
the two-verifier assumption. Recycled principal cannot enlarge the denominator.

Expected discriminator: the two-verifier route cannot meet the2% complete
lifecycle cap for10 tKAS at reference100, even with free private transfers and
zero overhead. Independent architecture review checked the inequality before
calculation. Preserve current requirements, profiles and native defaults.
