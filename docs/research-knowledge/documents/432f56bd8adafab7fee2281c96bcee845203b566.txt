The actual new-VK bodies quote **84,658,300 sompi** for the selected rehearsal:
funding preparation, founding, admission, one private transfer, Bob's partial
and remaining private exits, and Charlie's terminal private exit. This is a
four-verifier path. The bodies were constructed without native VM execution;
this report does not claim accepted history or confirmed payouts.

| Operation | Mining mass | Rate100 fee, sompi |
| --- | ---: | ---: |
| Source funding preparation | 9,114 | 911,400 |
| Founding, including GN536 | 25,746 | 2,574,600 |
| Public admission | 52,562 | 5,256,200 |
| Private transfer to two recipients | 189,587 | 18,958,700 |
| Bob partial private exit | 189,999 | 18,999,900 |
| Bob remaining private exit | 189,999 | 18,999,900 |
| Charlie terminal private exit | 189,576 | 18,957,600 |

Equal allocation of the 8,742,200-sompi ingress cost and paired transfer cost
gives Bob 51,850,250 sompi and Charlie 32,808,050 sompi of fees. Against each
10-KAS payment these are 5.185025% and 3.280805%. Bob's extra partial exit is
charged to Bob. The paired private transfer alone costs 9,479,350 sompi per
recipient, below the separate 1% ordinary-action target.

The 2% complete-lifecycle target fails even before this quoted example: one
two-recipient transfer plus both independent private exits requires three
Groth16 checks. Their rate100 verifier floor alone is 22,125,000 sompi per
recipient, above the 20,000,000-sompi target. No future users, retries or hidden
batch participants amortize that floor.

[`ACTUAL-FEE-PROFILE-01.json`](ACTUAL-FEE-PROFILE-01.json) pins every body,
actual amount, official mass result and fixed-body rate100/200/500 quote.
All eight rows, including a separately quoted continuing emergency REVEAL,
match the pinned integer source arithmetic exactly. At higher rates a changed
authorized fee or amount context requires its own fixed-point quote; the
existing rate100 authorizations do not authorize higher deductions. Mining
mass is the maximum of compute, twice estimated bytes, and contextual storage.

[`FEE-SHAPES-02.json`](FEE-SHAPES-02.json) records source-only shape arithmetic.
The original source-only founding row omitted GN536; that failure is retained
with an explicit [erratum](FEE-SHAPES-01-ERRATA.md). No native source, body or
proof changed because of the reporting correction.
