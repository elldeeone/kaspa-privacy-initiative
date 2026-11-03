# Optional owner-origin Exit transport experiment

This isolated prototype receives exact public Exit bytes. It has no wallet,
signer, accepted-head, settlement, submission or broadcast API.

`packet.py` wraps a 1,796-byte terminal or 1,844-byte continuing projection and
its 128-byte proof in one 4,096-byte frame. Random padding has no authorization
meaning. Decoding returns untrusted bytes; it does not verify a proof.

`transport.py` sends that frame through curl's SOCKS5 hostname path to a single
selected v3 onion endpoint. Stream-isolation tokens stay in a sealed config FD.
There are no automatic retries, redirects or direct-network fallback. A 202
response acknowledges transport receipt only. The eventual owner retains the
independent direct Exit route and may choose it explicitly.

`receiver.py` binds only loopback. It requires the selected common Host and one
canonical instance of each fixed header. Duplicate lengths, Transfer-Encoding
and identifying headers are refused. It preserves actual socket-acceptance
sequence/time, handler time, raw parser-visible request metadata, completion
time and received public bytes. It also records malformed requests and
unsupported methods. Completion order never replaces acceptance order.

Nine focused controls passed: exact byte round trips, malformed framing,
non-onion destinations, canonical HTTP shape, duplicate/ambiguous headers,
parser failures, reverse body-completion order and partial FD-allocation
cleanup. These used synthetic frames and real loopback HTTP sockets only.
The selected launcher and actual Tor route remain separately unqualified until
their own execution receipt exists. A marker file alone cannot establish an
empty namespace or tool provenance.

The intended launcher uses empty filesystem roots, selected public source and
tools, and only each role's own generated transport state. It never mounts an
Original, owner AK, payout secret, controller candidate path or another role's
state. Generated onion-service keys remain private transport state and are
never copied into public evidence. Installed-runtime trust must be stated
explicitly; observed hashes are not archive authentication.

This is not an anonymity experiment. Same-host observers can correlate launch,
pipe and network metadata. Public amounts, payouts, timing, counterparties and
nullifiers remain observable. In particular, the frozen METHOD02 comparison
keeps its source-known A/B ordering counterexample; this prototype neither
changes that workload nor removes that result. Later owner integration and a
separately frozen experiment are needed to measure a dispatcher-view change.
