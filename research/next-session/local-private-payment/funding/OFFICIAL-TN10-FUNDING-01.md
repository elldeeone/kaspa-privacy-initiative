# TN10 free funding: documented faucet, browser gate

**The official Kaspa Wiki lists [faucet-tn10.kaspanet.io](https://faucet-tn10.kaspanet.io/) for TN10 and names Kaspa Discord’s `#testnet` channel as the alternative for urgent test KAS.** These are documented funding routes; neither a successful claim nor available faucet inventory was established. [Primary testnet page](https://wiki.kaspa.org/en/testnets).

One read-only homepage GET through the existing Tor SOCKS5H/TLS transport at **2026-10-25 21:50:54 UTC** returned **HTTP403** with `cf-mitigated: challenge`. Its title was “Just a moment...” and it requested JavaScript and cookies. The browser challenge was not solved. No address, account, claim or payout request was submitted. The response does not identify a CAPTCHA type.

| Capability | Verified result |
| --- | --- |
| Officially documented TN10 faucet URL | Yes |
| Current response from that URL | Cloudflare browser challenge |
| Current payout amount / cooldown / public API | Unknown; blocked before the application UI |
| Automated funding available now | Not established |
| Other official documentation route | Ask in Discord `#testnet`; no message sent |

The Wiki also requests CPU-only testnet mining and asks participants to avoid GPU, FPGA and ASIC mining to preserve decentralization. That operational request should be considered separately before submitting GPU-generated work; an offline kernel prototype makes no network contribution. [Same primary page](https://wiki.kaspa.org/en/testnets).

The official [kaspanet/faucet repository](https://github.com/kaspanet/faucet) was archived on2022-09-28. Its code cannot establish today’s deployed amount, rate limit, endpoint or challenge behavior, so no old API is proposed as a workaround.

Exact public response hashes and retained raw paths are in [FAUCET-CAPABILITY-01.json](FAUCET-CAPABILITY-01.json). No private wallet, seed, old reserve or wallet address was read; no funding, mining reset, message, challenge bypass or block submission occurred.
