"""Public-only testnet transport. No wallet, proving, or chain-validation API.

Use selected official SDK transaction JSON after local full validation. SOCKS5h,
TLS and fresh Tor isolation are mandatory. Tor does not defeat a global timing
observer; the endpoint still sees the public request/transaction and its timing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import ssl
import subprocess
from dataclasses import dataclass
from urllib.parse import quote, urlsplit


class IngressError(RuntimeError):
    """No direct retry, weaker verification or implicit rebroadcast is allowed."""


def _url(value: str, scheme: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != scheme or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or any(c.isspace() for c in value)):
        raise IngressError("explicit TLS destination without auth/query/fragment required")
    # Destination names go to Tor; never resolve them with getaddrinfo locally.
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        raise IngressError("destination must be remote; proxy is loopback only")
    return value


def _integer(value: object, bits: int) -> bool:
    return type(value) is int and 0 <= value < (1 << bits)


def _hash(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _public_json(value: object) -> None:
    """Reject accidental private-envelope APIs; cannot classify arbitrary bytes.

    A caller can intentionally encode a secret into any public string. Privacy
    therefore requires the local builder boundary, not a keyword filter alone.
    """
    prohibited = {"seed", "privatekey", "spendingkey", "viewkey", "viewingkey",
                  "privatewitness", "witness", "noteplaintext", "scanindex",
                  "invoiceindex", "owner", "participant", "roster", "password"}
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str or key.replace("_", "").lower() in prohibited:
                raise IngressError("private envelope fields are not an ingress API")
            _public_json(item)
    elif isinstance(value, list):
        for item in value:
            _public_json(item)
    elif value is not None and type(value) not in {str, int, bool}:
        raise IngressError("public request must use exact integer JSON values")


def _request(method: str, params: dict, allow_broadcast: bool) -> None:
    _public_json(params)
    if type(params) is not dict:
        raise IngressError("public request params must be an object")
    keys = set(params)
    if method in {"getBlockDagInfo", "getServerInfo", "getInfo"} and not keys:
        return
    if method == "getBlocks" and keys == {"lowHash", "includeBlocks", "includeTransactions"}:
        if _hash(params["lowHash"]) and params["includeBlocks"] is True and params["includeTransactions"] is True:
            return
    if method == "getBlock" and keys == {"hash", "includeTransactions"}:
        if _hash(params["hash"]) and params["includeTransactions"] is True:
            return
    if method == "getVirtualChainFromBlock" and keys == {"startHash", "includeAcceptedTransactionIds"}:
        if _hash(params["startHash"]) and params["includeAcceptedTransactionIds"] is True:
            return
    if method == "submitTransaction" and allow_broadcast is True and keys == {"transaction", "allowOrphan"}:
        tx = params["transaction"]
        required = {"version", "inputs", "outputs", "lockTime", "subnetworkId", "gas", "payload"}
        permitted = required | {"mass", "storageMass", "verboseData"}
        if (type(tx) is not dict or not required <= set(tx) or set(tx) - permitted
                or params["allowOrphan"] is not False or not tx["inputs"] or not tx["outputs"]
                or type(tx["inputs"]) is not list or type(tx["outputs"]) is not list
                or not _integer(tx["version"], 16) or not _integer(tx["lockTime"], 64)
                or not _integer(tx["gas"], 64) or type(tx["payload"]) is not str
                or type(tx["subnetworkId"]) is not str):
            raise IngressError("complete public SDK transaction and allowOrphan=false required")
        for output in tx["outputs"]:
            if type(output) is not dict or not _integer(output.get("value"), 64):
                raise IngressError("output values must be integer sompi")
        for name in ("mass", "storageMass"):
            if name in tx and not _integer(tx[name], 64):
                raise IngressError("mass must be an exact unsigned integer")
        return
    raise IngressError("method/shape is outside the public testnet ingress contract")


@dataclass(frozen=True)
class TorIngress:
    proxy_port: int = 19050
    timeout: float | None = 300.0

    def __post_init__(self) -> None:
        if not _integer(self.proxy_port, 16) or self.proxy_port == 0:
            raise IngressError("explicit loopback SOCKS port required")
        if self.timeout is not None and (type(self.timeout) not in {int, float} or self.timeout <= 0):
            raise IngressError("timeout must be positive or None")

    def _proxy(self) -> str:
        # SOCKS credentials go only to the loopback Tor daemon. Never wallet IDs.
        return f"socks5h://{quote('<torS0X>0', safe='')}:{secrets.token_hex(32)}@127.0.0.1:{self.proxy_port}"

    def fetch_https_public(self, url: str) -> bytes:
        """Fetch a complete public history artifact. No private filtering API."""
        _url(url, "https")
        isolation = secrets.token_hex(32)
        args = ["/usr/bin/curl", "-q", "--silent", "--show-error", "--fail",
                "--proto", "=https", "--proto-redir", "=https", "--noproxy", "",
                "--socks5-hostname", f"127.0.0.1:{self.proxy_port}",
                "--proxy-user", f"<torS0X>0:{isolation}",
                "--max-time", str(self.timeout or 0), "--write-out", "\n%{http_code}", "--url", url]
        # -q is first: no ~/.curlrc, netrc, cookies or config-injected direct route.
        # No -L: curl never follows a redirect. No environment proxy bypass.
        result = subprocess.run(args, env={"PATH": "/usr/bin:/bin"}, capture_output=True)
        if result.returncode:
            raise IngressError("Tor HTTPS fetch failed; no direct fallback")
        body, separator, status = result.stdout.rpartition(b"\n")
        if not separator or len(status) != 3 or not status.startswith(b"2"):
            raise IngressError("HTTPS success required; redirects are not followed")
        return body

    async def rpc(self, url: str, method: str, params: dict, *, allow_broadcast: bool = False) -> dict:
        """One fresh TLS/SOCKS connection, one public RPC, no automatic replay.

        Before submit, the same peer must report testnet-10. This guards network
        selection, while local native validation authenticates the actual case.
        A submit response is a mempool acknowledgment, never confirmation.
        """
        _url(url, "wss")
        _request(method, params, allow_broadcast)
        # Freeze the validated public object before the first await. A caller
        # mutating its own dict during connection setup cannot alter the request.
        params = json.loads(json.dumps(params, separators=(",", ":"), allow_nan=False))
        from websockets.asyncio.client import connect

        class NoRedirectConnect(connect):
            def process_redirect(self, exc: Exception) -> Exception:
                return exc

        quiet = logging.Logger("public-tor-ingress", level=logging.CRITICAL + 1)
        quiet.addHandler(logging.NullHandler())
        try:
            async with asyncio.timeout(self.timeout):
                async with NoRedirectConnect(
                    url, proxy=self._proxy(), ssl=ssl.create_default_context(),
                    user_agent_header=None, additional_headers=None, compression=None,
                    open_timeout=self.timeout, ping_interval=None, ping_timeout=None,
                    max_size=None, logger=quiet,
                ) as ws:
                    async def call(rpc_method: str, rpc_params: dict, request_id: int) -> dict:
                        await ws.send(json.dumps({"id": request_id, "method": rpc_method, "params": rpc_params},
                                                 separators=(",", ":"), allow_nan=False))
                        while True:
                            response = json.loads(await ws.recv())
                            if type(response) is not dict:
                                raise IngressError("malformed wRPC response")
                            if response.get("id") != request_id:
                                continue  # Public unsolicited notifications are not results.
                            if response.get("method") != rpc_method or response.get("error") is not None:
                                raise IngressError("wRPC rejected public request")
                            if type(response.get("params")) is not dict:
                                raise IngressError("wRPC response missing params object")
                            return response["params"]

                    network = await call("getBlockDagInfo", {}, 1)
                    if network.get("network") != "testnet-10":
                        raise IngressError("peer does not report testnet-10")
                    if method == "getBlockDagInfo":
                        return network
                    return await call(method, params, 2)
        except IngressError:
            raise
        except Exception:
            # Do not include peer reply bodies, isolation credentials or stack logs.
            raise IngressError("Tor TLS wRPC failed; no direct fallback or replay") from None
