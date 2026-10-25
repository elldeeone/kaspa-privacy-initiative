"""Public local controls only. No external network, wallet or funded fixture."""
import asyncio
import json
import socket
import ssl
import unittest
from unittest.mock import patch

from tor_ingress import IngressError, TorIngress, _request, _url


def transaction():
    return {"version": 1, "inputs": [{"previousOutpoint": {"transactionId": "00" * 32, "index": 0},
            "signatureScript": "", "sequence": 0, "sigOpCount": 0, "computeBudget": 1}],
            "outputs": [{"value": 1, "scriptPublicKey": "0000"}], "lockTime": 0,
            "subnetworkId": "00" * 20, "gas": 0, "payload": "", "mass": 0}


class ContractControls(unittest.TestCase):
    def test_reject_non_tls_identified_or_filtered_urls(self):
        for url, scheme in [("ws://example.org", "wss"), ("https://a:b@example.org", "https"),
                            ("https://example.org/a?scanIndex=2", "https"),
                            ("https://example.org/a#owner", "https"), ("https://localhost", "https")]:
            with self.subTest(url=url), self.assertRaises(IngressError):
                _url(url, scheme)

    def test_no_private_or_owner_filter_api(self):
        for method, params in [("getUtxosByAddresses", {"addresses": ["public-fixture"]}),
                               ("getBlock", {"hash": "00" * 32, "includeTransactions": True, "viewKey": "fixture"}),
                               ("getInfo", {"scan_index": 1})]:
            with self.subTest(method=method), self.assertRaises(IngressError):
                _request(method, params, False)

    def test_submit_requires_explicit_release(self):
        with self.assertRaises(IngressError):
            _request("submitTransaction", {"transaction": transaction(), "allowOrphan": False}, False)

    def test_submit_refuses_float_bool_negative_overflow_sompi(self):
        for value in [True, 1.0, -1, 1 << 64]:
            tx = transaction()
            tx["outputs"][0]["value"] = value
            with self.subTest(value=value), self.assertRaises(IngressError):
                _request("submitTransaction", {"transaction": tx, "allowOrphan": False}, True)

    def test_complete_public_transaction_has_no_private_envelope(self):
        tx = transaction()
        _request("submitTransaction", {"transaction": tx, "allowOrphan": False}, True)
        tx["witness"] = {"seed": "public-fixture-only"}
        with self.assertRaises(IngressError):
            _request("submitTransaction", {"transaction": tx, "allowOrphan": False}, True)

    def test_public_sync_cursor_requires_canonical_public_hash(self):
        for cursor in ["owner-A", "00 " * 32, 7]:
            with self.subTest(cursor=cursor), self.assertRaises(IngressError):
                _request("getBlocks", {"lowHash": cursor, "includeBlocks": True, "includeTransactions": True}, False)
        _request("getBlocks", {"lowHash": "00" * 32, "includeBlocks": True, "includeTransactions": True}, False)

    def test_https_curl_has_no_ambient_config_fallback_or_redirect(self):
        class Result:
            returncode = 0
            stdout = b"complete public history\n200"

        with patch("tor_ingress.subprocess.run", return_value=Result()) as run:
            ingress = TorIngress()
            self.assertEqual(ingress.fetch_https_public("https://example.org/history.json"), b"complete public history")
            args = run.call_args.args[0]
            self.assertEqual(args[:2], ["/usr/bin/curl", "-q"])
            self.assertIn("--socks5-hostname", args)
            self.assertEqual(args[args.index("--noproxy") + 1], "")
            self.assertNotIn("-L", args)
            self.assertNotIn("--insecure", args)
            self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})

    def test_https_failure_has_no_second_attempt(self):
        class Result:
            returncode = 7

        with patch("tor_ingress.subprocess.run", return_value=Result()) as run:
            with self.assertRaises(IngressError):
                TorIngress().fetch_https_public("https://example.org/history.json")
            self.assertEqual(run.call_count, 1)

    def test_https_redirect_is_rejected(self):
        class Result:
            returncode = 0
            stdout = b"public fixture redirect\n302"

        with patch("tor_ingress.subprocess.run", return_value=Result()) as run:
            with self.assertRaises(IngressError):
                TorIngress().fetch_https_public("https://example.org/history.json")
            self.assertEqual(run.call_count, 1)


class TransportControls(unittest.IsolatedAsyncioTestCase):
    async def test_real_socks_hostname_auth_and_no_tls_downgrade(self):
        observed = []

        async def fake_socks(reader, writer):
            try:
                version, count = await reader.readexactly(2)
                methods = await reader.readexactly(count)
                self.assertEqual(version, 5)
                self.assertIn(2, methods)
                writer.write(b"\x05\x02")
                await writer.drain()
                auth_version, user_len = await reader.readexactly(2)
                user = await reader.readexactly(user_len)
                pass_len = (await reader.readexactly(1))[0]
                password = await reader.readexactly(pass_len)
                self.assertEqual(auth_version, 1)
                writer.write(b"\x01\x00")
                await writer.drain()
                self.assertEqual(await reader.readexactly(4), b"\x05\x01\x00\x03")
                host_len = (await reader.readexactly(1))[0]
                host = await reader.readexactly(host_len)
                port = int.from_bytes(await reader.readexactly(2), "big")
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                tls_prefix = await reader.readexactly(3)
                observed.append((user, password, host, port, tls_prefix))
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(fake_socks, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ingress = TorIngress(proxy_port=port, timeout=5)
            with patch.dict("os.environ", {"no_proxy": "*", "wss_proxy": "http://127.0.0.1:1"}):
                for _ in range(2):
                    with self.assertRaises(IngressError):
                        await ingress.rpc("wss://public-fixture.invalid:443", "getInfo", {})
        self.assertEqual(len(observed), 2)
        for user, password, host, dest_port, tls_prefix in observed:
            self.assertEqual(user, b"<torS0X>0")
            self.assertEqual(len(password), 64)
            self.assertEqual(host, b"public-fixture.invalid")
            self.assertEqual(dest_port, 443)
            self.assertEqual(tls_prefix[:2], b"\x16\x03")
        self.assertNotEqual(observed[0][1], observed[1][1])

    async def test_proxy_down_never_resolves_destination_or_retries(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        original = socket.getaddrinfo
        names = []

        def traced(host, *args, **kwargs):
            names.append(host)
            return original(host, *args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=traced), self.assertRaises(IngressError):
            await TorIngress(proxy_port=port, timeout=2).rpc("wss://public-fixture.invalid", "getInfo", {})
        self.assertNotIn("public-fixture.invalid", names)

    async def test_wrpc_framing_tls_and_network_gate(self):
        captured = []
        frames = []
        network = ["testnet-10"]

        class FakeWebSocket:
            async def send(self, raw):
                self.last = json.loads(raw)
                frames.append(self.last)

            async def recv(self):
                last = self.last
                params = {"network": network[0]} if last["method"] == "getBlockDagInfo" else {"transactionId": "public-fixture"}
                return json.dumps({"id": last["id"], "method": last["method"], "params": params})

        class FakeConnect:
            def __init__(self, url, **kwargs):
                captured.append((url, kwargs, self))

            async def __aenter__(self):
                return FakeWebSocket()

            async def __aexit__(self, *args):
                return False

        params = {"transaction": transaction(), "allowOrphan": False}
        with patch("websockets.asyncio.client.connect", FakeConnect):
            result = await TorIngress().rpc("wss://public-fixture.invalid", "submitTransaction", params, allow_broadcast=True)
            self.assertEqual(result["transactionId"], "public-fixture")
            self.assertEqual([f["method"] for f in frames], ["getBlockDagInfo", "submitTransaction"])
            frames.clear()
            network[0] = "mainnet"
            with self.assertRaises(IngressError):
                await TorIngress().rpc("wss://public-fixture.invalid", "submitTransaction", params, allow_broadcast=True)
            self.assertEqual([f["method"] for f in frames], ["getBlockDagInfo"])
        _, options, connection = captured[0]
        self.assertTrue(options["proxy"].startswith("socks5h://"))
        self.assertIsNone(options["user_agent_header"])
        self.assertIsNone(options["additional_headers"])
        self.assertEqual(options["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(options["ssl"].check_hostname)
        redirect_error = RuntimeError("public fixture redirect")
        self.assertIs(connection.process_redirect(redirect_error), redirect_error)
        self.assertNotEqual(captured[0][1]["proxy"], captured[1][1]["proxy"])


if __name__ == "__main__":
    unittest.main()
