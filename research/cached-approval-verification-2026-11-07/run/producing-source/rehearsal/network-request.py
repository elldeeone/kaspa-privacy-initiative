#!/usr/bin/env python3
"""Wallet-owned transport: no request or owner mapping is written by the driver."""
import importlib.util,json,pathlib,secrets,sys
p=pathlib.Path(__file__).resolve().parents[1]/'withdrawal-followup/network.py'
s=importlib.util.spec_from_file_location('retained_network',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=json.load(sys.stdin)
assert r['host'].endswith('.onion')
print(json.dumps(m.request(r['host'],80,r['message'],socks=r['socks'],isolation=secrets.token_hex(24).encode())))
