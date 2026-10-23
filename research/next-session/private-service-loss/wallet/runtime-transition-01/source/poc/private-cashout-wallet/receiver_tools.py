"""Exact-source V2 receive/tree reuse plus a sealed supported crypto adapter."""
import json
from pathlib import Path
import re
import sys
import types

from owner_rules import digest, hx, need, parse

V2_SOURCE_SHA256 = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
ROOT = Path(__file__).resolve().parents[2]


def recipient():
    path = ROOT / 'poc/future-recipient/v2/recipient.py'
    raw = path.read_bytes()
    need(digest(raw) == V2_SOURCE_SHA256, 'recipient-source-identity')
    name = '_kpx3_private_cashout_receiver_v2'
    if name not in sys.modules:
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        try:
            # Compile the authenticated bytes themselves, without a second
            # pathname read. Base Python/imported standard libraries are trusted.
            exec(compile(raw, str(path), 'exec'), module.__dict__)
        except BaseException:
            del sys.modules[name]
            raise
    return sys.modules[name]


class Crypto:
    def __init__(self, executable):
        self.executable = executable

    def call(self, operation, *, secret=None, public=None, payload=None):
        request = {'op': operation}
        for name, value in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
            if value is not None:
                request[name] = value.hex()
        process = self.executable.run(input=json.dumps(request))
        try:
            result = parse(process.stdout)
        except (ValueError, TypeError):
            raise recipient().Invalid('crypto-adapter') from None
        if process.returncode or type(result) is not dict or 'error' in result:
            error = result.get('error', 'adapter') if type(result) is dict else 'adapter'
            if type(error) is not str or re.fullmatch('[a-z0-9-]{1,80}', error) is None:
                error = 'adapter'
            raise recipient().Invalid('crypto-' + error)
        try:
            need(set(result) == {'hex'}, 'crypto-response-fields')
            return hx(result['hex'])
        except (ValueError, TypeError, KeyError):
            raise recipient().Invalid('crypto-adapter') from None

    def xonly(self, secret):
        return recipient().fixed(self.call('derive-xonly', secret=recipient().fixed(secret)))

    def delivery_public(self, secret):
        return recipient().fixed(self.call('derive-delivery', secret=recipient().fixed(secret)))

    def seal(self, public, plaintext):
        return self.call('seal', public=recipient().fixed(public), payload=plaintext)

    def unseal(self, secret, ciphertext):
        return self.call('unseal', secret=recipient().fixed(secret), payload=ciphertext)
