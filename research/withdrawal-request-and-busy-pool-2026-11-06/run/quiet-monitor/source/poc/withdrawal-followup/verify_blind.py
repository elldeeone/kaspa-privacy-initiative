#!/usr/bin/env python3
"""Independent public RSA equation for actual blind-issuance responses."""
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives.serialization import load_der_public_key

config=json.loads(Path(sys.argv[1]).read_text())
pk=load_der_public_key(bytes.fromhex(config['issuerDer'])).public_numbers()
count=0
for line in Path(sys.argv[2]).read_text().splitlines():
    event=json.loads(line)
    if event['request']['kind']!='issue' or 'error' in event['response']:continue
    blind=int.from_bytes(bytes.fromhex(event['request']['blindMessage']),'big')
    signature=int.from_bytes(bytes.fromhex(event['response']['blindSignature']),'big')
    assert 0<blind<pk.n and 0<signature<pk.n
    assert pow(signature,pk.e,pk.n)==blind
    count+=1
assert count==3
print(json.dumps({'publicBlindSignatureEquationsVerified':count}))
