#!/usr/bin/env python3
"""Extract five public plain-Ed25519 RFC 8032 vectors; never wallet secrets."""
import hashlib
import json
from pathlib import Path
import re
import sys

RFC_SHA256 = 'ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3'


def main():
    source, output = map(Path, sys.argv[1:])
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != RFC_SHA256:
        raise RuntimeError('unexpected RFC text; source change requires review')
    text = raw.decode().split('\n7.1.  Test Vectors for Ed25519\n', 1)[1].split('\n7.2.', 1)[0]
    vectors = []
    for block in text.split('-----TEST ')[1:]:
        def field(begin, end):
            body = block.split(begin, 1)[1].split(end, 1)[0]
            return ''.join(line.strip() for line in body.splitlines()
                           if re.fullmatch(r'[0-9a-f]+', line.strip()))
        sk = field('SECRET KEY:', 'PUBLIC KEY:')
        pk = field('PUBLIC KEY:', 'MESSAGE (')
        length = int(re.search(r'MESSAGE \(length (\d+) bytes?\)', block)[1])
        message = field('bytes):' if length != 1 else 'byte):', 'SIGNATURE:')
        sig = field('SIGNATURE:', '-----')
        if len(sk) != 64 or len(pk) != 64 or len(message) != 2*length or len(sig) != 128:
            raise RuntimeError('RFC vector extraction shape mismatch')
        vectors.append({'label':block.splitlines()[0].strip(),'sk':sk,'pk':pk,'message':message,'signature':sig})
    if len(vectors) != 5: raise RuntimeError('expected all five plain Ed25519 vectors')
    value = {'scope':'PUBLISHED_RFC8032_TEST_KEYS_NEVER_FUND','source':{
        'url':'https://www.rfc-editor.org/rfc/rfc8032.txt','sha256':RFC_SHA256,'section':'7.1'},'vectors':vectors}
    with output.open('x') as f: json.dump(value,f,indent=2);f.write('\n')
    print(json.dumps({'rfc8032PlainEd25519Vectors':len(vectors)}))


if __name__ == '__main__': main()
