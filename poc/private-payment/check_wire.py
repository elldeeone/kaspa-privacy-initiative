#!/usr/bin/env python3
"""Python/Rust differential public-codec checks; no private payment is proved."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import wire_format as wire


def fixture(corpus):
    def tagged(name): return hashlib.sha256(('KPI/P1/structural-fixture/' + name).encode()).hexdigest()
    intent = {name: tagged(name) for name in wire.IDS}
    intent['lane_id'] = tagged('lane_id')[:40]
    intent['network_genesis'] = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
    intent.update(operation_kind=1, append_mode=0, expiry_order_bound=None,
        anchor=corpus['commitment_tree'][0]['empty_roots'][32],
        nf=[x['note_nf'] for x in corpus['keys'][:2]],
        cmx_new=[x['cmx'] for x in corpus['note_encryption'][:2]],
        ephemeral_key=[x['ephemeral_key'] for x in corpus['note_encryption'][:2]],
        ciphertext=[x['c_enc'] for x in corpus['note_encryption'][:2]],
        deposit_reference=None, deposit_principal=0, exit_script=None, exit_principal=0,
        fee_script=None, private_fee_sompi=0)
    return intent


def main():
    binary, upstream, output = map(Path, sys.argv[1:])
    output.mkdir(exist_ok=False)
    corpus = json.loads(upstream.read_text()); base = fixture(corpus)
    script = {'version': 0, 'script': '20' + corpus['keys'][0]['ak'] + 'ac'}
    deposit = {'transaction_id': '11' * 32, 'index': 0, 'descriptor_hash': '22' * 32,
               'recovery_public_key': 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'}
    valid = []
    for expiry in (None, 0, (1 << 64) - 1):
        valid.append(('transfer-expiry-' + str(expiry), dict(base, expiry_order_bound=expiry)))
    valid.append(('transfer-fee-max', dict(base, private_fee_sompi=(1 << 64) - 1, fee_script=script)))
    for principal in (1, (1 << 64) - 1):
        valid.append(('credit-' + str(principal), dict(base, operation_kind=0,
            deposit_reference=deposit, deposit_principal=principal)))
    for mode in (0, 1):
        valid.append(('exit-mode-' + str(mode), dict(base, operation_kind=2, append_mode=mode,
            exit_script=script, exit_principal=1)))
    valid.append(('exit-principal-max', dict(base, operation_kind=2, append_mode=1,
        exit_script=script, exit_principal=(1 << 64) - 1)))
    results = []; truncations = 0
    with tempfile.TemporaryDirectory(prefix='kpi-wire-fixture-') as temp:
        source = Path(temp) / 'intent.json'

        def rust(value):
            source.write_text(json.dumps(value))
            return subprocess.run([str(binary.resolve()), str(source)],capture_output=True,text=True)

        for label, intent in valid:
            encoded = wire.encode(intent); other = rust(intent)
            if other.returncode or bytes.fromhex(other.stdout.strip()) != encoded:
                raise RuntimeError('Rust/Python bytes differ: ' + label + ' ' + other.stderr)
            if wire.decode(encoded) != intent: raise RuntimeError('roundtrip differs')
            for end in range(len(encoded)):
                try: wire.decode(encoded[:end])
                except ValueError: truncations += 1
                else: raise RuntimeError('truncation accepted')
            for suffix in (b'\0', b'\1', encoded):
                try: wire.decode(encoded + suffix)
                except ValueError: pass
                else: raise RuntimeError('trailing data accepted')
            results.append({'label': label, 'intent': intent, 'bytes': len(encoded),
                'encodedHex': encoded.hex(), 'intentId': hashlib.sha256(encoded).hexdigest()})
        invalid = []
        for field, values in {
            'operation_kind': [True, -1, 3, 0.0], 'append_mode': [True, 2, -1],
            'expiry_order_bound': [True, -1, 1 << 64, 1.0],
            'private_fee_sompi': [True, -1, 1 << 64, 1.0, '1'],
            'deposit_principal': [1], 'exit_principal': [1],
            'nf': [base['nf'][:1], base['nf'] * 2],
            'ciphertext': [[base['ciphertext'][0][:-2], base['ciphertext'][1]]],
            'anchor': [base['anchor'].upper()],
            'exit_script': [script],
        }.items():
            for value in values: invalid.append((field + ':' + str(value)[:30], dict(base, **{field: value})))
        invalid.extend([
            ('unknown-field', dict(base, unexpected=1)),
            ('missing-null-field', {k: v for k, v in base.items() if k != 'expiry_order_bound'}),
            ('missing-credit-authority', dict(base, operation_kind=0, deposit_principal=1)),
            ('exit-without-destination', dict(base, operation_kind=2, exit_principal=1)),
            ('empty-script', dict(base, private_fee_sompi=1, fee_script={'version':0,'script':''})),
            ('large-script', dict(base, private_fee_sompi=1, fee_script={'version':0,'script':'00'*10001})),
            ('script-version-overflow', dict(base, private_fee_sompi=1, fee_script={'version':65536,'script':'51'})),
            ('exit-only-transfer', dict(base, append_mode=1)),
            ('deposit-index-overflow', dict(base, operation_kind=0, deposit_principal=1,
                deposit_reference=dict(deposit,index=1<<32))),
        ])
        for label, value in invalid:
            try: wire.encode(value)
            except ValueError: pass
            else: raise RuntimeError('Python accepted ' + label)
            if rust(value).returncode == 0: raise RuntimeError('Rust accepted ' + label)
        # Positive edge cases supplement the frozen nine examples without
        # changing their established bytes or intent IDs.
        edge_cases = [
            dict(base, private_fee_sompi=1, fee_script={'version':65535, 'script':'00'*10000}),
            dict(base, private_fee_sompi=1, fee_script={'version':0, 'script':'51'}),
            dict(base, operation_kind=0, deposit_principal=1,
                 deposit_reference=dict(deposit,index=(1<<32)-1)),
        ]
        for value in edge_cases:
            encoded = wire.encode(value); other = rust(value)
            if other.returncode or bytes.fromhex(other.stdout.strip()) != encoded or wire.decode(encoded) != value:
                raise RuntimeError('script/deposit boundary interoperability failed')
        # The consensus envelope has no maps; JSON at the fixture boundary must
        # still reject duplicates rather than silently choosing one signature.
        duplicate = json.dumps(base).replace('"operation_kind": 1', '"operation_kind": 0, "operation_kind": 1')
        source.write_text(duplicate)
        duplicate_result = subprocess.run([str(binary.resolve()),str(source)],capture_output=True,text=True)
        if duplicate_result.returncode == 0: raise RuntimeError('duplicate JSON key accepted')
        for bad in (2,255):
            raw=bytearray(wire.encode(base));raw[len(wire.TAG)+244+2]=bad
            try: wire.decode(bytes(raw))
            except ValueError: pass
            else: raise RuntimeError('noncanonical option flag accepted')
    golden = {'scope':'STRUCTURAL_PUBLIC_INTENT_FIXTURES_NOT_VALID_PRIVATE_PAYMENTS_NEVER_BROADCAST',
              'note':'Crypto fields are unrelated published fixtures; there is no ownership/balance/encryption proof for these intents.',
              'vectors':results}
    frozen = json.loads((Path(__file__).parent/'vectors/intent-golden.json').read_text())
    if frozen != golden:
        raise RuntimeError('candidate bytes differ from retained golden corpus; review any format change explicitly')
    (output/'intent-golden.json').write_text(json.dumps(golden,indent=2)+'\n')
    report = {'scope':'PUBLIC_CODEC_INTEROPERABILITY_NOT_WALLET_PROOF_OR_AUDIT', 'goldenIntents':len(valid),
              'rustPythonEncodingMatches':True,'rejectedTruncations':truncations,
              'dualImplementationMalformedCases':len(invalid),'duplicateJsonRejected':True,
              'unknownOptionFlagsRejected':2,'retainedGoldenCorpusMatches':True,
              'additionalScriptDepositBoundaryCases':len(edge_cases),'nativeTransactions':0}
    (output/'wire-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__': main()
