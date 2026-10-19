#!/usr/bin/env python3
"""Independent public state/lineage reconstruction. Does not verify Groth16 or consensus."""
import hashlib
import json
import sys
from pathlib import Path

ZERO = bytes(32)
DEPTH = 16


def sha(data):
    return hashlib.sha256(data).digest()


def node(left, right):
    return sha(b'\x01' + left + right)


EMPTY = [ZERO]
for _ in range(DEPTH):
    EMPTY.append(node(EMPTY[-1], EMPTY[-1]))


def tree(leaves, index=None):
    path = []
    level = list(leaves)
    for depth in range(DEPTH):
        if index is not None:
            sibling = (index >> depth) ^ 1
            path.append(level[sibling] if sibling < len(level) else EMPTY[depth])
        level = [node(level[i], level[i + 1] if i + 1 < len(level) else EMPTY[depth])
                 for i in range(0, len(level), 2)]
    return (level[0] if level else EMPTY[DEPTH]), b''.join(path)


def u32(n):
    return n.to_bytes(4, 'little')


def nf_bytes(leaf):
    value, next_index, next_value = leaf
    return value + u32(next_index) + next_value


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def check(public):
    read = lambda name: json.loads((public / name).read_text())
    descriptor = read('descriptor.json')
    manifest = descriptor['identity']
    assert manifest['network'] == 'testnet-10'
    assert manifest['format'] == 'kpi-compact-deposits-v5'
    cm = [bytes(manifest['initial_commitment'])]
    external = {(u['txid'], u['index']): u for u in descriptor['sources'][1:]}
    assert len(cm) == 1
    nfs = [(ZERO, 0, ZERO)]
    cm_root = tree([sha(b'\0' + x) for x in cm])[0]
    roots = [cm_root]

    def state():
        return (b'\x05' + u32(len(cm)) + u32(len(nfs) - 1) +
                tree([sha(b'\0' + c) for c in cm])[0] +
                tree([sha(b'\x02' + nf_bytes(n)) for n in nfs])[0] +
                tree([sha(b'\x03' + u32(2*i+1) + r) for i, r in enumerate(roots)])[0])

    transactions = read('history.json')
    funding = transactions[0]
    assert funding['id'] == descriptor['funding_txid']
    previous = funding
    fees = 0
    for step, tx in enumerate(transactions[1:], 1):
        deposit = bytes.fromhex(tx['payload']).startswith(b'KPICD01\0')
        assert len(tx['inputs']) == (2 if deposit else 1)
        assert tx['inputs'][0]['previousOutpoint'] == {'transactionId': previous['id'], 'index': 0}
        sig = bytes.fromhex(tx['inputs'][0]['signatureScript'])
        assert sig[:2] == b'\x4c\x80' and sig[130:133] == b'\x4d\x00\x38'
        redeem = sig[133:]
        assert len(redeem) == 14336
        assert p2sh(redeem) == previous['outputs'][0]['scriptPublicKey']
        assert redeem[1:33] == bytes(manifest['domain'])
        assert redeem[36:141] == state()
        payload = bytes.fromhex(tx['payload'])
        assert len(payload) == 3892 and payload[:8] in (b'KPICR01\0', b'KPICD01\0')
        auth, cipher, wanted_state, witness = payload[8:273], payload[273:643], payload[643:748], payload[748:]
        assert auth[:8] == b'KPICU01\0' and auth[8:40] == bytes(manifest['domain'])
        count = int.from_bytes(auth[40:44], 'little')
        archive = [sha(b'\x03' + u32(2*i+1) + r) for i, r in enumerate(roots)]
        if deposit:
            assert count == 1 and len(nfs) > 1 and len(cm) >= 3
            assert witness[:1608] == bytes(1608)
            assert auth[172] == 1
            funding_input = tx['inputs'][1]['previousOutpoint']
            source = external.pop((funding_input['transactionId'], funding_input['index']))
            added = int(source['amount'])
            signature = bytes.fromhex(tx['inputs'][1]['signatureScript'])
            assert len(signature) == 66 and signature[0] == 65 and signature[-1] == 1
        else:
            added = 0
            assert 0 < count <= len(cm) and count % 2 == 1
            assert roots[(count-1)//2] == auth[44:76]
            assert tree(archive, (count-1)//2)[1] == witness[:512]
            value = auth[76:108]
            value_int = int.from_bytes(value, 'little')
            assert value_int and all(value != n[0] for n in nfs)
            pred = next(i for i, n in enumerate(nfs)
                        if int.from_bytes(n[0], 'little') < value_int and
                        (n[2] == ZERO or value_int < int.from_bytes(n[2], 'little')))
            old = nfs[pred]
            assert witness[512:516] == u32(pred) and witness[516:584] == nf_bytes(old)
            assert tree([sha(b'\x02' + nf_bytes(n)) for n in nfs], pred)[1] == witness[584:1096]
            new_index = len(nfs)
            nfs[pred] = (old[0], new_index, value)
            assert tree([sha(b'\x02' + nf_bytes(n)) for n in nfs], new_index)[1] == witness[1096:1608]
            nfs.append((value, old[1], old[2]))
        mode = auth[172]
        assert mode in (1, 2) and sha(cipher) == auth[233:265]
        if mode == 1:
            for i in range(2):
                assert tree([sha(b'\0' + c) for c in cm], len(cm))[1] == witness[1608+512*i:2120+512*i]
                output = auth[108+32*i:140+32*i]
                assert output != ZERO
                cm.append(output)
            assert tree(archive, len(roots))[1] == witness[2632:3144]
            roots.append(tree([sha(b'\0' + c) for c in cm])[0])
        else:
            assert auth[108:172] == bytes(64) and cipher == bytes(370) and witness[1608:] == bytes(1536)
        assert wanted_state == state()
        fee, payout = int.from_bytes(auth[181:189], 'little'), int.from_bytes(auth[173:181], 'little')
        reserve = int(previous['outputs'][0]['value'])
        assert int.from_bytes(auth[225:233], 'little') == (added if deposit else reserve if step == 1 else 0)
        terminal = len(cm) == len(nfs)-1
        assert len(tx['outputs']) == (1 if mode == 1 or terminal else 2)
        if not terminal:
            assert tx['outputs'][0]['scriptPublicKey'] == p2sh(redeem[:36] + wanted_state + redeem[141:])
            assert int(tx['outputs'][0]['value']) == reserve+added-payout-fee
        else:
            assert reserve == payout+fee and step == len(transactions)-1
        if mode == 2:
            output = tx['outputs'][0 if terminal else 1]
            assert int(output['value']) == payout and output['scriptPublicKey'] == auth[189:225].hex()
        else:
            assert payout == 0
        assert reserve + added - sum(int(o['value']) for o in tx['outputs']) == fee
        fees += fee
        previous = tx
    return {'transactions': len(transactions), 'commitments': len(cm), 'spends': len(nfs)-1,
            'all_claims_drained': len(cm) == len(nfs)-1, 'pool_fees_sompi': str(fees), 'independent_deposits': 3-len(external),
            'scope': 'Independent public state/lineage/amount reconstruction; not Groth16, consensus or anonymity verification'}


if __name__ == '__main__':
    print(json.dumps(check(Path(sys.argv[1])), indent=2))
