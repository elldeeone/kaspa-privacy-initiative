"""Finite private TN10 byte assembly; runtime domain, no network or public seeds.

Merkle/NF/layout formulas are adapted unchanged from the sealed candidate-C
experiment. Chain acceptance is established separately by the finite adapter.
All outputs here are private trial files, never a public fixture packet.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[2]
CLASS = 'PRIVATE_TN10_TEST_KAS_ONLY'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
sys.path.insert(0, str(ROOT / "poc/future-recipient/v2"))
from recipient import (Crypto, Delivery, ExpectedState, NFEntry, Receiver, Receipt,
 Snapshot, ZERO, h, u32, u64, recover, exit_witness)
RATE = 100
GENESIS_VALUE = 60_000_000
PAYMENT_VALUE = 1_000_000_000
MAX_SOMPI = 2_870_000_000_000_000_000
STATE_MAGIC = b"KPX2ST01"
AUTH_MAGIC = b"KPX2AU01"

def save(path, value):
 path=Path(path)
 path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
 fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
 with os.fdopen(fd,'wb') as f:
  f.write((json.dumps(value,indent=2,sort_keys=True)+'\n').encode())
  f.flush()
  os.fsync(f.fileno())

def load(path):
 return json.loads(Path(path).read_bytes())

def sompi(value):
 if type(value) is not int or not 0 <= value <= MAX_SOMPI:
  raise ValueError("integer sompi range")
 return value

class Core:
 def __init__(self, domain, trial_id):
  self.domain=exact(domain,32)
  self.trial_id=trial_id

 def state(self, snapshot):
     cm, nf = snapshot.roots()
     return STATE_MAGIC + self.domain + cm.root + u32(len(snapshot.deliveries)) + nf.root + u32(len(snapshot.nullifiers))

 def insert(self, snapshot, value):
     """Construct actual physical-index preserving NF witnesses, not sorted leaves."""
     value_int = int.from_bytes(value, 'little')
     if value == ZERO or any((e.value == value for e in snapshot.nullifiers)):
         raise ValueError('spent or zero NF')
     cm, tree = snapshot.roots()
     m = len(snapshot.nullifiers)
     pred_index, pred = max(((i, e) for i, e in enumerate(snapshot.nullifiers) if int.from_bytes(e.value, 'little') < value_int), key=lambda pair: (int.from_bytes(pair[1].value, 'little'), pair[0]))
     if pred.next_value != ZERO and value_int >= int.from_bytes(pred.next_value, 'little'):
         raise ValueError('NF interval')
     leaf = pred.value + pred.next_value + u32(pred.next_index)
     witness = u32(pred_index) + leaf + b''.join(tree.path(pred_index))
     replacement = NFEntry(pred.value, value, m)
     intermediate = tree.with_leaf(pred_index, replacement.leaf())
     witness += b''.join(intermediate.path(m))
     entries = list(snapshot.nullifiers)
     entries[pred_index] = replacement
     entries.append(NFEntry(value, pred.next_value, pred.next_index))
     result = Snapshot(list(snapshot.deliveries), entries)
     if len(witness) != 1160:
         raise ValueError('NF witness width')
     return (result, witness)

 def private_case(self, snapshot, receivers, input_indices, output_records, output_notes, previous_outpoint, reserve, fee):
     old_state = self.state(snapshot)
     old_cm, _ = snapshot.roots()
     inputs = []
     nfs = []
     for slot, specification in enumerate(input_indices):
         if specification is None:
             raise ValueError('finite trial requires two real Alice inputs')
         position, receiver, invoice_index = specification
         delivery = snapshot.deliveries[position]
         receipt = receiver.open(delivery.ciphertext)
         if receipt.index != invoice_index or receipt.commitment() != delivery.cm:
             raise ValueError('input ownership/position')
         keys = receiver.keys(invoice_index)
         nf = receiver.nullifier(receipt, position)
         nfs.append(nf)
         inputs.append({'real': True, 'note_hex168': receipt.note_bytes().hex(), 's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(), 'position': position, 'cm_path_hex': [x.hex() for x in old_cm.path(position)], 'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()})
     current = Snapshot(list(snapshot.deliveries), list(snapshot.nullifiers))
     public_witness = b''
     for slot, nf in enumerate(nfs):
         current, witness = self.insert(current, nf)
         public_witness += witness
     for delivery in output_records:
         cm_tree, _ = current.roots()
         if delivery.position != len(current.deliveries):
             raise ValueError('CM append position')
         public_witness += b''.join(cm_tree.path(delivery.position))
         current.deliveries.append(delivery)
     next_state = self.state(current)
     ciphers = b''.join((d.ciphertext for d in output_records))
     auth = AUTH_MAGIC + self.domain + previous_outpoint + old_state + u64(reserve) + u64(fee) + b''.join(nfs) + b''.join((d.cm for d in output_records)) + h(ciphers) + next_state + u64(reserve - fee)
     if len(auth) != 484 or len(public_witness) != 3344 or len(ciphers) != 528:
         raise ValueError('private widths')
     if sum((int.from_bytes(bytes.fromhex(i['note_hex168'])[64:72], 'little') for i in inputs)) != sum((n.value_sompi for n in output_notes)) + fee:
         raise ValueError('private exact conservation')
     fixture = {'classification': CLASS, 'trial_id': self.trial_id, 'auth_hex484': auth.hex(), 'inputs': inputs, 'outputs': [{'note_hex168': note.note_bytes().hex()} for note in output_notes]}
     vector = {'auth_hex': auth.hex(), 'cipher_hex': ciphers.hex(), 'public_witness_hex': public_witness.hex(), 'proof_hex': bytes(128).hex(), 'vk_hex': bytes(328).hex()}
     return (current, fixture, vector)

 def admit_payload(self, genesis, note, record, before, after, fee, change):
     cm_tree, _ = before.roots()
     payload = b'KPX2AD01' + self.domain + note.note_bytes() + record.cm + record.ciphertext + h(record.ciphertext) + b''.join(cm_tree.path(len(before.deliveries))) + self.state(after) + u64(fee) + u64(change) + genesis.note_bytes()
     if len(payload) != 1344:
         raise ValueError('ADMIT payload width')
     return payload

 def reveal_payload(self, receiver, claim, expected, snapshot, fee):
     witness = exit_witness(receiver, claim, expected, snapshot)
     note = claim.receipt
     pred = witness['predecessor']
     payload = b'KPX2RV01' + b'\x01' + note.owner + note.incoming + u64(note.value_sompi) + note.rho + receiver.keys(note.index).nf_secret + note.native_pk + u32(claim.position) + note.key_commitment + note.commitment() + b''.join((bytes.fromhex(p) for p in witness['cm_path'])) + u32(witness['predecessor_index']) + bytes.fromhex(pred['value']) + bytes.fromhex(pred['next_value']) + u32(pred['next_index']) + b''.join((bytes.fromhex(p) for p in witness['predecessor_path'])) + b''.join((bytes.fromhex(p) for p in witness['append_path_after_predecessor_update'])) + bytes.fromhex(witness['nf']) + bytes.fromhex(witness['intermediate_nf_root']) + bytes.fromhex(witness['successor_nf_root']) + u64(fee) + u64(note.value_sompi - fee)
     if len(payload) != 2029:
         raise ValueError('reveal payload width')
     return (payload, witness)


def exact(raw, length):
    if not isinstance(raw, str):
        raise ValueError('hex type')
    value = bytes.fromhex(raw)
    if len(value) != length or value.hex() != raw:
        raise ValueError('canonical hex length')
    return value


def dump_snapshot(snapshot):
    return {'deliveries': [d.public() for d in snapshot.deliveries], 'nullifiers': [{'value': e.value.hex(), 'next_value': e.next_value.hex(), 'next_index': e.next_index} for e in snapshot.nullifiers]}


def parse_snapshot(value):
    return Snapshot([Delivery(d['position'], exact(d['cm'], 32), exact(d['ciphertext'], 264)) for d in value['deliveries']], [NFEntry(exact(e['value'], 32), exact(e['next_value'], 32), e['next_index']) for e in value['nullifiers']])


def native_call(binary, mode, vector, directory):
    directory = Path(directory)
    if directory.exists():
        raise ValueError('fresh native operation directory')
    vector_path = directory.with_suffix('.vector.json')
    save(vector_path, vector)
    proc = subprocess.run([str(binary), mode, str(vector_path), str(directory)], capture_output=True, text=True, check=False)
    directory.mkdir(parents=True, exist_ok=True)
    save(directory / 'command-result.json', {'returncode': proc.returncode, 'mode': mode, 'stdout': proc.stdout, 'stderr': proc.stderr, 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest()})
    if proc.returncode:
        raise ValueError('native operation failed; preserved at ' + str(directory))
    metrics = load(directory / 'metrics.json')
    kind = mode.rsplit('-', 1)[0]
    if kind == 'private':
        expected_fee = int.from_bytes(bytes.fromhex(vector['auth_hex'])[196:204], 'little')
    elif kind == 'admit':
        expected_fee = int.from_bytes(bytes.fromhex(vector['payload_hex'])[1160:1168], 'little')
    elif kind == 'reveal':
        expected_fee = int.from_bytes(bytes.fromhex(vector['payload_hex'])[2013:2021], 'little')
    else:
        expected_fee = vector['fee_sompi']
    if metrics['actual_fee_sompi'] != expected_fee:
        raise ValueError('native actual fee differs from frozen vector')
    if mode.endswith('-run'):
        actual_full = load(directory / 'native-validation.json')['Full']
        if actual_full.get('accepted') is not True or actual_full['fee_sompi'] != expected_fee:
            raise ValueError('native Full fee differs from actual/vector fee')
    return metrics


def quote(binary, kind, make_vector, output, rate=RATE):
    """Monotone integer actual-body fee iteration; no native execution."""
    fee = 1
    attempts = []
    for attempt in range(256):
        vector = make_vector(fee)
        directory = output / f'quote-{kind}-{attempt:03d}'
        metrics = native_call(binary, kind + '-freeze', vector, directory)
        required = rate * metrics['mining_mass']
        attempts.append({'fee_sompi': fee, 'required_sompi': required, 'mining_mass': metrics['mining_mass'], 'directory': directory.name})
        if fee >= required:
            save(output / f'{kind}-fee-fixedpoint.json', {'rate': rate, 'fee_sompi': fee, 'attempts': attempts, 'native_executed': False, 'algorithm': 'from1, monotone max(fee, rate*actual mining mass)'})
            return (fee, vector, directory)
        fee = max(fee, required)
    raise ValueError('fee iteration incomplete; all 256 attempted bodies preserved')


def outpoint(directory, index=0):
    txid = exact((directory / 'txid-raw.hex').read_text().strip(), 32)
    return txid + u32(index)


def verify_link(previous_directory, next_directory, output_index=0, input_index=0):
    previous = load(previous_directory / 'transaction.json')
    following = load(next_directory / 'transaction.json')
    supplied = load(next_directory / 'supplied-context.json')
    expected = previous['outputs'][output_index]
    consumed = following['inputs'][input_index]['previousOutpoint']
    if consumed != {'transactionId': previous['id'], 'index': output_index}:
        raise ValueError('actual prior output outpoint mismatch')
    if supplied[input_index]['amount_sompi'] != expected['value'] or supplied[input_index]['script_public_key'] != expected['scriptPublicKey']:
        raise ValueError('supplied input amount/SPK differs from actual previous output')
    return {'previous_txid_raw_hex': previous['id'], 'index': output_index, 'amount_sompi': expected['value'], 'script_public_key': expected['scriptPublicKey'], 'checked_actual_body_and_supplied_context': True}
