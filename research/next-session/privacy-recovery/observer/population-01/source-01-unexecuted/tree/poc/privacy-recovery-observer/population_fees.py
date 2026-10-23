"""Exact pinned integer mass arithmetic, cross-checked against published metrics.

No native VM/proofs/parameters/RPC. New amount contexts are modeled quotes,
never repriced signed authorizations. All costs are charged to actual owners.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT/'research/next-session/exit-fee/cost_envelope.py'
HELPER_SHA = 'ea382803c79c07272c8485fb51505aabe27c90180e9f8e325de29f21f807a6df'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != HELPER_SHA:
    raise ValueError('fee arithmetic source changed')
SPEC = importlib.util.spec_from_file_location('native_fee_arithmetic', HELPER)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)
FLOOR, PAYOUT = 60_000_000, 10_000_000
MAX = 2_870_000_000_000_000_000


class FeeUnavailable(ValueError):
    pass


class Fees:
    def __init__(self, arm, rate):
        if arm not in ('direct_reveal','rerandomize_reveal','private_exit') or rate not in (100,200,500):
            raise ValueError('fee profile')
        self.rate = rate
        self.sig = 24616 if arm == 'private_exit' else 22587
        self.payload = 4400 if arm == 'private_exit' else 4356
        self.rows = []

    def quote(self, shape, inputs, outputs, sigs, budgets, payload, scripts, cap=MAX):
        size = 94+sum(54+s for s in sigs)+sum(18+s for s in scripts)+payload
        def describe(fee):
            return native.mass(size,scripts,budgets,inputs(fee),outputs(fee))
        row = native.least_fee(self.rate,describe,cap)
        if not row['passes']:
            raise FeeUnavailable('modeled fee/floor failure: '+shape)
        self.rows.append(dict(shape=shape,rate=self.rate,**row))
        return row['fee_sompi']

    def admission(self, owner, value, reserve):
        if owner == 0:
            f = self.quote('genesis-one-pool-output-GN536',lambda x:[(1,value+x)],
                lambda x:[(1,value)],[66],[10],536,[35])
        else:
            f = self.quote('admit-no-change',lambda x:[(1,reserve),(1,value+x)],
                lambda x:[(1,reserve+value)],[self.sig,66],[200,10],1344,[35])
        target = value+f
        funding = self.quote('ordinary-funding-with-returned-native-change',
            lambda x:[(1,target+FLOOR)],lambda x:[(1,target),(1,FLOOR-x)],
            [66],[10],0,[34,34],FLOOR-PAYOUT)
        return f, funding, dict(owner=owner,input_sompi=target+FLOOR,
            pool_funding_sompi=target,returned_native_change_sompi=FLOOR-funding,
            ordinary_fee=funding)

    def private(self, reserve, payout=0, terminal=False):
        if terminal:
            # Terminal demand is the complete remaining reserve after this fee.
            return self.quote('private-terminal',lambda x:[(1,reserve)],
                lambda x:[(1,reserve-x)],[self.sig],[1600],self.payload,[34],reserve-PAYOUT)
        return self.quote('private-P0' if payout == 0 else 'private-continuing-exit',
            lambda x:[(1,reserve)],lambda x:[(1,reserve-payout-x)]+([(1,payout)] if payout else []),
            [self.sig],[1600],self.payload,[35]+([34] if payout else []),reserve-payout-FLOOR)

    def reveal(self, reserve, value):
        remainder = reserve-value
        return self.quote('reveal-terminal' if not remainder else 'reveal-continuing',
            lambda x:[(1,reserve)],lambda x:([(1,remainder)] if remainder else [])+[(1,value-x)],
            [self.sig],[200],2029,([35] if remainder else [])+[34],value-PAYOUT)

    def reveal_for_net(self, reserve, payout):
        return self.quote('prospective-exact-net-reveal-continuing',lambda x:[(1,reserve)],
            lambda x:[(1,reserve-payout-x),(1,payout)],
            [self.sig],[200],2029,[35,34],reserve-payout-FLOOR)

    def reentry(self,reserve,coins,protected):
        total=sum(coins)
        fee0=self.quote('native-consolidation-for-reentry',lambda x:[(1,v) for v in coins],
            lambda x:[(1,total-protected-x)]+([(1,protected)] if protected else []),
            [66]*len(coins),[10]*len(coins),0,[34]+([34] if protected else []),total-protected-FLOOR)
        funding=total-protected-fee0
        fee1=self.quote('whole-funding-readmission',lambda x:[(1,reserve),(1,funding)],
            lambda x:[(1,reserve+funding-x)],[self.sig,66],[200,10],1344,[35],funding-FLOOR)
        return funding-fee1,fee0,fee1,funding


def validate_published_profile():
    """Checks the already published eight actual-body metrics, no new execution."""
    path = ROOT/'research/next-session/privacy-recovery/native/ACTUAL-FEE-PROFILE-01.json'
    if hashlib.sha256(path.read_bytes()).hexdigest() != '8274ae92e814bfedf700ddfc8bf70956cc7b2a5f1c874460a1feb57c88b1afee':
        raise ValueError('actual profile changed')
    profile = json.loads(path.read_text())
    for row in profile['rows']:
        size=94+sum(54+s for s in row['input_signature_script_lengths'])
        size+=sum(18+s for s in row['output_raw_script_lengths'])+row['payload_bytes']
        m=native.mass(size,row['output_raw_script_lengths'],row['input_compute_budgets'],
            [(1,int(v)) for v in row['inputs_sompi']],[(1,int(v)) for v in row['outputs_sompi']])
        for a,b in [('compute_mass','compute_mass'),('transient_mass','transient_mass'),
                    ('storage_mass','storage_mass'),('normalized_mining_mass','mining_mass')]:
            if m[a] != row['metrics'][b]:
                raise ValueError('published metric disagreement')
    return len(profile['rows'])
