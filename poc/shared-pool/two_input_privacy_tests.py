"""Independent tiny enumeration and hostile-input controls for H14."""
import copy
import itertools
import unittest
from two_input_privacy_observer import Model, decode, source_set
from two_input_privacy_z3 import Z3Model
from two_input_privacy_exact import ExactModel


def fixture(initial, operations):
    events=[]; count=1; balance=initial
    for i,(mode,deposit,payout,anchor) in enumerate(operations):
        balance += deposit-payout-1
        new=[] if mode==2 else [count,count+1]
        events.append(dict(id=f'tx{i}',minute=i,mode=mode,anchor_count=anchor,
            count_before=count,new=new,fee=1,deposit=deposit,payout=payout,reserve_out=balance,
            destination=f'dest{i}' if payout else None,funding_group=f'fund{i}' if deposit else None))
        count += len(new)
    return dict(schema='kpi-h14-public-v1',initial=dict(id='genesis',value=initial,funding_group='fund-genesis'),events=events)


def enumerate_histories(data):
    # Independent explicit ledger traversal: no SAT encoding, public upper bounds,
    # generator, source mapping, or private truth is reused.
    states=[([data['initial']['value']],frozenset(),{})]
    for i,e in enumerate(data['events']):
        following=[]
        for values,spent,history in states:
            choices=[()] if e['mode']==0 else [c for size in (1,2)
                for c in itertools.combinations([p for p in range(e['anchor_count']) if p not in spent and values[p]>0],size)]
            for c in choices:
                available=e['deposit']+sum(values[p] for p in c)-e['payout']-e['fee']
                if available<0:continue
                outputs=[[]] if e['mode']==2 and available==0 else [] if e['mode']==2 else [[a,available-a] for a in range(available+1)]
                for out in outputs:
                    vv=values+out; ss=spent|set(c); hh=dict(history)
                    if c:hh[i]=c
                    if sum(v for p,v in enumerate(vv) if p not in ss)==e['reserve_out']:
                        following.append((vv,ss,hh))
        states=following
    return {i:{h[i] for _,_,h in states} for i,e in enumerate(data['events']) if e['mode']!=0}


class ObserverControls(unittest.TestCase):
    def test_singleton(self):
        d=fixture(5,[(2,0,4,1)])
        self.assertEqual(Model(d,1,1).candidates(0),[(0,)])

    def test_independent_enumeration_and_symmetry(self):
        for initial,deposit,payout in [(5,5,3),(8,5,2),(6,4,1)]:
            total=initial+deposit-2
            d=fixture(initial,[(1,0,0,1),(0,deposit,0,0),(2,0,payout,5),(2,0,total-payout-2,5)])
            for end in range(1,len(d['events'])+1):
                prefix=dict(d,events=d['events'][:end]); oracle=enumerate_histories(prefix)
                m=Model(prefix,1,1)
                for event, expected in oracle.items():
                    self.assertEqual(set(m.candidates(event)),expected,(initial,deposit,payout,end,event))
                    self.assertEqual(set(Z3Model(prefix,1,1).candidates(event)),expected,('z3',initial,deposit,payout,end,event))
                    self.assertEqual(set(ExactModel(prefix,1,1).candidates(event)),expected,('exact',initial,deposit,payout,end,event))
            if initial==5:
                sources={source_set(c,m.births) for c in m.candidates(2)}
                self.assertIn((0,),sources);self.assertIn((1,),sources)

    def test_replay_and_zero_padding(self):
        d=fixture(5,[(1,0,0,1),(2,0,3,3)])
        m=Model(d,1,1);m.model.add(m.values[1]==0)
        self.assertFalse(m.check(1,(1,)))
        self.assertTrue(m.check(1,(2,)))
        self.assertFalse(m.check(1,(0,)))
        with self.assertRaises(ValueError):m.check(1,(1,1))
        with self.assertRaises(ValueError):m.check(1,(3,))

    def test_impossible_history(self):
        d=fixture(5,[(1,0,0,1),(0,5,0,0),(2,0,7,5)])
        m=Model(d,1,1)
        for p in range(1,5):m.model.add(m.values[p]==2)
        self.assertFalse(m.check())

    def test_horizon_order_preserves_prefix_information(self):
        from two_input_privacy_observer import analyze
        d=fixture(5,[(1,0,0,1),(0,5,0,0),(2,0,3,5),(2,0,3,5)])
        scale=60_000_000;d['initial']['value']*=scale
        for e in d['events']:
            for k in ('fee','deposit','payout','reserve_out'):e[k]*=scale
        result=analyze(d)
        for row in result['rows']:
            for horizon in row['joint']:
                prefix=dict(d,events=d['events'][:horizon['through']+1])
                expected=Model(prefix).candidates(row['event'])
                self.assertEqual({tuple(c) for c in horizon['input_sets']},set(expected))

    def test_malformed_projection(self):
        good=fixture(5,[(1,0,0,1),(2,0,3,3)])
        mutations=[('anchor_count',2),('fee',1.0),('fee',True),('payout',-1),('reserve_out',99),('id','genesis'),('new',[1,True])]
        for field,value in mutations:
            bad=copy.deepcopy(good);bad['events'][0][field]=value
            with self.assertRaises(ValueError,msg=field):decode(bad,1,1)
        bad=copy.deepcopy(good);bad['events'][0]['private_owner']='Alice'
        with self.assertRaises(ValueError):decode(bad,1,1)


class NativeDecoderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json
        from pathlib import Path
        rows=json.loads((Path(__file__).resolve().parent/'evidence/2026-10-20-two-input-tn10/trial/chain-confirmed.json').read_text())['transactions']
        g=rows[1]['transaction']
        cls.raw=dict(schema='kpi-h14-native-v1',initial=dict(txid=g['id'],index=0,
            amount=g['outputs'][0]['value'],spk=g['outputs'][0]['scriptPublicKey']),
            interval_minutes=10,transactions=[r['transaction'] for r in rows[2:]])

    def test_existing_native_trace(self):
        from two_input_privacy_native import project
        result=project(self.raw)
        self.assertEqual(len(result['events']),13)
        self.assertEqual(result['events'][-1]['reserve_out'],0)

    def test_native_public_mutations(self):
        from two_input_privacy_native import project
        # The Rust validator tests invalid proof bytes; this decoder tests the
        # structural/monetary fields actually used by reconstruction.
        for offset in (0,8,16,48,52,213,221,345,385,755):
            bad=copy.deepcopy(self.raw);t=bad['transactions'][0]
            b=bytearray.fromhex(t['payload']);b[offset]^=1;t['payload']=b.hex()
            with self.assertRaises(ValueError,msg=f'payload offset {offset}'):project(bad)
        # A different nonzero opaque nullifier needs cryptographic verification,
        # outside this framing decoder. Reuse, however, is publicly detectable.
        bad=copy.deepcopy(self.raw);t=bad['transactions'][0];b=bytearray.fromhex(t['payload'])
        b[116:148]=b[84:116];t['payload']=b.hex()
        with self.assertRaises(ValueError):project(bad)
        for field,value in [('value','1.0'),('value','00'),('value','999'),('scriptPublicKey','00')]:
            bad=copy.deepcopy(self.raw);bad['transactions'][0]['outputs'][0][field]=value
            with self.assertRaises(ValueError,msg=field):project(bad)
        bad=copy.deepcopy(self.raw);bad['transactions'][1]['inputs'][0]['previousOutpoint']['index']=1
        with self.assertRaises(ValueError):project(bad)


if __name__=='__main__':unittest.main()
