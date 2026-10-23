#!/usr/bin/env python3
"""Prospective arithmetic MODEL. No generation on import; no proving/native VM/RPC.

Only the unchanged independent demand sampler is reused from the rejected
working-balance experiment. Withdrawals never overshoot an exact net demand.
Genuine note/receipt crypto is reused; no valid Groth16/native witness is claimed.
"""
import copy
import importlib.util
import itertools
import sys
from pathlib import Path
from population_fees import Fees, FeeUnavailable

_SOURCE = Path(__file__).resolve().parents[1] / 'shared-pool/working_balance_model.py'
_SPEC = importlib.util.spec_from_file_location('demand_sampler', _SOURCE)
sampler = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sampler)
need, digest, integer = sampler.need, sampler.digest, sampler.integer
FLOOR, PAYOUT_FLOOR = 60_000_000, 10_000_000
MAX = 2_870_000_000_000_000_000
ARMS = ('direct_reveal', 'rerandomize_reveal', 'private_exit')
PROFILES = {'C': (), 'C+P': (0,), 'C+P+A': tuple(range(8))}
HORIZONS = ('payment', 'cashouts', 'drainage')
FIELDS = ('O', 'incoming', 'rho', 'K', 'nativePK')


def plan(seed, regime):
    """Exactly the old independent demands/prices; no changed seed or retries."""
    need(regime in ('overlap-independent', 'sparse-independent'), 'regime')
    return sampler.plan(seed, regime)



class Ledger:
    def __init__(self, work, opaque_seed, arm, crypto, regime, rate):
        need(arm in ARMS, 'arm')
        self.work, self.arm = work, arm
        self.fees = Fees(arm, rate)
        self.crypto = crypto
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'future-recipient/v2'))
        from recipient import Receiver, Receipt
        self.Receipt = Receipt
        self.domain = bytes.fromhex('aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2')
        keys = sampler.Stream(opaque_seed,'unfunded-model-receiver-seeds/'+arm+'/'+str(rate))
        self.receivers = [Receiver(keys.block(),self.domain,crypto) for _ in range(32)]
        self.labels = sampler.Labels(opaque_seed, 'private-exit-model/' + arm)
        self.notes, self.events, self.hidden, self.audit = [], [], [], []
        self.funding = []
        self.reserve = self.nf_count = 0
        self.costs = [0] * 32
        self.payouts = [0] * 32
        self.external_coins = [[] for _ in range(32)]
        self.earmarked = [0]*32
        self.payout_keys = set()
        self.payment_index, self.cashout_end = {}, None
        self.regime, self.rate = regime, rate
        for owner, value in enumerate(work['capitals']):
            self.admit(owner, value)

    def new_note(self, value, owner):
        integer(value, 0, MAX)
        need(value == 0 or value >= FLOOR, 'note floor')
        position = len(self.notes)
        if value:
            receiver = self.receivers[owner]
            invoice = receiver.invoice(position)
            receipt = self.Receipt.for_invoice(invoice,value,bytes.fromhex(self.labels.new()))
            raw = receipt.note_bytes()
            cipher = self.crypto.seal(invoice.delivery_pk,receipt.encode())
            cm, nf = receipt.commitment().hex(), receiver.nullifier(receipt,position).hex()
        else:
            import hashlib
            raw = bytes(72)+bytes.fromhex(self.labels.new())+bytes(64)
            cm = hashlib.sha256(b'KPX1NOT\0'+self.domain+raw).hexdigest()
            nf = self.labels.new()
            sink_pk = self.crypto.delivery_public(bytes.fromhex(self.labels.new()))
            plain = bytes.fromhex(''.join(self.labels.new() for _ in range(7)))[:216]
            cipher = self.crypto.seal(sink_pk,plain)
        need(len(cipher) == 264, 'genuine sealed ciphertext264')
        opening = {field:raw[start:end].hex() for field,start,end in
                   [('O',0,32),('incoming',32,64),('rho',72,104),('K',104,136),('nativePK',136,168)]}
        note = dict(position=position, cm=cm, value=value, owner=owner,
                    nf=nf, opening=opening, ciphertext=cipher.hex(), spent=False)
        self.notes.append(note)
        return position

    def public_note(self, p):
        n = self.notes[p]
        return dict(position=p, cm=n['cm'], value=n['value'], **n['opening'])

    def admit(self, owner, value):
        fee, funding_fee, funding = self.fees.admission(owner,value,self.reserve)
        funding['before_event']=len(self.events)
        self.funding.append(funding)
        self.costs[owner] += fee + funding_fee
        p = self.new_note(value, owner)
        self.reserve += value
        self.events.append(dict(ordinal=len(self.events), tx=self.labels.new(), minute=0,
            mode='genesis' if owner == 0 else 'admit', fee=fee, payout=0,
            payout_spk=None, reserve=self.reserve, n=len(self.notes), m=1,
            nf=[], cm=[self.notes[p]['cm']], ciphertext=[self.notes[p]['ciphertext']],
            prior_n=len(self.notes)-1, prior_m=1, prior_reserve=self.reserve-value,
            opening=self.public_note(p), funding_owner=owner,
            public_deposit=value+fee, terminal=False,reveal_key=None))
        self.hidden.append(dict(owner=owner, inputs=[], outputs=[p], purpose='admit',
                                payment=None, request=None))
        self.nf_count = 1

    def available(self, owner):
        return [p for p, n in enumerate(self.notes)
                if n['value'] and n['owner'] == owner and not n['spent']]

    def select(self, owner, cost, positive_output=False, exact=False):
        choices = []
        for size in (1, 2):
            for ps in itertools.combinations(self.available(owner), size):
                total = sum(self.notes[p]['value'] for p in ps)
                change = total-cost
                legal = change >= FLOOR if positive_output else change == 0 or change >= FLOOR
                if legal and (not exact or change == 0):
                    choices.append((total, size, ps))
        return list(min(choices)[2]) if choices else None

    def action(self, owner, ps, outputs, minute, purpose, *, payout=0,
               reveal=False, payment=None, request=None):
        need(ps and len(ps) <= 2 and len(set(ps)) == len(ps), 'input count/distinctness')
        need(all(p in self.available(owner) for p in ps), 'owned unspent inputs')
        need(not reveal or len(ps) == 1, 'REVEAL one note')
        total = sum(self.notes[p]['value'] for p in ps)
        terminal = self.reserve-total == 0 and not outputs and payout > 0
        fee = self.fees.reveal(self.reserve,total) if reveal else self.fees.private(self.reserve,payout,terminal)
        need(total == sum(v for v, _ in outputs) + payout + fee, 'conservation')
        need(payout == 0 or payout >= PAYOUT_FLOOR, 'payout floor')
        need(reveal or (self.reserve-payout-fee == 0) == terminal,'terminal zero/append framing')
        prior_n, prior_m, prior_r = len(self.notes), self.nf_count, self.reserve
        self.reserve -= payout+fee
        need(self.reserve == 0 or self.reserve >= FLOOR, 'reserve floor')
        if reveal:
            need(not outputs, 'REVEAL no outputs')
            nf = [self.notes[ps[0]]['nf']]
            new = []
        else:
            need((terminal and not outputs) or len(outputs) == 2, 'append shape')
            need(payout or any(v for v, _ in outputs), 'P0 positive output')
            nf = [self.notes[p]['nf'] for p in ps]
            nf += [self.labels.new() for _ in range(2-len(nf))]
            new = [self.new_note(v, o) for v, o in outputs]
        self.nf_count += len(nf)
        need(len(self.notes) <= 65535 and self.nf_count <= 2*len(self.notes)+1 <= 131071,
             'CM/NF state capacity')
        for p in ps:
            self.notes[p]['spent'] = True
        self.costs[owner] += fee
        self.payouts[owner] += payout
        # Each real input's native key differs from an owner-chosen new payout.
        # This model wallet also chooses globally distinct labels, an assumption
        # stronger than the circuit's per-input inequality and separately declared.
        pk = self.notes[ps[0]]['opening']['nativePK'] if reveal else None
        if payout and not reveal:
            while True:
                try: candidate = self.crypto.xonly(bytes.fromhex(self.labels.new())).hex()
                except ValueError as error:
                    if str(error) == 'crypto-scalar': continue
                    raise
                if (candidate not in self.payout_keys
                        and candidate not in {n['opening']['nativePK'] for n in self.notes}):
                    pk = candidate
                    self.payout_keys.add(pk)
                    break
        event = dict(ordinal=len(self.events), tx=self.labels.new(), minute=minute,
            mode='reveal' if reveal else 'private', fee=fee, payout=payout,
            payout_spk='000020'+pk+'ac' if payout else None,
            reserve=self.reserve, n=len(self.notes), m=self.nf_count,
            nf=nf, cm=[self.notes[p]['cm'] for p in new],
            ciphertext=[self.notes[p]['ciphertext'] for p in new],
            prior_n=prior_n, prior_m=prior_m, prior_reserve=prior_r,
            opening=self.public_note(ps[0]) if reveal else None,
            funding_owner=None, public_deposit=0, terminal=terminal,
            reveal_key=self.receivers[owner].keys(ps[0]).nf_secret.hex() if reveal else None)
        self.events.append(event)
        if payout:
            self.external_coins[owner].append(dict(tx=event['tx'],value=payout))
        self.hidden.append(dict(owner=owner, inputs=list(ps), outputs=new, purpose=purpose,
                                payment=payment, request=request))
        need(self.reserve == sum(n['value'] for n in self.notes if not n['spent']), 'backing')
        return new

    def pay(self, row):
        owner, amount = row['sender'], row['amount']
        fee = self.fees.private(self.reserve)
        ps = self.select(owner, amount+fee)
        if ps is None and sum(c['value'] for c in self.external_coins[owner]) > self.earmarked[owner]:
            self.reenter(owner,row['minute'])
            fee=self.fees.private(self.reserve)
            ps=self.select(owner,amount+fee)
        need(ps is not None, 'unfundable payment retained as failed history')
        change = sum(self.notes[p]['value'] for p in ps)-amount-fee
        self.payment_index[row['obligation']] = len(self.events)
        self.action(owner, ps, [(amount, row['recipient']), (change, owner if change else None)],
                    row['minute'], 'payment', payment=row['obligation'])

    def cash(self, row):
        owner, payout = row['owner'], row['amount']
        # No overshoot, clipping, re-entry, principal recycling or changed demand.
        completed, reason = False, None
        if self.arm == 'direct_reveal':
            ps=[]
            for p in self.available(owner):
                try: fee=self.fees.reveal(self.reserve,self.notes[p]['value'])
                except FeeUnavailable: continue
                if self.notes[p]['value']-fee == payout: ps.append(p)
            if ps:
                self.action(owner, [ps[0]], [], row['minute'], 'cash', payout=payout,
                            reveal=True, request=row['request'])
                completed = True
            else:
                reason = 'whole-note REVEAL cannot deliver this exact net demand'
        else:
            try:
                fee0 = self.fees.private(self.reserve) if self.arm == 'rerandomize_reveal' else 0
                fee1 = (self.fees.reveal_for_net(self.reserve-fee0,payout)
                        if self.arm == 'rerandomize_reveal' else self.fees.private(self.reserve,payout))
                cost = payout+fee0+fee1
                ps = self.select(owner,cost)
            except FeeUnavailable:
                ps,fee1=None,None
                reason='no legal fee-funded authorization for exact demand'
            if reason is not None:
                pass
            elif self.arm == 'rerandomize_reveal' and payout+fee1 < FLOOR:
                reason = 'rerandomized payout note below60M'
            elif ps is None:
                reason = 'no1/2-note combination funds demand, fees and legal change'
            else:
                change = sum(self.notes[p]['value'] for p in ps)-cost
                if self.arm == 'rerandomize_reveal':
                    new = self.action(owner, ps, [(payout+fee1, owner),
                        (change, owner if change else None)], row['minute'], 'rerandomize',
                        request=row['request'])
                    self.action(owner, [new[0]], [], row['minute'], 'cash', payout=payout,
                                reveal=True, request=row['request'])
                else:
                    self.action(owner, ps, [(change, owner if change else None), (0, None)],
                                row['minute'], 'cash', payout=payout, request=row['request'])
                completed = True
        if completed: self.earmarked[owner] += payout
        if row['urgent']:
            self.drain_owner(owner,row['minute'],'urgent',row['request'])
        self.audit.append(dict(request=row['request'], owner=owner, demand=payout,
            completed=completed, reason=reason,urgent=row['urgent'],
            urgent_completed=not self.available(owner) if row['urgent'] else None))

    def reenter(self,owner,minute):
        coins=self.external_coins[owner]
        protected=self.earmarked[owner]
        value,fee0,fee1,funding=self.fees.reentry(self.reserve,[c['value'] for c in coins],protected)
        sources=copy.deepcopy(coins)
        tx=self.labels.new()
        self.external_coins[owner]=[dict(tx=tx,value=protected)] if protected else []
        self.costs[owner] += fee0+fee1
        self.funding.append(dict(owner=owner,kind='reentry',tx=tx,sources=sources,
            before_event=len(self.events),protected_native_cash=protected,
            ordinary_fee=fee0,admission_fee=fee1,pool_funding_sompi=funding))
        p=self.new_note(value,owner)
        prior=self.reserve;self.reserve+=value
        self.events.append(dict(ordinal=len(self.events),tx=self.labels.new(),minute=minute,
            mode='admit',fee=fee1,payout=0,payout_spk=None,reserve=self.reserve,
            n=len(self.notes),m=self.nf_count,nf=[],cm=[self.notes[p]['cm']],
            ciphertext=[self.notes[p]['ciphertext']],prior_n=len(self.notes)-1,
            prior_m=self.nf_count,prior_reserve=prior,opening=self.public_note(p),
            funding_owner=owner,public_deposit=funding,terminal=False,reveal_key=None))
        self.hidden.append(dict(owner=owner,inputs=[],outputs=[p],purpose='reentry',payment=None,request=None))

    def drain(self):
        self.cashout_end = len(self.events)
        minute = self.work['final_minute']
        for owner in self.work['final_order']:
            minute += 1
            self.drain_owner(owner,minute,'drain')
        need(self.reserve == 0, 'complete drainage')

    def drain_owner(self,owner,minute,phase,request=None):
            while self.available(owner):
                p = min(self.available(owner))
                value = self.notes[p]['value']
                if self.arm == 'private_exit':
                    terminal = value == self.reserve
                    fee = None
                    try:
                        fee = self.fees.private(self.reserve,0 if terminal else max(PAYOUT_FLOOR,value-190000*self.rate),terminal)
                        # For full-note continuing exit, fix actual payout and
                        # repeat until both authorization and quote agree.
                        for _ in range(100):
                            if value-fee < PAYOUT_FLOOR:
                                raise FeeUnavailable('private claim below economic minimum')
                            checked = self.fees.private(self.reserve,value-fee,terminal)
                            if checked == fee: break
                            fee = checked
                        else: raise FeeUnavailable('private fee fixed point incomplete')
                        if value-fee < PAYOUT_FLOOR:
                            raise FeeUnavailable('private claim below economic minimum')
                    except FeeUnavailable:
                        fee = None
                    if fee is None:
                        revealing_fee = self.fees.reveal(self.reserve,value)
                        self.action(owner,[p],[],minute,phase+'_fee_fallback',payout=value-revealing_fee,reveal=True,request=request)
                    else:
                        outputs = [] if terminal else [(0, None), (0, None)]
                        self.action(owner, [p], outputs, minute, phase, payout=value-fee,request=request)
                elif self.arm == 'rerandomize_reveal':
                    try: fee0 = self.fees.private(self.reserve)
                    except FeeUnavailable: fee0 = value
                    v = value-fee0
                    if v < FLOOR:
                        # Explicit user-consented revealing escape; never erase it.
                        self.action(owner, [p], [], minute, phase+'_floor_fallback',
                                    payout=value-self.fees.reveal(self.reserve,value), reveal=True,request=request)
                    else:
                        new = self.action(owner, [p], [(v, owner), (0, None)], minute, 'rerandomize_'+phase,request=request)
                        self.action(owner, [new[0]], [], minute, phase,
                                    payout=v-self.fees.reveal(self.reserve,v), reveal=True,request=request)
                else:
                    self.action(owner, [p], [], minute, phase,
                                payout=value-self.fees.reveal(self.reserve,value), reveal=True,request=request)

    def public(self,end=None):
        end=len(self.events) if end is None else end
        return dict(schema='kpx3-population-arithmetic-public/v1', classification='SYNTHETIC_CONSTRAINT_MODEL',
            arm=self.arm, regime=self.regime, rate=self.rate, roles=list(range(32)),
            active_roles=list(range(8)), events=copy.deepcopy(self.events[:end]),
            ordinary_funding=copy.deepcopy([f for f in self.funding if f['before_event'] < end]),
            crypto_model='genuine real Note168/CM/NF/cipher264; dummy NFs opaque; no Groth16 or native transaction/state acceptance',
            invoice_model='V2 fresh per-note O/incoming/K/nativePK; deliveryPK not on chain',
            wallet_freshness='globally distinct modeled destinations; circuit only per-real-input inequality')

    def view(self, members, end):
        authored, owned = [], []
        for i, (e, h) in enumerate(zip(self.events[:end], self.hidden[:end], strict=True)):
            if h['owner'] in members:
                authored.append(dict(event=i, owner=h['owner'], inputs=h['inputs'],
                    outputs=[dict(self.public_note(p), owner=self.notes[p]['owner']) for p in h['outputs']]))
        born={p for h in self.hidden[:end] for p in h['outputs']}
        for n in self.notes:
            if n['owner'] in members and n['position'] in born:
                owned.append(dict(self.public_note(n['position']), owner=n['owner'], nf=n['nf']))
        return dict(schema='kpx3-population-participant-view/v1', members=list(members),
                    authored=authored, owned=owned)


def replay(work, opaque_seed, arm, crypto, regime, rate):
    ledger = Ledger(work, opaque_seed, arm, crypto, regime, rate)
    error = None
    try:
        cash = {r['after_payment']: r for r in work['cash_requests']}
        for row in work['payments']:
            ledger.pay(row)
            if row['obligation'] in cash:
                ledger.cash(cash[row['obligation']])
        ledger.drain()
    except ValueError as failure:
        error = str(failure)
    return ledger, error


