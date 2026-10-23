"""Independent arithmetic trace checks and aggregate-only blinded-model scoring.

Importing this module generates no data and executes no attacker/prover/native VM.
The controller must seal every prediction before this module receives a ledger.
Hash/amount bookkeeping is checked here; proof soundness, encryption anonymity,
native acceptance, NF key derivation and independent human roles are not proved.
"""
import hashlib
import hmac
import itertools
import json

FLOOR, PAYOUT, MAX = 60_000_000, 10_000_000, 2_870_000_000_000_000_000
S = 100_000_000
DOMAIN = bytes.fromhex('aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2')
VARIANTS = ('prior', 'opening', 'residual', 'cash_inverse')
METRICS = ('sender', 'recipient', 'relationship', 'amount_exact', 'amount_within_10pct')
PROFILES = {'C': (), 'C+P': (0,), 'C+P+A': tuple(range(8))}
HORIZONS = ('payment', 'cashouts', 'drainage')
COVERAGES = (5, 10, 25)
NOTE_FIELDS = {'position', 'cm', 'value', 'owner', 'nf', 'opening', 'ciphertext', 'spent'}
OPEN_FIELDS = {'O', 'incoming', 'rho', 'K', 'nativePK'}
EVENT_FIELDS = {'ordinal', 'tx', 'minute', 'mode', 'fee', 'payout', 'payout_spk',
    'reserve', 'n', 'm', 'nf', 'cm', 'ciphertext', 'prior_n', 'prior_m',
    'prior_reserve', 'opening', 'funding_owner', 'public_deposit', 'terminal', 'reveal_key'}


def need(value, message):
    if not value:
        raise ValueError('independent model validation: ' + message)


def integer(value, lo=0, hi=MAX):
    need(type(value) is int and lo <= value <= hi, 'integer/range')
    return value


def fields(value, expected, name):
    need(isinstance(value, dict) and set(value) == expected, name + ' fields')


def fixed(value, width=32):
    need(isinstance(value, str), 'hex string')
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError('independent model validation: hex') from None
    need(len(raw) == width and raw.hex() == value, 'canonical hex width')
    return raw


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def note_public(note):
    return dict(position=note['position'], cm=note['cm'], value=note['value'], **note['opening'])


def check_work(work):
    """Checks unchanged sampler support/requests, never its private seed."""
    fields(work, {'capitals', 'payments', 'cash_requests', 'final_order', 'final_minute', 'activity'}, 'work')
    need(len(work['capitals']) == 32 and all(v in (350*S, 700*S, 1400*S)
        and type(v) is int for v in work['capitals']), 'original net capital support')
    need(len(work['payments']) == 64 and len(work['cash_requests']) == 32, 'all original demands')
    need(sorted(work['final_order']) == list(range(32)), 'final owner permutation')
    seen = [0]*32
    minute = 0
    for i, row in enumerate(work['payments']):
        fields(row, {'obligation', 'sender', 'recipient', 'amount', 'minute'}, 'payment demand')
        a, b, value = row['sender'], row['recipient'], row['amount']
        integer(a, 0, 31); integer(b, 0, 31); integer(value, 10*S, 50*S)
        need(a != b and row['obligation'] == i and row['minute'] > minute, 'payment identities/order')
        if a < 8:
            need(value == 20*S + (a+1)*1000 + seen[a], 'unchanged active tag')
        else:
            need(value % 1_000_000 == 0, 'honest cent/invoice amount support')
        seen[a] += 1
        minute = row['minute']
    need(seen == work['activity'] and seen[:8] == [2]*8, 'activity counts')
    need(sorted(seen[8:]) == [0]*4+[1]*8+[2]*8+[6]*4, 'honest activity distribution')
    need([p['sender'] for p in work['payments'][:4]] == list(range(4)), 'first four active senders')
    early = [p['recipient'] for p in work['payments'][:4]]
    need(len(set(early)) == 4 and all(r >= 8 and seen[r] == 6 for r in early), 'first four recipients')
    for i, row in enumerate(work['cash_requests']):
        fields(row, {'request', 'owner', 'amount', 'minute', 'after_payment', 'urgent'}, 'cash demand')
        need(row['request'] == i and row['after_payment'] == 2*i+1, 'cash request schedule')
        integer(row['owner'], 0, 31)
        need(row['amount'] in (10*S, 20*S, 25*S), 'unchanged independent net demand')
        need(row['minute'] == work['payments'][2*i+1]['minute']+1, 'cash request time')
        need(type(row['urgent']) is bool and row['urgent'] == (i in (7, 23)), 'urgent demand retention')
    need(sorted(r['owner'] for r in work['cash_requests']) == list(range(32)), 'independent cash-owner permutation')
    need(work['final_minute'] == work['cash_requests'][-1]['minute']+60, 'original final horizon')


def checked_selection(notes, spent, before, owner, cost):
    """Independent least-total/fewest/positions selector, no generator call."""
    available = [p for p in range(before) if p not in spent
        and notes[p]['owner'] == owner and notes[p]['value'] >= FLOOR]
    choices = []
    for size in (1, 2):
        for ps in itertools.combinations(available, size):
            total = sum(notes[p]['value'] for p in ps)
            change = total-cost
            if change == 0 or change >= FLOOR:
                choices.append((total, size, ps))
    return list(min(choices)[2]) if choices else None


def validate(ledger):
    """Rewalk truth without calling Ledger.action/select/pay/drain/accounting."""
    from population_fees import Fees
    work, notes, events, hidden = ledger.work, ledger.notes, ledger.events, ledger.hidden
    check_work(work)
    need(ledger.arm in ('direct_reveal', 'rerandomize_reveal', 'private_exit'), 'arm')
    need(ledger.rate in (100, 200, 500), 'rate')
    need(len(events) == len(hidden) and len(events) >= 32, 'trace shape')
    need(type(ledger.cashout_end) is int and 32 <= ledger.cashout_end <= len(events), 'cashout horizon')
    fees = Fees(ledger.arm, ledger.rate)
    for p, n in enumerate(notes):
        fields(n, NOTE_FIELDS, 'note')
        need(n['position'] == p and type(n['spent']) is bool, 'note position/spent')
        value = integer(n['value'])
        need(value == 0 or value >= FLOOR, 'positive note floor')
        need((n['owner'] is None) == (value == 0), 'dummy owner')
        if value:
            integer(n['owner'], 0, 31)
        fields(n['opening'], OPEN_FIELDS, 'Note168 opening')
        o = {k: fixed(v) for k, v in n['opening'].items()}
        raw = o['O']+o['incoming']+value.to_bytes(8, 'little')+o['rho']+o['K']+o['nativePK']
        need(hashlib.sha256(b'KPX1NOT\0'+DOMAIN+raw).hexdigest() == n['cm'], 'actual Note168 CM')
        fixed(n['nf']); cipher = fixed(n['ciphertext'], 264)
        need(not cipher[31] & 128, 'corrected sealed-format policy')
        if not value:
            need(all(o[k] == bytes(32) for k in ('O', 'incoming', 'K', 'nativePK')), 'canonical dummy fields')
    need(len({n['cm'] for n in notes}) == len(notes), 'distinct note CMs')
    spent, used_nf = set(), set()
    reserve, next_pos, nf_count, last_minute = 0, 0, 1, 0
    charged, payouts = [0]*32, [0]*32
    incoming, outgoing, payment_fees = [0]*32, [0]*32, []
    payments, cash_payouts, request_events, fallbacks = {}, {}, {}, []
    expected_funding, external = [], [[] for _ in range(32)]
    earmarked, reentry_count = [0]*32, 0
    for i, (e, h) in enumerate(zip(events, hidden, strict=True)):
        fields(e, EVENT_FIELDS, 'event')
        fields(h, {'owner', 'inputs', 'outputs', 'purpose', 'payment', 'request'}, 'hidden event')
        owner = integer(h['owner'], 0, 31)
        integer(e['minute'])
        allowed_purposes = {'admit', 'reentry', 'payment', 'cash', 'rerandomize',
            'drain', 'urgent', 'rerandomize_drain', 'rerandomize_urgent',
            'drain_fee_fallback', 'urgent_fee_fallback',
            'drain_floor_fallback', 'urgent_floor_fallback'}
        need(h['purpose'] in allowed_purposes, 'declared wallet action only')
        need(e['ordinal'] == i and e['minute'] >= last_minute, 'accepted ordering/model time')
        need(e['mode'] == 'reveal' or e['reveal_key'] is None, 'only fallback publishes opening key')
        last_minute = e['minute']
        need(e['prior_n'] == next_pos and e['prior_m'] == nf_count
            and e['prior_reserve'] == reserve, 'actual prior context/count')
        fee, payout = integer(e['fee'], 1), integer(e['payout'])
        need(payout == 0 or payout >= PAYOUT, 'native payout floor')
        need(type(e['terminal']) is bool, 'terminal Boolean')
        ps, new = h['inputs'], h['outputs']
        need(isinstance(ps, list) and len(set(ps)) == len(ps), 'distinct selected notes')
        need(new == list(range(next_pos, next_pos+len(new))), 'new note positions')
        need(e['cm'] == [notes[p]['cm'] for p in new]
            and e['ciphertext'] == [notes[p]['ciphertext'] for p in new], 'all CM/cipher slots retained')
        need(all(type(p) is int and 0 <= p < next_pos and p not in spent
            and notes[p]['owner'] == owner and notes[p]['value'] >= FLOOR for p in ps), 'ownership/unspent/input floor')
        total, output = sum(notes[p]['value'] for p in ps), sum(notes[p]['value'] for p in new)
        integer(total); integer(output)
        if h['purpose'] == 'payment':
            need(h['payment'] is not None and h['request'] is None, 'payment request metadata')
            r = work['payments'][integer(h['payment'], 0, 63)]
            need(ps == checked_selection(notes, spent, next_pos, owner, r['amount']+fee),
                'actual private payment selection policy')
        elif h['purpose'] == 'rerandomize':
            need(ledger.arm == 'rerandomize_reveal' and e['mode'] == 'private'
                and not payout and len(new) == 2 and h['request'] is not None, 'cash rerandomization shape')
            r = work['cash_requests'][integer(h['request'], 0, 31)]
            need(i+1 < len(events) and hidden[i+1]['purpose'] == 'cash'
                and hidden[i+1]['request'] == h['request'], 'immediate exact-demand revealing cashout')
            cost = fee+events[i+1]['fee']+r['amount']
            need(ps == checked_selection(notes, spent, next_pos, owner, cost), 'rerandomize selector')
            need(notes[new[0]]['value'] == r['amount']+events[i+1]['fee']
                and notes[new[0]]['owner'] == owner
                and notes[new[1]]['owner'] == (owner if notes[new[1]]['value'] else None),
                'payout note and owner change include both fees')
        elif h['purpose'] == 'cash':
            need(h['request'] is not None and h['payment'] is None and payout > 0, 'cash demand metadata')
            if ledger.arm == 'private_exit':
                need(e['mode'] == 'private' and ps == checked_selection(notes, spent, next_pos, owner, payout+fee),
                    'private exact cash selection')
                need(len(new) == 2 and notes[new[0]]['owner'] == (owner if notes[new[0]]['value'] else None)
                    and notes[new[1]]['value'] == 0, 'private cash change then dummy')
            elif ledger.arm == 'rerandomize_reveal':
                need(e['mode'] == 'reveal' and i > 0 and hidden[i-1]['purpose'] == 'rerandomize'
                    and ps == [hidden[i-1]['outputs'][0]], 'revealing newly rerandomized payout note')
            else:
                need(e['mode'] == 'reveal', 'direct cash revealing branch')
        elif h['purpose'] in {'drain', 'urgent', 'drain_fee_fallback', 'urgent_fee_fallback',
                'drain_floor_fallback', 'urgent_floor_fallback', 'rerandomize_drain', 'rerandomize_urgent'}:
            need(h['payment'] is None, 'drain is not a hidden economic payment')
            if h['purpose'].startswith('rerandomize_'):
                need(ledger.arm == 'rerandomize_reveal' and e['mode'] == 'private'
                    and payout == 0 and len(new) == 2 and notes[new[0]]['owner'] == owner
                    and notes[new[1]]['value'] == 0, 'one-note rerandomized drain')
            else:
                need(payout > 0, 'drain releases native value')
            # A normal rerandomized drain reveals its just-created first output.
            just_rerandomized = i > 0 and hidden[i-1]['purpose'] == 'rerandomize_'+h['purpose']
            expected = min(p for p in range(next_pos) if p not in spent
                and notes[p]['owner'] == owner and notes[p]['value'])
            need(ps == ([hidden[i-1]['outputs'][0]] if just_rerandomized else [expected]),
                'ascending singleton drainage policy')
        if i < 32:
            need(owner == i and h['purpose'] == 'admit' and not ps and len(new) == 1, 'all 32 initial admissions')
            need(e['mode'] == ('genesis' if i == 0 else 'admit') and e['minute'] == 0, 'admission kind/time')
            need(notes[new[0]]['owner'] == owner and output == work['capitals'][owner], 'net admitted claim')
            expected_fee, funding_fee, funding = fees.admission(owner, output, reserve)
            funding['before_event'] = i
            need(fee == expected_fee and e['public_deposit'] == output+fee, 'actual admission fee/gross')
            need(e['funding_owner'] == owner and e['opening'] == note_public(notes[new[0]]), 'legitimate public funding owner')
            need(not payout and e['payout_spk'] is None and not e['nf'], 'admission no hidden cashout/NF')
            need(not e['terminal'], 'admission is continuing')
            need(h['payment'] is None and h['request'] is None, 'admission metadata')
            charged[owner] += funding_fee
            expected_funding.append(funding)
            reserve += output
        elif h['purpose'] == 'reentry':
            need(e['mode'] == 'admit' and not ps and len(new) == 1, 'readmission shape')
            need(not payout and e['payout_spk'] is None and not e['nf'], 'readmission no payout/NFs')
            need(not e['terminal'], 'readmission is continuing')
            need(h['payment'] is None and h['request'] is None, 'readmission metadata')
            need(len(ledger.funding) > len(expected_funding), 'readmission funding retained')
            funding = ledger.funding[len(expected_funding)]
            fields(funding, {'owner', 'kind', 'tx', 'sources', 'protected_native_cash',
                'ordinary_fee', 'admission_fee', 'pool_funding_sompi', 'before_event'}, 'readmission funding')
            need(funding['owner'] == owner and funding['kind'] == 'reentry', 'readmission funding owner')
            need(funding['before_event'] == i, 'readmission funding observation horizon')
            fixed(funding['tx'])
            need(funding['sources'] == external[owner], 'actual prior native payout UTXOs only')
            need(funding['protected_native_cash'] == earmarked[owner], 'all exact cash remains outside pool')
            value, ordinary_fee, admit_fee, gross = fees.reentry(reserve,
                [c['value'] for c in external[owner]], earmarked[owner])
            need(funding['ordinary_fee'] == ordinary_fee and funding['admission_fee'] == admit_fee
                and funding['pool_funding_sompi'] == gross,
                'contextual consolidation fee and readmission funding')
            need(fee == admit_fee and e['public_deposit'] == gross and output == value,
                'readmission fee deducted from real native bank')
            need(notes[new[0]]['owner'] == owner and e['funding_owner'] == owner
                and e['opening'] == note_public(notes[new[0]]), 'readmission ownership/opening')
            external[owner] = [dict(tx=funding['tx'], value=earmarked[owner])] if earmarked[owner] else []
            charged[owner] += ordinary_fee
            expected_funding.append(funding)
            reserve += output
            reentry_count += 1
            need(i+1 < len(events) and hidden[i+1]['purpose'] == 'payment'
                and hidden[i+1]['owner'] == owner and events[i+1]['minute'] == e['minute'],
                'readmission only for immediate same-owner payment demand')
        else:
            need(e['mode'] in ('private', 'reveal') and 1 <= len(ps) <= 2, 'supported spend branch')
            need(e['funding_owner'] is None and e['public_deposit'] == 0, 'no external sponsor/top-up')
            need(total == output+payout+fee, 'integer value conservation')
            if e['mode'] == 'reveal':
                need(len(ps) == 1 and not new and payout > 0, 'whole-note REVEAL shape')
                need(e['opening'] == note_public(notes[ps[0]]), 'exact disclosed Note168/position/CM')
                need(e['nf'] == [notes[ps[0]]['nf']], 'revealed positioned NF')
                reveal_key = fixed(e['reveal_key'])
                need(hashlib.sha256(b'KPX1KEY\0'+DOMAIN+reveal_key).hexdigest()
                    == notes[ps[0]]['opening']['K'], 'public reveal key commitment')
                expected_nf = hmac.new(reveal_key, b'KPX1NF\0\0'+DOMAIN
                    +bytes.fromhex(notes[ps[0]]['cm'])+ps[0].to_bytes(4, 'little'), hashlib.sha256).hexdigest()
                need(e['nf'] == [expected_nf], 'public-key-derived positioned HMAC NF')
                need(fee == fees.reveal(reserve, total), 'contextual revealing fee')
                expected_spk = '000020'+notes[ps[0]]['opening']['nativePK']+'ac'
                need(e['payout_spk'] == expected_spk, 'CM-bound fallback destination')
            else:
                need(e['opening'] is None and len(e['nf']) == 2, 'private no opening/two NFs')
                need(e['nf'][:len(ps)] == [notes[p]['nf'] for p in ps], 'selected positioned real NFs')
                terminal = reserve == total and not new and payout > 0
                need(terminal or len(new) == 2, 'continuing two-slot append')
                need(fee == fees.private(reserve, payout, terminal), 'contextual private fee')
                need(payout or output > 0, 'P0 positive output')
                if payout:
                    spk = fixed(e['payout_spk'], 36)
                    need(spk[:3] == b'\0\0\x20' and spk[-1] == 0xac, 'canonical native destination')
                    need(all(spk[3:35].hex() != notes[p]['opening']['nativePK'] for p in ps), 'per-real-input key inequality')
                else:
                    need(e['payout_spk'] is None, 'P0 canonical zero destination')
            reserve -= payout+fee
            need(reserve == 0 or reserve >= FLOOR, 'native reserve floor')
            need(e['terminal'] == (reserve == 0), 'terminal reserve branch')
            for nf in e['nf']:
                need(fixed(nf) != bytes(32) and nf not in used_nf, 'nonzero absent sequential NF')
                used_nf.add(nf)
            nf_count += len(e['nf'])
            spent.update(ps)
        need(e['reserve'] == reserve and e['n'] == next_pos+len(new)
            and e['m'] == nf_count, 'exact next context/count')
        need(e['n'] <= 65_535 and e['m'] <= 2*e['n']+1, 'state capacity')
        next_pos += len(new)
        need(reserve == sum(notes[p]['value'] for p in range(next_pos) if p not in spent), 'all positive liabilities backed')
        charged[owner] += fee
        payouts[owner] += payout
        if payout:
            external[owner].append(dict(tx=e['tx'], value=payout))
        if h['payment'] is not None:
            j = integer(h['payment'], 0, 63)
            need(j not in payments and h['purpose'] == 'payment', 'one actual economic payment per demand')
            request = work['payments'][j]
            need(owner == request['sender'] and e['minute'] == request['minute']
                and e['mode'] == 'private' and payout == 0 and len(new) == 2, 'exact payment execution')
            need(notes[new[0]]['value'] == request['amount'] and notes[new[0]]['owner'] == request['recipient'], 'private recipient amount')
            need(notes[new[1]]['owner'] == (owner if notes[new[1]]['value'] else None), 'sender change')
            payments[j] = i
            outgoing[owner] += request['amount']; incoming[request['recipient']] += request['amount']
            payment_fees.append(dict(payment=j, fee_sompi=fee, amount_sompi=request['amount'],
                                     exceeds_ordinary_1pct=100*fee > request['amount']))
        if h['request'] is not None:
            j = integer(h['request'], 0, 31)
            need(owner == work['cash_requests'][j]['owner'], 'cash owner')
            request_events.setdefault(j, []).append(i)
            if h['purpose'] == 'cash':
                cash_payouts[j] = cash_payouts.get(j, 0)+payout
                need(e['minute'] == work['cash_requests'][j]['minute'], 'no mandatory cashout delay')
                earmarked[owner] += payout
        if 'fallback' in h['purpose']:
            need(e['mode'] == 'reveal', 'fallback is explicitly revealing')
            fallbacks.append(dict(event=i, owner=owner, reason=h['purpose'], claim_sompi=total, fee_sompi=fee))
    need(next_pos == len(notes) and set(payments) == set(range(64)), 'complete payment/notes coverage')
    need(ledger.payment_index == payments, 'payment index')
    need(ledger.funding == expected_funding, 'all funding and returned native change')
    need(ledger.costs == charged and ledger.payouts == payouts, 'per-user actual fee/payout ledger')
    need(ledger.external_coins == external and ledger.earmarked == earmarked,
        'native UTXOs/protected cash reconstructed independently')
    need(all(n['spent'] == (p in spent) for p, n in enumerate(notes)), 'final spent flags')
    need(reserve == ledger.reserve == 0 and all(n['value'] == 0 or p in spent for p, n in enumerate(notes)), 'complete positive-liability drainage')
    need(len(ledger.audit) == 32 and [r['request'] for r in ledger.audit] == list(range(32)), 'all cash requests retained')
    cash_failures, urgent_failures = [], []
    for row, demand in zip(ledger.audit, work['cash_requests'], strict=True):
        need(row['owner'] == demand['owner'] and row['demand'] == demand['amount']
            and type(row['completed']) is bool, 'cash audit identity')
        delivered = cash_payouts.get(row['request'], 0)
        need(delivered in (0, demand['amount']) and row['completed'] == (delivered == demand['amount']), 'identical exact net demand/no clipping')
        need(row['completed'] or bool(row.get('reason')), 'failed request reason retained')
        if not row['completed']:
            cash_failures.append(dict(request=row['request'], owner=row['owner'], net_demand_sompi=row['demand'], reason=row['reason']))
        need(row['urgent'] == demand['urgent'], 'urgent request flag preserved')
        if demand['urgent']:
            at_cash, consumed_cash = set(), set()
            for e, h in zip(events, hidden, strict=True):
                if e['minute'] > demand['minute']:
                    break
                at_cash.update(h['outputs']); consumed_cash.update(h['inputs'])
            remaining = [p for p in at_cash-consumed_cash
                if notes[p]['owner'] == demand['owner'] and notes[p]['value']]
            need(type(row['urgent_completed']) is bool
                and row['urgent_completed'] == (not remaining), 'urgent full-owner exit assessment')
            if remaining:
                urgent_failures.append(dict(request=row['request'], owner=row['owner'],
                    remaining_claims=len(remaining), remaining_sompi=sum(notes[p]['value'] for p in remaining)))
        else:
            need(row['urgent_completed'] is None, 'ordinary request is not urgent')
    users = []
    for owner in range(32):
        funding = expected_funding[owner]
        net_native_input = funding['input_sompi']-funding['returned_native_change_sompi']
        external_value = sum(c['value'] for c in external[owner])
        need(external_value >= earmarked[owner], 'protected exact cash never recycled')
        need(net_native_input+incoming[owner] == external_value+charged[owner]+outgoing[owner],
            'per-owner value/fees without subsidy or recycled-principal inflation')
        users.append(dict(owner=owner, native_input_sompi=funding['input_sompi'],
            returned_native_change_sompi=funding['returned_native_change_sompi'],
            net_shielded_initial_sompi=work['capitals'][owner],
            outgoing_payment_principal_sompi=outgoing[owner], incoming_payment_principal_sompi=incoming[owner],
            total_actual_fees_sompi=charged[owner], cumulative_native_payouts_sompi=payouts[owner],
            final_native_value_sompi=external_value, protected_exact_cash_sompi=earmarked[owner]))
    payment_counts, pool_operations, ordinary_operations = [0]*32, [0]*32, [0]*32
    initial_gross_funding, recycled_gross_funding = [0]*32, [0]*32
    for request in work['payments']:
        payment_counts[request['sender']] += 1
    for event in hidden:
        pool_operations[event['owner']] += 1
    for funding in expected_funding:
        owner = funding['owner']
        ordinary_operations[owner] += 1  # Initial creation or native consolidation.
        values = recycled_gross_funding if funding.get('kind') == 'reentry' else initial_gross_funding
        values[owner] += funding['pool_funding_sompi']
    def share(values):
        return dict(adversary=sum(values[:8]), total=sum(values), by_owner=list(values))
    traffic = dict(economic_payment_count=share(payment_counts),
        economic_payment_value_sompi=share(outgoing),
        pool_chain_operation_count=share(pool_operations),
        ordinary_native_transaction_count=share(ordinary_operations),
        all_modeled_chain_operation_count=share([a+b for a, b in zip(pool_operations, ordinary_operations, strict=True)]),
        initial_net_shielded_principal_sompi=share(work['capitals']),
        initial_gross_pool_funding_sompi=share(initial_gross_funding),
        recycled_gross_readmission_sompi=share(recycled_gross_funding),
        interpretation='Realized traffic/value shares; recycled readmission is not new economic principal.')
    return dict(schema='kpx3-population-independent-validation/v1', complete=True,
        payments=64, cash_requests=32, exact_cash_requests_completed=32-len(cash_failures),
        cash_failures=cash_failures, urgent_full_exit_failures=urgent_failures,
        urgent_full_exits_completed=2-len(urgent_failures), reentries=reentry_count,
        revealing_fallbacks=fallbacks, complete_drainage=True,
        per_user=users, ordinary_payment_fee_checks=payment_fees,
        realized_active_shares=traffic,
        no_aggregate_lifecycle_cost_qualification=True,
        limits=['No independent proof/native execution; private unrevealed NF-key assignments remain model assumptions.',
                'Request seed independence and prediction-before-truth require controller provenance.'])


def expected_view(ledger, members, end):
    """Reconstruct only legitimately disclosed authored/owned records."""
    authored, owned, born = [], [], set()
    for i, h in enumerate(ledger.hidden[:end]):
        born.update(h['outputs'])
        if h['owner'] in members:
            authored.append(dict(event=i, owner=h['owner'], inputs=h['inputs'],
                outputs=[dict(note_public(ledger.notes[p]), owner=ledger.notes[p]['owner']) for p in h['outputs']]))
    for n in ledger.notes:
        if n['owner'] in members and n['position'] in born:
            owned.append(dict(note_public(n), owner=n['owner'], nf=n['nf']))
    return dict(schema='kpx3-population-participant-view/v1', members=list(members), authored=authored, owned=owned)


def known_records(public, view):
    """Only direct openings and declared participant/native-directory records."""
    values, owners = {}, {}
    native_owner = {coin['tx']: funding['owner'] for funding in public['ordinary_funding']
        for coin in funding.get('sources', [])}
    def add(note, owner=None):
        p = note['position']
        if p in values:
            need(values[p] == note['value'], 'consistent directly known opening value')
        values[p] = note['value']
        if owner is not None:
            need(p not in owners or owners[p] == owner, 'consistent directly known owner')
            owners[p] = owner
    for event in public['events']:
        if event['opening'] is not None:
            owner = event['funding_owner']
            if owner is None:
                owner = native_owner.get(event['tx'])
            add(event['opening'], owner)
    for note in view['owned']:
        add(note, note['owner'])
    for authored in view['authored']:
        for note in authored['outputs']:
            add(note, note['owner'])
    return values, owners


def _counter():
    return dict(correct=0, eligible=0)


def score(ledger, jobs):
    """Aggregate one ledger. No per-target labels/correctness leave the scorer."""
    validation = validate(ledger)
    buckets = {p: {h: {v: dict(metrics={m: _counter() for m in METRICS},
        selective_relationship={str(c): _counter() for c in COVERAGES}) for v in VARIANTS}
        for h in HORIZONS} for p in PROFILES}
    selective = {(p, h, v): [] for p in PROFILES for h in HORIZONS for v in VARIANTS}
    coverage, excluded = set(), {p: {h: {m: 0 for m in METRICS} for h in HORIZONS} for p in PROFILES}
    direct_records = {p: {h: dict(amount_known=0, amount_eligible=0,
        recipient_known=0, recipient_eligible=0) for h in HORIZONS} for p in PROFILES}
    for job in jobs:
        profile, horizon, end, prediction = (job[k] for k in ('profile', 'horizon', 'public_end', 'prediction'))
        need(profile in PROFILES and horizon in HORIZONS, 'job scope')
        integer(end, 32, len(ledger.events))
        if horizon == 'cashouts': need(end == ledger.cashout_end, 'cashout endpoint')
        if horizon == 'drainage': need(end == len(ledger.events), 'drainage endpoint')
        public = ledger.public(end)
        need(public['events'] == ledger.events[:end], 'exact accepted-prefix event export')
        need(public['ordinary_funding'] == [f for f in ledger.funding if f['before_event'] < end],
            'no future readmission/funding in observer prefix')
        view = expected_view(ledger, PROFILES[profile], end)
        record_values, record_owners = known_records(public, view)
        fields(prediction, {'schema', 'public_sha256', 'view_sha256', 'variants', 'rows'}, 'prediction')
        need(prediction['schema'] == 'kpx3-population-prediction/v1'
            and prediction['public_sha256'] == digest(public) and prediction['view_sha256'] == digest(view)
            and prediction['variants'] == list(VARIANTS), 'prediction scope/source binding')
        targets = [i for i, e in enumerate(public['events']) if e['mode'] == 'private' and not e['payout']]
        if horizon == 'payment':
            need(targets and targets[-1] == end-1, 'payment prefix exactly ends on target')
            targets = [end-1]
        need([r['event'] for r in prediction['rows']] == targets, 'all observable selected-horizon P0 targets predicted')
        scored = set(targets)
        members = set(PROFILES[profile])
        for row in prediction['rows']:
            fields(row, {'event', 'guesses', 'public_opening_facts'}, 'prediction row')
            fact = row['public_opening_facts']
            fields(fact, {'note_value_opened', 'exact_note_value', 'owner_known'}, 'direct known-note diagnostic')
            first = ledger.events[row['event']]['prior_n']
            need(fact == dict(note_value_opened=first in record_values,
                exact_note_value=record_values.get(first), owner_known=first in record_owners),
                'direct known-note facts reconstructed independently')
            fields(row['guesses'], set(VARIANTS), 'fixed variants')
            for guess in row['guesses'].values():
                fields(guess, {'sender', 'recipient', 'amount', 'rank'}, 'guess')
                integer(guess['sender'], 0, 31); integer(guess['recipient'], 0, 31); integer(guess['amount'])
                need(isinstance(guess['rank'], list) and len(guess['rank']) == 3
                    and all(type(x) is int and -(2**63) < x < 2**63 for x in guess['rank']), 'frozen public rank')
            need(row['guesses']['prior']['amount'] == 45*S
                and row['guesses']['prior']['rank'] == [0, 0, 0], 'unchanged distribution-aware 45-KAS prior')
            if row['event'] not in scored: continue
            event = row['event']; identity = (profile, horizon, event)
            need(identity not in coverage, 'no duplicate target scoring')
            coverage.add(identity)
            h = ledger.hidden[event]
            if h['purpose'] != 'payment': continue  # Hidden economic mask only here.
            request = ledger.work['payments'][h['payment']]
            a, b, amount = request['sender'], request['recipient'], request['amount']
            primary = a >= 8 and b >= 8
            if not primary: continue
            known = {'sender': a in members, 'recipient': a in members or b in members,
                'relationship': a in members, 'amount_exact': a in members or b in members,
                'amount_within_10pct': a in members or b in members}
            for metric in METRICS:
                excluded[profile][horizon][metric] += int(known[metric])
            diagnostic = direct_records[profile][horizon]
            if not known['amount_exact']:
                diagnostic['amount_eligible'] += 1
                diagnostic['amount_known'] += int(first in record_values)
            if not known['recipient']:
                diagnostic['recipient_eligible'] += 1
                diagnostic['recipient_known'] += int(first in record_owners)
            for variant, guess in row['guesses'].items():
                correct = dict(sender=guess['sender'] == a, recipient=guess['recipient'] == b,
                    relationship=guess['sender'] == a and guess['recipient'] == b,
                    amount_exact=guess['amount'] == amount,
                    amount_within_10pct=10*abs(guess['amount']-amount) <= amount)
                for metric in METRICS:
                    if known[metric]: continue
                    counter = buckets[profile][horizon][variant]['metrics'][metric]
                    counter['eligible'] += 1; counter['correct'] += int(correct[metric])
                if not known['relationship']:
                    selective[(profile, horizon, variant)].append((tuple(guess['rank']), event, correct['relationship']))
    all_p0 = {i for i, e in enumerate(ledger.events) if e['mode'] == 'private' and not e['payout']}
    need(all((p, 'payment', e) in coverage for p in PROFILES for e in all_p0), 'all payment-horizon P0 prefixes')
    for profile in PROFILES:
        for horizon in ('cashouts', 'drainage'):
            end = ledger.cashout_end if horizon == 'cashouts' else len(ledger.events)
            need(all((profile, horizon, e) in coverage for e in all_p0 if e < end), 'complete final horizons')
    for (profile, horizon, variant), rows in selective.items():
        ranked = sorted(rows, key=lambda r: (tuple(-x for x in r[0]), r[1]))
        for percent in COVERAGES:
            count = (len(ranked)*percent+99)//100
            buckets[profile][horizon][variant]['selective_relationship'][str(percent)] = dict(
                correct=sum(int(r[2]) for r in ranked[:count]), eligible=count,
                population=len(ranked), nominal_percent=percent)
    return dict(schema='kpx3-population-ledger-score/v1', classification='SYNTHETIC_CONSTRAINT_MODEL',
        arm=ledger.arm, regime=ledger.regime, rate=ledger.rate, complete=True,
        validation=validation, results=buckets, legitimate_known_exclusions=excluded,
        direct_opening_record_diagnostics=direct_records,
        preserved_prior=dict(successes=21103, denominator=100025, cap_percent=20, unchanged_failure=True),
        privacy_qualification=False, inference='Descriptive per-ledger counts only; independent-ledger uncertainty belongs to frozen aggregator.')
