"""Independent exact integer checking of solver-generated arithmetic certificates."""
from public_ledger import MAX, NOTE_FLOOR


class CertificateError(ValueError):
    pass


def require(condition, category):
    if not condition:
        raise CertificateError(category)


def check_certificate(ledger, certificate):
    require(type(certificate) is dict and set(certificate) == {'values', 'selected_positions'},
            'certificate-fields')
    values = certificate['values']
    require(type(values) is list and len(values) == len(ledger.notes), 'certificate-value-count')
    for note, value in zip(ledger.notes, values, strict=True):
        require(type(value) is int and 0 <= value <= MAX
                and (value == 0 or value >= NOTE_FLOOR), 'certificate-value-range')
        require(note.known_value is None or value == note.known_value, 'certificate-public-value')
    for position, low, high in ledger.bounds:
        require(low <= values[position] <= high, 'certificate-prior')
    rows = certificate['selected_positions']
    private = [event for event in ledger.events if event.kind == 'private']
    require(type(rows) is list and len(rows) == len(private), 'certificate-selection-count')
    choices = {}
    for event, row in zip(private, rows, strict=True):
        require(type(row) is dict and set(row) == {'event', 'position'}
                and type(row['event']) is int and row['event'] == event.ordinal
                and type(row['position']) is int, 'certificate-selection-fields')
        position = row['position']
        require(0 <= position < event.prior_count
                and ledger.notes[position].birth < event.ordinal, 'certificate-future-position')
        choices[event.ordinal] = position
    spent = set()
    for event in ledger.events:
        outputs = sum(values[p] for p in event.new_positions)
        if event.kind == 'ingress':
            require(outputs == event.ingress_value, 'certificate-ingress')
        else:
            position = choices[event.ordinal]
            require(position not in spent and values[position] >= NOTE_FLOOR,
                    'certificate-note-replayed-or-zero')
            require(values[position] == outputs + event.payout + event.fee,
                    'certificate-conservation')
            positive = sum(values[p] > 0 for p in event.new_positions)
            if event.payout:
                require(positive == 0 if ledger.policy == 'whole_claim' else positive <= 1,
                        'certificate-cashout-policy')
            else:
                require(1 <= positive <= 2, 'certificate-payment-policy')
            spent.add(position)
        remaining = sum(values[n.position] for n in ledger.notes
                        if n.birth <= event.ordinal and n.position not in spent)
        require(remaining == event.reserve, 'certificate-prefix-reserve')
    return True
