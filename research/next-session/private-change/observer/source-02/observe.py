#!/usr/bin/env python3
"""One public-only JSON stdin request; no generator or file input API."""
import json
import sys
import z3

from change_model import analyze
from certificate import CertificateError
from public_ledger import InputError, strict_json


def main():
    try:
        request = strict_json(sys.stdin.read())
        if type(request) is not dict or set(request) != {'public', 'value_priors'}:
            raise InputError('request-fields')
        answer = analyze(request['public'], request['value_priors'])
    except (CertificateError, z3.Z3Exception):
        answer = {'schema': 'kpx3-change-public-integer-analysis/v1',
                  'status': 'INCOMPLETE', 'reason': 'solver-or-certificate-failure',
                  'owner_link': 'NOT_MODELLED', 'financial_privacy_or_crypto_qualification': False}
    except (InputError, ValueError, TypeError):
        answer = {'schema': 'kpx3-change-public-integer-analysis/v1',
                  'status': 'REJECTED_INPUT', 'reason': 'strict-public-request',
                  'owner_link': 'NOT_MODELLED', 'financial_privacy_or_crypto_qualification': False}
    print(json.dumps(answer, sort_keys=True, separators=(',', ':'), allow_nan=False))


if __name__ == '__main__':
    main()
