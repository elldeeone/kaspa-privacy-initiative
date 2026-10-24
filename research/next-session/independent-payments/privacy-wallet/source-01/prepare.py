#!/usr/bin/env python3
"""Validate one PUBLIC payment request. Does not read a backup or prepare a proof."""
import argparse
import json
from pathlib import Path

from payment import Request, REQUEST_SCHEMA
from reuse import load


def main(args):
    c = load()
    domain = c.history.hexbytes(args.expected_domain_hex32, 32)
    request = Request.parse(Path(args.request).read_bytes(), domain)
    return {'schema': REQUEST_SCHEMA, 'domain_hex32': domain.hex(),
        'recipient_invoice_hex208': request.invoice.hex(),
        'net_principal_sompi': request.net_principal_sompi,
        'recipient_exit_credit_sompi': request.recipient_exit_credit_sompi,
        'classification': 'PUBLIC_REQUEST_ONLY_NO_AUTHORIZATION_OR_FEE_QUOTE'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--expected-domain-hex32', required=True)
    try:
        print(json.dumps(main(parser.parse_args()), sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit('single-payment public request refused') from None

