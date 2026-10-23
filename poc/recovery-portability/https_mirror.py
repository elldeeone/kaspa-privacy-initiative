#!/usr/bin/env python3
"""Retrieve exact public CAS bytes over verified HTTPS, then use capsule.py.

Mirrors never select code/keys or attest currentness. Literal loopback HTTP is
an explicit test-only option. Redirect/signed URL strings are never reported.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

import capsule as c


def _url(value, allow_loopback_http, *, redirect=False):
    try:
        split = urlsplit(value)
        port = split.port
    except (TypeError, ValueError):
        raise c.Invalid('mirror-URL-invalid') from None
    c.need(split.hostname is not None and split.username is None and split.password is None
           and not split.fragment and (redirect or not split.query), 'mirror-URL-policy')
    c.need(split.scheme == 'https' or (allow_loopback_http and split.scheme == 'http'
           and split.hostname in ('127.0.0.1', '::1')), 'mirror-HTTPS-required')
    c.need(port is None or 0 < port <= 65535, 'mirror-port')
    return split


class SafeRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, allow_loopback_http):
        self.allow_loopback_http = allow_loopback_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urlsplit(req.full_url)
        new = _url(newurl, self.allow_loopback_http, redirect=True)
        c.need(not (old.scheme == 'https' and new.scheme != 'https'), 'mirror-HTTPS-downgrade')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _refs(raw, root_sha, selection):
    c.need(c.sha(raw) == root_sha, 'capsule-root-mismatch')
    value = c.parse(raw)
    c.exact(value, {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
        'program_label', 'role', 'objects'}, 'capsule-fields')
    c.need(value['schema'] == 'kpx4-public-recovery-capsule/v1'
           and value['program_label'] == selection.program_label
           and value['role'] == selection.role, 'capsule-profile-role')
    c._identity(value, selection, 'capsule-identity')
    c.need(type(value['objects']) is list and len(value['objects']) == 5, 'capsule-object-count')
    refs = {}
    for ref in value['objects']:
        c.exact(ref, {'kind', 'sha256', 'bytes'}, 'capsule-object-fields')
        c.need(type(ref['kind']) is str and ref['kind'] in c.KINDS and ref['kind'] not in refs,
               'capsule-object-kind')
        c.hx(ref['sha256'], 32, 'capsule-object-digest')
        c.uint(ref['bytes'], 'capsule-object-length', positive=True)
        refs[ref['kind']] = ref
    c.need(list(refs) == sorted(c.KINDS), 'capsule-object-order')
    for kind, expected in (('descriptor', selection.descriptor_sha256),
        ('parameters_manifest', selection.parameters_manifest_sha256),
        ('public_parameters', selection.public_parameters_sha256),
        ('software_inventory', selection.software_inventory_sha256)):
        c.need(refs[kind]['sha256'] == expected, 'capsule-static-selection')
    c.need(refs['public_parameters']['bytes'] == selection.public_parameters_bytes,
           'capsule-PK-length-selection')
    return refs


@dataclass(frozen=True)
class RetrievedCapsule:
    staged: c.StagedCapsule
    transport_receipt: dict

    def public_receipt(self):
        return {'transport': self.transport_receipt, 'capsule': self.staged.public_receipt()}


def retrieve_capsule(expected_capsule_sha256, selection, mirror_bases,
                     new_output_directory, forbidden_paths=(), *, mode='spend_material',
                     allow_loopback_http=False):
    forbidden_paths = tuple(forbidden_paths)
    c.need(type(selection) is c.TrustedSelection, 'trusted-selection-required')
    c.need(mode in ('recognition', 'spend_material'), 'staging-mode')
    c.hx(expected_capsule_sha256, 32, 'capsule-root-digest')
    c._metadata_forbidden(forbidden_paths)
    c.need(type(mirror_bases) in (tuple, list) and bool(mirror_bases), 'mirror-bases')
    bases = []
    for base in mirror_bases:
        parsed = _url(base, allow_loopback_http)
        bases.append(urlunsplit((parsed.scheme, parsed.netloc,
            parsed.path.rstrip('/'), '', '')))
    output = c._path(new_output_directory)
    c.need(not output.exists() and not any(p.is_symlink() for p in output.parents),
           'fresh-retrieval-directory-required')
    try:
        output.mkdir(mode=0o700)
        cache = output / 'downloaded-cas'
        objects = cache / 'objects/sha256'
        objects.mkdir(parents=True, mode=0o700)
    except OSError:
        raise c.Invalid('retrieval-directory-unavailable') from None
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()),
                          SafeRedirect(allow_loopback_http))
    rejected, downloaded = [], []

    def fetch(kind, digest_hex, length=None):
        destination = objects / digest_hex
        if destination.exists():
            # This can only be a previously validated, owned object in the fresh
            # cache. Canonical schemas later reject semantic type confusion.
            return destination
        for ordinal, base in enumerate(bases):
            temporary = objects / (digest_hex + '.part-' + str(ordinal))
            try:
                request = Request(base + '/objects/sha256/' + digest_hex,
                    headers={'Accept-Encoding': 'identity',
                             'User-Agent': 'KPI-public-CAS-recovery/1'})
                with opener.open(request, timeout=300) as response:
                    _url(response.geturl(), allow_loopback_http, redirect=True)
                    c.need(response.status == 200, 'mirror-response-status')
                    c.need(response.headers.get('Content-Encoding', 'identity') == 'identity',
                           'mirror-content-encoding')
                    declared = response.headers.get('Content-Length')
                    if declared is not None:
                        c.need(declared.isdecimal(), 'mirror-content-length')
                        declared = int(declared)
                        c.need(declared == length if length is not None else declared <= 65536,
                               'mirror-content-length')
                    # The index has a fixed small structural schema. Object
                    # sizes are their selected exact lengths, not trial caps.
                    bound = length if length is not None else 65536
                    digest, total = hashlib.sha256(), 0
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, 'wb') as target:
                        while chunk := response.read(min(1024 * 1024, bound - total + 1)):
                            total += len(chunk)
                            c.need(total <= bound, 'mirror-object-length')
                            digest.update(chunk)
                            target.write(chunk)
                        target.flush()
                        os.fsync(target.fileno())
                c.need((length is None or total == length)
                       and digest.hexdigest() == digest_hex, 'mirror-object-digest')
                temporary.chmod(0o400)
                temporary.rename(destination)
                downloaded.append({'kind': kind, 'sha256': digest_hex,
                    'bytes': total, 'mirror_ordinal': ordinal})
                return destination
            except (c.Invalid, HTTPError, URLError, OSError, http.client.HTTPException) as error:
                reason = str(error) if isinstance(error, c.Invalid) else 'mirror-transport-unavailable'
                rejected.append({'kind': kind, 'mirror_ordinal': ordinal, 'reason': reason})
                if isinstance(error, HTTPError):
                    error.close()
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        raise c.Incomplete('matching-public-object-unavailable')

    manifest = fetch('capsule_index', expected_capsule_sha256)
    refs = _refs(c.read_public(manifest, forbidden_paths, maximum=65536),
                 expected_capsule_sha256, selection)
    for kind in sorted(c.SMALL_KINDS):
        fetch(kind, refs[kind]['sha256'], refs[kind]['bytes'])
    # Actual strict identity/schema checks precede any PK network request.
    preflight = c.stage_capsule(manifest, expected_capsule_sha256, selection,
        [cache], output / 'public-preflight', forbidden_paths, mode='recognition')
    if mode == 'spend_material':
        ref = refs['public_parameters']
        fetch('public_parameters', ref['sha256'], ref['bytes'])
        staged = c.stage_capsule(manifest, expected_capsule_sha256, selection,
            [cache], output / 'spend-material', forbidden_paths, mode='spend_material')
    else:
        staged = preflight
    receipt = {'schema': 'kpx4-public-CAS-retrieval/v1',
        'status': 'EXACT_PUBLIC_BYTES_RETRIEVED', 'mode': mode,
        'capsule_sha256': expected_capsule_sha256,
        'objects_downloaded': downloaded, 'rejected_mirror_candidates': rejected,
        'URLs_queries_or_credentials_emitted': False,
        'verified_TLS_required_except_explicit_literal_loopback_HTTP_test': True,
        'literal_loopback_HTTP_test_enabled': allow_loopback_http,
        'current_state_verified': False, 'spend_authorized': False,
        'independent_provider_or_retention_qualification': False,
        'private_contents_read': False}
    (output / 'PUBLIC-TRANSPORT-RECEIPT.json').write_bytes(c.encoded(receipt) + b'\n')
    return RetrievedCapsule(staged, receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('expected_capsule_sha256')
    parser.add_argument('trusted_selection', type=Path)
    parser.add_argument('new_output', type=Path)
    parser.add_argument('--mirror-base', action='append', required=True)
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    parser.add_argument('--mode', choices=('recognition', 'spend_material'), default='spend_material')
    parser.add_argument('--allow-loopback-http', action='store_true')
    args = parser.parse_args()
    try:
        selection = c.TrustedSelection.from_dict(c.parse(c.read_public(args.trusted_selection,
            args.forbidden, maximum=65536)))
        result = retrieve_capsule(args.expected_capsule_sha256, selection,
            args.mirror_base, args.new_output, args.forbidden, mode=args.mode,
            allow_loopback_http=args.allow_loopback_http)
        print(json.dumps(result.public_receipt(), sort_keys=True))
    except (c.Invalid, OSError):
        print(json.dumps({'status': 'INCOMPLETE_OR_INVALID', 'current_state_verified': False,
                          'spend_authorized': False}), file=__import__('sys').stderr)
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
