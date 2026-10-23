"""Anonymous verified-HTTPS byte retrieval against an external whole-file pin.

URLs are transport hints only. No downloaded code is imported or executed, no
cookies/auth/proxies are used, and no redirect query or complete URL is logged.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from trusted_util import c, fresh_parent

BUFFER = 1_048_576


def safe_url(value, allowed_hosts, *, redirect=False):
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (ValueError, TypeError):
        raise c.Invalid('invalid-HTTPS-location') from None
    c.need(parsed.scheme == 'https' and parsed.hostname in allowed_hosts
           and parsed.username is None and parsed.password is None
           and not parsed.fragment and (redirect or not parsed.query)
           and (port is None or 0 < port <= 65535), 'HTTPS-location-policy')
    return parsed


class StrictRedirect(HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 5

    def __init__(self, allowed_hosts):
        self.allowed_hosts = frozenset(allowed_hosts)
        self.events = []

    def redirect_request(self, request, response, code, message, headers, new_url):
        before = safe_url(request.full_url, self.allowed_hosts, redirect=True)
        after = safe_url(new_url, self.allowed_hosts, redirect=True)
        c.need(len(self.events) < 5, 'HTTPS-redirect-limit')
        self.events.append({'status': code, 'from_host': before.hostname,
                            'to_host': after.hostname})
        return super().redirect_request(request, response, code, message, headers, new_url)


def opener(allowed_hosts):
    redirect = StrictRedirect(allowed_hosts)
    context = ssl.create_default_context()
    c.need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
           'verified-TLS-required')
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), redirect), redirect


def error_category(error):
    if isinstance(error, c.Invalid):
        return str(error)
    if isinstance(error, HTTPError):
        error.close()
        return 'HTTPS-status-' + str(error.code)
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return 'TLS-certificate-verification-failed'
    return 'HTTPS-read-unavailable'


def fetch_object(urls, expected_bytes, expected_sha256, output, allowed_hosts,
                 forbidden_paths=()):
    forbidden_paths = tuple(forbidden_paths)
    c._metadata_forbidden(forbidden_paths)
    c.uint(expected_bytes, 'expected-object-length', positive=True)
    c.hx(expected_sha256, 32, 'expected-object-SHA256')
    c.need(type(allowed_hosts) in (list, tuple, set, frozenset) and bool(allowed_hosts)
           and all(type(host) is str and host == host.lower() and host for host in allowed_hosts),
           'selected-HTTPS-hosts-required')
    urls = tuple(urls)
    c.need(bool(urls), 'no-public-sources')
    for url in urls:
        safe_url(url, allowed_hosts)
    parent, name = fresh_parent(output)
    failures = []
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise c.Invalid('output-already-exists')
        for ordinal, url in enumerate(urls):
            temporary = '.partial-' + secrets.token_hex(16)
            published = False
            try:
                client, redirects = opener(allowed_hosts)
                request = Request(url, headers={'Accept-Encoding': 'identity',
                    'Accept': 'application/octet-stream', 'User-Agent': 'KPI-public-recovery/1'})
                total, digest = 0, hashlib.sha256()
                with client.open(request, timeout=600) as response:
                    location = safe_url(response.geturl(), allowed_hosts, redirect=True)
                    c.need(response.status == 200, 'HTTPS-success-status-required')
                    c.need(response.headers.get('Content-Encoding', 'identity') == 'identity',
                           'HTTPS-content-encoding')
                    declared = response.headers.get('Content-Length')
                    c.need(declared is None or (declared.isdecimal()
                           and int(declared) == expected_bytes), 'HTTPS-content-length')
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    with os.fdopen(fd, 'wb') as target:
                        while raw := response.read(min(BUFFER, expected_bytes - total + 1)):
                            total += len(raw)
                            c.need(total <= expected_bytes, 'HTTPS-object-trailing-bytes')
                            target.write(raw)
                            digest.update(raw)
                        c.need(total == expected_bytes and digest.hexdigest() == expected_sha256,
                               'HTTPS-whole-object-mismatch')
                        target.flush()
                        os.fsync(target.fileno())
                        os.fchmod(target.fileno(), 0o444)
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                        follow_symlinks=False)
                published = True
                os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
                return {'schema': 'kpx4-public-HTTPS-object-result/v1',
                    'status': 'EXTERNAL_WHOLE_IDENTITY_VERIFIED_AT_COPY',
                    'whole_bytes': total, 'whole_sha256': expected_sha256,
                    'selected_source_ordinal': ordinal, 'final_host': location.hostname,
                    'redirects': redirects.events, 'rejected_sources': failures,
                    'system_TLS_verified': True, 'URLs_queries_credentials_logged': False,
                    'downloaded_code_executed': False, 'current_state_verified': False,
                    'spend_authorized': False, 'provider_independence_or_retention_verified': False}
            except (c.Invalid, HTTPError, URLError, OSError, http.client.HTTPException) as error:
                failures.append({'source_ordinal': ordinal, 'reason': error_category(error)})
            finally:
                if not published:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass
        raise c.Incomplete('all-selected-public-sources-incomplete')
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', action='append', required=True)
    parser.add_argument('--expected-bytes', type=int, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--allowed-host', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    args = parser.parse_args()
    try:
        receipt = fetch_object(args.url, args.expected_bytes, args.expected_sha256,
            args.output, args.allowed_host, args.forbidden)
        print(json.dumps(receipt, sort_keys=True))
    except (c.Invalid, OSError):
        print(json.dumps({'status': 'PUBLIC_OBJECT_INCOMPLETE_OR_INVALID',
            'current_state_verified': False, 'spend_authorized': False}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
