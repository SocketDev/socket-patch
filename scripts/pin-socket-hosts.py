#!/usr/bin/env python3
"""Pin the production Socket patch hosts in the hosts file of a CI runner.

The compatibility workflows drive REAL package managers (bun, vlt, poetry,
...) against the production patch service. On GitHub's hosted macOS runners
the system resolver intermittently answers `patch.socket.dev` with
EAI_NONAME ("[Errno 8] nodename nor servname provided, or not known";
bun: `FailedToOpenSocket`) for minutes at a time, starting at job start or
mid-job, while the service itself is up (the ubuntu and windows legs of the
same run pass, and the same macOS cells pass before and after the window).
The runner's resolver is not under test, so the workflow takes it out of the
path: this script resolves each host once, verifies every address, and
prints `hosts(5)` lines the workflow appends to /etc/hosts.

Resolution tries the system resolver first, then DNS-over-HTTPS to IP-literal
endpoints (no DNS needed to reach them), retrying with backoff inside a
bounded window. An address is only pinned after a TLS handshake to it with
SNI = the host verifies the host's certificate, so a pinned address is one
that really serves that name; the package managers still verify TLS for the
hostname on every request. Both families are resolved; an IPv6 address is
pinned only when it verifies too, so a runner without an IPv6 route never gets
an unreachable entry.

Exit status is non-zero, with nothing printed, when a host cannot be pinned
within the window: the job then fails at this step, naming the host, rather
than in a hundred cells downstream.
"""

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.request

DEFAULT_HOSTS = ['patch.socket.dev', 'patches-api.socket.dev']
# DoH JSON endpoints reached by IP literal; both serve certificates with the
# IP in the subjectAltName, so they verify without any name resolution.
DOH_ENDPOINTS = [
    'https://1.1.1.1/dns-query?name={host}&type={rrtype}',
    'https://8.8.8.8/resolve?name={host}&type={rrtype}',
]
RR_TYPES = {'A': 1, 'AAAA': 28}


def log(message):
    print(message, file=sys.stderr, flush=True)


def system_resolve(host):
    infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def doh_resolve(host, template, timeout):
    addresses = []
    for rrtype, code in RR_TYPES.items():
        request = urllib.request.Request(template.format(host=host, rrtype=rrtype),
                                         headers={'accept': 'application/dns-json'})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            answer = json.loads(response.read()).get('Answer') or []
        # CNAME answers (type 5) precede the address records and are skipped.
        addresses += [record['data'] for record in answer if record.get('type') == code]
    return addresses


def verified(host, address, timeout):
    """A TLS handshake to `address` with SNI `host` verifies `host`'s cert."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((address, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError) as error:
        log(f'{host}: {address} failed verification: {error}')
        return False


def resolve(host, window, timeout):
    """Verified addresses of `host` (IPv4 first), or [] once `window` seconds pass."""
    sources = [('system resolver', lambda: system_resolve(host))]
    sources += [(template.split('/')[2], lambda t=template: doh_resolve(host, t, timeout))
                for template in DOH_ENDPOINTS]
    deadline = time.monotonic() + window
    attempt = 0
    fallback = []
    while True:
        attempt += 1
        for name, source in sources:
            try:
                candidates = source()
            except Exception as error:  # noqa: BLE001 - every source is best effort
                log(f'{host}: {name} attempt {attempt} failed: {error}')
                continue
            addresses = []
            for candidate in dict.fromkeys(candidates):
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if verified(host, candidate, timeout):
                    addresses.append(candidate)
            addresses.sort(key=lambda a: ipaddress.ip_address(a).version)
            # A source that only verified IPv6 is not enough on its own: try
            # the next one for an IPv4 address before settling for it.
            if any(ipaddress.ip_address(a).version == 4 for a in addresses):
                log(f'{host}: pinned {" ".join(addresses)} (from {name}, attempt {attempt})')
                return addresses
            log(f'{host}: {name} attempt {attempt} gave no verified IPv4 address')
            fallback = fallback or addresses
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return fallback
        time.sleep(min(5 * attempt, 30, remaining))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('hosts', nargs='*', default=DEFAULT_HOSTS)
    parser.add_argument('--window', type=float, default=300,
                        help='seconds to keep retrying a host before failing (default 300)')
    parser.add_argument('--timeout', type=float, default=10,
                        help='per-request timeout in seconds (default 10)')
    args = parser.parse_args(argv)
    lines = []
    for host in args.hosts:
        addresses = resolve(host, args.window, args.timeout)
        if not addresses:
            log(f'::error::could not resolve and verify {host} within {args.window:.0f} s')
            return 1
        lines += [f'{address} {host}' for address in addresses]
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    sys.exit(main())
