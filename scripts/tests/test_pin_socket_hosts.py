"""Hermetic coverage for scripts/pin-socket-hosts.py's resolution fallbacks."""

import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'pin_socket_hosts', Path(__file__).resolve().parents[1] / 'pin-socket-hosts.py')
pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pin)

HOST = 'patch.socket.dev'
EAI_NONAME = socket.gaierror(8, 'nodename nor servname provided, or not known')


def run(fn):
    with contextlib.redirect_stderr(io.StringIO()):
        return fn()


class PinSocketHostsTests(unittest.TestCase):
    def test_system_resolver_answer_is_pinned_when_it_verifies(self):
        with patch.object(pin, 'system_resolve', return_value=['172.66.3.58', '172.66.3.58']), \
                patch.object(pin, 'doh_resolve') as doh, \
                patch.object(pin, 'verified', return_value=True):
            self.assertEqual(run(lambda: pin.resolve(HOST, 0, 1)), ['172.66.3.58'])
        doh.assert_not_called()

    def test_doh_takes_over_when_the_system_resolver_fails(self):
        with patch.object(pin, 'system_resolve', side_effect=EAI_NONAME), \
                patch.object(pin, 'doh_resolve', return_value=['2606:4700:7::32d', '162.159.143.62']), \
                patch.object(pin, 'verified', return_value=True):
            self.assertEqual(run(lambda: pin.resolve(HOST, 0, 1)),
                             ['162.159.143.62', '2606:4700:7::32d'])

    def test_unverified_addresses_are_never_pinned(self):
        with patch.object(pin, 'system_resolve', return_value=['140.82.112.3']), \
                patch.object(pin, 'doh_resolve', return_value=['140.82.112.3']), \
                patch.object(pin, 'verified', return_value=False):
            self.assertEqual(run(lambda: pin.resolve(HOST, 0, 1)), [])

    def test_ipv6_only_is_a_last_resort(self):
        with patch.object(pin, 'system_resolve', return_value=['2606:4700:7::32d']), \
                patch.object(pin, 'doh_resolve', return_value=[]), \
                patch.object(pin, 'verified', return_value=True):
            self.assertEqual(run(lambda: pin.resolve(HOST, 0, 1)), ['2606:4700:7::32d'])

    def test_retries_until_the_resolver_recovers(self):
        answers = [EAI_NONAME, ['172.66.3.58']]
        with patch.object(pin, 'system_resolve', side_effect=answers), \
                patch.object(pin, 'doh_resolve', side_effect=OSError('no route')), \
                patch.object(pin, 'verified', return_value=True), \
                patch.object(pin.time, 'sleep') as sleep:
            self.assertEqual(run(lambda: pin.resolve(HOST, 60, 1)), ['172.66.3.58'])
        sleep.assert_called_once()

    def test_verification_handshake_refuses_tls_below_1_2(self):
        with patch.object(pin.socket, 'create_connection') as connect, \
                patch.object(pin.ssl, 'create_default_context') as make_context:
            self.assertTrue(pin.verified(HOST, '172.66.3.58', 5))
        context = make_context.return_value
        self.assertEqual(context.minimum_version, pin.ssl.TLSVersion.TLSv1_2)
        connect.assert_called_once_with(('172.66.3.58', 443), timeout=5)
        context.wrap_socket.assert_called_once_with(
            connect.return_value.__enter__.return_value, server_hostname=HOST)

    def test_main_prints_hosts_lines_and_fails_closed(self):
        out = io.StringIO()
        with patch.object(pin, 'resolve', return_value=['172.66.3.58']), \
                contextlib.redirect_stdout(out):
            self.assertEqual(pin.main([HOST]), 0)
        self.assertEqual(out.getvalue(), f'172.66.3.58 {HOST}\n')
        out = io.StringIO()
        with patch.object(pin, 'resolve', return_value=[]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pin.main([HOST]), 1)
        self.assertEqual(out.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
