"""Offline coverage for the scripts/perf record/replay benchmark harness."""

import concurrent.futures
import http.client
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
from unittest.mock import patch


PERF = Path(__file__).resolve().parents[1] / 'perf'
spec = importlib.util.spec_from_file_location('perf_replay', PERF / 'replay.py')
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)

BATCH = '/v0/orgs/acme/patches/batch'
KNOWN = {
    'pkg:npm/a@1.0.0': {'purl': 'pkg:npm/a@1.0.0', 'patches': [{'uuid': 'u-a'}]},
    'pkg:npm/c@3.0.0': {'purl': 'pkg:npm/c@3.0.0', 'patches': [{'uuid': 'u-c'}]},
}


class Upstream(http.server.BaseHTTPRequestHandler):
    """Stand-in for api.socket.dev: a batch endpoint and one detail GET."""
    protocol_version = 'HTTP/1.1'
    hits = []

    def log_message(self, *args):
        pass

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        Upstream.hits.append(self.path)
        purls = [c['purl'] for c in req['components']]
        self._reply(200, {'packages': [KNOWN[p] for p in purls if p in KNOWN],
                          'canAccessPaidPatches': True})

    def do_GET(self):
        Upstream.hits.append(self.path)
        self._reply(200, {'path': self.path})


def cfg(mode, **kw):
    argv = [mode, '--store', 'unused', '--route', '0=http://unused']
    c = replay.parse_args(argv)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def request(port, method, path, obj=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    body = json.dumps(obj).encode() if obj is not None else None
    conn.request(method, path, body=body, headers={'Content-Type': 'application/json'})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def batch_body(*purls):
    return {'components': [{'purl': p} for p in purls]}


def free_port_run(n):
    """First port of n consecutive free localhost ports."""
    for _ in range(50):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            base = s.getsockname()[1]
        if base + n > 65535:
            continue
        socks = []
        try:
            for p in range(base, base + n):
                s = socket.socket()
                socks.append(s)
                s.bind(('127.0.0.1', p))
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError('no run of free ports')


class SyntaxTests(unittest.TestCase):
    def test_replay_compiles(self):
        with tempfile.TemporaryDirectory() as temp:
            py_compile.compile(str(PERF / 'replay.py'), cfile=os.path.join(temp, 'r.pyc'), doraise=True)

    @unittest.skipUnless(shutil.which('bash'), 'bash not installed')
    def test_bench_sh_parses(self):
        subprocess.run(['bash', '-n', str(PERF / 'bench.sh')], check=True)


class KeyTests(unittest.TestCase):
    def test_body_key_ignores_key_and_purl_order(self):
        a = json.dumps({'components': ['pkg:npm/a@1', 'pkg:npm/b@2'], 'x': 1}).encode()
        b = json.dumps({'x': 1, 'components': ['pkg:npm/b@2', 'pkg:npm/a@1']}).encode()
        self.assertEqual(replay.canon_body(a), replay.canon_body(b))
        self.assertNotEqual(replay.canon_body(a), replay.canon_body(b'not json'))
        self.assertEqual(replay.canon_body(b''), '')

    def test_endpoint_kinds(self):
        self.assertEqual(replay.endpoint_kind('POST', BATCH), 'POST batch')
        self.assertEqual(replay.endpoint_kind('POST', '/patch/batch'), 'POST batch')
        self.assertEqual(replay.endpoint_kind('GET', '/v0/orgs/acme/patches/by-package/pkg%3Anpm%2Fa'),
                         'GET by-package')
        self.assertEqual(replay.endpoint_kind('GET', '/v0/orgs/acme/patches/view/u-a?x=1'), 'GET view')
        self.assertEqual(replay.endpoint_kind('POST', '/v0/orgs/acme/patches/package'), 'POST package-vendor')
        self.assertEqual(replay.endpoint_kind('GET', '/v0/organizations'), 'GET organizations')


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store_dir = os.path.join(self.temp.name, 'store')
        self.servers = []
        Upstream.hits = []

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.temp.cleanup()

    def serve(self, port, upstream, c, store, stats):
        s = replay.make_server(port, upstream, c, store, stats)
        self.servers.append(s)
        return s

    def upstream(self):
        s = replay.Server(('127.0.0.1', 0), Upstream)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        self.servers.append(s)
        return f'http://127.0.0.1:{s.server_port}'

    def test_bind_skips_reverse_lookup(self):
        # HTTPServer.server_bind calls socket.getfqdn(), which stalls ~35 s
        # under the macOS sandbox; the harness must never reach it.
        with patch('socket.getfqdn', side_effect=AssertionError('getfqdn called')):
            s = replay.Server(('127.0.0.1', 0), replay.Handler)
        self.assertEqual(s.server_name, '127.0.0.1')
        self.assertEqual(s.server_port, s.socket.getsockname()[1])
        s.server_close()

    def test_record_then_replay_reassembles_batches_and_counts_misses(self):
        up = self.upstream()
        rec = self.serve(0, up, cfg('record'), replay.Store(self.store_dir), replay.Stats())
        status, data = request(rec.server_port, 'POST', BATCH,
                               batch_body('pkg:npm/a@1.0.0', 'pkg:npm/b@2.0.0'))
        self.assertEqual(status, 200)
        self.assertEqual(request(rec.server_port, 'POST', BATCH, batch_body('pkg:npm/c@3.0.0'))[0], 200)
        self.assertEqual(request(rec.server_port, 'GET', '/v0/orgs/acme/patches/by-package/x')[0], 200)
        self.assertEqual(len(Upstream.hits), 3)

        # A fresh Store reloads everything from disk; replay never goes upstream.
        stats = replay.Stats()
        rep = self.serve(0, up, cfg('replay'), replay.Store(self.store_dir), stats)
        # One chunk spanning both recorded batches, in a new order, plus a purl
        # never seen while recording.
        status, data = request(rep.server_port, 'POST', BATCH,
                               batch_body('pkg:npm/c@3.0.0', 'pkg:npm/z@9.9.9', 'pkg:npm/b@2.0.0',
                                          'pkg:npm/a@1.0.0'))
        self.assertEqual(status, 200)
        got = json.loads(data)
        self.assertEqual([p['purl'] for p in got['packages']], ['pkg:npm/c@3.0.0', 'pkg:npm/a@1.0.0'])
        self.assertTrue(got['canAccessPaidPatches'])
        status, data = request(rep.server_port, 'GET', '/v0/orgs/acme/patches/by-package/x')
        self.assertEqual((status, json.loads(data)), (200, {'path': '/v0/orgs/acme/patches/by-package/x'}))
        self.assertEqual(request(rep.server_port, 'GET', '/v0/orgs/acme/patches/view/nope')[0], 599)
        self.assertEqual(len(Upstream.hits), 3)

        snap = stats.snapshot()
        self.assertEqual(snap['requests'], 3)
        self.assertEqual(snap['misses'], 1)
        self.assertEqual(snap['batch_unknown_purls'], 1)
        self.assertEqual(snap['by_kind'], {'POST batch': 1, 'GET by-package': 1, 'GET view': 1})
        self.assertEqual(snap['by_status'], {'200': 2, '599': 1})

    def test_fill_forwards_and_records_a_miss(self):
        up = self.upstream()
        stats = replay.Stats()
        rep = self.serve(0, up, cfg('replay', fill=True), replay.Store(self.store_dir), stats)
        self.assertEqual(request(rep.server_port, 'GET', '/v0/orgs/acme/patches/view/u-a')[0], 200)
        self.assertEqual(request(rep.server_port, 'GET', '/v0/orgs/acme/patches/view/u-a')[0], 200)
        self.assertEqual(len(Upstream.hits), 1)
        self.assertEqual(stats.snapshot()['misses'], 1)

    def test_unreachable_upstream_is_502_and_not_stored(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            dead = s.getsockname()[1]
        store = replay.Store(self.store_dir)
        rec = self.serve(0, f'http://127.0.0.1:{dead}', cfg('record', upstream_timeout=5),
                         store, replay.Stats())
        with patch('sys.stderr', new_callable=io.StringIO) as err:
            status, _ = request(rec.server_port, 'GET', '/v0/orgs/acme/patches/view/u-a')
        self.assertEqual(status, 502)
        self.assertIn('UPSTREAM ERROR GET /v0/orgs/acme/patches/view/u-a', err.getvalue())
        self.assertEqual(store.entries, {})
        self.assertEqual(replay.Store(self.store_dir).entries, {})

    def test_latency_is_per_request_and_max_inflight_is_counted(self):
        up = self.upstream()
        rec = self.serve(0, up, cfg('record'), replay.Store(self.store_dir), replay.Stats())
        request(rec.server_port, 'GET', '/v0/orgs/acme/patches/view/u-a')
        stats = replay.Stats()
        rep = self.serve(0, up, cfg('replay', latency_ms=1000.0), replay.Store(self.store_dir), stats)
        t = time.time()
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            codes = list(pool.map(lambda _: request(rep.server_port, 'GET',
                                                    '/v0/orgs/acme/patches/view/u-a')[0], range(4)))
        self.assertEqual(codes, [200] * 4)
        self.assertGreaterEqual(time.time() - t, 1.0)
        snap = stats.snapshot()
        self.assertEqual(snap['max_inflight'], 4)
        self.assertEqual(snap['connections'], 4)
        self.assertGreater(snap['avg_parallelism'], 1.0)
        stats.reset()
        self.assertEqual(stats.snapshot()['requests'], 0)


@unittest.skipUnless(all(shutil.which(t) for t in ('bash', 'curl', 'perl', 'shasum')),
                     'bench.sh needs bash, curl, perl and shasum')
class BenchScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fake_cli(self, name, suffix=''):
        """A stand-in binary: one batch POST through SOCKET_API_URL, echoed."""
        p = self.root / name
        p.write_text(textwrap.dedent(f'''\
            #!/usr/bin/env bash
            curl -sf -X POST "$SOCKET_API_URL{BATCH}" \\
              -H 'Content-Type: application/json' \\
              -d '{{"components":[{{"purl":"pkg:npm/a@1.0.0"}}]}}'
            echo "{suffix}"
            echo "args: $*" >&2
        '''))
        p.chmod(0o755)
        return str(p)

    def bench(self, *args, **env):
        full = dict(os.environ, CWD=str(self.root), OUT=str(self.root / 'out'), **env)
        return subprocess.run(['bash', str(PERF / 'bench.sh'), *args], env=full,
                              capture_output=True, text=True, timeout=300)

    def test_refuses_a_store_inside_the_repository(self):
        inside = PERF.parents[1] / 'target' / 'perf-store-must-not-exist'
        r = self.bench('replay', str(inside), '--', 'scan', BIN=shutil.which('true'))
        try:
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn('refusing a STORE inside the repository', r.stderr)
            self.assertFalse(inside.exists(), 'a refused STORE must not be created')
        finally:
            shutil.rmtree(inside, ignore_errors=True)

    def test_refuses_a_busy_port_without_killing_its_listener(self):
        port = free_port_run(3)
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', port + 2))
            busy.listen()
            r = self.bench('replay', str(self.root / 'store'), '--', 'scan',
                           BIN=shutil.which('true'), PORT=str(port))
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn(f'port {port + 2} is already in use', r.stderr)
            # The other bench's listener is still there and still accepting.
            with socket.create_connection(('127.0.0.1', port + 2), timeout=5):
                pass
        self.assertFalse((self.root / 'out' / 'proxy.log').exists(),
                         'replay.py must not start when a port is refused')

    def test_patch_and_proxy_ports_can_be_set_explicitly(self):
        # Three distinct, typically non-consecutive ports: hold all three
        # sockets open while the OS picks them.
        socks = [socket.socket() for _ in range(3)]
        try:
            for s in socks:
                s.bind(('127.0.0.1', 0))
            port, patch_port, proxy_port = (s.getsockname()[1] for s in socks)
        finally:
            for s in socks:
                s.close()
        r = self.bench('replay', str(self.root / 'store'), '0', '1', '--', 'scan',
                       BIN=shutil.which('true'), PORT=str(port),
                       PATCH_PORT=str(patch_port), PROXY_PORT=str(proxy_port))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        log = (self.root / 'out' / 'proxy.log').read_text()
        for p in (port, patch_port, proxy_port):
            self.assertIn(f'127.0.0.1:{p}', log)

    def test_ab_checks_stdout_sha_against_the_first_base_run(self):
        # Seed the store with the batch the fake CLI sends (unit tests never
        # reach the real services).
        store = replay.Store(str(self.root / 'store'))
        req = json.dumps(batch_body('pkg:npm/a@1.0.0')).encode()
        resp = json.dumps({'packages': [KNOWN['pkg:npm/a@1.0.0']], 'canAccessPaidPatches': False}).encode()
        store.put_batch(req, resp)
        port = str(free_port_run(3))
        same = self.fake_cli('same')
        r = self.bench('ab', str(self.root / 'store'), '5', '2', '--', 'scan', '--json',
                       BASE=same, NEW=same, PORT=port,
                       PRE_RUN=f'echo reset >> {self.root / "pre-run.log"}')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.root / 'pre-run.log').read_text(), 'reset\n' * 4)
        self.assertIn('OK: every run', r.stdout)
        self.assertEqual(r.stdout.count('vs_base=same'), 3)
        self.assertIn('stderr: identical across runs', r.stdout)
        self.assertIn('max_inflight= 1', r.stdout)
        out = (self.root / 'out' / 'ab-5ms-1-base.stdout').read_text()
        self.assertIn('pkg:npm/a@1.0.0', out)
        self.assertEqual((self.root / 'out' / 'ab-5ms-1-base.stderr').read_text(),
                         f'args: scan --json --cwd {self.root}\n')

        r = self.bench('ab', str(self.root / 'store'), '0', '1', '--', 'scan',
                       BASE=same, NEW=self.fake_cli('changed', suffix='extra'), PORT=port)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('vs_base=DIFFERS', r.stdout)
        self.assertIn('FAIL: 1 run(s) differ', r.stderr)


if __name__ == '__main__':
    unittest.main()
