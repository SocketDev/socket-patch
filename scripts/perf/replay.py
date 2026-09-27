#!/usr/bin/env python3
"""Record/replay HTTP stand-in for deterministic socket-patch benchmarks.

Each `--route PORT=UPSTREAM` opens a plain-HTTP listener on 127.0.0.1:PORT
that stands in for UPSTREAM (e.g. https://api.socket.dev). Point the CLI at
it with SOCKET_API_URL / SOCKET_PROXY_URL / SOCKET_PATCH_SERVER_URL (see
scripts/perf/bench.sh, which does this for you).

Modes
  record   forward every request upstream, store the response, serve it.
  replay   serve from the store only; a miss is a 599 (or forwarded and
           recorded when --fill is given).

Batch endpoints (POST .../patches/batch, POST /patch/batch) are replayed
SEMANTICALLY: recorded responses are split into per-purl entries and any
requested purl set is re-assembled, so a CLI that changes batch size,
chunking or purl order still replays deterministically. Purls never seen
while recording are counted in stats (`batch_unknown_purls`) and answered
as "no patches".

Latency: `--latency-ms N` sleeps N ms before each response (simulated RTT,
per request; concurrent requests sleep in parallel like a real network);
`--latency recorded` replays each response's measured upstream time.
`--conn-latency-ms N` adds N ms once per new TCP connection (TLS+TCP
handshake stand-in), exposing missing connection reuse.

Stats (requests, max in-flight, connections, per-endpoint counts, bytes,
timeline) are served at GET /__stats, reset with POST /__reset, and written
to --stats-file on SIGINT/SIGTERM.

The store holds real API responses (possibly paid-patch data): keep it
outside the repository.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
import re
import signal
import socketserver
import sys
import threading
import time
import urllib.parse

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding",
}
BATCH_RE = re.compile(r"(/v0/orgs/[^/]+/patches/batch|/patch/batch)$")
# Response headers that vary per request and would only add noise to a store.
VOLATILE = {"set-cookie", "date", "cf-ray", "server"}


def canon_body(body: bytes) -> str:
    """Order-insensitive key for a request body: JSON objects are key-sorted
    and lists of strings are sorted, so reordered purls hit the same entry."""
    if not body:
        return ""
    try:
        v = json.loads(body)
    except Exception:
        return hashlib.sha256(body).hexdigest()

    def norm(x):
        if isinstance(x, dict):
            return {k: norm(x[k]) for k in sorted(x)}
        if isinstance(x, list):
            xs = [norm(i) for i in x]
            if all(isinstance(i, str) for i in xs):
                return sorted(xs)
            return xs
        return x

    return hashlib.sha256(json.dumps(norm(v), sort_keys=True).encode()).hexdigest()


def endpoint_kind(method, path):
    """Coarse endpoint label for the per-kind request counts."""
    p = urllib.parse.urlsplit(path).path
    if BATCH_RE.search(p):
        return f"{method} batch"
    m = re.search(r"/patch(?:es)?/(by-package|by-cve|by-ghsa|view|diff|blob|package)/", p)
    if m:
        return f"{method} {m.group(1)}"
    if p.endswith("/patches/package") or p.endswith("/patch/package"):
        return f"{method} package-vendor"
    if "/organizations" in p:
        return f"{method} organizations"
    return f"{method} {'/'.join(p.split('/')[:4])}"


class Store:
    """entries.jsonl (one line per recorded exchange, last write wins),
    bodies/<sha256> (content-addressed response bodies) and
    batch_index.json (purl -> batch package entry, or null for "no patches")."""

    def __init__(self, root):
        self.root = root
        os.makedirs(os.path.join(root, "bodies"), exist_ok=True)
        self.lock = threading.Lock()
        self.entries = {}  # key -> entry
        self.batch = {}    # purl -> package entry (with patches) or None
        self.paid = False
        self._load()

    def _load(self):
        p = os.path.join(self.root, "entries.jsonl")
        if os.path.exists(p):
            with open(p) as f:
                for line in f:
                    if line.strip():
                        e = json.loads(line)
                        self.entries[e["key"]] = e
        b = os.path.join(self.root, "batch_index.json")
        if os.path.exists(b):
            with open(b) as f:
                d = json.load(f)
            self.batch = d["purls"]
            self.paid = d["canAccessPaidPatches"]

    def body(self, e):
        with open(os.path.join(self.root, "bodies", e["body"]), "rb") as f:
            return f.read()

    def put(self, key, method, path, status, headers, body, upstream_ms):
        sha = hashlib.sha256(body).hexdigest()
        bp = os.path.join(self.root, "bodies", sha)
        if not os.path.exists(bp):
            with open(bp, "wb") as f:
                f.write(body)
        e = {"key": key, "method": method, "path": path, "status": status,
             "headers": headers, "body": sha, "upstream_ms": upstream_ms}
        with self.lock:
            self.entries[key] = e
            with open(os.path.join(self.root, "entries.jsonl"), "a") as f:
                f.write(json.dumps(e) + "\n")
        return e

    def put_batch(self, req_body, resp_body):
        try:
            purls = [c["purl"] for c in json.loads(req_body)["components"]]
            resp = json.loads(resp_body)
        except Exception:
            return
        with self.lock:
            for p in purls:
                self.batch.setdefault(p, None)
            for pkg in resp.get("packages", []):
                self.batch[pkg["purl"]] = pkg
            self.paid = self.paid or bool(resp.get("canAccessPaidPatches"))
            with open(os.path.join(self.root, "batch_index.json"), "w") as f:
                json.dump({"purls": self.batch, "canAccessPaidPatches": self.paid}, f)

    def synth_batch(self, req_body):
        """Re-assemble a batch response for any purl set, in request order.
        Returns (body, number of purls never seen while recording)."""
        purls = [c["purl"] for c in json.loads(req_body)["components"]]
        pkgs, unknown = [], 0
        for p in purls:
            if p not in self.batch:
                unknown += 1
            elif self.batch[p] is not None:
                pkgs.append(self.batch[p])
        body = json.dumps({"packages": pkgs, "canAccessPaidPatches": self.paid}).encode()
        return body, unknown


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.t0 = time.time()
            self.requests = 0
            self.inflight = 0
            self.max_inflight = 0
            self.connections = 0
            self.max_open_connections = 0
            self.open_connections = 0
            self.by_kind = {}
            self.by_status = {}
            self.bytes_out = 0
            self.bytes_in = 0
            self.misses = 0
            self.batch_unknown_purls = 0
            self.timeline = []  # [start_s, end_s, kind, status]

    def snapshot(self):
        with self.lock:
            tl = self.timeline
            span = (max(e[1] for e in tl) - min(e[0] for e in tl)) if tl else 0.0
            busy = sum(e[1] - e[0] for e in tl)
            return {
                "requests": self.requests, "max_inflight": self.max_inflight,
                "connections": self.connections,
                "max_open_connections": self.max_open_connections,
                "by_kind": dict(self.by_kind), "by_status": dict(self.by_status),
                "bytes_out": self.bytes_out, "bytes_in": self.bytes_in,
                "misses": self.misses,
                "batch_unknown_purls": self.batch_unknown_purls,
                "first_request_s": round(min(e[0] for e in tl), 3) if tl else None,
                "last_response_s": round(max(e[1] for e in tl), 3) if tl else None,
                "network_span_s": round(span, 3),
                "summed_request_s": round(busy, 3),
                "avg_parallelism": round(busy / span, 2) if span else 0.0,
                "timeline": [[round(a, 4), round(b, 4), k, s] for a, b, k, s in tl],
            }


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "replay/1"

    def log_message(self, fmt, *args):
        if self.server.cfg.verbose:
            sys.stderr.write("[%d] %s\n" % (self.server.server_port, fmt % args))

    def setup(self):
        super().setup()
        st = self.server.stats
        with st.lock:
            st.connections += 1
            st.open_connections += 1
            st.max_open_connections = max(st.max_open_connections, st.open_connections)
        if self.server.cfg.conn_latency_ms:
            time.sleep(self.server.cfg.conn_latency_ms / 1000.0)

    def finish(self):
        try:
            super().finish()
        finally:
            # One handler thread per client connection: its upstream
            # keep-alive connections end with it.
            for conn in self.server.tls.__dict__.pop("conns", {}).values():
                conn.close()
            st = self.server.stats
            with st.lock:
                st.open_connections -= 1

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            out = b""
            while True:
                n = int(self.rfile.readline().strip().split(b";")[0], 16)
                if n == 0:
                    self.rfile.readline()
                    return out
                out += self.rfile.read(n)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, status, headers, body):
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() not in HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _control(self):
        st = self.server.stats
        if self.path.startswith("/__stats"):
            body = json.dumps(st.snapshot(), indent=1).encode()
            self._send(200, {"Content-Type": "application/json"}, body)
        elif self.path.startswith("/__reset"):
            st.reset()
            self._send(200, {}, b"ok")
        else:
            self._send(404, {}, b"")

    def _upstream(self, method, body):
        """Forward to the upstream over a per-thread keep-alive connection,
        retrying once on a dropped connection."""
        cfg = self.server.cfg
        up = urllib.parse.urlsplit(self.server.upstream)
        conns = self.server.tls.__dict__.setdefault("conns", {})
        conn = conns.get(up.netloc)
        for attempt in range(2):
            if conn is None:
                cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
                conn = cls(up.netloc, timeout=cfg.upstream_timeout)
                conns[up.netloc] = conn
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            hdrs["Accept-Encoding"] = "identity"
            try:
                t = time.time()
                conn.request(method, up.path.rstrip("/") + self.path, body=body or None, headers=hdrs)
                r = conn.getresponse()
                data = r.read()
                ms = (time.time() - t) * 1000
                rh = {k: v for k, v in r.getheaders()
                      if k.lower() not in HOP and k.lower() not in VOLATILE}
                return r.status, rh, data, ms
            except (http.client.HTTPException, OSError):
                conn.close()
                conn = None
                conns.pop(up.netloc, None)
                if attempt:
                    raise

    def _forward_and_store(self, key, method, body):
        """Record one exchange. An unreachable upstream is answered with a
        502 and NOT stored, so a flaky record run never poisons the store."""
        try:
            status, headers, data, upstream_ms = self._upstream(method, body)
        except (http.client.HTTPException, OSError) as e:
            sys.stderr.write(f"UPSTREAM ERROR {method} {self.path}: {e}\n")
            return 502, {"Content-Type": "text/plain"}, f"replay upstream error: {e}".encode(), 0.0, False
        self.server.store.put(key, method, self.path, status, headers, data, upstream_ms)
        return status, headers, data, upstream_ms, True

    def _handle(self):
        if self.path.startswith("/__"):
            return self._control()
        cfg, st, store = self.server.cfg, self.server.stats, self.server.store
        method = self.command
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else b""
        kind = endpoint_kind(method, self.path)
        with st.lock:
            st.requests += 1
            st.inflight += 1
            st.max_inflight = max(st.max_inflight, st.inflight)
            st.bytes_in += len(body)
        t0 = time.time()
        status = 599
        try:
            key = f"{self.server.upstream} {method} {self.path} {canon_body(body)}"
            is_batch = method == "POST" and BATCH_RE.search(urllib.parse.urlsplit(self.path).path)
            upstream_ms = 0.0
            if cfg.mode == "record":
                status, headers, data, upstream_ms, stored = self._forward_and_store(key, method, body)
                if stored and is_batch and status == 200:
                    store.put_batch(body, data)
            elif is_batch and store.batch:
                data, unknown = store.synth_batch(body)
                status, headers = 200, {"Content-Type": "application/json"}
                with st.lock:
                    st.batch_unknown_purls += unknown
                e = store.entries.get(key)
                upstream_ms = e["upstream_ms"] if e else cfg.default_recorded_ms
            else:
                e = store.entries.get(key)
                if e is None:
                    with st.lock:
                        st.misses += 1
                    if cfg.verbose:
                        sys.stderr.write(f"MISS {key}\n")
                if e is None and cfg.fill:
                    status, headers, data, upstream_ms, _ = self._forward_and_store(key, method, body)
                elif e is None:
                    status, headers, data = 599, {"Content-Type": "text/plain"}, b"replay miss"
                else:
                    status, headers, data, upstream_ms = e["status"], e["headers"], store.body(e), e["upstream_ms"]
            if cfg.mode == "replay":
                delay = upstream_ms / 1000.0 if cfg.latency == "recorded" else cfg.latency_ms / 1000.0
                if delay > 0:
                    time.sleep(delay)
            self._send(status, headers, data)
            with st.lock:
                st.bytes_out += len(data)
        finally:
            t1 = time.time()
            with st.lock:
                st.inflight -= 1
                st.by_kind[kind] = st.by_kind.get(kind, 0) + 1
                st.by_status[str(status)] = st.by_status.get(str(status), 0) + 1
                st.timeline.append([t0 - st.t0, t1 - st.t0, kind, status])

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_PATCH = _handle


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def server_bind(self):
        # Skip HTTPServer.server_bind's socket.getfqdn(): under the macOS
        # sandbox the reverse lookup stalls ~35 s before the port is usable.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def make_server(port, upstream, cfg, store, stats):
    """Bind one route (port 0 picks a free port) and serve it on a daemon
    thread. Every route shares one store and one stats object."""
    s = Server(("127.0.0.1", int(port)), Handler)
    s.cfg, s.store, s.stats = cfg, store, stats
    s.upstream, s.tls = upstream.rstrip("/"), threading.local()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["record", "replay"])
    ap.add_argument("--store", required=True)
    ap.add_argument("--route", action="append", required=True, help="PORT=UPSTREAM_URL")
    ap.add_argument("--latency-ms", type=float, default=0.0)
    ap.add_argument("--latency", choices=["fixed", "recorded"], default="fixed")
    ap.add_argument("--default-recorded-ms", type=float, default=100.0,
                    help="recorded latency for a synthesized batch with no exact entry")
    ap.add_argument("--conn-latency-ms", type=float, default=0.0)
    ap.add_argument("--fill", action="store_true", help="replay: forward+record misses")
    ap.add_argument("--stats-file")
    ap.add_argument("--upstream-timeout", type=float, default=120.0)
    ap.add_argument("--verbose", action="store_true")
    return ap.parse_args(argv)


def main():
    cfg = parse_args()
    store, stats = Store(cfg.store), Stats()
    for r in cfg.route:
        port, upstream = r.split("=", 1)
        s = make_server(port, upstream, cfg, store, stats)
        # bench.sh waits for this line before starting the CLI.
        sys.stderr.write(f"replay.py {cfg.mode}: http://127.0.0.1:{s.server_port} -> {upstream}\n")
    sys.stderr.flush()

    done = threading.Event()

    def stop(*_):
        done.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    done.wait()
    if cfg.stats_file:
        with open(cfg.stats_file, "w") as f:
            json.dump(stats.snapshot(), f, indent=1)
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
