//! The loopback HTTP server that stands in for every host a fixture
//! fetches from.
//!
//! The downloader config of `fixtures/bazel/common/downloader.cfg.tmpl`
//! rewrites `https://<host>/<path>` to `http://127.0.0.1:<port>/<host>/<path>`,
//! so one server plays every registry and the committed locks keep their
//! production URLs. A URL with nothing registered is answered 404 at once:
//! a rewrite to a closed port instead costs Bazel 12 to 79 seconds of
//! retries per miss. The request log is the `hosts` field of a cell report
//! and what the offline and withdrawal assertions read.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// The origin the fake Socket API advertises for every patched artifact
/// Bazel's downloader fetches. Whatever socket-patch then writes is
/// production-shaped and reaches this server through the rewrite. A
/// loopback `http` URL must never reach a file the downloader reads or
/// records: without a checksum it is refused on 5.4.1 to 9.3.2, and a
/// port recorded in `MODULE.bazel.lock` facts fails the next run.
pub const HOSTED_ORIGIN: &str = "https://patch.socket.dev";

/// What the server answers for one URL.
#[derive(Clone, Debug)]
enum Route {
    Body(Vec<u8>),
    /// A bare status: 403, 404 or 410 for a withdrawal twin.
    Status(u16),
}

/// One request the server received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// `<host>/<path>`: the original URL without its scheme.
    pub url: String,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    pub status: u16,
}

#[derive(Default)]
struct State {
    routes: Mutex<BTreeMap<String, Route>>,
    log: Mutex<Vec<Request>>,
}

pub struct FixtureServer {
    port: u16,
    state: Arc<State>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl FixtureServer {
    /// Listen on a free loopback port with an empty store.
    pub fn start() -> FixtureServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the fixture server");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State::default());
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let (state, stop) = (state.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    // One thread per connection: a ruleset tool may open
                    // hundreds at once, and a refused one fails its fetch.
                    let state = state.clone();
                    std::thread::spawn(move || serve_connection(stream, &state));
                }
            })
        };
        FixtureServer {
            port,
            state,
            stop,
            accept: Some(accept),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// `http://127.0.0.1:<port>`: the origin a fake Socket API hands out
    /// for a fetch path that does not go through Bazel's downloader (pip
    /// mode, cargo under crate_universe, the legacy package managers).
    /// Everything the downloader fetches is advertised under
    /// [`HOSTED_ORIGIN`] instead.
    pub fn loopback_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Serve `bytes` for `url`, written as the lock writes it
    /// (`https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz`).
    pub fn serve(&self, url: &str, bytes: impl Into<Vec<u8>>) {
        self.route(url, Route::Body(bytes.into()));
    }

    /// Answer `url` with a bare `status`.
    pub fn serve_status(&self, url: &str, status: u16) {
        self.route(url, Route::Status(status));
    }

    fn route(&self, url: &str, route: Route) {
        self.state.routes.lock().unwrap().insert(key(url), route);
    }

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.state.log.lock().unwrap().clone()
    }

    /// The hosts asked for, sorted and unique: a report's `hosts` field.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .requests()
            .iter()
            .map(|r| r.url.split('/').next().unwrap_or_default().to_string())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// The requests for `url`.
    pub fn requests_for(&self, url: &str) -> Vec<Request> {
        let key = key(url);
        let all = self.requests();
        all.into_iter().filter(|r| r.url == key).collect()
    }

    /// At least one request arrived. Every assertion about what the host
    /// did *not* receive starts here: with a warm repository cache Bazel
    /// sends nothing at all, and "no request with a credential" would
    /// pass without having tested anything.
    pub fn assert_reached(&self, what: &str) {
        assert!(
            !self.requests().is_empty(),
            "{what}: the fixture server received no request, so this run proves nothing \
             about what Bazel sends (is the repository cache warm?)"
        );
    }

    /// `url` was not asked for, by a run that did reach the server. The
    /// offline assertion: "no request for the package's own URL".
    pub fn assert_not_requested(&self, url: &str, what: &str) {
        self.assert_reached(what);
        let hits = self.requests_for(url);
        assert!(hits.is_empty(), "{what}: {url} was requested: {hits:?}");
    }

    /// No request carried the header `name` (any case), on a run that did
    /// reach the server: no `Authorization` leaves the machine.
    pub fn assert_no_header(&self, name: &str, what: &str) {
        self.assert_reached(what);
        let name = name.to_ascii_lowercase();
        let with: Vec<String> = self
            .requests()
            .into_iter()
            .filter(|r| r.headers.iter().any(|(n, _)| *n == name))
            .map(|r| r.url)
            .collect();
        assert!(
            with.is_empty(),
            "{what}: requests carried `{name}`: {with:?}"
        );
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

/// `https://host/path?q`, `host/path?q` and the request target
/// `/host/path?q` all name the route `host/path?q`. Only a leading scheme
/// is dropped: a query string may hold a URL of its own.
fn key(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.unwrap_or(url).trim_start_matches('/').to_string()
}

/// Answer one request and close: Bazel's downloader and the package
/// managers all cope with `Connection: close`, and it keeps the server free
/// of per-connection state.
fn serve_connection(mut stream: TcpStream, state: &State) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(n) if n > 0 && head.len() < 64 * 1024 => head.extend_from_slice(&buf[..n]),
            // Closed, timed out, or an oversized head: nothing to answer.
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_string();
    let url = key(request_line.next().unwrap_or_default());
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let route = state.routes.lock().unwrap().get(&url).cloned();
    let (status, body) = match (method.as_str(), route) {
        ("GET" | "HEAD", Some(Route::Body(body))) => (200, body),
        ("GET" | "HEAD", Some(Route::Status(status))) => (status, Vec::new()),
        ("GET" | "HEAD", None) => (404, Vec::new()),
        _ => (405, Vec::new()),
    };
    state.log.lock().unwrap().push(Request {
        method: method.clone(),
        url,
        headers,
        status,
    });
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    if method != "HEAD" {
        let _ = stream.write_all(&body);
    }
    let _ = stream.flush();
}
