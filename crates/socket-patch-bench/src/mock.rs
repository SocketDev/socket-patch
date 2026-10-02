//! The local patch API every benchmark run talks to.
//!
//! One responder stands in for all three Socket hosts the CLI can reach
//! (`api.socket.dev`, the public proxy `patches-api.socket.dev`, and the
//! artifact host `patch.socket.dev`), each on its own port so connection
//! reuse behaves as it does against the real, separate hosts. Answers are
//! computed from the scenario's catalog, so a CLI that changes batch
//! sizes, chunking or request order still gets the same data.
//!
//! It is a deliberately small HTTP/1.1 server on std threads, one thread
//! per connection: the CLI's client speaks HTTP/1.1 only, so concurrent
//! requests arrive on concurrent connections, and a simulated latency
//! sleeps on each in parallel like a real network would. Nothing here
//! shares a runtime with the harness, so starting and stopping a server
//! cannot stall a run.
//!
//! Every request is classified and counted. A request the mock does not
//! recognize is answered `599` and recorded as unexpected, which fails the
//! run's validation: the benchmark must never silently measure an error
//! path because the CLI started calling something new.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{json, Value};

/// One patch the catalog serves.
#[derive(Debug, Clone)]
pub struct PatchSpec {
    /// The purl exactly as the CLI sends it in a batch request.
    pub purl: String,
    pub uuid: String,
    pub tier: &'static str,
    pub severity: &'static str,
    /// The `POST .../patches/package` result for this uuid
    /// (a `PackageVendorResult`).
    pub reference: Value,
    /// The `GET .../patches/view/<uuid>` body (a `PatchResponse`).
    pub view: Value,
}

#[derive(Debug, Default)]
pub struct Catalog {
    /// Batch answers (`BatchPatchInfo`) per purl.
    by_purl: HashMap<String, Vec<Value>>,
    /// Detail answers (`PatchSearchResult`) per purl.
    search: HashMap<String, Vec<Value>>,
    references: HashMap<String, Value>,
    views: HashMap<String, Value>,
    /// Raw bodies served by path on the artifact host (wheels, tarballs).
    files: HashMap<String, (Vec<u8>, &'static str)>,
    pub can_access_paid: bool,
}

impl Catalog {
    pub fn new(patches: &[PatchSpec], can_access_paid: bool) -> Self {
        let mut c = Catalog {
            can_access_paid,
            ..Default::default()
        };
        for (i, p) in patches.iter().enumerate() {
            let cve = format!("CVE-2024-{}", 10000 + i);
            let ghsa = format!("GHSA-bnch-{:04x}-{:04x}", i / 0x10000, i % 0x10000);
            c.by_purl.entry(p.purl.clone()).or_default().push(json!({
                "uuid": p.uuid,
                "purl": p.purl,
                "tier": p.tier,
                "cveIds": [cve],
                "ghsaIds": [ghsa],
                "severity": p.severity,
                "title": format!("Synthetic patch for {}", p.purl),
                "publishedAt": "2024-06-01T00:00:00Z",
            }));
            c.search.entry(p.purl.clone()).or_default().push(json!({
                "uuid": p.uuid,
                "purl": p.purl,
                "publishedAt": "2024-06-01T00:00:00Z",
                "description": format!("Synthetic patch for {}", p.purl),
                "license": "MIT",
                "tier": p.tier,
                "vulnerabilities": {
                    ghsa: {
                        "cves": [cve],
                        "summary": "synthetic vulnerability",
                        "severity": p.severity,
                        "description": "synthetic vulnerability",
                    }
                },
            }));
            c.references.insert(p.uuid.clone(), p.reference.clone());
            c.views.insert(p.uuid.clone(), p.view.clone());
        }
        c
    }

    pub fn serve_file(&mut self, path: &str, body: Vec<u8>, content_type: &'static str) {
        self.files.insert(path.to_string(), (body, content_type));
    }
}

/// Request counts for one run.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub by_kind: BTreeMap<String, u64>,
    pub unexpected: Vec<String>,
    /// Most requests being answered at once.
    pub max_inflight: usize,
    inflight: usize,
}

impl Stats {
    pub fn total(&self) -> u64 {
        self.by_kind.values().sum()
    }
}

/// The routes, in one place, so classification and answers cannot drift.
#[derive(Debug, PartialEq, Eq)]
enum Route<'a> {
    Batch,
    References,
    View(&'a str),
    ByPackage(&'a str),
    Organizations,
    File(&'a str),
}

fn route<'a>(method: &str, path: &'a str) -> Option<Route<'a>> {
    // Authenticated `/v0/orgs/<org>/patches/<x>` and proxy `/patch/<x>`.
    let rest = path
        .strip_prefix("/v0/orgs/")
        .and_then(|p| p.split_once("/patches/").map(|(_, r)| r))
        .or_else(|| path.strip_prefix("/patch/"));
    match (method, rest) {
        ("POST", Some("batch")) => Some(Route::Batch),
        ("POST", Some("package")) => Some(Route::References),
        ("GET", Some(r)) if r.starts_with("view/") => Some(Route::View(&r[5..])),
        ("GET", Some(r)) if r.starts_with("by-package/") => Some(Route::ByPackage(&r[11..])),
        ("GET", None) if path == "/v0/organizations" => Some(Route::Organizations),
        _ => None,
    }
}

impl Route<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Route::Batch => "batch",
            Route::References => "references",
            Route::View(_) => "view",
            Route::ByPackage(_) => "by-package",
            Route::Organizations => "organizations",
            Route::File(_) => "artifact",
        }
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(v: Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&v).unwrap(),
        }
    }
}

/// Answer one request from the catalog (`None`: not something the mock
/// serves).
fn answer(c: &Catalog, route: &Route<'_>, body: &[u8]) -> Option<Response> {
    Some(match route {
        Route::Batch => {
            let body: Value = serde_json::from_slice(body).ok()?;
            let mut packages = Vec::new();
            for comp in body["components"].as_array()? {
                let purl = comp["purl"].as_str()?;
                if let Some(patches) = c.by_purl.get(purl) {
                    packages.push(json!({ "purl": purl, "patches": patches }));
                }
            }
            Response::json(
                json!({ "packages": packages, "canAccessPaidPatches": c.can_access_paid }),
            )
        }
        Route::References => {
            let body: Value = serde_json::from_slice(body).ok()?;
            let mut results = serde_json::Map::new();
            for uuid in body["uuids"].as_array()? {
                let uuid = uuid.as_str()?;
                let r = c
                    .references
                    .get(uuid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "status": "not_found" }));
                results.insert(uuid.to_string(), r);
            }
            Response::json(json!({ "results": results }))
        }
        Route::View(uuid) => Response::json(c.views.get(*uuid)?.clone()),
        Route::ByPackage(encoded) => Response::json(json!({
            "patches": c.search.get(&percent_decode(encoded)).cloned().unwrap_or_default(),
            "canAccessPaidPatches": c.can_access_paid,
        })),
        Route::Organizations => Response::json(json!({
            "organizations": { "bench": {
                "id": "bench", "name": null, "image": null, "plan": "enterprise", "slug": crate::ORG,
            } }
        })),
        Route::File(path) => {
            let (body, ty) = c.files.get(*path)?;
            Response {
                status: 200,
                content_type: ty,
                body: body.clone(),
            }
        }
    })
}

struct Shared {
    catalog: RwLock<Catalog>,
    stats: Mutex<Stats>,
    delay: Duration,
    stop: AtomicBool,
}

/// One parsed request.
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    close: bool,
}

fn read_request(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad request line",
        ));
    };
    let (method, target) = (method.to_string(), target.to_string());
    let mut len = 0usize;
    let mut chunked = false;
    let mut close = false;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 {
            return Ok(None);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.parse().unwrap_or(0),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                "connection" => close = v.eq_ignore_ascii_case("close"),
                _ => {}
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            r.read_line(&mut size)?;
            let hex = size.trim().split(';').next().unwrap_or("0");
            let n = usize::from_str_radix(hex, 16).unwrap_or(0);
            let mut chunk = vec![0; n + 2];
            r.read_exact(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else if len > 0 {
        body.resize(len, 0);
        r.read_exact(&mut body)?;
    }
    // Only the path routes; a query string never selects another answer.
    let path = target.split('?').next().unwrap_or("").to_string();
    Ok(Some(Request {
        method,
        path,
        body,
        close,
    }))
}

fn respond(shared: &Shared, req: &Request) -> Response {
    let catalog = shared.catalog.read().unwrap();
    // Artifact paths share the proxy's `/patch/` prefix: a served file
    // wins over the API routes.
    let routed = if req.method == "GET" && catalog.files.contains_key(&req.path) {
        Some(Route::File(&req.path))
    } else {
        route(&req.method, &req.path)
    };
    let answered = routed.as_ref().and_then(|r| answer(&catalog, r, &req.body));
    let mut stats = shared.stats.lock().unwrap();
    match (routed, answered) {
        (Some(r), Some(resp)) => {
            *stats.by_kind.entry(r.kind().to_string()).or_default() += 1;
            resp
        }
        _ => {
            stats
                .unexpected
                .push(format!("{} {}", req.method, req.path));
            Response {
                status: 599,
                content_type: "text/plain",
                body: b"socket-patch-bench: unexpected request".to_vec(),
            }
        }
    }
}

fn serve_connection(stream: TcpStream, shared: Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    while let Ok(Some(req)) = read_request(&mut reader) {
        {
            let mut stats = shared.stats.lock().unwrap();
            stats.inflight += 1;
            stats.max_inflight = stats.max_inflight.max(stats.inflight);
        }
        let resp = respond(&shared, &req);
        if !shared.delay.is_zero() {
            std::thread::sleep(shared.delay);
        }
        let reason = if resp.status == 200 {
            "OK"
        } else {
            "Unexpected"
        };
        let head = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n",
            resp.status,
            resp.content_type,
            resp.body.len(),
            if req.close {
                "Connection: close\r\n"
            } else {
                ""
            }
        );
        let wrote = writer
            .write_all(head.as_bytes())
            .and_then(|_| writer.write_all(&resp.body))
            .and_then(|_| writer.flush());
        {
            let mut stats = shared.stats.lock().unwrap();
            stats.inflight = stats.inflight.saturating_sub(1);
        }
        if wrote.is_err() || req.close {
            return;
        }
    }
}

/// One listening host.
pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn uri(&self) -> String {
        format!("http://{}", self.addr)
    }
}

fn listen(shared: Arc<Shared>) -> std::io::Result<Server> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if shared.stop.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(stream) = stream {
                let shared = shared.clone();
                std::thread::spawn(move || serve_connection(stream, shared));
            }
        }
    });
    Ok(Server { addr })
}

/// The three stand-in hosts.
pub struct MockApi {
    pub api: Server,
    pub proxy: Server,
    pub patch: Server,
    shared: Arc<Shared>,
}

impl MockApi {
    /// Start the three hosts on an empty catalog (artifact URLs embed the
    /// artifact host's port, so the catalog is built after this and handed
    /// over with [`Self::set_catalog`]).
    pub fn start(delay: Duration) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            catalog: RwLock::new(Catalog::default()),
            stats: Mutex::new(Stats::default()),
            delay,
            stop: AtomicBool::new(false),
        });
        Ok(Self {
            api: listen(shared.clone())?,
            proxy: listen(shared.clone())?,
            patch: listen(shared.clone())?,
            shared,
        })
    }

    pub fn set_catalog(&self, catalog: Catalog) {
        *self.shared.catalog.write().unwrap() = catalog;
    }

    /// Take the counts since the last call.
    pub fn take_stats(&self) -> Stats {
        std::mem::take(&mut *self.shared.stats.lock().unwrap())
    }
}

impl Drop for MockApi {
    fn drop(&mut self) {
        // Wake each accept loop so its thread exits; connection threads end
        // when the (already exited) CLI's sockets read EOF.
        self.shared.stop.store(true, Ordering::Relaxed);
        for s in [&self.api, &self.proxy, &self.patch] {
            let _ = TcpStream::connect(s.addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_cover_authenticated_and_proxy_paths() {
        assert_eq!(
            route("POST", "/v0/orgs/acme/patches/batch"),
            Some(Route::Batch)
        );
        assert_eq!(route("POST", "/patch/batch"), Some(Route::Batch));
        assert_eq!(
            route("POST", "/v0/orgs/acme/patches/package"),
            Some(Route::References)
        );
        assert_eq!(route("GET", "/patch/view/abc"), Some(Route::View("abc")));
        assert_eq!(
            route("GET", "/v0/organizations"),
            Some(Route::Organizations)
        );
        assert_eq!(
            route(
                "GET",
                "/v0/orgs/acme/patches/by-package/pkg%3Anpm%2F%40s%2Fa%401.0.0"
            ),
            Some(Route::ByPackage("pkg%3Anpm%2F%40s%2Fa%401.0.0"))
        );
        assert_eq!(route("DELETE", "/patch/batch"), None);
        assert_eq!(route("GET", "/somewhere/else"), None);
    }

    #[test]
    fn percent_decoding_matches_the_cli_encoding() {
        assert_eq!(
            percent_decode("pkg%3Anpm%2F%40s%2Fa%401.0.0"),
            "pkg:npm/@s/a@1.0.0"
        );
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%2"), "a%2");
    }

    fn http(uri: &str, req: &str) -> String {
        let mut s = TcpStream::connect(uri.trim_start_matches("http://")).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn serves_every_route_and_counts_it() {
        let spec = PatchSpec {
            purl: "pkg:npm/@s/a@1.0.0".into(),
            uuid: "u-1".into(),
            tier: "free",
            severity: "high",
            reference: json!({ "status": "granted", "url": "x" }),
            view: json!({ "uuid": "u-1" }),
        };
        let mock = MockApi::start(Duration::ZERO).unwrap();
        let mut cat = Catalog::new(&[spec], false);
        cat.serve_file(
            "/patch/npm/a.tgz",
            b"bytes".to_vec(),
            "application/octet-stream",
        );
        mock.set_catalog(cat);

        let batch = r#"{"components":[{"purl":"pkg:npm/@s/a@1.0.0"},{"purl":"pkg:npm/b@1.0.0"}]}"#;
        let out = http(
            &mock.api.uri(),
            &format!(
                "POST /v0/orgs/o/patches/batch HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{batch}",
                batch.len()
            ),
        );
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(
            out.contains("\"uuid\":\"u-1\"") && !out.contains("pkg:npm/b@"),
            "{out}"
        );

        let out = http(
            &mock.proxy.uri(),
            "GET /patch/by-package/pkg%3Anpm%2F%40s%2Fa%401.0.0 HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert!(out.contains("\"vulnerabilities\""), "{out}");

        let refs = r#"{"uuids":["u-1","u-2"]}"#;
        let out = http(
            &mock.api.uri(),
            &format!(
                "POST /patch/package HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{refs}\r\n0\r\n\r\n",
                refs.len()
            ),
        );
        assert!(
            out.contains("\"granted\"") && out.contains("\"not_found\""),
            "{out}"
        );

        let out = http(
            &mock.patch.uri(),
            "GET /patch/npm/a.tgz HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert!(out.ends_with("bytes"), "{out}");

        let out = http(
            &mock.patch.uri(),
            "GET /nope HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 599"), "{out}");

        let stats = mock.take_stats();
        assert_eq!(stats.by_kind.get("batch"), Some(&1));
        assert_eq!(stats.by_kind.get("by-package"), Some(&1));
        assert_eq!(stats.by_kind.get("references"), Some(&1));
        assert_eq!(stats.by_kind.get("artifact"), Some(&1));
        assert_eq!(stats.unexpected, vec!["GET /nope".to_string()]);
        assert_eq!(mock.take_stats().total(), 0);
    }

    #[test]
    fn keep_alive_connections_serve_several_requests() {
        let mock = MockApi::start(Duration::ZERO).unwrap();
        mock.set_catalog(Catalog::default());
        let req = "GET /v0/organizations HTTP/1.1\r\n\r\n";
        let last = "GET /v0/organizations HTTP/1.1\r\nConnection: close\r\n\r\n";
        let out = http(&mock.api.uri(), &format!("{req}{req}{last}"));
        assert_eq!(out.matches("HTTP/1.1 200").count(), 3, "{out}");
        assert_eq!(mock.take_stats().by_kind.get("organizations"), Some(&3));
    }
}
