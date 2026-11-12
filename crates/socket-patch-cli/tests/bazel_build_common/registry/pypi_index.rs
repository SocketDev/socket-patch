//! Emulation of `pypi.org/simple`: one PEP 503 page per project of a
//! [`pypi_files`](super::pypi_files) tree, in two flavours that must not
//! be mixed.
//!
//! - [`mount`] is for everything Bazel's downloader fetches (rules_python
//!   2.x, also without `experimental_index_url`). The page sits at the
//!   production URL and its links are production URLs; the downloader
//!   rewrite brings each request here. Nothing on this path is
//!   body-rewritten: rules_python stores the link it read in
//!   `MODULE.bazel.lock` facts, and a link with this server's port failed
//!   the next run after 79 seconds.
//! - [`mount_pip_mode`] is for pip (rules_python <= 1.2.x and every
//!   WORKSPACE `pip_parse`). pip runs `--isolated` and fetches by itself,
//!   so no rewrite reaches it: its index sits under a prefix of its own
//!   and links back to this server. Such a fixture commits `extra_pip_args
//!   = ["--index-url", ...]`; `--repo_env=PIP_INDEX_URL=` alone leaks to
//!   pypi.org.
//!
//! rules_python >= 2.0 also asks the index for the about 31 packages of
//! its own `rules_python_publish_deps` hub on every evaluation of the
//! `pip` extension. Those pages are not emulated: a cell rewrites only the
//! URLs [`mount`] returns and leaves the rest of `pypi.org` on its
//! allowlist (DESIGN 9.3, the downloader row).

use super::super::fixture_server::FixtureServer;
use super::pypi_files::Distribution;

pub const HOST: &str = "pypi.org";

/// The route prefix of the pip-mode index: `<loopback origin>/<this>/<project>/`.
pub const PIP_MODE_PREFIX: &str = "pip-mode/simple";

/// pip accepts an index page only under an HTML or PEP 691 media type.
const HTML: &str = "text/html";

/// The PEP 503 page of `project`: one anchor per distribution, with the
/// digest as the URL fragment and `href` choosing the link.
pub fn page(
    project: &str,
    distributions: &[Distribution],
    href: &dyn Fn(&Distribution) -> String,
) -> String {
    let mut html = format!(
        "<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" \
         content=\"1.0\">\n    <title>Links for {project}</title>\n  </head>\n  <body>\n    \
         <h1>Links for {project}</h1>\n"
    );
    for d in distributions.iter().filter(|d| d.project == project) {
        html.push_str(&format!(
            "    <a href=\"{}#sha256={}\">{}</a><br />\n",
            href(d),
            d.sha256,
            d.file
        ));
    }
    html.push_str("  </body>\n</html>\n");
    html
}

/// The projects of `distributions`, sorted and unique.
fn projects(distributions: &[Distribution]) -> Vec<&str> {
    let mut names: Vec<&str> = distributions.iter().map(|d| d.project.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Serve the page of every project at `base/<project>/` and, for a client
/// that drops the slash, `base/<project>`. Returns the URLs served.
fn serve_pages(
    server: &FixtureServer,
    base: &str,
    distributions: &[Distribution],
    href: &dyn Fn(&Distribution) -> String,
) -> Vec<String> {
    let mut urls = Vec::new();
    for project in projects(distributions) {
        let html = page(project, distributions, href);
        for url in [format!("{base}/{project}/"), format!("{base}/{project}")] {
            server.serve_as(&url, HTML, html.clone());
            urls.push(url);
        }
    }
    urls
}

/// The downloader flavour: `https://pypi.org/simple/<project>/` with
/// production links. Returns the URLs served, for a narrow rewrite.
pub fn mount(server: &FixtureServer, distributions: &[Distribution]) -> Vec<String> {
    let base = format!("https://{HOST}/simple");
    serve_pages(server, &base, distributions, &Distribution::url)
}

/// The pip flavour. Returns the `--index-url` value: a loopback URL, which
/// may be written into a workspace copy and never into a committed file or
/// anything Bazel's downloader reads.
pub fn mount_pip_mode(server: &FixtureServer, distributions: &[Distribution]) -> String {
    let origin = server.loopback_origin();
    let loopback = |d: &Distribution| d.url().replacen("https://", &format!("{origin}/"), 1);
    // The route is the path alone: pip asks this server directly, with no
    // host segment in front as a rewritten request has.
    serve_pages(server, PIP_MODE_PREFIX, distributions, &loopback);
    format!("{origin}/{PIP_MODE_PREFIX}")
}

#[test]
fn the_downloader_index_keeps_production_links_and_the_pip_index_links_back() {
    use super::pypi_files::{self, fetch};

    let wheel = |file: &str| Distribution::new(file, file.as_bytes().to_vec()).unwrap();
    let tree = [
        wheel("spdep-2.0.0-py3-none-any.whl"),
        wheel("spvictim-1.0.0-py3-none-any.whl"),
        wheel("spvictim-1.0.0.tar.gz"),
    ];
    let server = FixtureServer::start();
    pypi_files::mount(&server, &tree);
    let served = mount(&server, &tree);
    assert_eq!(
        served,
        [
            "https://pypi.org/simple/spdep/",
            "https://pypi.org/simple/spdep",
            "https://pypi.org/simple/spvictim/",
            "https://pypi.org/simple/spvictim",
        ]
    );
    let text = |url: &str| {
        let (status, body) = fetch(&server, url);
        assert_eq!(status, 200, "{url}");
        String::from_utf8(body).unwrap()
    };
    let port = format!(":{}", server.port());

    let production = text("https://pypi.org/simple/spvictim/");
    assert_eq!(production, text("https://pypi.org/simple/spvictim"));
    // Both files of the project, no file of another, and no trace of this
    // server: the downloader records what it read.
    for d in &tree[1..] {
        let anchor = format!("<a href=\"{}#sha256={}\">{}</a>", d.url(), d.sha256, d.file);
        assert!(
            production.contains(&anchor),
            "{anchor} not in:\n{production}"
        );
    }
    assert!(!production.contains("spdep"), "{production}");
    assert!(
        !production.contains("127.0.0.1") && !production.contains(&port),
        "{production}"
    );

    let index = mount_pip_mode(&server, &tree);
    assert_eq!(
        index,
        format!("{}/pip-mode/simple", server.loopback_origin())
    );
    let pip = text(&format!("{index}/spvictim/"));
    // Every link is one pip can fetch from this server, digest included.
    let links: Vec<&str> = pip
        .split("href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap())
        .collect();
    assert_eq!(links.len(), 2, "{pip}");
    for (link, d) in links.iter().zip(&tree[1..]) {
        let (url, digest) = link.split_once("#sha256=").unwrap();
        assert!(url.starts_with(&server.loopback_origin()), "{link}");
        assert_eq!(digest, d.sha256);
        assert_eq!(fetch(&server, url), (200, d.bytes.clone()));
    }
    // An unknown project is a miss, on both flavours.
    assert_eq!(fetch(&server, "https://pypi.org/simple/requests/").0, 404);
    assert_eq!(fetch(&server, &format!("{index}/requests/")).0, 404);
}
