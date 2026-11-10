//! Socket origin: whether a string a lockfile or package-manager config
//! records routes a package to a Socket patch, and to which one.
//!
//! The goal is one classifier that every reader applies. Today discovery and
//! the redirect's hosted unwind apply it, but some readers still classify
//! on their own: the lock inventory's PyPI view
//! (`vendor::lock_inventory::pypi::hosted_pypi_reference`) adds its own
//! url-tail grammar, discovery's PyPI diagnostics (`vex::discover::pypi_other`)
//! compare hosts directly, the upstream restore keeps its own known-origin
//! list, and the inventory matches hosted urls on any host. The lock-model
//! stack moves them here (`docs/design/lock-model-unification.md`).
//!
//! * **hosted** — [`hosted_patch_uuid`]: an `http(s)` url on Socket's patch
//!   server or on an operator-configured origin, under a path the server
//!   serves patches from, the patch uuid its last canonical-uuid path
//!   segment. `OriginPolicy::hosted_uuid` answers the
//!   same question with a memoized fast path for the plain registry urls
//!   every lock is full of;
//! * **vendored** — [`vendor_ref`] / [`vendor_ref_decorated`] /
//!   [`vendor_uuid_dir`]: a path that STARTS at this project's
//!   `.socket/vendor/<eco>/<uuid>/`, its leaf traversal-safe;
//! * **names** — `socket_patch_name_uuid`: the `socket-patch-<uuid>`
//!   registry, repository and source names.
//!
//! `OriginPolicy::locate` computes the hosted and vendored answers for one
//! string at once.
//!
//! The format models ([`crate::formats`]) stay pure: they hand out the raw
//! location strings and never apply the host policy (their architecture
//! test bans it). The readers that apply a model to a project apply this
//! module. See `docs/design/lock-model-unification.md`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment};
use crate::utils::purl_key::canonical_base_purl;
use crate::vendor::path::{leaf_to_purl, ECOSYSTEM_DIRS, VENDOR_DIR};

// ── hosted urls ──────────────────────────────────────────────────────────

/// Public host of Socket's patch server: the origin every production hosted
/// artifact / registry URL is served from (`https://patch.socket.dev/patch/…`,
/// `…/patch-registry/…`), and the root of the Go module namespace
/// [`crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX`].
pub const SOCKET_PATCH_SERVER_HOST: &str = "patch.socket.dev";

/// The Socket patch uuid a lockfile-recorded HOSTED reference names, or
/// `None` when `url` is not a Socket-hosted patch URL — the inverse of the
/// rewriters, used by `vex`'s manifest-less lockfile discovery.
///
/// Recognition is deliberately strict, because the answer decides whether a
/// committed (tamper-able) lockfile line becomes an attestation input:
///
/// * the ORIGIN must be Socket's patch server (`https://` +
///   [`SOCKET_PATCH_SERVER_HOST`]) or one of `extra_origins` — the
///   operator's `--patch-server-url` deployment, compared on scheme + host +
///   port. A uuid inside any other host's URL is a user's own dependency
///   source, never a patch reference;
/// * no userinfo — a Socket-written URL never carries credentials;
/// * no backslash, whitespace or control character: url parsers disagree
///   about them (the WHATWG parser this reads with takes `\` for `/` and
///   drops tabs and newlines; libcurl and PHP read
///   `https://patch.socket.dev\@evil.example/…` as host `evil.example`), so
///   the host such a url names depends on the client that fetches it;
/// * the path is one the patch server serves a patch under
///   ([`served_tail`]): `patch/<eco>/…`, `patch-registry/<eco>/…` or
///   `gopatch/…`, with no percent-encoded `/` or `\`, which a server may
///   decode into a path that leaves the patch;
/// * the uuid is the LAST segment of that path passing the canonical-uuid
///   grammar: hosted URLs carry the grant token in the level before the
///   uuid (`…/patch/npm/<name>/<ver>/<token>/<uuid>/<leaf>`,
///   `…/patch-registry/<eco>/<token>/<uuid>/…`), and grant tokens may
///   themselves be uuid-shaped, so "the first uuid" would elect the token.
///
/// Every spelling the lock formats record the same URL in is accepted: a
/// `#fragment` (yarn classic `#<sha1>`, pip `#sha256=`) and a `?query` are
/// ignored; `\/`-escaped slashes (older composer locks) are unescaped; a
/// wholly percent-encoded URL (yarn berry's `__archiveUrl=` binding) is
/// decoded; a cargo source-kind prefix (`sparse+`, `registry+`) is dropped;
/// surrounding whitespace is trimmed. Path segments are percent-decoded
/// AFTER splitting, so an encoded `/` can never manufacture a segment.
pub fn hosted_patch_uuid(url: &str, extra_origins: &[String]) -> Option<String> {
    use crate::utils::purl::percent_decode_purl_component;

    let (parsed, socket_host) = accepted_hosted_url(url, extra_origins)?;
    let path = parsed.path().to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return None;
    }
    let segments: Vec<&str> = parsed.path_segments()?.collect();
    served_tail(&segments, !socket_host)?
        .iter()
        .rev()
        .map(|segment| percent_decode_purl_component(segment).into_owned())
        .find(|segment| is_canonical_uuid(segment))
}

/// The path levels under which the patch server serves a patch's artifacts
/// and registry indexes, each followed by the ecosystem.
const SERVE_ROOTS: [&str; 2] = ["patch", "patch-registry"];

/// The root of the Go module namespace, followed by the patch uuid
/// ([`crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX`]).
const GO_SERVE_ROOT: &str = "gopatch";

/// The path segments below the level a patch is served under —
/// `patch/<eco>/`, `patch-registry/<eco>/` (`<eco>` one of
/// [`ECOSYSTEM_DIRS`]) or `gopatch/` — or `None` when the path has no such
/// level: any other path of the host (another endpoint, a uuid that merely
/// appears in it) names no patch. Socket's own server serves these levels
/// first in the path; an operator's deployment may sit under a path prefix
/// (`prefixed`), where the first such level counts.
fn served_tail<'a>(segments: &'a [&'a str], prefixed: bool) -> Option<&'a [&'a str]> {
    let tail_at = |i: usize| {
        let root = *segments.get(i)?;
        if root == GO_SERVE_ROOT {
            Some(i + 1)
        } else if SERVE_ROOTS.contains(&root) && ECOSYSTEM_DIRS.contains(segments.get(i + 1)?) {
            Some(i + 2)
        } else {
            None
        }
    };
    let start = if prefixed {
        (0..segments.len()).find_map(tail_at)?
    } else {
        tail_at(0)?
    };
    segments.get(start..)
}

/// `url` normalized the way [`hosted_patch_url_uuids`] reads it: `\/`
/// unescaped, a percent-encoded `http(s)://` url decoded, and a Cargo
/// `sparse+` / `registry+` source prefix stripped. `None` without a
/// `://`, and for a url holding a backslash, whitespace or a control
/// character once normalized: no two url parsers read those alike (see
/// [`hosted_patch_uuid`]), so the url is refused before any parser sees it.
fn normalized_hosted_url(url: &str) -> Option<String> {
    use crate::utils::purl::percent_decode_purl_component;

    let unescaped = url.trim().replace("\\/", "/");
    let lower = unescaped.to_ascii_lowercase();
    let decoded = if lower.starts_with("https%3a%2f%2f") || lower.starts_with("http%3a%2f%2f") {
        percent_decode_purl_component(&unescaped).into_owned()
    } else {
        unescaped
    };
    if decoded
        .chars()
        .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    // `sparse+https://…` / `registry+https://…` (Cargo.lock `source`).
    let (scheme, _) = decoded.split_once("://")?;
    Some(match scheme.rsplit_once('+') {
        Some((kind, _)) if !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_alphabetic()) => {
            decoded[kind.len() + 1..].to_string()
        }
        _ => decoded,
    })
}

/// The patch uuid `url` names when read as a hosted url of its OWN origin
/// ([`hosted_patch_uuid`]'s grammar with the url's origin taken as
/// configured): what a lock entry on an origin a run was not given claims
/// to resolve from. Only a url in a Socket patch server's path shape
/// ([`served_tail`], under any path prefix) counts: any other url merely
/// ending in the uuid (an artifact store's blob path) resolves from
/// elsewhere. Userinfo is dropped first: Socket never writes one, so
/// `https://patch.socket.dev@evil.example/patch/…` is a look-alike on the
/// host after the `@`, never an accepted origin.
pub(crate) fn hosted_shape_uuid(url: &str) -> Option<String> {
    let normalized = normalized_hosted_url(url)?;
    let mut parsed = reqwest::Url::parse(&normalized).ok()?;
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    let origin = parsed.origin().ascii_serialization();
    hosted_patch_uuid(parsed.as_str(), &[origin])
}

/// `url` parsed, when it is an `http(s)` url with no userinfo on an
/// accepted origin — Socket's patch server or one of `extra_origins` — and
/// whether that origin is Socket's own: the origin half of
/// [`hosted_patch_uuid`]'s rules, after [`normalized_hosted_url`].
fn accepted_hosted_url(url: &str, extra_origins: &[String]) -> Option<(reqwest::Url, bool)> {
    let text = normalized_hosted_url(url)?;
    let parsed = reqwest::Url::parse(&text).ok()?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let socket_host = parsed.scheme() == "https"
        && parsed.host_str() == Some(SOCKET_PATCH_SERVER_HOST)
        && parsed.port_or_known_default() == Some(443);
    let configured = extra_origins.iter().any(|origin| {
        reqwest::Url::parse(origin.trim()).is_ok_and(|o| {
            o.scheme() == parsed.scheme()
                && o.host_str().is_some()
                && o.host_str() == parsed.host_str()
                && o.port_or_known_default() == parsed.port_or_known_default()
        })
    });
    (socket_host || configured).then_some((parsed, socket_host))
}

/// EVERY canonical-uuid path segment of a url on an accepted origin
/// ([`hosted_patch_uuid`]'s origin rules), in path order (the grant token
/// first when it is uuid-shaped, the patch uuid last), or `None` when `url`
/// is not on one. Deliberately wider than [`hosted_patch_uuid`], which also
/// demands a served path: `vex` discovery uses this to RECOGNIZE every
/// Socket identity a lockfile mentions, including the malformed or
/// rejected shapes whose "last uuid" is not a patch, so that no ledger
/// claim for such a uuid is decided from raw text.
pub fn hosted_patch_url_uuids(url: &str, extra_origins: &[String]) -> Option<Vec<String>> {
    use crate::utils::purl::percent_decode_purl_component;

    let (parsed, _) = accepted_hosted_url(url, extra_origins)?;
    Some(
        parsed
            .path_segments()?
            .map(|segment| percent_decode_purl_component(segment).into_owned())
            .filter(|segment| is_canonical_uuid(segment))
            .collect(),
    )
}

/// The host of `url` when it is a PLAIN `http(s)` url — printable ASCII
/// only, no `%`, `\\` or userinfo, a DNS name of letters, digits, `.` and
/// `-` whose last label starts with a letter — lowercased, which is then
/// exactly what [`hosted_patch_url_uuids`]'s url
/// parse would call its host (no decoding, IDNA mapping or IP-address
/// reading applies to such a name). `None` for anything else, which takes
/// the full parse.
fn plain_url_domain(url: &str) -> Option<String> {
    let url = url.trim();
    if !url
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'%' && b != b'\\')
    {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    // `sparse+https://…` / `registry+https://…`, as the parse strips it.
    let scheme = match scheme.rsplit_once('+') {
        Some((kind, scheme))
            if !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_alphabetic()) =>
        {
            scheme
        }
        _ => scheme,
    };
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return None,
        None => authority,
    };
    let last = host.strip_suffix('.').unwrap_or(host).rsplit('.').next()?;
    let plain = !host.is_empty()
        && !rest.starts_with('/')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && last.starts_with(|c: char| c.is_ascii_alphabetic())
        && !host
            .split('.')
            .any(|label| label.len() >= 4 && label[..4].eq_ignore_ascii_case("xn--"));
    plain.then(|| host.to_ascii_lowercase())
}

/// The host policy one run classifies under: Socket's patch server plus the
/// operator's `--patch-server-url` origins.
#[derive(Debug)]
pub(crate) struct OriginPolicy<'a> {
    origins: &'a [String],
    /// The hosts a Socket-hosted url can name, lowercased (see
    /// [`Self::hosts`]).
    hosts: OnceLock<BTreeSet<String>>,
    /// [`Self::hosts`] as an ASCII-case-insensitive matcher.
    host_finder: OnceLock<aho_corasick::AhoCorasick>,
}

impl<'a> OriginPolicy<'a> {
    pub(crate) fn new(origins: &'a [String]) -> Self {
        OriginPolicy {
            origins,
            hosts: OnceLock::new(),
            host_finder: OnceLock::new(),
        }
    }

    /// The configured extra origins.
    pub(crate) fn origins(&self) -> &'a [String] {
        self.origins
    }

    /// The hosts a Socket-hosted url can name: Socket's patch server and
    /// each configured origin's host, lowercased. Built once per policy.
    fn hosts(&self) -> &BTreeSet<String> {
        self.hosts.get_or_init(|| {
            let mut hosts = BTreeSet::from([SOCKET_PATCH_SERVER_HOST.to_string()]);
            hosts.extend(self.origins.iter().filter_map(|o| {
                reqwest::Url::parse(o.trim())
                    .ok()?
                    .host_str()
                    .map(str::to_ascii_lowercase)
            }));
            hosts
        })
    }

    /// A matcher for any of [`Self::hosts`] in any ASCII case: the cheap
    /// pre-filter of discovery's identity sweep (only a token naming an
    /// accepted host can be ours). Built once per policy.
    pub(crate) fn host_finder(&self) -> &aho_corasick::AhoCorasick {
        self.host_finder.get_or_init(|| {
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(self.hosts())
                .expect("literal host patterns")
        })
    }

    /// The patch uuid of a Socket-HOSTED url, or `None` for anything else
    /// (see [`hosted_patch_uuid`] for the accepted
    /// spellings and the host allowlist).
    ///
    /// A plain url ([`plain_url_domain`]) on any other host is answered
    /// without parsing it: every lock entry's registry url comes through
    /// here.
    pub(crate) fn hosted_uuid(&self, url: &str) -> Option<String> {
        if let Some(host) = plain_url_domain(url) {
            if !self.hosts().contains(&host) {
                return None;
            }
        }
        hosted_patch_uuid(url, self.origins)
    }

    /// Classify `s` (see [`Located`]).
    pub(crate) fn locate(&self, s: &str, opts: LocateOpts) -> Located {
        let vendored = match opts.grammar {
            LeafGrammar::Literal => vendor_ref(s),
            LeafGrammar::Decorated => vendor_ref_decorated(s),
        };
        let decorated_leaf = opts.decorated_check
            && opts.grammar == LeafGrammar::Literal
            && is_decorated_vendor_path(s);
        Located {
            vendored,
            hosted: self.hosted_uuid(s),
            decorated_leaf,
        }
    }
}

// ── names ────────────────────────────────────────────────────────────────

/// The uuid of a Socket-owned registry / repository / source NAME:
/// `socket-patch-<uuid>` (cargo `[registries.*]` + Cargo.toml `registry =`,
/// maven `<repository><id>`, nuget `<add key>`) or, with
/// `vendored = true`, `socket-patch-vendor-<uuid>` (maven's vendored repo
/// id). Exact grammar only — a suffix or a non-canonical uuid is not ours.
pub(crate) fn socket_patch_name_uuid(name: &str, vendored: bool) -> Option<String> {
    crate::patch::redirect::generation::pin_name_uuid(name.trim(), vendored).map(str::to_string)
}

// ── vendored paths ───────────────────────────────────────────────────────

/// A vendored artifact reference recovered from a wiring string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRef {
    /// Vendor ecosystem dir (`npm`, `cargo`, `pypi`, …).
    pub eco: String,
    pub uuid: String,
    /// The natural leaf, lock-format suffixes stripped ([`strip_leaf_suffix`]),
    /// forward-slashed, no trailing slash.
    pub leaf: String,
    /// `.socket/vendor/<eco>/<uuid>/<leaf>` — the root-relative artifact path.
    pub artifact_rel: String,
}

/// Recover a vendored artifact reference from a lockfile/config string that
/// points into THIS project's `.socket/vendor/`: `file:` / `./` / bare
/// spellings, backslashed Windows spellings, and `\/`-escaped JSON text.
///
/// Stricter than [`crate::vendor::parse_vendor_path`] (which finds the anchor
/// anywhere, for the orphan sweep): the anchor must START the path. A
/// `../.socket/vendor/…` or absolute spelling points the package manager at
/// an artifact OUTSIDE the project root, and verifying the root's same-named
/// artifact instead would attest bytes the build never consumes. Callers
/// whose format legitimately prefixes the project root (hatch
/// `{root:uri}/`, maven `file://${project.basedir}/`, pnpm-legacy absolute
/// importer paths) strip that exact prefix first.
///
/// The leaf must be a traversal-safe relative path, taken LITERALLY: npm,
/// pnpm, bun, composer, bundler, go, cargo, maven, nuget and every pypi
/// lock read the string as a file path, so a leaf carrying `#` or `::` is
/// rejected (`None`) rather than cut — `…/foo-1.0.0.tgz#evil.tgz` is a file
/// of that literal name, which npm installs while the cut leaf would verify
/// the good `foo-1.0.0.tgz` beside it. The formats whose grammar DEFINES
/// those decorations use [`vendor_ref_decorated`] instead.
pub fn vendor_ref(s: &str) -> Option<VendorRef> {
    vendor_ref_with(s, false)
}

/// [`vendor_ref`] for the formats that decorate a vendored path: yarn
/// classic `#<sha1>`, berry `#./…::hash=…` fragments and `::locator=…`
/// bindings, and url-form pip / Hatch references (`file:…#sha256=…`,
/// `{root:uri}/…#sha256=…`). The leaf keeps only its natural name — the
/// decorations ([`strip_leaf_suffix`]) are cut before the literal-path
/// checks.
pub fn vendor_ref_decorated(s: &str) -> Option<VendorRef> {
    vendor_ref_with(s, true)
}

fn vendor_ref_with(s: &str, decorated: bool) -> Option<VendorRef> {
    let rest = root_anchored_vendor_rest(s)?;
    let mut it = rest.splitn(3, '/');
    let eco = it.next()?;
    let uuid = it.next()?;
    let leaf_raw = it.next()?;
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) {
        return None;
    }
    let leaf = if decorated {
        strip_leaf_suffix(leaf_raw)
    } else if leaf_raw.contains('#') || leaf_raw.contains("::") {
        return None;
    } else {
        leaf_raw
    };
    let leaf = leaf.trim_end_matches('/');
    if leaf.is_empty() || !is_safe_multi_segment(leaf) {
        return None;
    }
    Some(VendorRef {
        eco: eco.to_string(),
        uuid: uuid.to_string(),
        leaf: leaf.to_string(),
        artifact_rel: format!("{VENDOR_DIR}/{eco}/{uuid}/{leaf}"),
    })
}

/// `(eco, uuid)` for a root-anchored string that ends AT the uuid dir
/// (`.socket/vendor/nuget/<uuid>`, a maven repository url's path) — the
/// shapes [`vendor_ref`] rejects for having no leaf.
pub fn vendor_uuid_dir(s: &str) -> Option<(String, String)> {
    let rest = root_anchored_vendor_rest(s)?;
    let (eco, uuid) = rest.trim_end_matches('/').split_once('/')?;
    if !ECOSYSTEM_DIRS.contains(&eco) || !is_canonical_uuid(uuid) {
        return None;
    }
    Some((eco.to_string(), uuid.to_string()))
}

/// Whether `s` is a vendored artifact path [`vendor_ref`] rejects ONLY for
/// a `#` / `::` in its leaf (what [`vendor_ref_decorated`] would have cut):
/// to a literal-path format that names another file, which extractors
/// diagnose rather than skip silently.
pub(crate) fn is_decorated_vendor_path(s: &str) -> bool {
    vendor_ref(s).is_none() && vendor_ref_decorated(s).is_some()
}

/// Everything after a LEADING `.socket/vendor/` anchor (after `file:`,
/// `./`, backslash and `\/` normalization), or `None`: the writers' own
/// root-anchoring rule ([`crate::vendor::path::vendor_rest_from`]), so
/// discovery attests exactly the references the writers claim.
fn root_anchored_vendor_rest(s: &str) -> Option<String> {
    crate::vendor::path::vendor_rest_from("", s)
}

/// Cut the lock-format decorations off a vendored leaf: everything from the
/// first `#` (yarn classic `#<sha1>`, berry `#./<path>::hash=…`, pip/hatch
/// `#sha256=…`) or `::` (berry `::locator=…`).
pub fn strip_leaf_suffix(leaf: &str) -> &str {
    let cut = [leaf.find('#'), leaf.find("::")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(leaf.len());
    &leaf[..cut]
}

/// The canonical base purl a vendored leaf names (see
/// [`crate::vendor::path`]'s leaf table), suffixes stripped and pypi names
/// canonicalized. `None` when the leaf is not a recognizable artifact name.
pub fn vendored_leaf_purl(eco: &str, leaf: &str) -> Option<String> {
    leaf_to_purl(eco, strip_leaf_suffix(leaf).trim_end_matches('/'))
        .map(|purl| canonical_base_purl(&purl))
}

/// How a lock format spells a vendored leaf: literally ([`vendor_ref`]) or
/// with `#` / `::` decorations after it ([`vendor_ref_decorated`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafGrammar {
    /// The string is a file path: a `#` / `::` belongs to the leaf.
    Literal,
    /// The format defines `#` / `::` decorations after the leaf (yarn
    /// classic / berry, url-form pip and Hatch references).
    Decorated,
}

/// What [`OriginPolicy::locate`] computes for one wiring string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocateOpts {
    pub(crate) grammar: LeafGrammar,
    /// [`LeafGrammar::Literal`] only: also report a vendored path whose leaf
    /// carries a decoration ([`is_decorated_vendor_path`]) — the npm, pnpm
    /// and bun extractors diagnose it; composer and the pypi readers do not
    /// check it.
    pub(crate) decorated_check: bool,
}

impl LocateOpts {
    /// A literal path, decorated leaves reported (npm, pnpm, bun).
    pub(crate) const LITERAL_CHECKED: Self = LocateOpts {
        grammar: LeafGrammar::Literal,
        decorated_check: true,
    };
    /// A literal path, decorated leaves not checked (composer, pypi locks,
    /// bare pip / Hatch paths).
    pub(crate) const LITERAL: Self = LocateOpts {
        grammar: LeafGrammar::Literal,
        decorated_check: false,
    };
    /// A decorated spelling (yarn, url-form pip / Hatch references).
    pub(crate) const DECORATED: Self = LocateOpts {
        grammar: LeafGrammar::Decorated,
        decorated_check: false,
    };
}

/// Where one lockfile / config string points — every identity decision an
/// extractor takes from it, computed once. Each extractor keeps its own
/// decision ORDER over the fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Located {
    /// The root-anchored vendored artifact the string names, read with the
    /// requested [`LeafGrammar`].
    pub(crate) vendored: Option<VendorRef>,
    /// The patch uuid of a Socket-hosted url ([`OriginPolicy::hosted_uuid`]),
    /// computed eagerly: it needs an http(s) url on an allowed origin while
    /// `vendored` needs the string to START at `.socket/vendor/`, so at most
    /// one of the two is ever set.
    pub(crate) hosted: Option<String>,
    /// [`is_decorated_vendor_path`] when [`LocateOpts::decorated_check`] is
    /// set (Literal grammar only), else `false`.
    pub(crate) decorated_leaf: bool,
}

/// The Socket wiring a lock location carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Wired {
    Hosted(String),
    Vendored(VendorRef),
}

impl Wired {
    pub(crate) fn uuid(&self) -> &str {
        match self {
            Wired::Hosted(uuid) => uuid,
            Wired::Vendored(vref) => &vref.uuid,
        }
    }

    /// The same patch artifact: the same hosted uuid, or the same vendored
    /// artifact path.
    pub(crate) fn same_artifact(&self, other: &Wired) -> bool {
        match (self, other) {
            (Wired::Hosted(a), Wired::Hosted(b)) => a == b,
            (Wired::Vendored(a), Wired::Vendored(b)) => a.artifact_rel == b.artifact_rel,
            _ => false,
        }
    }
}

/// Whether `s` points into SOME `.socket/vendor/` tree, any anchoring
/// (backslashes folded) — a Socket-shaped string whose rejection is worth a
/// diagnostic (cargo `[patch]` paths, gem remotes, composer path dists,
/// maven repository urls).
pub(crate) fn names_vendor_dir(s: &str) -> bool {
    s.replace('\\', "/").contains(&format!("{VENDOR_DIR}/"))
}

/// [`names_vendor_dir`] that also folds JSON / TOML `\/` escapes (the pypi
/// readers).
pub(crate) fn mentions_vendor_dir(s: &str) -> bool {
    s.replace("\\/", "/")
        .replace('\\', "/")
        .contains(&format!("{VENDOR_DIR}/"))
}

/// Whether `s` STARTS at this project's `.socket/vendor/` after the `file:`
/// / `./` spellings [`vendor_ref_decorated`] accepts (yarn's rule; `\/` is
/// not folded).
pub(crate) fn root_anchored_spelling(s: &str) -> bool {
    let norm = s.trim().replace('\\', "/");
    let norm = norm.strip_prefix("file:").unwrap_or(&norm);
    let norm = norm.strip_prefix("./").unwrap_or(norm);
    norm.starts_with(&format!("{VENDOR_DIR}/"))
}

/// Whether vendored artifact `vref` is the npm tarball the vendor backends
/// write for `purl` (`[@scope/]<name>-<version>.tgz` in the npm vendor dir)
/// — the leaf rule the npm, pnpm and yarn extractors share.
pub(crate) fn npm_vendored_tarball_names(vref: &VendorRef, purl: &str) -> bool {
    vref.eco == "npm" && vendored_leaf_purl("npm", &vref.leaf).as_deref() == Some(purl)
}

#[cfg(test)]
mod hosted_patch_uuid_tests {
    //! `hosted_patch_uuid` is the trust gate between a committed lockfile
    //! line and a VEX attestation input: pin the accepted spellings AND the
    //! rejections (foreign hosts, credentials, non-canonical tokens).
    use super::*;

    const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    /// A uuid-SHAPED grant token: the fixtures use them, and production
    /// tokens are not guaranteed otherwise — the LAST uuid segment must win.
    const TOKEN: &str = "11111111-2222-4333-8444-555555555555";

    fn none() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn artifact_and_registry_shapes_yield_the_patch_uuid_not_the_token() {
        for url in [
            format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{TOKEN}/{UUID}/left-pad-1.3.0.tgz"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz"),
            format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/{UUID}/"),
            format!("https://patch.socket.dev/patch-registry/gem/{TOKEN}/{UUID}/gems/rack-2.2.3.gem"),
            format!("https://patch.socket.dev/patch-registry/maven/{TOKEN}/{UUID}/maven2"),
            format!("https://patch.socket.dev/patch-registry/nuget/{TOKEN}/{UUID}/index.json"),
            format!("sparse+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/"),
            format!("registry+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/"),
        ] {
            assert_eq!(
                hosted_patch_uuid(&url, &none()).as_deref(),
                Some(UUID),
                "{url}"
            );
        }
    }

    #[test]
    fn lock_format_spellings_are_normalized() {
        let url = format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/left-pad-1.3.0.tgz");
        // yarn classic `#<sha1>`, pip/hatch `#sha256=`, a stray query.
        for spelled in [
            format!("{url}#0123456789abcdef0123456789abcdef01234567"),
            format!("{url}#sha256=abc"),
            format!("{url}?x=1"),
            // composer's `\/`-escaped slashes.
            url.replace('/', "\\/"),
            // yarn berry's percent-encoded `__archiveUrl=` binding value.
            url.replace(':', "%3A").replace('/', "%2F"),
            format!("  {url}  "),
        ] {
            assert_eq!(
                hosted_patch_uuid(&spelled, &none()).as_deref(),
                Some(UUID),
                "{spelled}"
            );
        }
    }

    #[test]
    fn foreign_hosts_credentials_and_plain_http_are_refused() {
        for url in [
            format!("https://registry.npmjs.org/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev.evil.example/{TOKEN}/{UUID}/x.tgz"),
            format!("https://evil.example/patch.socket.dev/{TOKEN}/{UUID}/x.tgz"),
            format!("http://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev:8443/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://user:pw@patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("git+ssh://patch.socket.dev/{UUID}"),
            format!("file:.socket/vendor/npm/{UUID}/x.tgz"),
            format!("patch.socket.dev/gopatch/{UUID}"),
        ] {
            assert_eq!(hosted_patch_uuid(&url, &none()), None, "{url}");
        }
    }

    #[test]
    fn non_canonical_segments_are_not_patch_uuids() {
        for url in [
            // Placeholder tokens (fixtures use `uuid`, `tok`, `some-uuid`).
            "https://patch.socket.dev/patch/npm/tok/uuid/x.tgz".to_string(),
            // Uppercase is not the canonical grammar.
            format!(
                "https://patch.socket.dev/patch/npm/tok/{}/x.tgz",
                UUID.to_ascii_uppercase()
            ),
            // A uuid only in the query / fragment is not a path level.
            format!("https://patch.socket.dev/patch/npm/x.tgz?u={UUID}"),
            format!("https://patch.socket.dev/patch/npm/x.tgz#{UUID}"),
            // An encoded `/` cannot split a segment into a uuid.
            format!("https://patch.socket.dev/patch/npm/tok%2F{UUID}/x.tgz"),
        ] {
            assert_eq!(hosted_patch_uuid(&url, &none()), None, "{url}");
        }
    }

    #[test]
    fn configured_patch_server_origin_is_accepted_exactly() {
        let origins = vec!["http://127.0.0.1:4545/some/base".to_string()];
        let url = format!("http://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID}/x.tgz");
        assert_eq!(hosted_patch_uuid(&url, &origins).as_deref(), Some(UUID));
        // Same host, other port / scheme: a different origin.
        for other in [
            format!("http://127.0.0.1:4546/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://127.0.0.1:4545/patch/npm/{TOKEN}/{UUID}/x.tgz"),
        ] {
            assert_eq!(hosted_patch_uuid(&other, &origins), None, "{other}");
        }
        // The default host stays accepted alongside the override, and a
        // malformed override is ignored rather than widening the allowlist.
        let default = format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/x.tgz");
        assert_eq!(hosted_patch_uuid(&default, &origins).as_deref(), Some(UUID));
        assert_eq!(hosted_patch_uuid(&url, &["not a url".to_string()]), None);
    }

    /// Every `url` the classifiers accept, for a list none may accept.
    fn accepted(urls: &[String], origins: &[String]) -> Vec<String> {
        urls.iter()
            .filter(|url| {
                hosted_patch_uuid(url, origins).is_some()
                    || OriginPolicy::new(origins).hosted_uuid(url).is_some()
                    || hosted_patch_url_uuids(url, origins).is_some()
                    || hosted_shape_uuid(url).is_some()
            })
            .cloned()
            .collect()
    }

    /// Url parsers disagree about `\`, whitespace and control characters:
    /// the WHATWG parser reads `\` as `/` and drops tabs and newlines, while
    /// libcurl and PHP's `parse_url` (Composer's `dist.url`) read
    /// `https://patch.socket.dev\@evil.example/…` as host `evil.example`
    /// with userinfo `patch.socket.dev\`. A url whose host depends on who
    /// parses it is never Socket's, in any spelling the readers normalize.
    #[test]
    fn urls_whose_host_depends_on_the_parser_are_refused() {
        let tail = format!("/patch/npm/foo/1.0.0/{TOKEN}/{UUID}/foo-1.0.0.tgz");
        let urls = [
            format!("https://patch.socket.dev\\@evil.example{tail}"),
            format!("https://patch.socket.dev\\\\@evil.example{tail}"),
            format!("https:\\\\patch.socket.dev{tail}"),
            format!("https://patch.socket.dev\\patch\\npm\\{TOKEN}\\{UUID}\\foo-1.0.0.tgz"),
            // The `\/` unescape leaves the stray backslash in place.
            format!(
                "https:\\/\\/patch.socket.dev\\\\@evil.example{}",
                tail.replace('/', "\\/")
            ),
            // A wholly percent-encoded url decodes to one.
            format!(
                "https%3A%2F%2Fpatch.socket.dev%5C%40evil.example{}",
                tail.replace('/', "%2F")
            ),
            format!("https://pat\tch.socket.dev{tail}"),
            format!("https://patch.socket.dev\n{tail}"),
            format!("https://patch.socket.dev/patch/npm/fo o/1.0.0/{TOKEN}/{UUID}/foo-1.0.0.tgz"),
            format!("https://patch.socket.dev{tail}\r\nHost: evil.example"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/foo\u{0}.tgz"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/foo\u{7f}.tgz"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/foo\u{a0}.tgz"),
            format!("https%3A%2F%2Fpatch.socket.dev%2Fpatch%2Fnpm%2F{TOKEN}%2F{UUID}%2Ffoo%09.tgz"),
        ];
        assert_eq!(accepted(&urls, &none()), Vec::<String>::new());
        // A foreign origin's look-alike is no hosted shape either.
        let foreign = [format!("https://mirror.example\\@evil.example{tail}")];
        assert_eq!(
            accepted(&foreign, &["https://mirror.example".to_string()]),
            Vec::<String>::new()
        );
        // Surrounding whitespace is the lock format's, not the url's.
        assert_eq!(
            hosted_patch_uuid(&format!(" \thttps://patch.socket.dev{tail}\n"), &none()).as_deref(),
            Some(UUID)
        );
    }

    /// A patch is served under `patch/<eco>/…`, `patch-registry/<eco>/…` or
    /// `gopatch/…` — first in the path on Socket's own server. A uuid
    /// anywhere else on the host names no patch, and neither does one a
    /// percent-encoded `/` or `\` could move the request away from.
    #[test]
    fn only_a_served_path_names_a_patch() {
        let refused = [
            format!("https://patch.socket.dev/x/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/patch/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/patch/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/patch/telemetry/{UUID}"),
            format!("https://patch.socket.dev/patch-registry/{TOKEN}/{UUID}/"),
            format!("https://patch.socket.dev/patch-registry/jsr/{TOKEN}/{UUID}/"),
            format!("https://patch.socket.dev/gem/{TOKEN}/{UUID}/"),
            // The root is not first, or the uuid comes before it.
            format!("https://patch.socket.dev/files/patch/npm/{TOKEN}/{UUID}/x.tgz"),
            format!("https://patch.socket.dev/{UUID}/patch/npm/x.tgz"),
            format!("https://patch.socket.dev/{UUID}/gopatch/x"),
            format!("https://patch.socket.dev/patch/{UUID}/npm/x.tgz"),
            // Encoded separators.
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/..%2f..%2fother"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/..%2F..%2Fother"),
            format!("https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/..%5c..%5Cother"),
            format!("https://patch.socket.dev/patch/npm/a%2fb/1.0.0/{TOKEN}/{UUID}/b-1.0.0.tgz"),
            format!("https://patch.socket.dev/patch%2fnpm/{TOKEN}/{UUID}/x.tgz"),
            format!("sparse+https://patch.socket.dev/x/{TOKEN}/{UUID}/index/"),
        ];
        for url in &refused {
            assert_eq!(hosted_patch_uuid(url, &none()), None, "{url}");
            assert_eq!(OriginPolicy::new(&[]).hosted_uuid(url), None, "{url}");
        }
        for url in [
            format!("https://patch.socket.dev/gopatch/{UUID}"),
            format!("https://patch.socket.dev/gopatch/{UUID}/v2"),
            format!(
                "https://patch.socket.dev/patch-registry/golang/patch.socket.dev/gopatch/{UUID}/@v/v1.4.2-socketpatch.1.zip"
            ),
            format!("https://patch.socket.dev/patch/npm/@scope/pkg/2.0.0/{TOKEN}/{UUID}/pkg-2.0.0.tgz"),
            format!("https://patch.socket.dev/patch/npm/%40scope/pkg/2.0.0/{TOKEN}/{UUID}/pkg-2.0.0.tgz"),
            format!(
                "https://patch.socket.dev/patch/composer/monolog/monolog/3.0.2/{TOKEN}/{UUID}/monolog-3.0.2.zip"
            ),
            format!(
                "https://patch.socket.dev/patch/maven/com.google.code.gson/gson/2.10.1/{TOKEN}/{UUID}/gson-2.10.1.jar"
            ),
            format!(
                "https://patch.socket.dev/patch/pypi/six/1.16.0/{TOKEN}/{UUID}/six-1.16.0-py2.py3-none-any.whl"
            ),
            format!("https://patch.socket.dev/patch/cargo/serde/1.0.0/{TOKEN}/{UUID}/serde-1.0.0.crate"),
            format!("https://patch.socket.dev/patch-registry/pypi/{TOKEN}/{UUID}/simple/"),
            format!("https://patch.socket.dev/patch-registry/npm/{TOKEN}/{UUID}/"),
            format!(
                "https://patch.socket.dev/patch-registry/maven/{TOKEN}/{UUID}/maven2/com/google/code/gson/gson/2.10.1-socket.7c8d9e0f/gson-2.10.1-socket.7c8d9e0f.jar"
            ),
            format!(
                "https://patch.socket.dev/patch-registry/nuget/{TOKEN}/{UUID}/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
            ),
        ] {
            assert_eq!(
                hosted_patch_uuid(&url, &none()).as_deref(),
                Some(UUID),
                "{url}"
            );
        }
        // An operator's deployment may serve the same shape under a path
        // prefix; a uuid outside that shape is still no patch there.
        let origins = vec!["https://patches.internal.example/socket".to_string()];
        let served = format!(
            "https://patches.internal.example/socket/patch/pypi/six/1.16.0/{TOKEN}/{UUID}/six-1.16.0-py2.py3-none-any.whl"
        );
        assert_eq!(hosted_patch_uuid(&served, &origins).as_deref(), Some(UUID));
        for url in [
            format!("https://patches.internal.example/socket/{TOKEN}/{UUID}/x.whl"),
            format!("https://patches.internal.example/{UUID}/patch/pypi/x.whl"),
            format!("https://patches.internal.example/socket/patch/pypi/{TOKEN}/{UUID}/..%2fx.whl"),
        ] {
            assert_eq!(hosted_patch_uuid(&url, &origins), None, "{url}");
        }
        // Recognition stays wider than identity: a uuid on the host that
        // names no patch is still one discovery is authoritative for.
        assert_eq!(
            hosted_patch_url_uuids(&refused[0], &none()),
            Some(vec![UUID.to_string()])
        );
    }

    /// The Go hosted namespace lives on the same host the URL allowlist
    /// pins — the two spellings of "Socket's patch server" cannot drift.
    #[test]
    fn go_module_namespace_is_on_the_patch_server_host() {
        assert!(crate::vendor::go_mod_edit::HOSTED_GO_MODULE_PREFIX
            .starts_with(&format!("{SOCKET_PATCH_SERVER_HOST}/")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    /// A uuid-SHAPED grant token.
    const TOKEN: &str = "11111111-2222-4333-8444-555555555555";

    #[test]
    fn vendor_ref_strips_lock_suffixes_and_requires_a_root_anchor() {
        let a = UUID;
        for spelled in [
            format!("file:.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!("file:./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!("./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!(".socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
            format!(".socket\\vendor\\npm\\{a}\\left-pad-1.3.0.tgz"),
            format!(".socket\\/vendor\\/npm\\/{a}\\/left-pad-1.3.0.tgz"),
            // yarn classic `#<sha1>`, berry fragment + locator, pip `#sha256=`.
            format!("file:./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz#0123abcd"),
            format!(
                "./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz#./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz::hash=abc123&locator=app%40workspace%3A."
            ),
            format!("./.socket/vendor/npm/{a}/left-pad-1.3.0.tgz::locator=app%40workspace%3A."),
        ] {
            let decorated = spelled.contains('#') || spelled.contains("::");
            // The literal-path reader refuses a decorated leaf outright: to
            // npm / pnpm / bun / … it names a DIFFERENT file.
            assert_eq!(vendor_ref(&spelled).is_none(), decorated, "{spelled}");
            let v = vendor_ref_decorated(&spelled).unwrap_or_else(|| panic!("{spelled}"));
            assert_eq!(v.eco, "npm", "{spelled}");
            assert_eq!(v.uuid, a, "{spelled}");
            assert_eq!(v.leaf, "left-pad-1.3.0.tgz", "{spelled}");
            assert_eq!(
                v.artifact_rel,
                format!(".socket/vendor/npm/{a}/left-pad-1.3.0.tgz"),
                "{spelled}"
            );
        }
        // Dir-shaped leaves keep their nesting, trailing slash dropped.
        let v = vendor_ref(&format!(
            "./.socket/vendor/golang/{a}/github.com/foo/bar@v1.2.3/"
        ))
        .unwrap();
        assert_eq!(v.leaf, "github.com/foo/bar@v1.2.3");
    }

    #[test]
    fn vendor_ref_rejects_escapes_foreign_anchors_and_bad_uuids() {
        let a = UUID;
        for bad in [
            // The package manager would read OUTSIDE the project root.
            format!("../.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("file:../.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("/abs/project/.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            format!("sub/.socket/vendor/npm/{a}/x-1.0.0.tgz"),
            // Traversal inside the leaf.
            format!(".socket/vendor/npm/{a}/../../../etc/passwd"),
            format!(".socket/vendor/npm/{a}/a//b.tgz"),
            // No leaf / uuid-dir only / unknown eco / non-canonical uuid.
            format!(".socket/vendor/npm/{a}"),
            format!(".socket/vendor/npm/{a}/"),
            format!(".socket/vendor/jsr/{a}/x-1.0.0.tgz"),
            format!(".socket/vendor/npm/{}/x-1.0.0.tgz", a.to_ascii_uppercase()),
            ".socket/vendor/npm/not-a-uuid/x-1.0.0.tgz".to_string(),
            "https://registry.npmjs.org/x/-/x-1.0.0.tgz".to_string(),
        ] {
            assert_eq!(vendor_ref(&bad), None, "{bad}");
        }
    }

    #[test]
    fn vendor_uuid_dir_accepts_only_the_bare_uuid_dir() {
        let a = UUID;
        assert_eq!(
            vendor_uuid_dir(&format!(".socket/vendor/nuget/{a}")),
            Some(("nuget".to_string(), a.to_string()))
        );
        assert_eq!(
            vendor_uuid_dir(&format!("./.socket/vendor/maven/{a}/")),
            Some(("maven".to_string(), a.to_string()))
        );
        assert_eq!(
            vendor_uuid_dir(&format!(".socket/vendor/nuget/{a}/x.nupkg")),
            None
        );
        assert_eq!(
            vendor_uuid_dir(&format!("../.socket/vendor/nuget/{a}")),
            None
        );
        assert_eq!(vendor_uuid_dir(".socket/vendor/nuget/nope"), None);
    }

    #[test]
    fn vendored_leaf_purl_strips_and_canonicalizes() {
        assert_eq!(
            vendored_leaf_purl("npm", "@scope/pkg-1.2.3.tgz#deadbeef").as_deref(),
            Some("pkg:npm/@scope/pkg@1.2.3")
        );
        assert_eq!(
            vendored_leaf_purl(
                "pypi",
                "Python_Dateutil-2.8.2-py2.py3-none-any.whl#sha256=ab"
            )
            .as_deref(),
            Some("pkg:pypi/python-dateutil@2.8.2")
        );
        assert_eq!(
            vendored_leaf_purl("cargo", "serde-1.0.0/").as_deref(),
            Some("pkg:cargo/serde@1.0.0")
        );
        assert_eq!(vendored_leaf_purl("npm", "not-a-tarball"), None);
    }

    #[test]
    fn socket_patch_names_are_exact() {
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID}"), false).as_deref(),
            Some(UUID)
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-vendor-{UUID}"), true).as_deref(),
            Some(UUID)
        );
        // The hosted grammar never matches the vendored id and vice versa.
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-vendor-{UUID}"), false),
            None
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID}"), true),
            None
        );
        assert_eq!(
            socket_patch_name_uuid(&format!("socket-patch-{UUID}-x"), false),
            None
        );
        assert_eq!(socket_patch_name_uuid("socket-patch-nope", false), None);
    }

    /// [`OriginPolicy::hosted_uuid`]'s plain-url shortcut answers exactly
    /// what the full parse does, for plain urls on other hosts and for
    /// every spelling it must leave to the parse.
    #[test]
    fn hosted_uuid_shortcut_agrees_with_the_full_parse() {
        let (a, t) = (UUID, TOKEN);
        let path = format!("/patch/npm/x/1.0.0/{t}/{a}/x-1.0.0.tgz");
        let hosts = [
            "patch.socket.dev",
            "PATCH.Socket.DEV",
            "patch.socket.dev.",
            "patch.socket.dev:443",
            "patch.socket.dev:8443",
            "patch.socket.dev:",
            "registry.npmjs.org",
            "registry.npmjs.org:443",
            "127.0.0.1:4545",
            "127.0.0.1",
            "0x7f.0.0.1:4545",
            "127.1:4545",
            "[::1]:4545",
            "staging.example.com:8443",
            "Staging.Example.COM:8443",
            "staging.example.com",
            "xn--stging-bua.example.com",
            "user@patch.socket.dev",
            "user:pw@registry.npmjs.org",
            "patch%2esocket.dev",
            "patch.soc\tket.dev",
            "patch.socket.dev\\",
            "foo.123",
            "foo.0x1f",
            "",
        ];
        let urls: Vec<String> = hosts
            .iter()
            .flat_map(|host| {
                [
                    format!("https://{host}{path}"),
                    format!("http://{host}{path}"),
                    format!("HTTPS://{host}{path}"),
                    format!("sparse+https://{host}{path}"),
                    format!("git+https://{host}{path}"),
                    format!("https:///{host}{path}"),
                    format!("https://{host}?q={path}"),
                    format!("  https://{host}{path}  "),
                    format!("https://{host}"),
                ]
            })
            .chain([
                format!("https:\\/\\/patch.socket.dev{}", path.replace('/', "\\/")),
                format!("https%3A%2F%2Fpatch.socket.dev{}", path.replace('/', "%2F")),
                "file:x.tgz".to_string(),
                "npm:x@1.0.0".to_string(),
                "https://".to_string(),
            ])
            .collect();
        for origins in [
            vec![],
            vec!["http://127.0.0.1:4545".to_string()],
            vec![
                "https://staging.example.com:8443".to_string(),
                "http://[::1]:4545".to_string(),
                "https://xn--stging-bua.example.com".to_string(),
            ],
        ] {
            let ctx = OriginPolicy::new(&origins);
            for url in &urls {
                assert_eq!(
                    ctx.hosted_uuid(url),
                    hosted_patch_uuid(url, &origins),
                    "{url} under {origins:?}"
                );
            }
            assert_eq!(
                ctx.hosted_uuid(&format!("https://patch.socket.dev{path}"))
                    .as_deref(),
                Some(a)
            );
        }
        assert_eq!(
            plain_url_domain("https://Registry.NPMJS.org/x"),
            Some("registry.npmjs.org".into())
        );
        for not_plain in [
            "https://127.0.0.1/x",
            "https://a%2eb.com/x",
            "https://u@a.com/x",
            "https://xn--a.com/x",
        ] {
            assert_eq!(plain_url_domain(not_plain), None, "{not_plain}");
        }
    }
}
