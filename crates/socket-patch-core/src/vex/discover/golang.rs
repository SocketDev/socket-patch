//! Go modules — root `go.mod` (and `go.work`; the in-root members' `go.mod`
//! at a go.work root without one) `replace` directives, pinned by `go.sum`
//! (`go.work.sum`).
//!
//! Both Socket backends wire a Go patch the
//! same way — a `replace` keyed on the ORIGINAL module + version — and differ
//! only in the right-hand side, which [`go_mod_edit::parse_replace_entries`]
//! classifies ([`ReplaceOwner`], go_mod_edit.rs:63-90):
//!
//! | owner | what our tools write | ref |
//! |---|---|---|
//! | [`ReplaceOwner::Hosted`] (`scan --mode hosted`, `rewrite_golang`) | `replace M v => patch.socket.dev/gopatch/<uuid> <sver>` + go.sum `patch.socket.dev/gopatch/<uuid> <sver> h1:…` and `…<sver>/go.mod h1:…` (`go mod tidy` may prune the first) | hosted, `integrity_required` iff the zip line is present |
//! | [`ReplaceOwner::Vendor`] (`vendor`, `vendor_go_module`) | `replace M v => ./.socket/vendor/golang/<uuid>/M@v` | vendored |
//! | [`ReplaceOwner::GoPatches`] (`apply`'s redirect) | `replace M v => ./.socket/go-patches/M@v` | none — no uuid; the CLI's `synthesize_go_patches` verifies those |
//!
//! Both writers emit the single-line form or rewrite an existing socket
//! line in place (so block members `\tM v => …` occur too), always with the
//! LEFT version and always `./`-prefixed, forward-slashed paths. The purl is
//! the LEFT side — `pkg:golang/<M>@<v>`, the module the build no longer
//! fetches — never the right-hand module.
//!
//! # What counts (rule 10: what the go command READS)
//!
//! * **Hosted identity** is the module path itself (not a URL, so not
//!   [`super::DiscoverCtx::hosted_uuid`]): exactly
//!   [`HOSTED_GO_MODULE_PREFIX`]`<uuid>`, optionally followed by one Go
//!   major-version suffix `/v<N>` (`N >= 2`; the design doc reserves it for
//!   v2+ originals, nothing ships it yet). The namespace is grant-free, so
//!   any other segment — a (uuid-shaped) grant token before the uuid, a
//!   placeholder, an uppercase uuid — is not something we write and is
//!   diagnosed, never "last uuid wins". The host is fixed: the hosted
//!   rewriter refuses module paths outside this namespace, and a
//!   `--patch-server-url` deployment does not change Go module paths, so
//!   the origin allowlist does not apply here.
//! * **Pin.** The hosted rewriter refuses to write the replace without BOTH
//!   go.sum lines, but `go mod tidy` then drops the zip line whenever no
//!   package of the replaced module is loaded (a transitive module only MVS
//!   reads keeps just its `/go.mod` line), and the build stays green. So
//!   the pin is the `/go.mod` line for the Socket module+version: exactly
//!   one well-formed hash for it, plus at most one well-formed zip hash.
//!   With the zip line, `integrity_required = true` and `locked_integrity`
//!   is its `h1:` dirhash ([`LockIntegrity::GoH1`]). Without it (the tidy
//!   state) `integrity_required = false`: the module path carries the patch
//!   uuid and go compiles none of its packages, so the pinned replace alone
//!   is the attestation basis — but MVS also keeps the `/go.mod` line of a
//!   version it reads and does not select, so a `/go.mod`-only pin whose
//!   version the main modules' `require`s or go.sum show is not selected
//!   ([`go_build_list::select`]) is inert: diagnosed, no ref. With a
//!   `go.work` the build list is MVS over every `use` member's module
//!   graph ([`GoWorkspace::selection`], with the dependencies' go.mod files
//!   read from the module cache when the root is on disk): a pin of either
//!   kind whose replaced version a member's or a dependency's `require`
//!   raises, or that is itself a `use` member, is inert. Sum files are no
//!   evidence there (go only appends to `go.work.sum`), and without the
//!   dependencies' go.mod files nothing read shows a dependency did not
//!   raise it, so a `/go.mod`-only pin is never the basis
//!   (`integrity_required = true`); the CLI's selection gate withholds
//!   what the module graph does not prove. Anything else — no `/go.mod` line, two
//!   different hashes for one line, a non-dirhash `h1:` (both a go
//!   `SECURITY ERROR`), a line of other than three tokens anywhere in a
//!   sum file (go rejects the whole file) — is not a pin:
//!   `integrity_required = true`, no `locked_integrity`. Hashes of other
//!   algorithms are ignored, as go ignores them. The sum files are the
//!   ones go verifies against: the root `go.sum`, or with a `go.work`,
//!   `go.work.sum` and each in-root `use` member's `go.sum` (the root's
//!   only when `.` is a member). Under `GOWORK=off` go ignores `go.work`,
//!   so discovery reads neither it nor its sum files. A `GOWORK` naming
//!   another file than the root's `go.work`, or a relative one (which go
//!   rejects), leaves the workspace unreadable here: every Go ref becomes
//!   a diagnostic.
//!   NB for the CLI's installed-tree basis: under a hosted replace the
//!   module cache's `M@v` (if any, e.g. from before the redirect) is
//!   pristine BY CONSTRUCTION — the build consumes
//!   `patch.socket.dev/gopatch/<uuid>@<sver>`.
//! * **Vendored identity** comes from [`vendor_ref`] over the replace PATH
//!   (root-anchored: a `../…/.socket/vendor/golang/…` or absolute target —
//!   which `detect_owner` still classifies as `Vendor` — points the build at
//!   another tree and is diagnosed). The leaf must name the SAME module and
//!   version as the left side ([`vendored_leaf_purl`]): `vendor` always
//!   writes `M v => …/<uuid>/M@v`, and a drifted pair is exactly the case
//!   `vendor` itself refuses to call "already patched".
//! * **Stale pins are inert.** `replace M v` applies only when the build
//!   selects `M@v`; a `require M v'` with `v' != v` (a `go get -u` after the
//!   redirect — the design doc's "upgrade drift") silently builds the
//!   unpatched module, which is why the hosted rewriter refuses to write
//!   one (`redirect_golang_version_mismatch`). Such a directive is
//!   diagnosed ([`DIAG_REF_INVALID`]), not emitted. A module absent from
//!   `require` (pre-1.17 go.mod omitting indirect deps) is not provably
//!   inert and is emitted.
//! * **Version-less replaces** (`replace M => …`, hand edits — neither
//!   writer emits them) apply to whatever version is selected: the version
//!   is taken from `require`; with no `require` for `M` the patched version
//!   is unknown ([`DIAG_REF_UNATTRIBUTABLE`]). A versioned replace for the
//!   same `M@<required>` in the same file takes precedence in Go, so the
//!   version-less one is then inert too.
//! * **`go.work`** (hand-written — no Socket tool writes it) uses the same
//!   `replace` grammar and paths relative to the (root) workspace dir; its
//!   refs are emitted with `source_file = "go.work"`, and hosted pins looked
//!   up in the sum files above. Versions are checked against the root
//!   `go.mod`'s `require` in module mode, and in workspace mode against the
//!   highest version any read member requires. go.work replaces override
//!   go.mod replaces in Go, but rule 10 leaves cross-file precedence to the
//!   CLI's `wiring_conflict` gate. In-root members' go.mod files are read
//!   for their `require`s and their go.sum for pins; their replaces only
//!   when the root has no go.mod of its own (a go.work root), each emitted
//!   with its own `source_file` (`<member>/go.mod`).
//! * **Hand-edit tolerance**: a UTF-8 BOM, CRLF line ends, tab-separated
//!   tokens, `replace(` without a space, `// comments`, and Go string
//!   literals (`"github.com/foo/bar"`, `` `…` ``) around escape- and
//!   whitespace-free tokens are all read as the go command would. A
//!   `( … )` block that is never closed (or a stray `)` / nested block)
//!   makes the whole file unparseable to go, so it yields
//!   [`DIAG_LOCKFILE_UNPARSEABLE`] and no refs.
//! * `vendor/modules.txt` (`go mod vendor`) only mirrors go.mod's replaces
//!   and is not read.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use super::{
    golang_purl, vendor_ref, vendored_leaf_purl, DiscoverCtx, Discovery, PatchedRef,
    DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::go_env::go_env;
use crate::vendor::go_build_list::{self, Selection};
use crate::vendor::go_mod_edit::{
    self, block_structure_error, hosted_module_uuid, normalize_for_read, ReplaceEntry,
    ReplaceOwner, HOSTED_GO_MODULE_PREFIX,
};
use crate::vendor::go_sum_edit::{go_semver_cmp, go_sum_lines, is_h1_dirhash};
use crate::vendor::go_workspace::{self, in_root_dir, same_dir_key, GoWork, GoWorkspace, Member};
use crate::vendor::lock_inventory::LockIntegrity;

const GO_MOD: &str = "go.mod";
const GO_SUM: &str = "go.sum";
const GO_WORK: &str = "go.work";
const GO_WORK_SUM: &str = "go.work.sum";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    extract_gowork(ctx, out, go_env("GOWORK").as_deref()).await;
}

/// [`extract`] for an explicit `GOWORK` value.
async fn extract_gowork(ctx: &DiscoverCtx<'_>, out: &mut Discovery, gowork: Option<&str>) {
    match gowork {
        Some("off") => extract_with(ctx, out, false).await,
        None | Some("") | Some("auto") => extract_with(ctx, out, true).await,
        Some(gowork) => match unread_workspace(ctx, gowork) {
            None => extract_with(ctx, out, true).await,
            Some(why) => withhold(ctx, out, &why).await,
        },
    }
}

/// Why the `go.work` an explicit `GOWORK` names is not the root's, which
/// is the only one discovery reads (`None`: it is).
fn unread_workspace(ctx: &DiscoverCtx<'_>, gowork: &str) -> Option<String> {
    let root = ctx.disk_root();
    let why = match go_workspace::resolve_with(root.unwrap_or(Path::new("")), Some(gowork)) {
        GoWork::Invalid(why) => why,
        GoWork::File(file) => {
            let own = root.map(|r| r.join(GO_WORK)).filter(|own| own.is_file());
            if own.is_some_and(|own| same_dir_key(&own) == same_dir_key(&file)) {
                return None;
            }
            format!(
                "GOWORK={gowork} names a workspace other than this directory's {GO_WORK}, \
                 which discovery cannot read"
            )
        }
        GoWork::None => return None,
    };
    Some(why)
}

/// Discovery under a workspace it cannot read: what it would find reported
/// as unattested, never as refs.
async fn withhold(ctx: &DiscoverCtx<'_>, out: &mut Discovery, why: &str) {
    let mut found = Discovery::default();
    extract_with(ctx, &mut found, true).await;
    out.diagnostics.append(&mut found.diagnostics);
    for r in found.refs {
        let file = r.source_file.to_string_lossy().into_owned();
        out.diag(
            DIAG_REF_INVALID,
            &file,
            format!("{file}: the replace of {} is not attested: {why}", r.purl),
        );
    }
}

/// [`extract`], with `workspaces` false under `GOWORK=off`: go then ignores
/// `go.work`, its replaces and its sum files.
async fn extract_with(ctx: &DiscoverCtx<'_>, out: &mut Discovery, workspaces: bool) {
    let go_mod = match ctx.read_text(GO_MOD, out).await {
        Some(text) => parse_go_file(GO_MOD, &text, out),
        None => None,
    };
    let go_work = if workspaces {
        ctx.read_text(GO_WORK, out).await
    } else {
        None
    };
    let go_work = go_work.and_then(|text| parse_go_file(GO_WORK, &text, out));
    let workspace = match go_work.as_deref() {
        Some(work) => Some(read_workspace(ctx, out, go_mod.as_deref(), work).await),
        None => None,
    };

    // The go.mod files whose replaces apply: the root's, or (a go.work root
    // with no module of its own) each in-root member's.
    let mut files: Vec<(String, Vec<ReplaceEntry>)> = Vec::new();
    match (&go_mod, &workspace) {
        (Some(text), _) => {
            files.push((GO_MOD.to_string(), go_mod_edit::parse_replace_entries(text)))
        }
        (None, Some(ws)) => {
            for (dir, member) in &ws.in_root {
                if let Some(text) = ws.model.members[*member].go_mod.as_deref() {
                    files.push((
                        member_file(dir, GO_MOD),
                        go_mod_edit::parse_replace_entries(text),
                    ));
                }
            }
        }
        (None, None) => {}
    }
    if let Some(text) = &go_work {
        files.push((
            GO_WORK.to_string(),
            go_mod_edit::parse_replace_entries(text),
        ));
    }
    let any_hosted = files
        .iter()
        .flat_map(|(_, entries)| entries)
        .any(|e| e.owner == Some(ReplaceOwner::Hosted));
    let graph = Graph::new(go_mod.as_deref(), workspace.as_ref().map(|ws| &ws.model));
    let mut sums = SumPins::default();
    if any_hosted {
        let sum_files = match &workspace {
            Some(ws) => ws.sum_files.clone(),
            None => vec![GO_SUM.to_string()],
        };
        sums = SumPins::read(ctx, out, &sum_files).await;
    }
    for (file, entries) in &files {
        extract_file(out, file, entries, &graph, &sums);
    }
}

/// The build list's evidence: the root module's go.mod, or the workspace.
struct Graph<'a> {
    /// The versions the build requires: the root go.mod's `require`s, or in
    /// workspace mode the highest each read member requires.
    required: HashMap<String, String>,
    root: Option<&'a str>,
    workspace: Option<&'a GoWorkspace>,
}

impl<'a> Graph<'a> {
    fn new(go_mod: Option<&'a str>, workspace: Option<&'a GoWorkspace>) -> Self {
        let required = match workspace {
            Some(ws) => {
                let mut max: HashMap<String, String> = HashMap::new();
                for text in ws.members.iter().filter_map(|m| m.go_mod.as_deref()) {
                    for (module, v) in go_mod_edit::parse_required_versions(text) {
                        match max.get(&module) {
                            Some(cur) if go_semver_cmp(cur, &v).is_ge() => {}
                            _ => {
                                max.insert(module, v);
                            }
                        }
                    }
                }
                max
            }
            None => go_mod
                .map(go_mod_edit::parse_required_versions)
                .unwrap_or_default(),
        };
        Graph {
            required,
            root: go_mod,
            workspace,
        }
    }

    /// Which version the build selects against the patched `version`
    /// ([`go_build_list::select`] over the root go.mod and the root go.sum's
    /// zip lines, or [`GoWorkspace::selection`]).
    fn select(&self, module: &str, version: &str, zips: &[&str]) -> Selection {
        match self.workspace {
            Some(ws) => ws.selection(module, version),
            None => {
                let root = self.root.unwrap_or_default();
                go_build_list::select(
                    go_mod_edit::prunes_module_graph(root),
                    self.required.get(module).map(String::as_str),
                    zips,
                    version,
                )
            }
        }
    }
}

/// The `go.work` in effect, as discovery reads it.
struct Workspace {
    /// Members outside the root, or whose go.mod is unreadable, carry no
    /// go.mod, which leaves every selection unknown.
    model: GoWorkspace,
    /// `(root-relative dir, index into model.members)` of in-root members.
    in_root: Vec<(String, usize)>,
    /// The sum files go verifies against in workspace mode: `go.work.sum`
    /// and each member's `go.sum` (the root's only when `.` is a member).
    sum_files: Vec<String>,
}

async fn read_workspace(
    ctx: &DiscoverCtx<'_>,
    out: &mut Discovery,
    go_mod: Option<&str>,
    go_work: &str,
) -> Workspace {
    let mut members = Vec::new();
    let mut in_root = Vec::new();
    let mut sum_files = vec![GO_WORK_SUM.to_string()];
    for raw in go_mod_edit::parse_use_dirs(go_work) {
        let Some(dir) = in_root_dir(&raw) else {
            members.push(Member {
                dir: raw.into(),
                go_mod: None,
                go_sum: None,
            });
            continue;
        };
        let text = if dir.is_empty() {
            go_mod.map(str::to_string)
        } else {
            let rel = member_file(&dir, GO_MOD);
            match ctx.read_text(&rel, out).await {
                Some(text) => parse_go_file(&rel, &text, out),
                None => None,
            }
        };
        let sum = member_file(&dir, GO_SUM);
        let go_sum = ctx.read_text(&sum, out).await;
        if !sum_files.contains(&sum) {
            sum_files.push(sum);
        }
        in_root.push((dir.clone(), members.len()));
        members.push(Member {
            dir: dir.into(),
            go_mod: text,
            go_sum,
        });
    }
    let work_sum = ctx.read_text(GO_WORK_SUM, out).await;
    let mut model = GoWorkspace {
        work_file: GO_WORK.into(),
        work: go_work.to_string(),
        work_sum,
        members,
        graph: None,
    };
    if let Some(root) = ctx.disk_root() {
        let mut on_disk = model.clone();
        on_disk.work_file = root.join(GO_WORK);
        for member in &mut on_disk.members {
            member.dir = root.join(&member.dir);
        }
        on_disk.read_graph().await;
        model.graph = on_disk.graph;
    }
    Workspace {
        model,
        in_root,
        sum_files,
    }
}

/// Normalize a go.mod-grammar file (BOM, simple string literals) and check
/// its block structure; `None` (with a diagnostic) when go could not parse
/// it at all.
fn parse_go_file(file: &str, text: &str, out: &mut Discovery) -> Option<String> {
    let text = normalize_for_read(text);
    if let Some(problem) = block_structure_error(&text) {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file}: {problem}; no patched modules read from it"),
        );
        return None;
    }
    Some(text)
}

/// Emit the refs of one parsed file's Socket-owned `replace` directives.
fn extract_file(
    out: &mut Discovery,
    file: &str,
    entries: &[ReplaceEntry],
    graph: &Graph<'_>,
    sums: &SumPins,
) {
    let required = &graph.required;
    // Versioned directives of ANY owner: they shadow a version-less replace
    // of the same module at that version.
    let versioned: HashSet<(&str, &str)> = entries
        .iter()
        .filter_map(|e| Some((e.module.as_str(), e.version.as_deref()?)))
        .collect();
    for entry in entries {
        match entry.owner {
            Some(ReplaceOwner::Hosted) => {
                let Some(rhs) = entry.rhs_module.as_deref() else {
                    continue;
                };
                let Some(uuid) = hosted_module_uuid(rhs) else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {}: `{rhs}` is not a Socket patch module \
                             (`{HOSTED_GO_MODULE_PREFIX}<patch-uuid>`)",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(rhs_version) = entry
                    .rhs_version
                    .as_deref()
                    .filter(|v| is_safe_single_segment(v))
                else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {rhs}: missing or unsafe replacement version",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(purl) = replaced_purl(entry, graph, &versioned, file, out) else {
                    continue;
                };
                // `replaced_purl` resolved the version from one of the two.
                let req = required.get(&entry.module).map(String::as_str);
                let version = entry.version.as_deref().or(req).unwrap_or_default();
                let zips = sums.zip_versions(&entry.module);
                let selected = graph.select(&entry.module, version, &zips);
                let pin = sums.pin(rhs, rhs_version);
                // Outside a workspace the socket module's zip line shows it
                // is the one built; in one, another member may raise the
                // module above the replaced version all the same.
                let proven = matches!(pin, SumPin::Zip(_)) && graph.workspace.is_none();
                if let Some(other) = selected.other_version().filter(|_| !proven) {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} {version} is inert: the build selects \
                             {other}, so it uses the unpatched module",
                            entry.module
                        ),
                    );
                    continue;
                }
                let (integrity, integrity_required) = match pin {
                    SumPin::Zip(h1) => (Some(LockIntegrity::GoH1(h1)), true),
                    // MVS reads (and go.sum keeps the `/go.mod` line of)
                    // versions it does not select, and a workspace build
                    // keeps no member's `require` tidy: there nothing read
                    // here proves the replaced version is the one built.
                    SumPin::GoModOnly => (None, graph.workspace.is_some()),
                    SumPin::Unpinned => (None, true),
                };
                let url = format!("{rhs}@{rhs_version}");
                out.push(PatchedRef::hosted(
                    purl,
                    uuid,
                    file,
                    Some(url.as_str()),
                    integrity,
                    integrity_required,
                ));
            }
            Some(ReplaceOwner::Vendor) => {
                let Some(path) = entry.path.as_deref() else {
                    continue;
                };
                // A member go.mod's path is relative to the member, never
                // the project-root vendor tree.
                let anchored = match file.rsplit_once('/') {
                    Some((dir, _)) => format!("./{dir}/{}", path.trim_start_matches("./")),
                    None => path.to_string(),
                };
                let Some(vref) = vendor_ref(&anchored).filter(|v| v.eco == "golang") else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {path}: not a project-root \
                             `./.socket/vendor/golang/<patch-uuid>/<module>@<version>` path",
                            entry.module
                        ),
                    );
                    continue;
                };
                let Some(purl) = replaced_purl(entry, graph, &versioned, file, out) else {
                    continue;
                };
                if vendored_leaf_purl("golang", &vref.leaf).as_deref() != Some(purl.as_str()) {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: replace {} => {path}: the vendored copy does not name {purl}",
                            entry.module
                        ),
                    );
                    continue;
                }
                out.push(PatchedRef::vendored(purl, &vref, file, None));
            }
            // Socket-shaped but not something we write (another tree's copy,
            // an absolute path, a malformed hosted module): diagnosed, never a ref.
            None if is_foreign_socket_target(entry) => {
                let target = entry
                    .path
                    .as_deref()
                    .or(entry.rhs_module.as_deref())
                    .unwrap_or_default();
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: replace {} => {target}: not a project-root \
                         `./.socket/vendor/golang/<patch-uuid>/<module>@<version>` path or \
                         `{HOSTED_GO_MODULE_PREFIX}<patch-uuid>` module",
                        entry.module
                    ),
                );
            }
            // `.socket/go-patches/` carries no uuid; user replaces are not ours.
            Some(ReplaceOwner::GoPatches) | None => {}
        }
    }
}

/// A replace target no socket backend owns that still names Socket's vendor
/// tree or hosted module namespace.
fn is_foreign_socket_target(entry: &ReplaceEntry) -> bool {
    entry
        .path
        .as_deref()
        .is_some_and(|p| p.replace('\\', "/").contains(".socket/vendor/golang/"))
        || entry
            .rhs_module
            .as_deref()
            .is_some_and(|m| m.starts_with(HOSTED_GO_MODULE_PREFIX))
}

/// `pkg:golang/<M>@<v>` for the module a Socket `replace` substitutes, with
/// the version the build actually applies it at — or `None` (diagnosed)
/// when the directive is inert or its version is unknowable.
fn replaced_purl(
    entry: &ReplaceEntry,
    graph: &Graph<'_>,
    versioned: &HashSet<(&str, &str)>,
    file: &str,
    out: &mut Discovery,
) -> Option<String> {
    let module = entry.module.as_str();
    let req = graph.required.get(module).map(String::as_str);
    let basis = if graph.workspace.is_some() {
        "the workspace requires"
    } else {
        "go.mod requires"
    };
    let version = match (entry.version.as_deref(), req) {
        (Some(v), Some(r)) if v != r => {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: replace {module} {v} is inert: {basis} {module} {r}, \
                     so the build uses the unpatched module"
                ),
            );
            return None;
        }
        (Some(v), _) => v,
        (None, Some(r)) if versioned.contains(&(module, r)) => {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: version-less replace {module} is inert: another replace pins \
                     {module} {r}, the required version"
                ),
            );
            return None;
        }
        (None, Some(r)) => r,
        (None, None) => {
            out.diag(
                DIAG_REF_UNATTRIBUTABLE,
                file,
                format!(
                    "{file}: version-less replace {module} and no require for it: cannot tell \
                     which version is patched"
                ),
            );
            return None;
        }
    };
    let purl = golang_purl(module, version);
    if purl.is_none() {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: replace {module} {version}: unsafe module coordinates"),
        );
    }
    purl
}

/// go.sum pins of Socket hosted modules, keyed `(module, version)`, from
/// every sum file go verifies against.
#[derive(Default)]
struct SumPins {
    /// Zip-line `h1:` hashes.
    zip: HashMap<(String, String), BTreeSet<String>>,
    /// `/go.mod`-line `h1:` hashes.
    gomod: HashMap<(String, String), BTreeSet<String>>,
    /// Keys with an `h1:` hash that is not a dirhash: go fails the
    /// comparison with a `SECURITY ERROR`.
    malformed: HashSet<(String, String)>,
    /// A sum file has a line go cannot parse, so every build fails.
    unparseable: bool,
    /// Every module's zip-line versions (the build-list evidence).
    zip_versions: HashMap<String, Vec<String>>,
}

/// What the sum files pin for one Socket `module@version`.
#[derive(Debug, PartialEq, Eq)]
enum SumPin {
    /// Both lines: the zip line's `h1:`.
    Zip(String),
    /// Only the `/go.mod` line (`go mod tidy` pruned the zip line).
    GoModOnly,
    Unpinned,
}

impl SumPins {
    async fn read(ctx: &DiscoverCtx<'_>, out: &mut Discovery, files: &[String]) -> Self {
        let mut pins = SumPins::default();
        for file in files {
            if let Some(text) = ctx.read_text(file, out).await {
                pins.add(&text, file != GO_WORK_SUM);
            }
        }
        pins
    }

    /// `selects`: whether the file's zip lines show what the build selects.
    /// go only ever appends to `go.work.sum`, so its lines outlive the
    /// requirement that raised a module.
    fn add(&mut self, text: &str, selects: bool) {
        // go rejects a whole go.sum with any non-blank line of other than
        // three tokens (only `go mod tidy` skips it).
        if text
            .lines()
            .any(|l| !matches!(l.split_whitespace().count(), 0 | 3))
        {
            self.unparseable = true;
            return;
        }
        for line in go_sum_lines(text) {
            if !line.go_mod && selects {
                self.zip_versions
                    .entry(line.module.to_string())
                    .or_default()
                    .push(line.version.to_string());
            }
            // go ignores hashes of algorithms it does not know.
            if !line.module.starts_with(HOSTED_GO_MODULE_PREFIX) || !line.hash.starts_with("h1:") {
                continue;
            }
            let key = (line.module.to_string(), line.version.to_string());
            if !is_h1_dirhash(line.hash) {
                self.malformed.insert(key);
            } else if line.go_mod {
                self.gomod
                    .entry(key)
                    .or_default()
                    .insert(line.hash.to_string());
            } else {
                self.zip
                    .entry(key)
                    .or_default()
                    .insert(line.hash.to_string());
            }
        }
    }

    /// The pin of `module@version`: one unambiguous `/go.mod` hash, and at
    /// most one zip hash.
    fn pin(&self, module: &str, version: &str) -> SumPin {
        let key = (module.to_string(), version.to_string());
        let one = |hashes: Option<&BTreeSet<String>>| match hashes {
            Some(h) if h.len() == 1 => h.iter().next().cloned(),
            _ => None,
        };
        if self.unparseable || self.malformed.contains(&key) || one(self.gomod.get(&key)).is_none()
        {
            return SumPin::Unpinned;
        }
        match self.zip.get(&key) {
            None => SumPin::GoModOnly,
            some => one(some).map_or(SumPin::Unpinned, SumPin::Zip),
        }
    }

    fn zip_versions(&self, module: &str) -> Vec<&str> {
        self.zip_versions
            .get(module)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

fn member_file(dir: &str, file: &str) -> String {
    match dir {
        "" => file.to_string(),
        dir => format!("{dir}/{file}"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;
    use crate::vendor::go_mod_edit::{
        ensure_replace_entry, replace_target_path, upsert_hosted_replace_entry,
        HOSTED_GO_MODULE_PREFIX,
    };

    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
    /// The committed hosted fixture's patch uuid (grant token `1111…`).
    const FIXTURE_UUID: &str = "55555555-5555-5555-5555-555555555555";
    const FIXTURE_ZIP_H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";
    const ZIP_H1: &str = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const MOD_H1: &str = "h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    const BASE_GO_MOD: &str =
        "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n";

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract_with(c, o, true)))
            .await
    }

    async fn gowork_off(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract_with(c, o, false)))
            .await
    }

    fn gopatch(uuid: &str) -> String {
        format!("{HOSTED_GO_MODULE_PREFIX}{uuid}")
    }

    fn go_sum_for(uuid: &str, sver: &str) -> String {
        let m = gopatch(uuid);
        format!("{m} {sver} {ZIP_H1}\n{m} {sver}/go.mod {MOD_H1}\n")
    }

    fn vendored_rel(uuid: &str) -> String {
        format!(".socket/vendor/golang/{uuid}/{MODULE}@{VERSION}")
    }

    /// Exactly the go.mod the `vendor` backend writes (its own upsert).
    async fn vendored_project(uuid: &str, base: &str) -> Project {
        let p = Project::new();
        p.write("go.mod", base);
        let base_rel = format!(".socket/vendor/golang/{uuid}");
        assert!(
            ensure_replace_entry(p.root(), MODULE, VERSION, &base_rel, false)
                .await
                .expect("vendor upsert")
        );
        p
    }

    #[tokio::test]
    async fn golden_hosted_fixture_yields_the_patch_uuid_with_its_go_sum_pin() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/expected");
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, FIXTURE_UUID, WiringMode::Hosted)]);
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("go.mod"));
        assert!(r.integrity_required);
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::GoH1(FIXTURE_ZIP_H1.to_string()))
        );
        assert!(r.lockfile_basis_ok());
        assert_eq!(
            r.url.as_deref(),
            Some(format!("{}@v1.4.2-socketpatch.1", gopatch(FIXTURE_UUID)).as_str())
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn golden_hosted_input_has_no_refs() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/input");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn hosted_rewriter_output_is_recognized_single_line_and_in_block() {
        // The rewriter's own upsert, appended and refreshed inside a block.
        let appended = upsert_hosted_replace_entry(
            BASE_GO_MOD,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.2",
        )
        .unwrap()
        .unwrap();
        let in_block = format!(
            "{BASE_GO_MOD}\nreplace (\n\tgithub.com/x/y v1.0.0 => ../y\n\t{MODULE} {VERSION} => ./.socket/go-patches/{MODULE}@{VERSION}\n)\n"
        );
        let refreshed = upsert_hosted_replace_entry(
            &in_block,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.2",
        )
        .unwrap()
        .unwrap();
        assert!(refreshed.contains(&format!("\t{MODULE} {VERSION} => {}", gopatch(UUID_A))));
        for go_mod in [appended, refreshed] {
            let p = Project::new();
            p.write("go.mod", &go_mod)
                .write("go.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.2"));
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            assert!(out.refs[0].lockfile_basis_ok(), "{go_mod}");
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    /// A go.sum line of fewer or more than three tokens is not a line go
    /// (or the rewriter) writes, so it is never the pin.
    #[tokio::test]
    async fn go_sum_lines_with_the_wrong_token_count_are_not_the_pin() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n");
        for go_sum in [
            format!("{m} {sver} {ZIP_H1} extra\n{m} {sver}/go.mod {MOD_H1}\n"),
            format!("{m} {sver}\n{m} {sver}/go.mod {MOD_H1}\n"),
            format!("{m} {sver} {ZIP_H1}\n{m} {sver}/go.mod {MOD_H1} // x\n"),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod).write("go.sum", &go_sum);
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.refs[0].locked_integrity, None, "{go_sum:?}");
            assert!(!out.refs[0].lockfile_basis_ok(), "{go_sum:?}");
        }
    }

    /// `go mod tidy` keeps only the `/go.mod` line of a replaced module whose
    /// packages nothing imports, and the build stays green: that line alone
    /// is the pin, with nothing to lock the (never fetched) zip to. Not in a
    /// workspace, whose selection go.mod cannot show.
    #[tokio::test]
    async fn tidy_pruned_zip_line_leaves_a_go_mod_line_pin() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n");
        for (file, sum_file) in [("go.mod", "go.sum"), ("go.work", "go.work.sum")] {
            let p = Project::new();
            if file == "go.mod" {
                p.write("go.mod", &go_mod);
            } else {
                p.write("go.mod", BASE_GO_MOD).write(
                    "go.work",
                    format!("go 1.21\n\nuse .\n\nreplace {MODULE} {VERSION} => {m} {sver}\n"),
                );
            }
            p.write(sum_file, format!("{m} {sver}/go.mod {MOD_H1}\n"));
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            let r = &out.refs[0];
            let attests = file == "go.mod";
            assert_eq!(r.locked_integrity, None, "{file}");
            assert_eq!(r.integrity_required, !attests, "{file}");
            assert_eq!(r.lockfile_basis_ok(), attests, "{file}");
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    #[tokio::test]
    async fn hosted_pin_requires_the_go_mod_line_and_one_hash_per_line() {
        let m = gopatch(UUID_A);
        let go_mod =
            format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} v1.4.2-socketpatch.1\n");
        for go_sum in [
            // No go.sum at all.
            None,
            // Zip line only.
            Some(format!("{m} v1.4.2-socketpatch.1 {ZIP_H1}\n")),
            // Conflicting zip hashes (a union-merged go.sum).
            Some(format!(
                "{}{m} v1.4.2-socketpatch.1 {MOD_H1}\n",
                go_sum_for(UUID_A, "v1.4.2-socketpatch.1")
            )),
            // Conflicting `/go.mod` hashes, with and without the zip line.
            Some(format!(
                "{}{m} v1.4.2-socketpatch.1/go.mod {ZIP_H1}\n",
                go_sum_for(UUID_A, "v1.4.2-socketpatch.1")
            )),
            Some(format!(
                "{m} v1.4.2-socketpatch.1/go.mod {MOD_H1}\n{m} v1.4.2-socketpatch.1/go.mod {ZIP_H1}\n"
            )),
            // Pinned at another socket version (both lines, or the tidy
            // `/go.mod` line).
            Some(go_sum_for(UUID_A, "v1.4.2-socketpatch.9")),
            Some(format!("{m} v1.4.2-socketpatch.9/go.mod {MOD_H1}\n")),
            // Malformed hash, on either line.
            Some(format!(
                "{m} v1.4.2-socketpatch.1 h1:short\n{m} v1.4.2-socketpatch.1/go.mod {MOD_H1}\n"
            )),
            Some(format!(
                "{}{m} v1.4.2-socketpatch.1/go.mod h1:short\n",
                go_sum_for(UUID_A, "v1.4.2-socketpatch.1")
            )),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            if let Some(sum) = &go_sum {
                p.write("go.sum", sum);
            }
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            let r = &out.refs[0];
            assert_eq!(r.locked_integrity, None, "{go_sum:?}");
            assert!(r.integrity_required);
            assert!(!r.lockfile_basis_ok(), "{go_sum:?}");
        }
    }

    #[tokio::test]
    async fn vendored_backend_output_is_recognized() {
        let p = vendored_project(UUID_B, BASE_GO_MOD).await;
        let go_mod = std::fs::read_to_string(p.root().join("go.mod")).unwrap();
        assert!(go_mod.contains(&format!(
            "replace {MODULE} {VERSION} => ./{}",
            vendored_rel(UUID_B)
        )));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
        let r = &out.refs[0];
        assert_eq!(
            r.artifact_rel.as_deref(),
            Some(vendored_rel(UUID_B).as_str())
        );
        assert_eq!(r.source_file, std::path::PathBuf::from("go.mod"));
        assert!(!r.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        // `replace_target_path` is the one shape both agree on.
        assert_eq!(
            replace_target_path(&format!(".socket/vendor/golang/{UUID_B}"), MODULE, VERSION),
            format!("./{}", vendored_rel(UUID_B))
        );
    }

    #[tokio::test]
    async fn vendor_takeover_of_hosted_replace_leaves_only_the_vendored_ref() {
        let hosted = upsert_hosted_replace_entry(
            BASE_GO_MOD,
            MODULE,
            VERSION,
            &gopatch(UUID_A),
            "v1.4.2-socketpatch.1",
        )
        .unwrap()
        .unwrap();
        let p = vendored_project(UUID_B, &hosted).await;
        // The stale go.sum lines survive a takeover; they pin nothing.
        p.write("go.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.1"));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn crlf_bom_tabs_quotes_and_block_members_are_tolerated() {
        let a = gopatch(UUID_A);
        let go_mod = format!(
            "\u{feff}module example.com/app\r\n\r\ngo 1.21\r\n\r\nrequire (\r\n\t{MODULE} {VERSION} // indirect\r\n\tgithub.com/b/c v0.1.0\r\n)\r\n\r\nreplace(\r\n\t\"{MODULE}\"\t{VERSION}\t=>\t`{a}` \"v1.4.2-socketpatch.1\" // socket\r\n\tgithub.com/b/c v0.1.0 => .\\.socket\\vendor\\golang\\{UUID_B}\\github.com\\b\\c@v0.1.0\r\n)\r\n"
        );
        let p = Project::new();
        p.write("go.mod", go_mod).write(
            "go.sum",
            go_sum_for(UUID_A, "v1.4.2-socketpatch.1").replace('\n', "\r\n"),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (PURL, UUID_A, WiringMode::Hosted),
                (
                    "pkg:golang/github.com/b/c@v0.1.0",
                    UUID_B,
                    WiringMode::Vendored,
                ),
            ],
        );
        let hosted = out
            .refs
            .iter()
            .find(|r| r.mode == WiringMode::Hosted)
            .unwrap();
        assert!(hosted.lockfile_basis_ok());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn go_work_replaces_are_read_with_go_work_sum_pins() {
        let p = Project::new();
        p.write("go.mod", BASE_GO_MOD)
            .write(
                "go.work",
                format!(
                    "go 1.21\n\nuse .\n\nreplace {MODULE} {VERSION} => {} v1.4.2-socketpatch.1\n",
                    gopatch(UUID_A)
                ),
            )
            .write("go.work.sum", go_sum_for(UUID_A, "v1.4.2-socketpatch.1"));
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("go.work"));
        assert!(r.lockfile_basis_ok());
    }

    /// In workspace mode go verifies against every member's go.sum, so the
    /// zip line may live there; a member outside the root is not read.
    #[tokio::test]
    async fn workspace_member_go_sum_holds_the_zip_line() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n");
        for (use_dir, member_sum, pinned) in [
            ("./svc", "svc/go.sum", true),
            ("svc/", "svc/go.sum", true),
            ("../svc", "../svc/go.sum", false),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod)
                .write(
                    "go.work",
                    format!("go 1.21\n\nuse (\n\t.\n\t{use_dir}\n)\n"),
                )
                .write("go.sum", format!("{m} {sver}/go.mod {MOD_H1}\n"));
            if pinned {
                p.write(member_sum, format!("{m} {sver} {ZIP_H1}\n"));
            }
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            let r = &out.refs[0];
            if pinned {
                assert_eq!(
                    r.locked_integrity,
                    Some(LockIntegrity::GoH1(ZIP_H1.to_string())),
                    "{use_dir}"
                );
                assert!(r.integrity_required);
                assert!(r.lockfile_basis_ok(), "{use_dir}");
            } else {
                assert_eq!(r.locked_integrity, None, "{use_dir}");
                // Nor can its `require` show the `/go.mod` line's version
                // is the one the workspace selects.
                assert!(!r.lockfile_basis_ok(), "{use_dir}");
            }
        }
    }

    /// A workspace builds the union of its members' requirements, and a
    /// member's dependency can raise the module past every `require` while
    /// go writes the missing sums to `go.work.sum` itself: a `/go.mod`-only
    /// pin there is never the basis, and a higher `require` makes it
    /// inert. A sum file's zip line does not: go never drops one from
    /// `go.work.sum` once nothing raises the module any more, and a
    /// member's go.sum may be as stale.
    #[tokio::test]
    async fn workspace_go_mod_only_pin_is_never_the_basis() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let svc = |go: &str, require: &str| format!("module example.com/svc\n\ngo {go}\n{require}");
        let req = |v: &str| format!("\nrequire {MODULE} {v}\n");
        let zip = |v: &str| format!("{MODULE} {v} {ZIP_H1}\n{MODULE} {v}/go.mod {MOD_H1}\n");
        let mid = "\nrequire example.com/mid v1.0.0\n";
        for (name, uses, svc_mod, svc_sum, work_sum, inert) in [
            (
                "member requires it too",
                ". ./svc",
                Some(svc("1.21", &req(VERSION))),
                None,
                None,
                false,
            ),
            (
                "member does not require it",
                ". ./svc",
                Some(svc("1.21", "")),
                None,
                None,
                false,
            ),
            (
                "member requires a lower version",
                ". ./svc",
                Some(svc("1.21", &req("v1.4.1"))),
                None,
                None,
                false,
            ),
            (
                "member's dependency, sums not yet written",
                ". ./svc",
                Some(svc("1.21", mid)),
                None,
                None,
                false,
            ),
            (
                "member's dependency, go.work.sum written",
                ". ./svc",
                Some(svc("1.21", mid)),
                None,
                Some(zip("v1.5.0")),
                false,
            ),
            (
                "stale go.work.sum zip line, member requires it",
                ". ./svc",
                Some(svc("1.21", &req(VERSION))),
                None,
                Some(zip("v1.5.0")),
                false,
            ),
            (
                "member's dependency, member go.sum",
                ". ./svc",
                Some(svc("1.21", mid)),
                Some(zip("v1.5.0")),
                None,
                false,
            ),
            (
                "member requires a higher version",
                ". ./svc",
                Some(svc("1.21", &req("v1.5.0"))),
                Some(zip("v1.5.0")),
                None,
                true,
            ),
            (
                "go 1.16 member builds a higher zip",
                ". ./svc",
                Some(svc("1.16", &req("v1.4.1"))),
                Some(zip("v1.5.0")),
                None,
                false,
            ),
            (
                "only a higher /go.mod line",
                ". ./svc",
                Some(svc("1.21", mid)),
                None,
                Some(format!("{MODULE} v1.5.0/go.mod {MOD_H1}\n")),
                false,
            ),
            ("member go.mod missing", ". ./svc", None, None, None, false),
            (
                "member outside the root",
                ". ../svc",
                None,
                None,
                None,
                false,
            ),
            (
                "member outside the root, higher zip",
                ". ../svc",
                None,
                None,
                Some(zip("v1.5.0")),
                false,
            ),
            (
                "root not a member",
                "./svc",
                Some(svc("1.21", &req(VERSION))),
                None,
                None,
                false,
            ),
            (
                "root not a member, nothing requires it",
                "./svc",
                Some(svc("1.21", "")),
                None,
                None,
                false,
            ),
        ] {
            let p = Project::new();
            p.write("go.mod", BASE_GO_MOD)
                .write(
                    "go.work",
                    format!(
                        "go 1.21\n\nuse (\n{}\n)\n\nreplace {MODULE} {VERSION} => {m} {sver}\n",
                        uses.replace(' ', "\n")
                    ),
                )
                .write(
                    "go.work.sum",
                    format!(
                        "{m} {sver}/go.mod {MOD_H1}\n{}",
                        work_sum.unwrap_or_default()
                    ),
                );
            if let Some(text) = &svc_mod {
                p.write("svc/go.mod", text);
            }
            if let Some(text) = &svc_sum {
                p.write("svc/go.sum", text);
            }
            let out = run(&p).await;
            if inert {
                assert_refs(&out, &[]);
                assert_eq!(out.diagnostics.len(), 1, "{name}");
                assert_eq!(out.diagnostics[0].code, DIAG_REF_INVALID, "{name}");
                assert!(
                    out.diagnostics[0].detail.contains("v1.5.0"),
                    "{name}: {:?}",
                    out.diagnostics
                );
            } else {
                assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
                assert!(out.refs[0].integrity_required, "{name}");
                assert!(!out.refs[0].lockfile_basis_ok(), "{name}");
                assert_eq!(out.refs[0].locked_integrity, None, "{name}");
                assert!(out.diagnostics.is_empty(), "{name}: {:?}", out.diagnostics);
            }
        }
    }

    /// A workspace's sum files are only appended to, so the socket zip line
    /// can outlive the build that wrote it: a member that requires a higher
    /// version makes even a zip-pinned replace inert.
    #[tokio::test]
    async fn workspace_zip_pin_is_inert_under_a_higher_member_require() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        for (member_version, inert) in [(VERSION, false), ("v1.4.1", false), ("v1.5.0", true)] {
            let p = Project::new();
            p.write("go.mod", BASE_GO_MOD)
                .write(
                    "go.work",
                    format!(
                        "go 1.21\n\nuse (\n\t.\n\t./svc\n)\n\nreplace {MODULE} {VERSION} => {m} {sver}\n"
                    ),
                )
                .write(
                    "go.work.sum",
                    format!("{m} {sver} {ZIP_H1}\n{m} {sver}/go.mod {MOD_H1}\n"),
                )
                .write(
                    "svc/go.mod",
                    format!("module example.com/svc\n\ngo 1.21\n\nrequire {MODULE} {member_version}\n"),
                );
            let out = run(&p).await;
            if inert {
                assert_refs(&out, &[]);
                assert_eq!(out.diagnostics.len(), 1, "{member_version}");
                assert_eq!(out.diagnostics[0].code, DIAG_REF_INVALID);
                let detail = &out.diagnostics[0].detail;
                assert!(
                    detail.contains("is inert") && detail.contains("v1.5.0"),
                    "{detail}"
                );
            } else {
                assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
                assert_eq!(
                    out.refs[0].locked_integrity,
                    Some(LockIntegrity::GoH1(ZIP_H1.to_string())),
                    "{member_version}"
                );
                assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
            }
        }
    }

    /// go verifies against the sum files of the mode it builds in: in
    /// workspace mode `go.work.sum` and the members' go.sum (the root's only
    /// when `.` is a member); under `GOWORK=off` the root go.sum alone, with
    /// go.work and its replaces ignored.
    #[tokio::test]
    async fn sum_files_follow_the_build_mode() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let pair = go_sum_for(UUID_A, sver);
        let replace = format!("replace {MODULE} {VERSION} => {m} {sver}\n");
        let svc = format!("module example.com/svc\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n");
        let pinned = |out: &Discovery| {
            assert_refs(out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            out.refs[0].locked_integrity.is_some()
        };

        // Root not a member: its go.sum is not consulted.
        let p = Project::new();
        p.write("go.mod", BASE_GO_MOD)
            .write("go.work", format!("go 1.21\n\nuse ./svc\n\n{replace}"))
            .write("svc/go.mod", &svc)
            .write("go.sum", &pair);
        let out = run(&p).await;
        assert!(!pinned(&out));
        assert!(!out.refs[0].lockfile_basis_ok());
        p.write("svc/go.sum", &pair);
        assert!(pinned(&run(&p).await));

        // GOWORK=off: the go.work replace does not apply at all.
        let p = Project::new();
        p.write("go.mod", BASE_GO_MOD)
            .write("go.work", format!("go 1.21\n\nuse .\n\n{replace}"))
            .write("go.work.sum", &pair)
            .write("go.sum", &pair);
        assert_refs(&gowork_off(&p).await, &[]);
        // A go.mod replace is pinned by the root go.sum only.
        let p = Project::new();
        p.write("go.mod", format!("{BASE_GO_MOD}\n{replace}"))
            .write("go.work", "go 1.21\n\nuse .\n")
            .write("go.work.sum", &pair);
        assert!(!pinned(&gowork_off(&p).await));
        p.write("go.sum", &pair);
        assert!(pinned(&gowork_off(&p).await));
    }

    /// In a go < 1.17 graph MVS keeps the `/go.mod` line of a version it only
    /// reads: a `/go.mod`-only pin whose version go.sum shows is not the one
    /// selected is inert.
    #[tokio::test]
    async fn go_mod_line_only_pin_of_an_unselected_version_is_inert() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!(
            "module example.com/app\n\ngo 1.16\n\nrequire example.com/mid v1.0.0\n\n\
             replace {MODULE} {VERSION} => {m} {sver}\n"
        );
        let pin = format!("{m} {sver}/go.mod {MOD_H1}\n");
        for (extra, inert) in [
            (
                format!("{MODULE} v1.5.0 {ZIP_H1}\n{MODULE} v1.5.0/go.mod {MOD_H1}\n"),
                true,
            ),
            (format!("{MODULE} v1.5.0/go.mod {MOD_H1}\n"), false),
            (format!("{MODULE} v1.4.1 {ZIP_H1}\n"), true),
            (String::new(), false),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod)
                .write("go.sum", format!("{extra}{pin}"));
            let out = run(&p).await;
            if inert {
                assert_refs(&out, &[]);
                assert_eq!(out.diagnostics.len(), 1, "{extra}");
                assert_eq!(out.diagnostics[0].code, DIAG_REF_INVALID);
                assert!(out.diagnostics[0].detail.contains("is inert"));
            } else {
                assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
                assert!(out.refs[0].lockfile_basis_ok(), "{extra}");
            }
        }
        // With the zip line the socket module is loaded, so it is selected.
        let p = Project::new();
        p.write("go.mod", &go_mod).write(
            "go.sum",
            format!("{MODULE} v1.5.0 {ZIP_H1}\n{}", go_sum_for(UUID_A, sver)),
        );
        assert_refs(&run(&p).await, &[(PURL, UUID_A, WiringMode::Hosted)]);
    }

    /// go rejects a whole go.sum over one line of the wrong token count, and
    /// ignores hashes of algorithms it does not know.
    #[tokio::test]
    async fn sum_file_parse_rules_follow_go() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let go_mod = format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n");
        let pair = go_sum_for(UUID_A, sver);
        for (go_sum, pinned) in [
            (format!("a.com/x v1.0.0 h1:x= extra\n{pair}"), false),
            (format!("a.com/x v1.0.0\n{pair}"), false),
            (format!("\n  \n{pair}"), true),
            (format!("{pair}{m} {sver} h2:whatever\n"), true),
            (format!("{pair}{m} {sver}/go.mod h1:short\n"), false),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod).write("go.sum", &go_sum);
            let out = run(&p).await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.refs[0].lockfile_basis_ok(), pinned, "{go_sum:?}");
            assert_eq!(out.refs[0].locked_integrity.is_some(), pinned, "{go_sum:?}");
        }
    }

    #[tokio::test]
    async fn go_mod_and_go_work_both_wiring_emit_both_refs() {
        // Rule 10: no cross-file precedence — the CLI gates the conflict.
        let p = vendored_project(UUID_B, BASE_GO_MOD).await;
        p.write(
            "go.work",
            format!(
                "go 1.21\nuse .\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                (PURL, UUID_A, WiringMode::Hosted),
                (PURL, UUID_B, WiringMode::Vendored),
            ],
        );
    }

    #[tokio::test]
    async fn stale_pin_after_a_require_bump_is_inert() {
        let bumped = BASE_GO_MOD.replace("bar v1.4.2", "bar v1.5.0");
        let hosted = format!(
            "{bumped}\nreplace {MODULE} {VERSION} => {} v1.4.2-socketpatch.1\n",
            gopatch(UUID_A)
        );
        let vendored = format!(
            "{bumped}\nreplace {MODULE} {VERSION} => ./{}\n",
            vendored_rel(UUID_B)
        );
        for (go_mod, is_hosted) in [(hosted, true), (vendored, false)] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{go_mod}");
            assert!(out.diagnostics[0].detail.contains("inert"));
            assert!(out.diagnostics[0].detail.starts_with("go.mod: "));
            // The inert directive's patch is RECOGNIZED, so a ledger claim
            // for it is dead — the CLI must not re-derive "live" from the
            // uuid still sitting in go.mod's text (rule 11).
            let claim = if is_hosted {
                out.hosted_claim(PURL, UUID_A)
            } else {
                out.vendored_claim(PURL, UUID_B, &vendored_rel(UUID_B))
            };
            assert_eq!(claim, Some(false), "{go_mod}");
        }
    }

    #[tokio::test]
    async fn module_missing_from_require_is_still_emitted() {
        let go_mod = format!(
            "module example.com/app\n\ngo 1.16\n\nreplace {MODULE} {VERSION} => ./{}\n",
            vendored_rel(UUID_B)
        );
        let p = Project::new();
        p.write("go.mod", go_mod);
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn versionless_replace_takes_the_required_version() {
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} => ./{}\n",
                vendored_rel(UUID_B)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);

        // No require → unknowable version.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "module example.com/app\n\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);

        // A versioned (user) replace for the required version wins in Go.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => ../fork\nreplace {MODULE} => {} v1.4.2-socketpatch.1\n",
                gopatch(UUID_A)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn vendored_leaf_must_name_the_replaced_module_and_version() {
        for target in [
            format!("./.socket/vendor/golang/{UUID_B}/{MODULE}@v1.0.0"),
            format!("./.socket/vendor/golang/{UUID_B}/github.com/foo/other@{VERSION}"),
            format!("./.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}/sub"),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {target}\n"),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{target}");
        }
    }

    #[tokio::test]
    async fn path_traversal_and_out_of_root_targets_are_rejected() {
        let cases = [
            // Traversal inside the leaf.
            format!("replace {MODULE} {VERSION} => ./.socket/vendor/golang/{UUID_B}/../../../../etc@{VERSION}"),
            // An artifact outside the project root (detect_owner still says Vendor).
            format!("replace {MODULE} {VERSION} => ../other/.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}"),
            format!("replace {MODULE} {VERSION} => /abs/app/.socket/vendor/golang/{UUID_B}/{MODULE}@{VERSION}"),
            // Non-canonical uuid dir.
            format!("replace {MODULE} {VERSION} => ./.socket/vendor/golang/{}/{MODULE}@{VERSION}", UUID_B.to_uppercase()),
            // Traversal in the replaced module path.
            format!("replace github.com/../../evil {VERSION} => ./.socket/vendor/golang/{UUID_B}/github.com/../../evil@{VERSION}"),
            format!("replace github.com/../evil {VERSION} => {} v1.4.2-socketpatch.1", gopatch(UUID_A)),
        ];
        for line in cases {
            let p = Project::new();
            p.write("go.mod", format!("module example.com/app\n\n{line}\n"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(
                !out.diagnostics.is_empty()
                    && out.diagnostics.iter().all(|d| d.code == DIAG_REF_INVALID),
                "{line}: {:?}",
                out.diagnostics
            );
        }
    }

    #[tokio::test]
    async fn only_the_exact_socket_module_namespace_is_hosted() {
        let a = UUID_A;
        // Not ours at all: silent.
        for rhs in [
            format!("evil.example/gopatch/{a}"),
            format!("patch.socket.dev.evil.example/gopatch/{a}"),
            format!("evil.example/patch.socket.dev/gopatch/{a}"),
            "github.com/fork/bar".to_string(),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {rhs} v1.4.2\n"),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{rhs}: {:?}", out.diagnostics);
        }
        // Socket-namespaced but not something we write: diagnosed, and the
        // uuid-shaped grant token is never elected.
        for rhs in [
            format!("patch.socket.dev/gopatch/{TOKEN}/{a}"),
            format!("patch.socket.dev/gopatch/{a}/{TOKEN}"),
            "patch.socket.dev/gopatch/{{PATCH_UUID}}".to_string(),
            "patch.socket.dev/gopatch/".to_string(),
            format!("patch.socket.dev/gopatch/{}", a.to_uppercase()),
            format!("patch.socket.dev/gopatch/{a}/v1"),
            format!("patch.socket.dev/gopatch/{a}/v02"),
        ] {
            let p = Project::new();
            p.write(
                "go.mod",
                format!(
                    "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {rhs} v1.4.2-socketpatch.1\n"
                ),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{rhs}");
        }
        // Major-version suffix for v2+ originals.
        let p = Project::new();
        p.write(
            "go.mod",
            "module example.com/app\n\nrequire github.com/foo/bar/v3 v3.0.1\n\n\
             replace github.com/foo/bar/v3 v3.0.1 => patch.socket.dev/gopatch/"
                .to_string()
                + a
                + "/v3 v3.0.1-socketpatch.1\n",
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                "pkg:golang/github.com/foo/bar/v3@v3.0.1",
                a,
                WiringMode::Hosted,
            )],
        );
        // Missing replacement version (invalid go.mod) is diagnosed.
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {}\n",
                gopatch(a)
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    #[tokio::test]
    async fn registry_deps_user_replaces_and_go_patches_yield_nothing() {
        let p = Project::new();
        p.write(
            "go.mod",
            format!(
                "{BASE_GO_MOD}require github.com/x/y v1.0.0\n\nreplace (\n\tgithub.com/x/y v1.0.0 => ../y\n\t{MODULE} {VERSION} => ./.socket/go-patches/{MODULE}@{VERSION}\n)\n// replace {MODULE} {VERSION} => {} v1\n",
                gopatch(UUID_A)
            ),
        )
        .write(
            "go.sum",
            "github.com/x/y v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn malformed_go_mod_is_a_diagnostic_not_a_panic() {
        let a = gopatch(UUID_A);
        for (go_mod, code) in [
            (
                format!("module m\n\nreplace (\n\t{MODULE} {VERSION} => {a} v1\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
            (
                format!("module m\n)\nreplace {MODULE} {VERSION} => {a} v1\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
            (
                format!("module m\nreplace (\nrequire (\n{MODULE} {VERSION} => {a} v1\n)\n)\n"),
                DIAG_LOCKFILE_UNPARSEABLE,
            ),
        ] {
            let p = Project::new();
            p.write("go.mod", &go_mod);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![code], "{go_mod}");
            assert!(out.diagnostics[0].detail.starts_with("go.mod: "));
        }
        // Non-UTF-8 bytes: unreadable, not a panic.
        let p = Project::new();
        p.write("go.mod", b"module m\n\xff\xfe replace\n".as_slice());
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
        // Garbage that happens to be UTF-8: nothing, silently.
        let p = Project::new();
        p.write("go.mod", "=> => replace => \"\"\" `` \u{0}\n");
        let out = run(&p).await;
        assert_refs(&out, &[]);
    }

    #[tokio::test]
    async fn orchestrator_runs_the_golang_extractor() {
        let p = Project::new();
        p.copy_fixture("redirect/golang/gomod/basic/expected");
        let out = p.discover().await;
        assert!(out.wires(PURL, FIXTURE_UUID, WiringMode::Hosted));
    }

    /// A go.work root with no go.mod of its own: each in-root member's
    /// go.mod replace is read (its own file as the source), pinned by that
    /// member's go.sum; an out-of-root member leaves the selection unproven.
    #[tokio::test]
    async fn go_work_root_without_go_mod_reads_member_replaces() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let member = format!(
            "module example.com/a\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n\n\
             replace {MODULE} {VERSION} => {m} {sver}\n"
        );
        let p = Project::new();
        p.write("go.work", "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n")
            .write("a/go.mod", &member)
            .write("a/go.sum", go_sum_for(UUID_A, sver))
            .write(
                "b/go.mod",
                format!("module example.com/b\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
            );
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        assert_eq!(
            out.refs[0].source_file,
            std::path::PathBuf::from("a/go.mod")
        );
        assert!(out.refs[0].lockfile_basis_ok());

        // Under GOWORK=off there is no workspace and no module here.
        assert_refs(&gowork_off(&p).await, &[]);
    }

    /// An explicit `GOWORK` other than the root's go.work (another file, or a
    /// relative path go rejects) leaves the workspace unread: what discovery
    /// finds is diagnosed, never a ref.
    #[tokio::test]
    async fn gowork_naming_another_workspace_attests_nothing() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let p = Project::new();
        p.write("go.work", "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n")
            .write(
                "a/go.mod",
                format!(
                    "module example.com/a\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n\n\
                     replace {MODULE} {VERSION} => {m} {sver}\n"
                ),
            )
            .write("a/go.sum", go_sum_for(UUID_A, sver))
            .write("b/go.mod", "module example.com/b\n\ngo 1.21\n");
        let extract = |gowork: Option<String>| {
            let p = &p;
            async move {
                let ctx = p.ctx();
                let mut out = Discovery::default();
                super::extract_gowork(&ctx, &mut out, gowork.as_deref()).await;
                out
            }
        };
        let own = p.root().join("go.work").to_string_lossy().into_owned();
        for gowork in [None, Some("auto".to_string()), Some(own)] {
            let out = extract(gowork.clone()).await;
            assert_eq!(out.refs.len(), 1, "{gowork:?}: {:?}", out.diagnostics);
            assert!(
                out.diagnostics.is_empty(),
                "{gowork:?}: {:?}",
                out.diagnostics
            );
        }
        let elsewhere = p.root().join("a").join("go.work");
        for (gowork, why) in [
            ("go.work".to_string(), "not an absolute path"),
            ("/nonexistent/go.work".to_string(), "other than"),
            (elsewhere.to_string_lossy().into_owned(), "other than"),
        ] {
            let out = extract(Some(gowork.clone())).await;
            assert!(out.refs.is_empty(), "{gowork}");
            assert_eq!(out.diagnostics.len(), 1, "{gowork}: {:?}", out.diagnostics);
            assert_eq!(out.diagnostics[0].code, DIAG_REF_INVALID);
            assert!(
                out.diagnostics[0].detail.contains(why),
                "{gowork}: {:?}",
                out.diagnostics
            );
        }
        let out = extract(Some("off".to_string())).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
    }

    /// In a workspace the socket module's zip line does not prove the
    /// replaced version is built: another member requiring a higher one
    /// makes the pin inert, as for a `/go.mod`-only pin.
    #[tokio::test]
    async fn workspace_zip_pin_of_a_raised_module_is_inert() {
        let m = gopatch(UUID_A);
        let sver = "v1.4.2-socketpatch.1";
        let p = Project::new();
        p.write(
            "go.mod",
            format!("{BASE_GO_MOD}\nreplace {MODULE} {VERSION} => {m} {sver}\n"),
        )
        .write("go.sum", go_sum_for(UUID_A, sver))
        .write("go.work", "go 1.21\n\nuse (\n\t.\n\t./svc\n)\n")
        .write(
            "svc/go.mod",
            format!("module example.com/svc\n\ngo 1.21\n\nrequire {MODULE} v1.5.0\n"),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.detail.contains("is inert") && d.detail.contains("v1.5.0")),
            "{:?}",
            out.diagnostics
        );
        // Without the workspace the zip line is the proof.
        let out = gowork_off(&p).await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        assert!(out.refs[0].lockfile_basis_ok());
    }
}
