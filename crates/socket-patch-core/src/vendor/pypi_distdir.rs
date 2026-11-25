//! PyPI vendored mode for a project whose `requirements.txt` a Bazel hub
//! reads: the patched wheel as a download cache of Bazel.
//!
//! rules_python builds no wheel from the path line that vendored mode
//! writes ([`super::bazel_hub`]). It does build the line hosted mode
//! writes, `<name> @ <URL of the wheel on the patch host>
//! --hash=sha256:<hex>`: its hub fetches such a wheel with Bazel's
//! downloader, and that one takes a file of the download's name and sha256
//! from a `--distdir` before it asks a host ([`crate::bazel::distdir`]). So
//! here vendored mode writes
//!
//! 1. the package's line of `requirements.txt` as hosted mode writes it, by
//!    hosted mode's own rewriter;
//! 2. the patched wheel, fetched once, at `.socket/vendor/pypi/<uuid>/`
//!    under the name its URL ends in, with what vendored mode keeps beside
//!    every wheel;
//! 3. one `common --distdir=<that directory>` line in the `.bazelrc` at the
//!    Bazel root ([`sync_bazelrc`]).
//!
//! The build then takes the committed wheel and asks no host. The ledger
//! entry is an ordinary one of the requirements flavor whose record holds
//! the URL line in the place of the path line ([`line_of`]), so the revert
//! of that flavor puts the pin back, and lockfile discovery reads the line
//! as the wiring of that entry ([`claim`]): `list`, `vex`, `vendor
//! --check`, `rollback` and `remove` see a vendored package.
//!
//! It is written only where [`gate`] can show from the checkout that it
//! works, and the refusal of [`super::bazel_hub`] stands everywhere else.
//! Three limits come with the line being the hosted one. pip outside Bazel
//! asks the patch host for the wheel. Bazel replaces a changed or missing
//! copy from the patch host, without a message, when it can reach it.
//! And what holds the committed wheel to the patch is `vendor --check`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::bazel::{distdir, BazelRoot};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::formats::governing_locks::PYPI_REQUIREMENTS as FILE;
use crate::patch::redirect::requirements::rewrite;
use crate::patch::redirect::{grant, DepOverride, Integrity, RewriteResult};
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string, run_blocking};
use crate::utils::line_endings::split_lines;
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};
use crate::utils::purl_key::{canonical_base_purl, PurlKey};
use crate::utils::requirements::{direct_reference, logical_lines, requires_hashes, strip_comment};
use crate::vex::discover::{Discovery, Recognized, WiringMode};

use super::bazel_hub::PYPI_CODE;
use super::path::vendor_uuid_dir_rel;
use super::pypi_requirements::{one_pin, RECORD_KIND};
use super::state::{
    load_state_shared as load_state, lookup_entry, VendorEntry, WiringAction, WiringRecord,
};
use super::VendorWarning;

/// The code of the warning a run gives with the form: what it does not do.
pub const NOTICE: &str = "vendor_pypi_bazel_download_cache";

/// Whether `line` is one requirement that holds the release `purl` by a
/// URL of the patch `uuid`: the line of this form.
pub(super) fn names(line: &str, purl: &str, uuid: &str) -> bool {
    let Some((name, _)) = parse_pypi_purl(strip_purl_qualifiers(purl)) else {
        return false;
    };
    let named = |(of, url): (&str, &str)| {
        canonicalize_pypi_name(of) == canonicalize_pypi_name(&name)
            && url.split('/').any(|level| level == uuid)
    };
    !line.contains(['\n', '\r']) && direct_reference(strip_comment(line)).is_some_and(named)
}

/// The line of `requirements.txt` that `entry` wrote, when the entry is
/// one of this form.
pub fn line_of(entry: &VendorEntry) -> Option<&str> {
    let own = |rec: &&WiringRecord| rec.kind == RECORD_KIND && rec.file == FILE;
    let own = entry.wiring.iter().filter(own);
    let line = own.filter_map(|rec| rec.new.as_ref()?.as_str()).next()?;
    (entry.ecosystem == "pypi" && names(line, &entry.base_purl, &entry.uuid)).then_some(line)
}

/// Where the committed wheel is pinned, `(path, sha256)`, when the project
/// already holds the package `purl` in this form for the patch `uuid`: the
/// ledger has the entry and `requirements.txt` its line. Such a run writes
/// nothing, whatever the workspace says now.
pub(super) async fn in_sync(project: &Path, purl: &str, uuid: &str) -> Option<(String, String)> {
    let state = load_state(project).await.ok()?;
    let entry = lookup_entry(&state.entries, purl).filter(|entry| entry.uuid == uuid)?;
    let line = line_of(entry)?;
    let content = read_regular_to_string(&project.join(FILE)).await.ok()?;
    let held = logical_lines(&content)
        .iter()
        .any(|own| own.text.trim() == line.trim());
    held.then(|| (entry.artifact.path.clone(), entry.artifact.sha256.clone()))
}

/// `content` with the pin back that an older patch of `purl` replaced in
/// this form: the newer patch `uuid` is then written over that pin, and
/// records it as its own original.
async fn without_older(project: &Path, purl: &str, uuid: &str, content: String) -> String {
    let Ok(state) = load_state(project).await else {
        return content;
    };
    let older = lookup_entry(&state.entries, purl).filter(|entry| entry.uuid != uuid);
    let Some((line, older)) = older.and_then(|older| Some((line_of(older)?, older))) else {
        return content;
    };
    let pin: Option<String> = older.wiring.iter().find_map(|rec| {
        let lines = rec.original.as_ref()?.as_array()?.iter();
        lines.map(Value::as_str).collect()
    });
    let lines = split_lines(&content).into_iter();
    let restored = |(text, eol): (&str, &str)| match (text.trim() == line.trim(), &pin) {
        (true, Some(pin)) => format!("{pin}{eol}"),
        _ => format!("{text}{eol}"),
    };
    lines.map(restored).collect()
}

/// What hosted mode is granted for the release `purl`: the patch `uuid` as
/// the wheel at `url` with `sha256`. `None` for a purl that names no
/// release of a PyPI package.
fn granted(purl: &str, uuid: &str, (url, sha256): (&str, &str)) -> Option<DepOverride> {
    let (name, version) = parse_pypi_purl(strip_purl_qualifiers(purl))?;
    Some(DepOverride {
        ecosystem: "pypi".to_string(),
        name: name.to_string(),
        namespace: None,
        version: version.to_string(),
        token: String::new(),
        patch_uuid: uuid.to_string(),
        artifact_url: url.to_string(),
        npm_registry_url: None,
        registry_override: None,
        integrity: Integrity {
            sha256: Some(sha256.to_string()),
            ..Integrity::default()
        },
    })
}

/// `content` with the pin of the release `purl` as hosted mode writes it
/// for the wheel at `url` with `sha256`, and the record of that edit. Or
/// why the line is not written: hosted mode's rewriter does not pin the
/// package there, or the line would hold more than the form was measured
/// with, a name, the URL and one `--hash`.
fn planned(
    content: &str,
    purl: &str,
    uuid: &str,
    (url, sha256): (&str, &str),
) -> Result<(String, WiringRecord), String> {
    let Some(dep) = granted(purl, uuid, (url, sha256)) else {
        return Err(format!("{purl} names no release of a PyPI package"));
    };
    let (name, version) = (&dep.name, &dep.version);
    if !requires_hashes(content) {
        return Err(format!(
            "{FILE} pins no hashes, and Bazel takes a committed wheel only for a download \
             that the line gives a sha256"
        ));
    }
    let files = BTreeMap::from([(FILE.to_string(), content.to_string())]);
    let mut result = RewriteResult::default();
    rewrite(&files, std::slice::from_ref(&dep), &mut result);
    let (edit, new) = match (&result.edits[..], result.files.remove(FILE)) {
        ([edit], Some(new)) if result.warnings.is_empty() => (edit, new),
        _ => {
            let why = result.warnings.first().map(|warning| &*warning.detail);
            let why = why.unwrap_or("it holds no pin for hosted mode to rewrite");
            return Err(format!(
                "hosted mode does not pin {name}=={version} in {FILE}: {why}"
            ));
        }
    };
    let text = |value: &Option<Value>| value.as_ref().and_then(Value::as_str).map(str::to_string);
    let (original, line) = (text(&edit.original), text(&edit.new));
    let (original, line) = (original.unwrap_or_default(), line.unwrap_or_default());
    let plain = format!("{name} @ {url} --hash=sha256:{sha256}");
    if line != plain || !one_pin(&original, &canonicalize_pypi_name(name), version) {
        return Err(format!(
            "the requirement of {name}=={version} in {FILE} is more than one exact pin with its \
             hashes (extras, a marker, an option, a comment or an indent), and Bazel was \
             measured with the plain line"
        ));
    }
    // Each line of the pin with its own line break, but for the last.
    let lines = split_lines(&original).into_iter();
    let lines = lines.map(|(text, eol)| Value::String(format!("{text}{eol}")));
    let at = content
        .find(&original)
        .map_or(0, |at| content[..at].matches('\n').count());
    let record = WiringRecord {
        file: FILE.to_string(),
        kind: RECORD_KIND.to_string(),
        action: WiringAction::Rewritten,
        key: Some(format!("{FILE}:{}", at + 1)),
        original: Some(Value::Array(lines.collect())),
        new: Some(Value::String(line)),
    };
    Ok((new, record))
}

/// Why vendored mode cannot show, from the checkout, that this form works
/// for the package `purl` of `project` and its patch `uuid`, where a call
/// of the workspace `root` hands Bazel one of `locks`, the files of the
/// project a run could rewrite. `Ok` when it can:
///
/// - the project pins in `requirements.txt` alone, with no lock of a tool
///   beside it;
/// - the workspace shows that a build takes the wheel from the line
///   ([`distdir::ready`]): the hub reads that file and no other of the
///   project, the releases of rules_python and Bazel are ones it is shown
///   for, and no rc file names a downloader setting;
/// - hosted mode pins the package in that file, in a line of the measured
///   shape ([`planned`]), or the file holds a pin that hosted mode made;
/// - a line of this form that the ledger knows is still as it was written.
pub(super) async fn gate(
    project: &Path,
    root: &BazelRoot,
    locks: &[String],
    (purl, uuid): (&str, &str),
) -> Result<(), String> {
    if !super::pypi::pins_in_requirements_alone(project, purl).await {
        return Err(format!(
            "a tool's lock of this project holds the package beside {FILE}, and the form is \
             for a project that pins in {FILE} alone"
        ));
    }
    let (root, locks) = (root.clone(), locks.to_vec());
    let dir = root.dir.clone();
    run_blocking(move || distdir::ready(&root, FILE, &locks)).await?;
    rc_committed(&dir).await?;
    let content = read_regular_to_string(&project.join(FILE)).await;
    let content = content.map_err(|e| format!("{FILE} cannot be read: {e}"))?;
    let content = without_older(project, purl, uuid, content).await;
    let name = parse_pypi_purl(strip_purl_qualifiers(purl)).map(|(name, _)| name);
    let name = canonicalize_pypi_name(&name.unwrap_or_default());
    let by_url = |line: &crate::utils::requirements::LogicalLine| {
        let held = direct_reference(strip_comment(&line.text));
        held.is_some_and(|(of, _)| canonicalize_pypi_name(of) == name)
    };
    let planned = planned(&content, purl, uuid, ("-", &"0".repeat(64)));
    if planned.is_ok() || !logical_lines(&content).iter().any(by_url) {
        return planned.map(drop);
    }
    // The file holds the package by a URL. Where the ledger has the package
    // in this form, that is the line of the form, and no longer as it was
    // written ([`in_sync`] and [`without_older`] know it as written): a
    // run over it would fetch the wheel and then not write the line.
    // Elsewhere it is a pin that hosted mode made, where its URL is one of
    // a patch (which host serves it is judged with the pin): the run that
    // takes it over puts the registry's pin back first, and the line is
    // judged then ([`wire`]). Any other URL is the user's own reference,
    // which no run takes over: declined here, before anything is fetched.
    let state = load_state(project).await.unwrap_or_default();
    if lookup_entry(&state.entries, purl)
        .and_then(line_of)
        .is_some()
    {
        return Err(format!(
            "the line that socket-patch wrote for this wheel in {FILE} has been changed since: \
             put it back as it was, or run `socket-patch vendor --revert` and vendor the package \
             again"
        ));
    }
    let of_a_patch = |line: &crate::utils::requirements::LogicalLine| {
        let held = direct_reference(strip_comment(&line.text));
        // The URL of a patch names the patch's id before its file.
        let patch = |url| super::lock_inventory::pypi::hosted_artifact_url(url).ok();
        let names_patch =
            |url| patch(url).is_some_and(|at| at.uuid_level.is_some_and(|id| !id.is_empty()));
        held.is_some_and(|(of, url)| canonicalize_pypi_name(of) == name && names_patch(url))
    };
    if logical_lines(&content).iter().any(of_a_patch) {
        return Ok(());
    }
    Err(format!(
        "{FILE} names the package by a URL of its own, and the form is written over a pin of \
         one version with its hashes"
    ))
}

/// Why the `.bazelrc` at the Bazel root `dir` would not reach a fresh
/// checkout: git ignores it and does not track it. The committed wheel
/// does (its own guard asks git), but without the rc file's line a build
/// of that checkout downloads the wheel from the patch host. A tracked
/// file is never ignored, and git that cannot answer, or a root outside a
/// work tree, lets it through, as the wheel's guard does.
async fn rc_committed(dir: &Path) -> Result<(), String> {
    let rc = [".bazelrc".to_string()];
    match super::npm_dir::ignoring_rule_lines(dir, &rc, false).await {
        Ok(Some(rules)) => Err(format!(
            ".bazelrc is ignored by git and not tracked ({}), so a fresh checkout would not have \
             the line that makes Bazel take the committed wheel: commit .bazelrc or stop \
             ignoring it",
            super::npm_dir::summarize_rules(&rules)
        )),
        _ => Ok(()),
    }
}

/// Whether the file `artifact` is a wheel that every platform installs
/// (`<name>-<version>-<python>-none-any.whl`): what a build has taken from
/// a `--distdir` here. A source distribution and a wheel of one platform
/// reach the hub through other code, which no build here has run.
fn for_every_platform(artifact: &str) -> bool {
    artifact.ends_with("-none-any.whl")
}

/// Write the line of this form for the release `purl`, whose patched wheel
/// `wheel` (its file name) was fetched from `url` and has `sha256`: the
/// record of the edit, for the ledger. The URL is held to what hosted mode
/// asks of a grant, to naming the patch `uuid` on a patch host (`origins`
/// are the operator's own), and to ending in the name of the committed
/// file, by which Bazel finds it.
pub(super) async fn wire(
    project: &Path,
    purl: &str,
    uuid: &str,
    (wheel, url, sha256): (&str, &str, &str),
    origins: &[String],
) -> Result<Vec<WiringRecord>, (&'static str, String)> {
    let declined = |why: String| (PYPI_CODE, why);
    if !for_every_platform(wheel) {
        return Err(declined(format!(
            "the patch service serves {wheel}, and the form was built with a wheel for every \
             platform (`-none-any.whl`) alone, not with a source distribution or a wheel of \
             one platform"
        )));
    }
    let hosted = super::lock_inventory::pypi::hosted_pypi_reference(url, origins);
    let of_patch = hosted.is_some_and(|at| at.uuid_level.as_deref() == Some(uuid));
    if !of_patch || !url.ends_with(&format!("/{wheel}")) {
        return Err(declined(format!(
            "the patch service gave no URL for {wheel} that names the patch on a patch host \
             and ends in the name of the file"
        )));
    }
    let flaw = granted(purl, uuid, (url, sha256)).map(|dep| grant::check(&dep, origins));
    if let Some(Err(grant::Flaw::Malformed(why) | grant::Flaw::InsecureUrl(why))) = flaw {
        return Err(declined(format!(
            "hosted mode does not write the grant of the patched wheel: {why}"
        )));
    }
    let path = project.join(FILE);
    let before = read_regular_to_string(&path).await;
    let before = before.map_err(|e| declined(format!("{FILE} cannot be read: {e}")))?;
    let content = without_older(project, purl, uuid, before).await;
    let (content, record) = planned(&content, purl, uuid, (url, sha256)).map_err(declined)?;
    super::common::refuse_symlinked(project, &[FILE]).await?;
    match atomic_write_bytes_preserving_mode(&path, content.as_bytes()).await {
        Ok(()) => Ok(vec![record]),
        Err(e) => Err((
            "pypi_requirements_write_failed",
            format!("cannot write {FILE}: {e}"),
        )),
    }
}

/// What a run that wrote the form says of it: what it rests on, and the
/// three things it does not do.
pub(super) fn notice(name: &str, version: &str, wheel: &str) -> VendorWarning {
    VendorWarning::new(
        NOTICE,
        format!(
            "{name}=={version} is vendored as a download cache of Bazel: {FILE} names the \
             patched wheel by its URL on the patch host, as hosted mode does, and a \
             `--distdir` line of the .bazelrc at the Bazel root makes the build take the \
             committed copy {wheel} and ask no host: commit that file with the copy. pip \
             outside Bazel still asks the patch host. Bazel replaces a changed or missing copy \
             from the patch host, without a message, when it can reach it. `socket-patch \
             vendor --check` is what holds the committed wheel to the patch."
        ),
    )
}

/// Make the `.bazelrc` at the Bazel root of `project` agree with the
/// wheels the project has committed in this form ([`distdir::sync`]): the
/// directory of each ledger entry of the form has its line while it
/// exists. Without `add`, and with a ledger that cannot be read, lines are
/// only taken away. Outside a Bazel workspace nothing is read or written,
/// and that lookup is all the call costs. For a user who switched the
/// Bazel support off ([`crate::bazel::off`]) no line is added, as outside
/// one; the line of a directory that is gone still goes, so that the undo
/// of a download cache an earlier run wrote is whole.
pub async fn sync_bazelrc(project: &Path, add: bool) -> Result<Option<PathBuf>, String> {
    let (dir, add) = (project.to_path_buf(), add && !crate::bazel::off());
    let Some(root) = run_blocking(move || crate::bazel::root_of(&dir)).await else {
        return Ok(None);
    };
    let state = load_state(project).await.unwrap_or_default();
    let cached = state
        .entries
        .values()
        .filter(|entry| line_of(entry).is_some());
    let dirs: Vec<String> = cached
        .filter_map(|entry| vendor_uuid_dir_rel("pypi", &entry.uuid))
        .collect();
    run_blocking(move || distdir::sync(&root, &dirs, add)).await
}

/// For lockfile discovery of the project at `root`: a reference of
/// `requirements.txt` to a wheel on the patch host is the wiring of a
/// vendored copy where a ledger entry of this form wrote that line. It is
/// then a vendored reference to the entry's wheel, and what the file says
/// of the patch (its id, and the grant in its URL) names no hosted pin.
/// Without such an entry nothing changes.
pub(crate) async fn claim(root: &Path, out: &mut Discovery) {
    let line = |r: &crate::vex::discover::PatchedRef| {
        r.mode == WiringMode::Hosted && r.source_file == Path::new(FILE)
    };
    if !out.refs.iter().any(line) {
        return;
    }
    let Ok(state) = load_state(root).await else {
        return;
    };
    let Discovery {
        refs, recognized, ..
    } = out;
    for entry in state.entries.values().filter(|e| line_of(e).is_some()) {
        let key = canonical_base_purl(&entry.base_purl);
        let own = refs
            .iter_mut()
            .filter(|r| line(r) && r.uuid == entry.uuid && PurlKey::same(&r.purl, &key));
        for wired in own {
            let url = wired.url.take().unwrap_or_default();
            wired.mode = WiringMode::Vendored;
            wired.artifact_rel = Some(entry.artifact.path.trim_start_matches("./").to_string());
            wired.integrity_required = false;
            let (file, hosted) = (wired.source_file.clone(), WiringMode::Hosted);
            let of_url = |id: &Recognized| url.split('/').any(|level| level == id.uuid);
            recognized.retain(|id| !(id.mode == hosted && id.file == file && of_url(id)));
            recognized.push(Recognized {
                uuid: entry.uuid.clone(),
                mode: WiringMode::Vendored,
                file,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const PURL: &str = "pkg:pypi/six@1.16.0";
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PINS: &str = "idna==3.7 \\\n    --hash=sha256:1111\nsix==1.16.0 \\\n    \
                        --hash=sha256:2222 \\\n    --hash=sha256:3333\n";

    fn url(uuid: &str) -> String {
        format!(
            "https://patch.socket.dev/patch/pypi/six/1.16.0/tok/{uuid}/six-1.16.0-py3-none-any.whl"
        )
    }

    /// An untracked `.bazelrc` that git ignores, there or not yet, would
    /// not reach a fresh checkout; one that is tracked, or not ignored,
    /// does.
    #[tokio::test]
    async fn an_ignored_untracked_bazelrc_is_declined() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let git = |args: &[&str]| {
            let status = std::process::Command::new(&git)
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(root)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        assert_eq!(rc_committed(root).await, Ok(()), "no rule ignores it");
        std::fs::write(root.join(".gitignore"), ".bazelrc\n").unwrap();
        let missing = rc_committed(root).await.unwrap_err();
        assert!(missing.contains(".gitignore:1:.bazelrc"), "{missing}");
        std::fs::write(root.join(".bazelrc"), "build --jobs=4\n").unwrap();
        let untracked = rc_committed(root).await.unwrap_err();
        assert!(untracked.starts_with(".bazelrc is ignored"), "{untracked}");
        git(&["add", "-f", ".bazelrc"]);
        assert_eq!(
            rc_committed(root).await,
            Ok(()),
            "a tracked file is committed"
        );
    }

    #[test]
    fn only_a_wheel_for_every_platform_is_one_the_form_is_written_for() {
        assert!(for_every_platform("six-1.16.0-py2.py3-none-any.whl"));
        for other in [
            "six-1.16.0.tar.gz",
            "six-1.16.0.zip",
            "lxml-5.2.0-cp311-cp311-manylinux_2_28_x86_64.whl",
            "pkg-1.0-cp311-abi3-any.whl",
        ] {
            assert!(!for_every_platform(other), "{other}");
        }
    }

    #[test]
    fn the_line_is_hosted_mode_s_and_the_record_restores_the_pin() {
        let url = url(UUID);
        let (new, record) = planned(PINS, PURL, UUID, (&url, SHA)).unwrap();
        let line = format!("six @ {url} --hash=sha256:{SHA}");
        assert_eq!(
            new,
            format!("idna==3.7 \\\n    --hash=sha256:1111\n{line}\n")
        );
        assert_eq!(record.new, Some(Value::String(line.clone())));
        assert_eq!(record.key.as_deref(), Some("requirements.txt:3"));
        let pin = serde_json::json!([
            "six==1.16.0 \\\n",
            "    --hash=sha256:2222 \\\n",
            "    --hash=sha256:3333"
        ]);
        assert_eq!(record.original, Some(pin));
        assert!(names(&line, PURL, UUID));
        // Another package, another patch, a path line and two lines are
        // not the line of this entry.
        let other = "22222222-2222-4222-8222-222222222222";
        assert!(!names(&line, "pkg:pypi/idna@3.7", UUID));
        assert!(!names(&line, PURL, other));
        assert!(!names(
            "./.socket/vendor/pypi/x/six-1.16.0-py3-none-any.whl",
            PURL,
            UUID
        ));
        assert!(!names(&format!("{line}\nidna==3.7"), PURL, UUID));
        // CRLF files keep their line breaks in the record.
        let crlf = PINS.replace('\n', "\r\n");
        let (new, record) = planned(&crlf, PURL, UUID, (&url, SHA)).unwrap();
        assert!(new.ends_with(&format!("{line}\r\n")), "{new:?}");
        let first = record.original.as_ref().and_then(|lines| lines[0].as_str());
        assert_eq!(first, Some("six==1.16.0 \\\r\n"));
    }

    /// The line is written for one exact pin with its hashes, where
    /// hosted mode pins the package, and for nothing else.
    #[test]
    fn a_requirement_that_is_not_the_measured_shape_is_not_written() {
        let pin = "six==1.16.0 --hash=sha256:2222\n";
        assert!(planned(pin, PURL, UUID, (&url(UUID), SHA)).is_ok());
        for (content, names) in [
            ("six==1.16.0\n", "pins no hashes"),
            (
                "idna==3.7 --hash=sha256:1\n",
                "hosted mode does not pin six==1.16.0",
            ),
            ("six>=1.16.0 --hash=sha256:2\n", "hosted mode does not pin"),
            ("six==1.15.0 --hash=sha256:2\n", "hosted mode does not pin"),
            (
                "-r base.txt\nidna==3.7 --hash=sha256:1\n",
                "hosted mode does not pin",
            ),
            (
                "six[x]==1.16.0 --hash=sha256:2\n",
                "is more than one exact pin",
            ),
            (
                "six==1.16.0 ; python_version > '3' --hash=sha256:2\n",
                "is more than",
            ),
            (
                "six==1.16.0 --hash=sha256:2  # ours\n",
                "is more than one exact pin",
            ),
            (
                "  six==1.16.0 --hash=sha256:2\n",
                "is more than one exact pin",
            ),
            ("six --hash=sha256:2\n", "is more than one exact pin"),
        ] {
            let why = planned(content, PURL, UUID, (&url(UUID), SHA)).unwrap_err();
            assert!(why.contains(names), "{content:?}: {why}");
        }
        assert!(planned(pin, "pkg:npm/six@1.16.0", UUID, (&url(UUID), SHA)).is_err());
    }
}
