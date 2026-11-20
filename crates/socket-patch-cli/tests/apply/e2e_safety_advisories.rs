//! End-to-end: assert the typed JSON envelope `sidecars[]` shape
//! for every ecosystem's post-apply advisory path.
//!
//! These tests drive the `socket-patch apply` binary as a subprocess
//! against handcrafted package layouts (the same layouts the crawlers
//! find on real installs). For each ecosystem we:
//!
//!   1. Stage the package directory the crawler expects.
//!   2. Write `.socket/manifest.json` referencing a synthetic PURL.
//!   3. Drop the `after_hash` blob under `.socket/blobs/<hash>` so
//!      apply runs fully offline.
//!   4. Invoke `socket-patch apply --json` with `--global-prefix`
//!      pointed at the package root, plus any per-ecosystem env
//!      overrides (e.g. `NUGET_PACKAGES=<path>`, `GOMODCACHE=<path>`).
//!   5. Parse the JSON envelope and assert the structured
//!      `envelope.sidecars[]` record matches the ecosystem's
//!      expected `code` / `severity` / `files[]` contract.
//!
//! These are the load-bearing tests that lock the **typed** sidecar
//! JSON contract (codes are stable snake_case enum tags, severity is
//! a stable bucket) that downstream consumers — CI bots, the Socket
//! dashboard, jq pipelines, telemetry — branch on. A future refactor
//! that renames a code, flips a severity, or moves the data
//! elsewhere fires here loudly.
//!
//! Network: no. Toolchain: none. These run on every PR.

use std::path::Path;

use crate::common;

use common::{
    git_sha256, parse_json_envelope, run_with_env, write_blob, write_minimal_manifest, PatchEntry,
};
// The cargo sidecar test needs the bare (un-framed) digest used in
// `.cargo-checksum.json`.
use common::sha256_hex;

/// Helper: stage a package layout + manifest + blob, run apply, and
/// return the parsed JSON envelope.
///
/// `package_root` is the directory the crawler will be pointed at via
/// `--global-prefix`; the manifest lives in `cwd/.socket/`. The two
/// are separated because `--global-prefix` semantics expect the
/// ecosystem's root (e.g. `$GOMODCACHE`, `$NUGET_PACKAGES`, site-
/// packages) which is not the same as the `--cwd` where `.socket/`
/// lives.
///
/// `extra_env` adds env vars only to the child process (the parent's
/// env is untouched so tests stay parallel-safe).
fn apply_and_parse(
    cwd: &Path,
    package_root: &Path,
    extra_env: &[(&str, &str)],
) -> serde_json::Value {
    let (code, stdout, stderr) = run_with_env(
        cwd,
        &[
            "apply",
            "--json",
            "--cwd",
            cwd.to_str().unwrap(),
            "--global-prefix",
            package_root.to_str().unwrap(),
        ],
        extra_env,
    );
    if stdout.trim().is_empty() {
        panic!("socket-patch apply emitted no JSON.\nstderr:\n{stderr}");
    }
    let env = parse_json_envelope(&stdout);

    // Run-level contract: a sidecar record is meaningless unless the
    // underlying patch actually landed *and the run reported success*.
    // Every test in this file stages exactly one offline patch that
    // must apply cleanly, so lock the whole-run shape here once. This
    // closes the loophole where a regression that flips the run to
    // partialFailure / non-zero exit, mis-records the patch event, or
    // drops the summary count would still slip past the per-ecosystem
    // `sidecars[]` assertions below.
    assert_eq!(
        code, 0,
        "apply must exit 0 on a clean offline apply.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        env["command"], "apply",
        "envelope.command must be `apply`.\nenv: {env}"
    );
    assert_eq!(
        env["status"], "success",
        "apply must report status=success (not partialFailure/error).\nenv: {env}"
    );
    assert_eq!(
        env["dryRun"], false,
        "these applies are NOT dry runs — bytes must hit disk.\nenv: {env}"
    );
    assert_eq!(
        env.get("error"),
        None,
        "a successful apply must carry no top-level error.\nenv: {env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        summary["applied"], 1,
        "exactly one package must be applied.\nenv: {env}"
    );
    assert_eq!(
        summary["failed"], 0,
        "no patch event may be `failed`.\nenv: {env}"
    );
    // The real apply path must have recorded an `applied` patch event —
    // proves the sidecar rode on an actual on-disk patch rather than a
    // fabricated / short-circuited record.
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope.events must be an array.\nenv: {env}"));
    assert!(
        events.iter().any(|e| e["action"] == "applied"),
        "apply must record at least one `applied` event.\nenv: {env}"
    );

    env
}

/// Assert the per-ecosystem contract that a `sidecars[]` record JOINs
/// to an `applied` `events[]` record by `purl` (the documented schema
/// invariant downstream consumers rely on), and that the run produced
/// exactly the one sidecar record this test staged. Both the sidecar
/// `purl` and the event `purl` derive from the same `package_key`, so a
/// mismatch here means the wiring between the apply loop and the
/// sidecar emitter regressed.
fn assert_sidecar_joins_applied_event(env: &serde_json::Value, record: &serde_json::Value) {
    let sidecars = env["sidecars"].as_array().expect("sidecars array");
    assert_eq!(
        sidecars.len(),
        1,
        "exactly one sidecar record expected for a single staged package.\nenv: {env}"
    );
    let purl = record["purl"]
        .as_str()
        .unwrap_or_else(|| panic!("sidecar record.purl must be a string.\nrecord: {record}"));
    assert!(!purl.is_empty(), "sidecar record.purl must be non-empty");
    let events = env["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == record["purl"] && e["action"] == "applied"),
        "sidecar record (purl={purl}) must JOIN to an `applied` event of the same purl.\nenv: {env}"
    );
}

/// Locate the first `envelope.sidecars[]` record matching the given
/// ecosystem tag, or panic with the full envelope on miss. Tests use
/// this to drill into the per-ecosystem record without re-implementing
/// the lookup five times.
fn find_sidecar_record<'a>(env: &'a serde_json::Value, ecosystem: &str) -> &'a serde_json::Value {
    let sidecars = env["sidecars"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope.sidecars must be an array.\nenv: {env}"));
    sidecars
        .iter()
        .find(|s| s["ecosystem"] == ecosystem)
        .unwrap_or_else(|| {
            panic!(
                "envelope.sidecars must contain a record with ecosystem={ecosystem}.\nenv: {env}"
            )
        })
}

// ─────────────────────────────────────────────────────────────────────
// PyPI — advisory-only, code = pypi_record_stale
// ─────────────────────────────────────────────────────────────────────

/// Without `--json` a sidecar advisory is a `Warning:` line on stderr,
/// the same advisory of two packages printed once; `--silent` mutes it,
/// and a run that writes nothing has none to print.
#[test]
fn sidecar_advisory_is_printed_in_human_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let site_packages = cwd.join("site-packages");
    let (original, patched) = (b"# original\n", b"# patched\n");
    let (before, after) = (git_sha256(original), git_sha256(patched));
    let socket_dir = cwd.join(".socket");
    let mut patches = serde_json::Map::new();
    for name in ["requests", "urllib3"] {
        let dist_info = site_packages.join(format!("{name}-2.28.0.dist-info"));
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 2.28.0\n"),
        )
        .unwrap();
        std::fs::write(site_packages.join(format!("{name}.py")), original).unwrap();
        patches.insert(
            format!("pkg:pypi/{name}@2.28.0"),
            serde_json::json!({
                "uuid": format!("20000001-0000-4001-8001-0000000000{:02}", patches.len()),
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { format!("package/{name}.py"): { "beforeHash": before, "afterHash": after } },
                "vulnerabilities": {},
                "description": "advisory fixture",
                "license": "MIT",
                "tier": "free"
            }),
        );
    }
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
    write_blob(&socket_dir, &after, patched);
    let apply = |extra: &[&str]| {
        let mut args = vec![
            "apply",
            "--cwd",
            cwd.to_str().unwrap(),
            "--global-prefix",
            site_packages.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        run_with_env(cwd, &args, &[])
    };
    let advisories = |stderr: &str| stderr.matches("Warning: PyPI: run `pip check`").count();

    let (code, stdout, stderr) = apply(&[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        advisories(&stderr),
        1,
        "one advisory for the two packages.\nstderr:\n{stderr}"
    );

    // Everything is already patched: nothing written, nothing to advise.
    let (code, _, stderr) = apply(&[]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(advisories(&stderr), 0, "stderr:\n{stderr}");

    for name in ["requests", "urllib3"] {
        std::fs::write(site_packages.join(format!("{name}.py")), original).unwrap();
    }
    let (code, _, stderr) = apply(&["--silent"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(advisories(&stderr), 0, "--silent mutes warnings:\n{stderr}");
}

/// PyPI: patching a file inside a `dist-info`-discovered package
/// emits a `pypi_record_stale` advisory at severity `warning`.
///
/// Locks in the contract: PyPI's sidecar path is advisory-only (no
/// file rewrites yet — `.dist-info/RECORD` rewriter is a follow-up),
/// `files[]` is present but empty, and the advisory carries the
/// stable `pypi_record_stale` enum tag.
#[test]
fn pypi_apply_emits_pypi_record_stale_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let site_packages = cwd.join("site-packages");

    // Stage a synthetic dist-info that the python crawler will
    // recognize (`Name:` + `Version:` headers in METADATA).
    let dist_info = site_packages.join("requests-2.28.0.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.28.0\n",
    )
    .unwrap();

    // The file we'll "patch". The Python crawler returns the
    // site-packages dir itself as `pkg_path`, so the manifest
    // file_name is resolved relative to site-packages.
    let target = site_packages.join("payload.py");
    let original = b"# original\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"# patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:pypi/requests@2.28.0",
        "20000001-0000-4001-8001-000000000001",
        &[PatchEntry {
            file_name: "package/payload.py",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &site_packages, &[]);

    // The patch landed on disk before the sidecar fired.
    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "pypi");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(
        record["purl"], "pkg:pypi/requests@2.28.0",
        "record must denormalize the PURL.\nrecord: {record}"
    );
    // Advisory-only: files[] is present but empty.
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "pypi advisory-only path must report no files[]; got {record}"
    );
    let advisory = record
        .get("advisory")
        .unwrap_or_else(|| panic!("advisory missing.\nrecord: {record}"));
    assert_eq!(
        advisory["code"], "pypi_record_stale",
        "code contract: pypi must emit pypi_record_stale"
    );
    assert_eq!(
        advisory["severity"], "warning",
        "severity contract: pypi advisory is severity=warning"
    );
    // The advisory message is the operator-facing remediation guidance —
    // a bare non-empty check would accept any garbage string. Pin the
    // stable, load-bearing tokens the production constant carries: the
    // `pip check` instruction and the `.dist-info/RECORD` it points at.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("pip check") && msg.contains("RECORD"),
        "pypi advisory.message must guide the operator to `pip check` the .dist-info/RECORD; got {msg:?}"
    );
}

/// A pixi project as `pixi install` leaves it: `pixi.toml`, `pixi.lock`
/// and one package (`certifi`, a single data file) in the `default`
/// environment under `.pixi/envs`, a conda prefix. The manifest holds a
/// patch for that file under the release-qualified purl the patch service
/// records. Returns the installed file.
fn pixi_project_with_patch(cwd: &Path, installed: &[u8]) -> std::path::PathBuf {
    std::fs::write(
        cwd.join("pixi.toml"),
        "[workspace]\nname = \"analysis\"\nchannels = [\"conda-forge\"]\nplatforms = [\"linux-64\"]\n",
    )
    .unwrap();
    std::fs::write(cwd.join("pixi.lock"), "version: 6\n").unwrap();
    let prefix = cwd.join(".pixi").join("envs").join("default");
    std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
    std::fs::write(prefix.join("conda-meta").join("pixi"), "{}").unwrap();
    let site_packages = if cfg!(windows) {
        prefix.join("Lib").join("site-packages")
    } else {
        prefix.join("lib").join("python3.13").join("site-packages")
    };
    let dist_info = site_packages.join("certifi-2026.7.22.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.4\nName: certifi\nVersion: 2026.7.22\n",
    )
    .unwrap();
    std::fs::write(dist_info.join("INSTALLER"), "conda\n").unwrap();
    std::fs::create_dir_all(site_packages.join("certifi")).unwrap();
    let target = site_packages.join("certifi").join("cacert.pem");
    std::fs::write(&target, installed).unwrap();

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl",
        "20000001-0000-4001-8001-000000000077",
        &[PatchEntry {
            file_name: "certifi/cacert.pem",
            before_hash: &git_sha256(PIXI_UPSTREAM),
            after_hash: &git_sha256(PIXI_PATCHED),
        }],
    );
    write_blob(&socket_dir, &git_sha256(PIXI_PATCHED), PIXI_PATCHED);
    target
}

const PIXI_UPSTREAM: &[u8] = b"# the PyPI release's bundle\n";
const PIXI_PATCHED: &[u8] = b"# the patched bundle\n";

/// `socket-patch apply` after `pixi install` runs with nothing activated
/// (no `pixi run`, no `CONDA_PREFIX`): it finds the package in
/// `.pixi/envs/default`, patches it, and its advisory names what reverts a
/// pixi install, not `pip`, which a pixi environment has none of.
#[test]
fn pixi_project_apply_needs_no_activation_and_names_pixi() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let target = pixi_project_with_patch(cwd, PIXI_UPSTREAM);

    let (code, stdout, stderr) = run_with_env(cwd, &["apply", "--cwd", cwd.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), PIXI_PATCHED);
    assert!(
        stderr.contains("pixi installed these packages")
            && stderr.contains("`pixi reinstall`")
            && stderr.contains("`socket-patch apply`"),
        "stderr:\n{stderr}"
    );
    assert!(!stderr.contains("pip check"), "stderr:\n{stderr}");

    // The second run finds the same copy, already patched.
    let (code, stdout, stderr) = run_with_env(cwd, &["apply", "--cwd", cwd.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("already patched"), "stdout:\n{stdout}");
}

/// A conda build is not always the PyPI release byte for byte. A copy whose
/// file is neither side of the patch is left exactly as it is, and the
/// failure says why: the copy is installed, in a conda environment, and
/// its bytes are not the release's.
#[test]
fn pixi_project_apply_refuses_a_conda_build_that_differs_from_the_release() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let conda_build = b"# the PyPI release's bundle, changed by the conda recipe\n";
    let target = pixi_project_with_patch(cwd, conda_build);

    let (code, stdout, stderr) = run_with_env(cwd, &["apply", "--cwd", cwd.to_str().unwrap()], &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), conda_build);
    assert!(
        stderr.contains("Failed to patch pkg:pypi/certifi@2026.7.22: no matching variant found")
            && stderr.contains("is in a conda environment")
            && stderr.contains("match none of the releases the patch was made for"),
        "stderr:\n{stderr}"
    );
    // The copy is named: a project may hold one per environment.
    let site_packages = target.parent().unwrap().parent().unwrap();
    assert!(
        stderr.contains(&site_packages.display().to_string()),
        "stderr:\n{stderr}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// conda builds are patched only as the PyPI release they repackage
// ─────────────────────────────────────────────────────────────────────

const CONDA_REFUSAL: &str = "conda_build_not_pypi_release";

/// One installed distribution in the `default` pixi environment of `cwd`,
/// with one file, and a manifest record replacing that file (the PyPI
/// release's bytes are `release`). `installer` is the copy's `INSTALLER`
/// (`None`: none written) and `purelib` its `WHEEL` purity.
struct CondaCopy<'a> {
    name: &'a str,
    version: &'a str,
    purl: &'a str,
    installer: Option<&'a str>,
    purelib: bool,
    file: &'a str,
    installed: &'a [u8],
    release: &'a [u8],
}

const CONDA_PATCHED: &[u8] = b"# patched\n";

fn stage_conda_copy(cwd: &Path, copy: &CondaCopy<'_>) -> std::path::PathBuf {
    std::fs::write(cwd.join("pixi.toml"), "[workspace]\nname = \"a\"\n").unwrap();
    let prefix = cwd.join(".pixi").join("envs").join("default");
    std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
    std::fs::write(prefix.join("conda-meta").join("pixi"), "{}").unwrap();
    let site_packages = if cfg!(windows) {
        prefix.join("Lib").join("site-packages")
    } else {
        prefix.join("lib").join("python3.13").join("site-packages")
    };
    let dist_info = site_packages.join(format!("{}-{}.dist-info", copy.name, copy.version));
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        format!(
            "Metadata-Version: 2.4\nName: {}\nVersion: {}\n",
            copy.name, copy.version
        ),
    )
    .unwrap();
    if let Some(installer) = copy.installer {
        std::fs::write(dist_info.join("INSTALLER"), format!("{installer}\n")).unwrap();
    }
    std::fs::write(
        dist_info.join("WHEEL"),
        format!("Wheel-Version: 1.0\nRoot-Is-Purelib: {}\n", copy.purelib),
    )
    .unwrap();
    let target = site_packages.join(copy.file);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, copy.installed).unwrap();

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        copy.purl,
        "20000001-0000-4001-8001-000000000088",
        &[PatchEntry {
            file_name: copy.file,
            before_hash: &git_sha256(copy.release),
            after_hash: &git_sha256(CONDA_PATCHED),
        }],
    );
    write_blob(&socket_dir, &git_sha256(CONDA_PATCHED), CONDA_PATCHED);
    target
}

fn apply_in(cwd: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["apply", "--cwd", cwd.to_str().unwrap()];
    args.extend_from_slice(extra);
    run_with_env(cwd, &args, &[])
}

const CONDA_NOT_SUPPORTED: &str = "compiled conda packages are not supported yet";

/// What a run that skipped a compiled conda build says: a warning with
/// the rule's code, and no failure of any kind.
fn assert_skipped_as_not_supported(stderr: &str, at: &str) {
    assert!(
        stderr.contains(&format!("Warning: pkg:pypi/pillow@12.3.0: {CONDA_REFUSAL}"))
            && stderr.contains(CONDA_NOT_SUPPORTED),
        "{at}\nstderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches(CONDA_REFUSAL).count(),
        1,
        "one warning for the copy: {at}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Error:")
            && !stderr.contains("no matching installed package")
            && !stderr.contains("socket-patch remove"),
        "{at}\nstderr:\n{stderr}"
    );
}

/// A compiled conda package is built separately from the PyPI wheel and
/// links conda's own libraries. Its Python files are often the wheel's
/// byte for byte, as here, and that is not enough: compiled conda
/// packages are not supported yet. The copy is skipped with a warning,
/// nothing is written to it, and the run does not fail, with or without
/// `--force`, for a platform wheel's record or a pure-Python wheel's.
#[test]
fn a_compiled_conda_build_is_skipped_even_when_the_file_matches() {
    let release = b"# PIL/TarIO.py as PyPI ships it\n";
    for purl in [
        "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
        "pkg:pypi/pillow@12.3.0?artifact_id=py3-none-any-whl",
        "pkg:pypi/pillow@12.3.0",
    ] {
        for flags in [
            &[][..],
            &["--force"][..],
            &["--allow-patch-conflicts"][..],
            &["--dry-run"][..],
        ] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let target = stage_conda_copy(
                tmp.path(),
                &CondaCopy {
                    name: "pillow",
                    version: "12.3.0",
                    purl,
                    installer: Some("conda"),
                    purelib: false,
                    file: "PIL/TarIO.py",
                    installed: release,
                    release,
                },
            );
            let at = format!("{purl} {flags:?}");
            let (code, stdout, stderr) = apply_in(tmp.path(), flags);
            assert_eq!(code, 0, "{at}\nstdout:\n{stdout}\nstderr:\n{stderr}");
            assert_eq!(std::fs::read(&target).unwrap(), release, "{at}");
            assert_skipped_as_not_supported(&stderr, &at);
            assert!(stderr.contains("Root-Is-Purelib: false"), "{at}\n{stderr}");
            assert!(
                stdout.contains("not supported") && !stdout.contains("1 not found on disk"),
                "{at}\nstdout:\n{stdout}"
            );
        }
    }
}

/// The usual compiled conda build is not the wheel file for file either
/// (a recipe patches a source, the wheel's extension modules are not
/// there). It is skipped the same way, not failed as a copy that matches
/// no release, and `apply --check` agrees: a copy `apply` skips is not
/// drift. Under `--json` each record is a `skipped` event with the code.
#[test]
fn a_compiled_conda_build_that_differs_from_the_wheel_is_skipped_and_checks_clean() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let conda_build = b"# PIL/TarIO.py as the conda recipe patched it\n";
    let purl = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "pillow",
            version: "12.3.0",
            purl,
            installer: Some("conda"),
            purelib: false,
            file: "PIL/TarIO.py",
            installed: conda_build,
            release: b"# PIL/TarIO.py as PyPI ships it\n",
        },
    );
    add_sibling_record(
        tmp.path(),
        purl,
        "pkg:pypi/pillow@12.3.0?artifact_id=py3-none-any-whl",
    );

    for flags in [&[][..], &["--force"][..], &["--check"][..]] {
        let (code, stdout, stderr) = apply_in(tmp.path(), flags);
        let at = format!("{flags:?}");
        assert_eq!(code, 0, "{at}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(std::fs::read(&target).unwrap(), conda_build, "{at}");
        assert_skipped_as_not_supported(&stderr, &at);
        assert!(
            stdout.contains("2 not supported") || stdout.contains("2 patches not supported"),
            "{at}\nstdout:\n{stdout}"
        );
    }

    for flags in [&["--json"][..], &["--check", "--json"][..]] {
        let (code, stdout, stderr) = apply_in(tmp.path(), flags);
        assert_eq!(code, 0, "{flags:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
        assert_eq!(envelope["status"], "success", "{flags:?}\n{stdout}");
        let events = envelope["events"].as_array().expect("events");
        assert_eq!(events.len(), 2, "{flags:?}\n{stdout}");
        for event in events {
            assert_eq!(event["action"], "skipped", "{flags:?}\n{stdout}");
            assert_eq!(event["errorCode"], CONDA_REFUSAL, "{flags:?}\n{stdout}");
        }
    }
}

/// A pure-Python conda build whose file is not the release's (a recipe
/// that changes the source): `--force` and `--allow-patch-conflicts` let
/// a patch overwrite local changes to the distribution it was made for,
/// but a conda build that differs is another distribution, and its file
/// is never overwritten.
#[test]
fn no_flag_overwrites_a_conda_build_file_that_is_not_the_release() {
    let conda_build = b"# changed by the conda recipe\n";
    // A record keyed by the bare purl names no release artifact, so the
    // apply command hands it straight to the engine: the same answer.
    for purl in [
        "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl",
        "pkg:pypi/certifi@2026.7.22",
    ] {
        for flags in [&["--force"][..], &["--allow-patch-conflicts"][..]] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let target = stage_conda_copy(
                tmp.path(),
                &CondaCopy {
                    name: "certifi",
                    version: "2026.7.22",
                    purl,
                    installer: Some("conda"),
                    purelib: true,
                    file: "certifi/core.py",
                    installed: conda_build,
                    release: b"# the PyPI release's file\n",
                },
            );
            let (code, stdout, stderr) = apply_in(tmp.path(), flags);
            assert_eq!(
                code, 1,
                "{purl} {flags:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert_eq!(
                std::fs::read(&target).unwrap(),
                conda_build,
                "{purl} {flags:?}"
            );
        }
    }
}

/// pip and uv install the PyPI wheel itself into a conda prefix (pixi's
/// `[pypi-dependencies]`, or `pip install` in a conda environment). That
/// copy is the release the patch was made from, compiled or not, and is
/// patched as anywhere else.
#[test]
fn a_wheel_pip_or_uv_installed_into_a_conda_prefix_is_patched() {
    let release = b"# PIL/TarIO.py as PyPI ships it\n";
    for installer in ["pip", "uv-pixi"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = stage_conda_copy(
            tmp.path(),
            &CondaCopy {
                name: "pillow",
                version: "12.3.0",
                purl: "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
                installer: Some(installer),
                purelib: false,
                file: "PIL/TarIO.py",
                installed: release,
                release,
            },
        );
        let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
        assert_eq!(code, 0, "{installer}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            CONDA_PATCHED,
            "{installer}"
        );
        assert!(!stderr.contains(CONDA_REFUSAL), "{installer}\n{stderr}");
    }
}

/// What an earlier Socket patch wrote into a pure-Python conda build is
/// not a difference between that build and the PyPI release: a newer
/// patch for the same release still replaces it, as on any other copy.
#[test]
fn an_earlier_socket_patch_still_gives_way_on_a_pure_python_conda_build() {
    let earlier_patch = b"# what the earlier patch wrote\n";
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "certifi",
            version: "2026.7.22",
            purl: "pkg:pypi/certifi@2026.7.22",
            installer: Some("conda"),
            purelib: true,
            file: "certifi/core.py",
            installed: earlier_patch,
            release: b"# the PyPI release's file\n",
        },
    );
    write_blob(
        &tmp.path().join(".socket"),
        &git_sha256(earlier_patch),
        earlier_patch,
    );
    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), CONDA_PATCHED);
}

/// A manifest can hold the source distribution's record beside the
/// wheel's (both match a release whose files are the same in each). On a
/// pure-Python conda build the wheel's record patches the copy and the
/// sdist's finds it patched: the run succeeds, as it does in a venv.
#[test]
fn an_sdist_record_beside_the_wheels_does_not_fail_a_pure_python_conda_build() {
    let release = b"# the PyPI release's file\n";
    let tmp = tempfile::tempdir().expect("tempdir");
    let wheel = "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl";
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "certifi",
            version: "2026.7.22",
            purl: wheel,
            installer: Some("conda"),
            purelib: true,
            file: "certifi/core.py",
            installed: release,
            release,
        },
    );
    let manifest_path = tmp.path().join(".socket").join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut sdist = manifest["patches"][wheel].clone();
    sdist["uuid"] = "20000001-0000-4001-8001-000000000089".into();
    manifest["patches"]["pkg:pypi/certifi@2026.7.22?artifact_id=tar-gz"] = sdist;
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), CONDA_PATCHED);
    assert!(!stderr.contains(CONDA_REFUSAL), "stderr:\n{stderr}");
}

/// Copies the manifest record of `from` in `cwd` to the key `to`: a second
/// record of the same release, replacing the same files.
fn add_sibling_record(cwd: &Path, from: &str, to: &str) {
    let manifest_path = cwd.join(".socket").join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut record = manifest["patches"][from].clone();
    record["uuid"] = "20000001-0000-4001-8001-000000000090".into();
    manifest["patches"][to] = record;
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

const SIBLING_PURE: &str = "pkg:pypi/charset-normalizer@3.4.4?artifact_id=py3-none-any-whl";
const SIBLING_PLATFORM: &str =
    "pkg:pypi/charset-normalizer@3.4.4?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";

/// A conda build of a release that has a pure wheel's record and a
/// platform wheel's record replacing the same file.
fn sibling_records_copy<'a>(
    purelib: bool,
    installed: &'a [u8],
    release: &'a [u8],
) -> CondaCopy<'a> {
    CondaCopy {
        name: "charset-normalizer",
        version: "3.4.4",
        purl: SIBLING_PURE,
        installer: Some("conda"),
        purelib,
        file: "charset_normalizer/api.py",
        installed,
        release,
    }
}

/// A release with a platform wheel beside its pure-Python one (a project
/// that compiles an optional speed-up) has a record for each, and its
/// Python files are the same in both. A pure-Python conda build is the
/// pure wheel: that record patches the copy, and the platform wheel's
/// record, which a conda build never takes, then finds its file patched,
/// as it does in a venv. The run succeeds with or without `--force`, and
/// neither record is reported as refused or as not installed.
///
/// The records are tried in an order that does not depend on the
/// manifest's map. Each run is a new process with its own map order, so
/// the rounds are a guard, by chance, against that order mattering again:
/// with it, the platform wheel's record came first in some runs, was
/// refused, and failed a run that had patched the file.
#[test]
fn a_platform_wheel_record_beside_the_pure_one_does_not_fail_a_pure_python_conda_build() {
    let release = b"# the PyPI release's file\n";
    for flags in [&[][..], &["--force"][..]] {
        for round in 0..4 {
            let tmp = tempfile::tempdir().expect("tempdir");
            let target =
                stage_conda_copy(tmp.path(), &sibling_records_copy(true, release, release));
            add_sibling_record(tmp.path(), SIBLING_PURE, SIBLING_PLATFORM);

            // A dry run first: the copy can be patched, and nothing is.
            let (code, stdout, stderr) = apply_in(tmp.path(), &[flags, &["--dry-run"]].concat());
            assert_eq!(
                code, 0,
                "{flags:?} round {round}, dry run\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), release);
            assert!(
                !stderr.contains(CONDA_REFUSAL) && !stderr.contains("Failed to patch"),
                "{flags:?} round {round}, dry run\nstderr:\n{stderr}"
            );

            // Then the patch, and a second run that finds it in place.
            for run in ["first", "second"] {
                let (code, stdout, stderr) = apply_in(tmp.path(), flags);
                let at = format!("{flags:?} round {round}, {run} run");
                assert_eq!(code, 0, "{at}\nstdout:\n{stdout}\nstderr:\n{stderr}");
                assert_eq!(std::fs::read(&target).unwrap(), CONDA_PATCHED, "{at}");
                assert!(
                    !stderr.contains(CONDA_REFUSAL)
                        && !stderr.contains("Failed to patch")
                        && !stderr.contains("no matching installed package"),
                    "{at}\nstderr:\n{stderr}"
                );
                assert!(
                    stdout.contains("0 not found on disk")
                        && stdout.contains(&format!("{SIBLING_PLATFORM} (already patched)")),
                    "{at}\nstdout:\n{stdout}"
                );
            }
        }
    }

    // The platform wheel's record on its own is still refused.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut alone = sibling_records_copy(true, release, release);
    alone.purl = SIBLING_PLATFORM;
    let target = stage_conda_copy(tmp.path(), &alone);
    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), release);
    assert!(stderr.contains(CONDA_REFUSAL), "stderr:\n{stderr}");
}

/// A copy that fails is reported once, with its own cause. A pure-Python
/// conda build whose file is not the release's fails under the pure
/// wheel's record, for that file; the platform wheel's record is not
/// refused on top of it.
#[test]
fn a_conda_build_two_records_fail_on_is_reported_once() {
    let release = b"# the PyPI release's file\n";
    let conda_build = b"# changed by the conda recipe\n";
    let failures = |stderr: &str| stderr.matches("Failed to patch").count();

    // `--force` hands both records to the engine whatever the file holds.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(
        tmp.path(),
        &sibling_records_copy(true, conda_build, release),
    );
    add_sibling_record(tmp.path(), SIBLING_PURE, SIBLING_PLATFORM);
    let (code, stdout, stderr) = apply_in(tmp.path(), &["--force"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), conda_build);
    assert_eq!(failures(&stderr), 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains(&format!("Failed to patch {SIBLING_PURE}"))
            && !stderr.contains(CONDA_REFUSAL)
            && !stderr.contains("no matching installed package"),
        "stderr:\n{stderr}"
    );

    // The platform wheel's record alone, on the same pure-Python build:
    // refused, with how to drop the record.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut alone = sibling_records_copy(true, release, release);
    alone.purl = SIBLING_PLATFORM;
    stage_conda_copy(tmp.path(), &alone);
    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(failures(&stderr), 1, "stderr:\n{stderr}");
    assert!(
        stderr.contains(CONDA_REFUSAL)
            && stderr.contains(
                "`socket-patch remove pkg:pypi/charset-normalizer@3.4.4` drops its record"
            ),
        "stderr:\n{stderr}"
    );
}

/// `--strict` fails on any file that is not the patch's original. The
/// conda rule tightens `--force` and `--allow-patch-conflicts`; it must
/// not loosen `--strict`, which here refuses even content an earlier
/// Socket patch wrote.
#[test]
fn strict_stays_strict_on_a_conda_build() {
    let earlier_patch = b"# what the earlier patch wrote\n";
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "certifi",
            version: "2026.7.22",
            purl: "pkg:pypi/certifi@2026.7.22",
            installer: Some("conda"),
            purelib: true,
            file: "certifi/core.py",
            installed: earlier_patch,
            release: b"# the PyPI release's file\n",
        },
    );
    write_blob(
        &tmp.path().join(".socket"),
        &git_sha256(earlier_patch),
        earlier_patch,
    );
    let (code, stdout, stderr) = apply_in(tmp.path(), &["--strict"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), earlier_patch);
}

/// A compiled conda build an earlier release patched, in a release with
/// two records: it holds the pure wheel's patch, and the platform wheel's
/// record also replaces a file the copy holds unpatched. `apply` reports
/// the copy as already patched under the record it holds and passes over
/// the other, and `apply --check` agrees: the copy is judged as a whole,
/// not once per record, so it is in sync.
#[test]
fn a_compiled_conda_build_holding_one_records_patch_is_in_sync() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pure = "pkg:pypi/pillow@12.3.0?artifact_id=py3-none-any-whl";
    let platform = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "pillow",
            version: "12.3.0",
            purl: pure,
            installer: Some("conda"),
            purelib: false,
            file: "PIL/TarIO.py",
            installed: CONDA_PATCHED,
            release: b"# PIL/TarIO.py as PyPI ships it\n",
        },
    );
    add_sibling_record(tmp.path(), pure, platform);
    let second = b"# PIL/TiffImagePlugin.py as PyPI ships it\n";
    let second_path = target.parent().unwrap().join("TiffImagePlugin.py");
    std::fs::write(&second_path, second).unwrap();
    let manifest_path = tmp.path().join(".socket").join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["patches"][platform]["files"]["PIL/TiffImagePlugin.py"] = serde_json::json!({
        "beforeHash": git_sha256(second),
        "afterHash": git_sha256(CONDA_PATCHED),
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(&format!("{pure} (already patched)")),
        "stdout:\n{stdout}"
    );
    assert!(!stderr.contains(CONDA_REFUSAL), "stderr:\n{stderr}");
    assert_eq!(std::fs::read(&second_path).unwrap(), second);

    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Patches are in sync (1 patch checked)."),
        "stdout:\n{stdout}"
    );
    assert!(
        !stderr.contains("OUT OF SYNC") && !stderr.contains(CONDA_REFUSAL),
        "stderr:\n{stderr}"
    );
}

/// A copy's path is its site-packages directory, which every package of
/// the environment shares. A compiled conda build that already holds its
/// patch is in sync, and that says nothing about another package beside
/// it: an unpatched wheel pip installed there is still out of sync, not
/// "not installed".
#[test]
fn a_compiled_conda_build_holding_its_patch_does_not_hide_another_packages_drift() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "pillow",
            version: "12.3.0",
            purl: "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
            installer: Some("conda"),
            purelib: false,
            file: "PIL/TarIO.py",
            installed: CONDA_PATCHED,
            release: b"# PIL/TarIO.py as PyPI ships it\n",
        },
    );
    // certifi, as pip installed it, in the same site-packages: unpatched.
    let site_packages = target.parent().unwrap().parent().unwrap();
    let dist_info = site_packages.join("certifi-2026.7.22.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.4\nName: certifi\nVersion: 2026.7.22\n",
    )
    .unwrap();
    std::fs::write(dist_info.join("INSTALLER"), "pip\n").unwrap();
    std::fs::write(
        dist_info.join("WHEEL"),
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n",
    )
    .unwrap();
    let certifi_release = b"# certifi/core.py as PyPI ships it\n";
    std::fs::create_dir_all(site_packages.join("certifi")).unwrap();
    std::fs::write(
        site_packages.join("certifi").join("core.py"),
        certifi_release,
    )
    .unwrap();
    let certifi = "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl";
    let manifest_path = tmp.path().join(".socket").join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["patches"][certifi] = serde_json::json!({
        "uuid": "20000001-0000-4001-8001-000000000091",
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "certifi/core.py": {
            "beforeHash": git_sha256(certifi_release),
            "afterHash": git_sha256(CONDA_PATCHED),
        } },
        "vulnerabilities": {},
        "description": "t",
        "license": "MIT",
        "tier": "free",
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains(&format!("{certifi}: patch not applied")) && !stderr.contains("pillow"),
        "stderr:\n{stderr}"
    );
    assert!(!stdout.contains("not installed"), "stdout:\n{stdout}");

    // `apply` patches certifi and leaves pillow as it is; then all is in sync.
    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Patches are in sync (2 patches checked)."),
        "stdout:\n{stdout}"
    );
}

/// conda's Python ships `lib/python3.1 -> python3.13`, so an
/// environment's site-packages is found under two spellings. It is one
/// copy: `apply` and `apply --check` each skip a compiled conda build in
/// it once, with one warning.
#[cfg(unix)]
#[test]
fn a_compiled_conda_build_under_two_spellings_of_its_directory_is_skipped_once() {
    let release = b"# PIL/TarIO.py as PyPI ships it\n";
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "pillow",
            version: "12.3.0",
            purl: "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
            installer: Some("conda"),
            purelib: false,
            file: "PIL/TarIO.py",
            installed: release,
            release,
        },
    );
    let lib = tmp
        .path()
        .join(".pixi")
        .join("envs")
        .join("default")
        .join("lib");
    std::os::unix::fs::symlink("python3.13", lib.join("python3.1")).unwrap();

    for flags in [&[][..], &["--check"][..]] {
        let (code, stdout, stderr) = apply_in(tmp.path(), flags);
        let at = format!("{flags:?}");
        assert_eq!(code, 0, "{at}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(std::fs::read(&target).unwrap(), release, "{at}");
        assert_skipped_as_not_supported(&stderr, &at);
    }
}

/// Copies `from` to `to`, files and directories.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// A project with the package in two environments: conda's compiled
/// build in one, the PyPI wheel pip installed in the other. `apply`
/// patches the wheel, skips the conda build with its warning, and
/// succeeds. `apply --check` is then in sync, and under `--json` says both
/// things: the record is patched wherever it can be, and one copy was
/// skipped.
#[test]
fn a_compiled_conda_build_beside_a_pip_installed_wheel_is_skipped_and_the_wheel_patched() {
    let release = b"# PIL/TarIO.py as PyPI ships it\n";
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
    let conda_copy = stage_conda_copy(
        tmp.path(),
        &CondaCopy {
            name: "pillow",
            version: "12.3.0",
            purl,
            installer: Some("conda"),
            purelib: false,
            file: "PIL/TarIO.py",
            installed: release,
            release,
        },
    );
    let envs = tmp.path().join(".pixi").join("envs");
    copy_tree(&envs.join("default"), &envs.join("wheels"));
    let in_wheels = |path: &Path| {
        envs.join("wheels")
            .join(path.strip_prefix(envs.join("default")).unwrap())
    };
    let site_packages = conda_copy.parent().unwrap().parent().unwrap();
    std::fs::write(
        in_wheels(
            &site_packages
                .join("pillow-12.3.0.dist-info")
                .join("INSTALLER"),
        ),
        "pip\n",
    )
    .unwrap();
    let wheel_copy = in_wheels(&conda_copy);

    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&wheel_copy).unwrap(), CONDA_PATCHED);
    assert_eq!(std::fs::read(&conda_copy).unwrap(), release);
    assert_skipped_as_not_supported(&stderr, "apply");
    assert!(
        stdout.contains("1 of 1 targeted patch applied") && !stdout.contains("not supported"),
        "the wheel's copy says more than the skip:\n{stdout}"
    );

    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Patches are in sync (1 patch checked)."),
        "stdout:\n{stdout}"
    );
    assert_skipped_as_not_supported(&stderr, "apply --check");

    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check", "--json"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    assert_eq!(envelope["status"], "success", "{stdout}");
    let events = envelope["events"].as_array().expect("events");
    let codes: Vec<&str> = events
        .iter()
        .map(|event| event["errorCode"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(codes, ["already_patched", CONDA_REFUSAL], "{stdout}");
    assert_eq!(
        events[0]["reason"], "every installed copy that can be patched is patched",
        "{stdout}"
    );
}

/// An earlier release patched compiled conda builds whose Python file
/// matched. Such a copy already holds the patch: nothing is written to it,
/// so there is nothing to skip, and `apply` reports it as what it is,
/// patched.
#[test]
fn a_compiled_conda_build_that_already_holds_the_patch_is_reported_as_patched() {
    let copy = |installed: &'static [u8]| CondaCopy {
        name: "pillow",
        version: "12.3.0",
        purl: "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
        installer: Some("conda"),
        purelib: false,
        file: "PIL/TarIO.py",
        installed,
        release: b"# PIL/TarIO.py as PyPI ships it\n",
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = stage_conda_copy(tmp.path(), &copy(CONDA_PATCHED));
    let (code, stdout, stderr) = apply_in(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("already patched"), "stdout:\n{stdout}");
    assert!(!stderr.contains(CONDA_REFUSAL), "stderr:\n{stderr}");
    assert_eq!(std::fs::read(&target).unwrap(), CONDA_PATCHED);

    // `apply --check` agrees: the copy is in sync.
    let (code, stdout, stderr) = apply_in(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("1 patch checked"), "stdout:\n{stdout}");
    assert!(!stderr.contains(CONDA_REFUSAL), "stderr:\n{stderr}");
}

// ─────────────────────────────────────────────────────────────────────
// Gem — advisory-only, code = gem_bundle_install_reverts
// ─────────────────────────────────────────────────────────────────────

/// Gem: patching a file inside a `<name>-<version>` gem directory
/// emits a `gem_bundle_install_reverts` advisory at severity `warning`.
///
/// The Ruby crawler treats `<gem_path>/<name>-<version>/` with a
/// `lib/` subdirectory as a valid gem (no `.gemspec` required for
/// the lib-only case).
#[test]
fn gem_apply_emits_gem_bundle_install_reverts_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let gem_root = cwd.join("gems");
    let gem_dir = gem_root.join("rails-7.1.0");
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();

    let target = gem_dir.join("lib").join("rails.rb");
    let original = b"module Rails; end\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"module Rails; VERSION = '7.1.0-patched'.freeze; end\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:gem/rails@7.1.0",
        "20000002-0000-4002-8002-000000000002",
        &[PatchEntry {
            file_name: "package/lib/rails.rb",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &gem_root, &[]);

    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "gem");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(record["purl"], "pkg:gem/rails@7.1.0");
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "gem advisory-only path must report no files[]; got {record}"
    );
    let advisory = record.get("advisory").expect("advisory missing");
    assert_eq!(
        advisory["code"], "gem_bundle_install_reverts",
        "code contract: gem must emit gem_bundle_install_reverts"
    );
    assert_eq!(advisory["severity"], "warning");
    // Pin the stable operator-guidance token rather than just non-empty:
    // the gem advisory tells the operator that `bundle install` reverts.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("bundle install"),
        "gem advisory.message must warn that `bundle install` reverts the patch; got {msg:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Go — advisory-only, code = go_mod_verify_fails
// ─────────────────────────────────────────────────────────────────────

/// Go: patching a file inside a `$GOMODCACHE/<encoded-module>@<ver>/`
/// directory emits a `go_mod_verify_fails` advisory at severity
/// `warning`.
///
/// The Go crawler expects the GOMODCACHE layout: an encoded module
/// path followed by `@<version>/`. We pass both `--global-prefix` and
/// `GOMODCACHE` for redundancy (the apply CLI consumes the former,
/// some downstream code paths read the latter).
#[test]
fn golang_apply_emits_go_mod_verify_fails_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let cache = cwd.join("gomodcache");
    // GOMODCACHE layout: <encoded-module>@<version>/. For
    // `github.com/gin-gonic/gin` there are no uppercase letters,
    // so the encoded form equals the path verbatim.
    let module_dir = cache
        .join("github.com")
        .join("gin-gonic")
        .join("gin@v1.9.1");
    std::fs::create_dir_all(&module_dir).unwrap();

    let target = module_dir.join("gin.go");
    let original = b"package gin\n";
    std::fs::write(&target, original).unwrap();

    let patched = b"package gin\n// patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "20000003-0000-4003-8003-000000000003",
        &[PatchEntry {
            file_name: "package/gin.go",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &cache, &[("GOMODCACHE", cache.to_str().unwrap())]);

    assert_eq!(std::fs::read(&target).unwrap(), patched);

    let record = find_sidecar_record(&env, "golang");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(record["purl"], "pkg:golang/github.com/gin-gonic/gin@v1.9.1");
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "golang advisory-only path must report no files[]; got {record}"
    );
    let advisory = record.get("advisory").expect("advisory missing");
    assert_eq!(
        advisory["code"], "go_mod_verify_fails",
        "code contract: golang must emit go_mod_verify_fails"
    );
    assert_eq!(advisory["severity"], "warning");
    // Pin the stable operator-guidance token rather than just non-empty:
    // the Go advisory points at `go mod verify`.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("go mod verify"),
        "golang advisory.message must point the operator at `go mod verify`; got {msg:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// NuGet — file deletion (no advisory), code path proves
// `.nupkg.metadata` is removed and recorded as `Deleted`
// ─────────────────────────────────────────────────────────────────────

/// NuGet (unsigned): patching a file inside a `<lowercase-name>/<ver>/`
/// global-cache layout deletes `.nupkg.metadata` (the on-disk content
/// hash sidecar) and records the deletion under
/// `envelope.sidecars[].files[]`. No advisory is emitted for the
/// unsigned case — the deletion alone is the operator surface.
#[test]
fn nuget_apply_deletes_metadata_and_records_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    // Global cache layout: <lowercase-name>/<version>/
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();

    // The on-disk metadata sidecar the NuGet fixup will remove.
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000004-0000-4004-8004-000000000004",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &packages,
        &[("NUGET_PACKAGES", packages.to_str().unwrap())],
    );

    // Patch landed.
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    // Sidecar deleted the metadata file.
    assert!(
        !pkg_dir.join(".nupkg.metadata").exists(),
        "nuget fixup must delete .nupkg.metadata"
    );

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(
        record["purl"].as_str().map(|s| s.to_lowercase()),
        Some("pkg:nuget/newtonsoft.json@13.0.3".to_string()),
        "record must carry the package PURL.\nrecord: {record}"
    );
    let files = record["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "expected one file entry for .nupkg.metadata deletion; got {record}"
    );
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(
        files[0]["action"], "deleted",
        "action contract: .nupkg.metadata is `deleted`, not `rewritten`"
    );
    // No advisory on the unsigned path — the sidecar emits files
    // only. Either `advisory` is absent from JSON or `null`.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "unsigned nuget path must not emit an advisory; got {record}"
    );
}

/// NuGet `has_signed_marker` non-UTF8 filename: a file with a non-UTF8
/// name in the package directory is byte-matched (it is not a
/// `.nupkg.sha512` marker) and left untouched. The fixup continues — no
/// advisory; the `.nupkg.metadata` deletion still fires because we stage
/// it too.
///
/// Unix-only (`OsStr::from_bytes` is Unix-gated). Skips where the
/// filesystem rejects non-UTF8 names.
#[cfg(unix)]
#[test]
fn nuget_apply_with_non_utf8_filename_in_pkg_dir() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();
    // Drop a file with a non-UTF8 name into the package dir;
    // `has_signed_marker` matches entries on their raw bytes, so this one
    // is simply not a marker. Some networked filesystems reject non-UTF8
    // names; skip there.
    let bad_name = OsStr::from_bytes(&[0xff, 0xfe, b'-', b'b', b'a', b'd']);
    let bad_path = pkg_dir.join(bad_name);
    if std::fs::write(&bad_path, b"binary").is_err() {
        eprintln!("SKIP: filesystem rejects non-UTF8 filenames");
        return;
    }
    // Without the fixture this would pass as a plain `.nupkg.metadata`
    // deletion and guard nothing.
    assert!(
        bad_path.exists(),
        "non-UTF8 fixture file must exist so has_signed_marker's None arm is reached"
    );

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000007-0000-4007-8007-000000000007",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &packages,
        &[("NUGET_PACKAGES", packages.to_str().unwrap())],
    );

    // Patch landed and .nupkg.metadata removal succeeded; the
    // non-UTF8 file didn't trip the sidecar (the implicit-skip arm
    // is what we're locking in).
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    assert!(!pkg_dir.join(".nupkg.metadata").exists());
    // The non-UTF8 file must be untouched — the fixup skips it (it is not
    // a `.nupkg.sha512` marker) rather than deleting or mangling it. Proves
    // the skip arm ran and left the directory otherwise intact.
    assert!(
        bad_path.exists(),
        "non-UTF8 file must survive the fixup (skipped, not deleted)"
    );

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);
    let files = record["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "metadata deletion expected");
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(files[0]["action"], "deleted");
    // No advisory — the non-UTF8 file is NOT a `.nupkg.sha512`
    // marker (its name isn't even valid UTF-8), so the signed-
    // package branch stays cold.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "non-UTF8 file must not trigger the signed-marker advisory; got {record}"
    );
}

/// NuGet sidecar I/O-error boundary: when `.nupkg.metadata` exists
/// as a *directory* (not a file), `tokio::fs::remove_file` fails
/// with a non-NotFound error and `nuget::fixup` returns
/// `SidecarError::Io`. The boundary in `apply_package_patch` fails the
/// package: the patched file is put back, the event is `failed`, and the
/// `sidecar_fixup_failed` record carries the reason.
///
/// Covers the non-NotFound arm of the remove_file match in
/// `patch/sidecars/nuget.rs::fixup` — the path the existing
/// success and signed-package tests can't reach. As with the
/// cargo equivalent, the directory-as-file ruse beats chmod
/// because it fails uniformly across uids and platforms.
#[test]
fn nuget_apply_with_metadata_directory_reports_sidecar_fixup_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();
    // `.nupkg.metadata` as a non-empty directory. remove_file
    // refuses to unlink a directory; that's an EISDIR-class I/O
    // error, not NotFound.
    std::fs::create_dir(pkg_dir.join(".nupkg.metadata")).unwrap();
    std::fs::write(
        pkg_dir.join(".nupkg.metadata").join("placeholder"),
        b"non-empty so the dir can't be remove_file-removed even on permissive platforms",
    )
    .unwrap();

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000006-0000-4006-8006-000000000006",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let (code, stdout, stderr) = run_with_env(
        cwd,
        &[
            "apply",
            "--json",
            "--cwd",
            cwd.to_str().unwrap(),
            "--global-prefix",
            packages.to_str().unwrap(),
        ],
        &[("NUGET_PACKAGES", packages.to_str().unwrap())],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "partialFailure", "{env}");

    // The package is as it was: the patched file was put back.
    assert_eq!(std::fs::read(&target).unwrap(), original);

    let record = find_sidecar_record(&env, "nuget");
    let events = env["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["purl"] == record["purl"]
            && e["action"] == "failed"
            && e["error"]
                .as_str()
                .is_some_and(|e| e.contains("sidecar fixup failed"))),
        "the record must join a `failed` event that names the sidecar: {env}"
    );
    let advisory = record.get("advisory").expect("advisory");
    assert_eq!(advisory["code"], "sidecar_fixup_failed");
    assert_eq!(advisory["severity"], "error");
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".nupkg.metadata"),
        "advisory message must reference the metadata path; got {msg:?}"
    );
    // The boundary wraps the SidecarError with a stable, recognizable
    // prefix consumers key on; a bare "contains the path" check would
    // pass on an unrelated message that merely mentions the file.
    assert!(
        msg.contains("sidecar fixup failed"),
        "fixup-failed advisory must carry the stable `sidecar fixup failed` prefix; got {msg:?}"
    );
    // Boundary contract: failure path emits NO files[] entries.
    let files = record["files"].as_array().expect("files array");
    assert!(
        files.is_empty(),
        "failed fixup must not report any deleted files; got {record}"
    );
}

/// NuGet (signed): when the package also carries a `.nupkg.sha512`
/// signature sidecar, the typed payload surfaces BOTH the metadata-
/// deleted file entry AND a `nuget_signed_package_tampered` advisory
/// at severity `warning`. The old single-variant `SidecarOutcome`
/// design lost the advisory in this case; the typed schema keeps
/// both visible.
#[test]
fn nuget_apply_signed_package_emits_files_and_advisory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let packages = cwd.join("nuget-packages");
    let pkg_dir = packages.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(pkg_dir.join("lib")).unwrap();

    // Both the content-hash sidecar AND the signed-package marker.
    std::fs::write(
        pkg_dir.join(".nupkg.metadata"),
        r#"{"contentHash":"deadbeef"}"#,
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("newtonsoft.json.13.0.3.nupkg.sha512"),
        "abc123",
    )
    .unwrap();

    let target = pkg_dir.join("payload.txt");
    let original = b"hello\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"hello patched\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "20000005-0000-4005-8005-000000000005",
        &[PatchEntry {
            file_name: "package/payload.txt",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(
        cwd,
        &packages,
        &[("NUGET_PACKAGES", packages.to_str().unwrap())],
    );

    // Patch landed and the signature marker did NOT get clobbered.
    assert_eq!(std::fs::read(&target).unwrap(), patched);
    assert!(
        pkg_dir.join("newtonsoft.json.13.0.3.nupkg.sha512").exists(),
        "signed-package fixup must leave the .nupkg.sha512 marker in place"
    );
    assert!(
        !pkg_dir.join(".nupkg.metadata").exists(),
        "signed-package fixup must still delete .nupkg.metadata"
    );

    let record = find_sidecar_record(&env, "nuget");
    assert_sidecar_joins_applied_event(&env, record);

    // Files[] still carries the metadata deletion — even in the
    // signed-package case the new schema does NOT collapse this
    // away (old design's bug).
    let files = record["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "metadata deletion must still be reported");
    assert_eq!(files[0]["path"], ".nupkg.metadata");
    assert_eq!(files[0]["action"], "deleted");

    // AND the signed-package advisory rides alongside.
    let advisory = record.get("advisory").unwrap_or_else(|| {
        panic!("signed package must emit an advisory alongside files[].\nrecord: {record}")
    });
    assert_eq!(
        advisory["code"], "nuget_signed_package_tampered",
        "code contract: signed-package case emits nuget_signed_package_tampered"
    );
    assert_eq!(advisory["severity"], "warning");
    // Pin the stable token: the signed-package advisory names the
    // `.nupkg.sha512` signature sidecar it cannot honestly recompute.
    let msg = advisory["message"].as_str().unwrap_or("");
    assert!(
        msg.contains(".nupkg.sha512"),
        "signed-package advisory.message must reference the .nupkg.sha512 signature sidecar; got {msg:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Cargo — file rewrite (no advisory), code path proves
// `.cargo-checksum.json` is rewritten to the on-disk hash and recorded
// as `Rewritten`. This is the only sidecar in the shipped binary that
// *rewrites* a file, so it must have an end-to-end guard — not just
// core-crate unit tests on `cargo::fixup`.
// ─────────────────────────────────────────────────────────────────────

/// Cargo: patching a file inside a `<name>-<version>/` registry-cache
/// crate rewrites `<crate>/.cargo-checksum.json` so the patched file's
/// entry reflects its new on-disk SHA-256, records the rewrite under
/// `envelope.sidecars[].files[]` with action `rewritten`, and emits NO
/// advisory (the rewrite keeps `cargo build` happy — there is nothing
/// to warn the operator about).
///
/// Independently derives the expected post-patch digest with the bare
/// (un-Git-framed) `sha256_hex` cargo uses, then reads the rewritten
/// checksum file back off disk and pins it — so a regression that
/// stops rewriting, rewrites the wrong value, clobbers the untouched
/// sibling / `package` tarball hash, or mislabels the action fires loudly.
#[test]
fn cargo_apply_rewrites_checksum_and_records_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    let registry = cwd.join("registry-src");
    // Registry layout: <name>-<version>/ with a Cargo.toml the crawler
    // verifies against the PURL (name=mycrate, version=1.0.0).
    let crate_dir = registry.join("mycrate-1.0.0");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"mycrate\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let target = crate_dir.join("src").join("lib.rs");
    let original = b"// original lib\n";
    std::fs::write(&target, original).unwrap();
    let patched = b"// patched lib\n";
    let before = git_sha256(original);
    let after = git_sha256(patched);

    // Pre-existing `.cargo-checksum.json` with a STALE hash for the file
    // we patch, an UNTOUCHED sibling entry, and the `package` tarball
    // hash. The fixup must rewrite ONLY the patched entry and preserve
    // the rest verbatim.
    let stale_lib = "00".repeat(32);
    let untouched_sibling = "11".repeat(32);
    let package_hash = "deadbeefpackagehash";
    let checksum_path = crate_dir.join(".cargo-checksum.json");
    std::fs::write(
        &checksum_path,
        format!(
            r#"{{"files":{{"src/lib.rs":"{stale_lib}","Cargo.toml":"{untouched_sibling}"}},"package":"{package_hash}"}}"#
        ),
    )
    .unwrap();

    let socket_dir = cwd.join(".socket");
    write_minimal_manifest(
        &socket_dir,
        "pkg:cargo/mycrate@1.0.0",
        "20000008-0000-4008-8008-000000000008",
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket_dir, &after, patched);

    let env = apply_and_parse(cwd, &registry, &[]);

    // Patch landed on disk before the sidecar fired.
    assert_eq!(std::fs::read(&target).unwrap(), patched);

    // The checksum file was rewritten on disk: the patched entry now
    // carries the REAL post-patch bare-sha256 (derived independently here,
    // NOT read back from the same value we'd be checking), the stale value
    // is gone, and the untouched sibling + `package` tarball hash survive.
    let post: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&checksum_path).unwrap())
            .expect(".cargo-checksum.json must stay valid JSON after rewrite");
    let expected = sha256_hex(patched);
    assert_eq!(
        post["files"]["src/lib.rs"].as_str(),
        Some(expected.as_str()),
        "patched-file checksum must be rewritten to the on-disk sha256; got {post}"
    );
    assert_ne!(
        post["files"]["src/lib.rs"].as_str(),
        Some(stale_lib.as_str()),
        "stale pre-patch checksum must NOT survive the rewrite; got {post}"
    );
    assert_eq!(
        post["files"]["Cargo.toml"].as_str(),
        Some(untouched_sibling.as_str()),
        "an unpatched sibling's checksum must be preserved verbatim; got {post}"
    );
    assert_eq!(
        post["package"].as_str(),
        Some(package_hash),
        "the `package` tarball hash must be preserved verbatim; got {post}"
    );

    let record = find_sidecar_record(&env, "cargo");
    assert_sidecar_joins_applied_event(&env, record);
    assert_eq!(record["purl"], "pkg:cargo/mycrate@1.0.0");
    let files = record["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "cargo fixup rewrites exactly one file (.cargo-checksum.json); got {record}"
    );
    assert_eq!(files[0]["path"], ".cargo-checksum.json");
    assert_eq!(
        files[0]["action"], "rewritten",
        "action contract: .cargo-checksum.json is `rewritten`, not `deleted`"
    );
    // The success path emits files only — no advisory rides along.
    assert!(
        record.get("advisory").is_none() || record["advisory"].is_null(),
        "cargo checksum rewrite must not emit an advisory; got {record}"
    );
}
