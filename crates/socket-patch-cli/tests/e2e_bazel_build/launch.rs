//! Real-Bazel tests of the harness itself: a launched Bazel stays inside
//! its scratch root, a lock write stops the live server, a cell survives a
//! server that was killed, and the shared probe rule builds over a file and
//! a tree artifact (with no network on the toy cell, and as a record-only
//! canary on any line). The standing versions of probes T1 (isolation
//! flags) and T4 (proof ladder), and the checks of the harness's own lock
//! and shutdown rules; every other test in this suite relies on what these
//! assert.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::bazel_build_common::env::{self, Group, System};
use crate::bazel_build_common::isolation::{self, OutsideState};
use crate::bazel_build_common::probe_report::{self, Report};
use crate::bazel_build_common::proof::{Anchor, PROBE};
use crate::bazel_build_common::server::{self, Cell};
use crate::bazel_build_common::toy;
use crate::bazel_build_common::workspace::{MODULE_LOCK, PROBE_BZL};

/// `path` with links resolved, so a path Bazel printed compares equal to
/// the one the harness passed.
fn resolved(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// The names in `dir`, sorted, for a report.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The selected Bazel is the pinned version, and with the harness's
/// startup set and environment its server keeps every write inside the
/// scratch root: the output base and install base are under
/// `--output_user_root`, the JVM's temp directory is the scratch one, and
/// no default Bazel or bazelisk location was created or changed. Only
/// `info` and `shutdown` run, so the test needs no network and no fixture.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_launch_isolated() {
    const TEST: &str = "bazel_core_launch_isolated";
    let outside = OutsideState::capture();
    let Some(mut cell) = Cell::open(TEST, Group::Core, None) else {
        return;
    };
    // Both root markers, so every line finds its workspace.
    cell.write("MODULE.bazel", "");
    cell.write("WORKSPACE", "");

    let version = cell.bazel.version.text.clone();
    assert_eq!(cell.info("release"), format!("release {version}"));
    let output_base = PathBuf::from(cell.info("output_base"));
    let install_base = PathBuf::from(cell.info("install_base"));
    let root = resolved(&cell.scratch.output_user_root);
    for (what, path) in [
        ("output base", &output_base),
        ("install base", &install_base),
    ] {
        assert!(
            resolved(path).starts_with(&root),
            "the {what} {} is outside --output_user_root {}",
            path.display(),
            root.display()
        );
    }
    assert_eq!(
        resolved(cell.info("repository_cache")),
        resolved(&cell.scratch.repository_cache)
    );
    assert_eq!(
        resolved(cell.info("workspace")),
        resolved(&cell.scratch.workspace)
    );

    let pid: u32 = cell
        .info("server_pid")
        .parse()
        .expect("a numeric server pid");
    assert_eq!(
        cell.server_pid(),
        Some(pid),
        "the pid file names the server"
    );
    // The JVM's temp files: its temp directory is the scratch one, and it
    // wrote no perf-data file into the shared one.
    let jvm = isolation::server_cmdline(&output_base);
    let tmpdir = format!("-Djava.io.tmpdir={}", cell.scratch.tmp.display());
    assert!(
        jvm.contains(&tmpdir),
        "the server JVM lacks {tmpdir}: {jvm:?}"
    );
    assert!(jvm.iter().any(|arg| arg == "-XX:-UsePerfData"), "{jvm:?}");
    assert_eq!(isolation::stray_perf_data(pid), Vec::<PathBuf>::new());
    outside.assert_untouched("with the server running");

    let jvm_tmp = entries(&cell.scratch.tmp);
    let home = entries(&cell.scratch.home);
    cell.report
        .detail("output_base", output_base.to_string_lossy())
        .detail("install_base", install_base.to_string_lossy())
        .detail("jvm_tmp_entries", jvm_tmp)
        .detail("home_entries", home);

    cell.shutdown();
    assert_eq!(cell.server_pid(), None, "the server is gone after shutdown");
    // `close` asserts that the scratch root, output base included, is removed.
    let report = cell.close();
    outside.assert_untouched("after the cell closed");
    report.ran();
}

/// Whether `check` panics.
fn panics(check: &dyn Fn()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(check)).is_err()
}

/// Lock rule 1 against a live server: every harness write of
/// `MODULE.bazel.lock` (`write_module_lock`, and a tree copy that carries
/// a lock) stops the server first, and the plain `Cell::write` refuses the
/// file, so no test can edit the lock under a server that would revert it.
/// A second `probe.bzl` is refused too. Only `info` and `shutdown` run:
/// no network and no fixture.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_lock_writes_stop_the_server() {
    const TEST: &str = "bazel_core_lock_writes_stop_the_server";
    const LOCK: &[u8] = b"{\"lockFileVersion\": 0}\n";
    let outside = OutsideState::capture();
    let Some(cell) = Cell::open(TEST, Group::Core, None) else {
        return;
    };
    cell.write("MODULE.bazel", "");
    cell.write("WORKSPACE", "");
    let live_server = || -> u32 {
        let pid = cell
            .info("server_pid")
            .parse()
            .expect("a numeric server pid");
        assert_eq!(cell.server_pid(), Some(pid), "a server runs");
        pid
    };

    let first = live_server();
    cell.write_module_lock(LOCK);
    assert_eq!(
        cell.server_pid(),
        None,
        "write_module_lock left server {first} running"
    );
    assert_eq!(cell.module_lock().as_deref(), Some(LOCK));

    // The plain write refuses the lock and writes nothing, also under a
    // live server (whatever that server itself made of the file).
    live_server();
    let before = cell.module_lock();
    assert!(
        panics(&|| cell.write(MODULE_LOCK, "{}")),
        "Cell::write must refuse {MODULE_LOCK}"
    );
    assert_eq!(cell.module_lock(), before, "the refused write wrote");

    // A tree that carries a lock is a lock write as well.
    let tree = cell.scratch.root.join("saved");
    std::fs::create_dir_all(&tree).expect("create the saved tree");
    std::fs::write(tree.join(MODULE_LOCK), b"{}\n").expect("write the saved lock");
    std::fs::write(tree.join("MODULE.bazel"), "").expect("write the saved module file");
    assert!(cell.server_pid().is_some(), "a server runs before the copy");
    cell.copy_tree_from(&tree);
    assert_eq!(
        cell.server_pid(),
        None,
        "copy_tree_from left a server running"
    );
    assert_eq!(cell.module_lock().as_deref(), Some(&b"{}\n"[..]));

    cell.install_probe_rule();
    assert!(cell.scratch.workspace.join(PROBE_BZL).is_file());
    assert!(
        panics(&|| cell.install_probe_rule()),
        "a second {PROBE_BZL} must be refused"
    );

    let report = cell.close();
    outside.assert_untouched("after the cell closed");
    report.ran();
}

/// `SIGKILL`: the server gets no chance to run its shutdown hooks.
#[cfg(unix)]
fn kill_hard(pid: u32) -> bool {
    let pid = libc::pid_t::try_from(pid).expect("a pid");
    // SAFETY: `kill` takes two integers and touches no memory.
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}

#[cfg(not(unix))]
fn kill_hard(_: u32) -> bool {
    false
}

/// A server that dies without its shutdown hooks (a crash that halts the
/// JVM, the OOM killer) leaves `server.pid.txt` behind, and `bazel
/// shutdown` then exits 0 without touching it. The cell must read that as
/// "no server", not as a server that survived the shutdown: every lock
/// write and `Cell::close` go through the same check.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_shutdown_after_the_server_was_killed() {
    const TEST: &str = "bazel_core_shutdown_after_the_server_was_killed";
    if !cfg!(unix) {
        probe_report::skip_na(&Report::new(TEST), "the test kills the server with SIGKILL");
        return;
    }
    let outside = OutsideState::capture();
    let Some(cell) = Cell::open(TEST, Group::Core, None) else {
        return;
    };
    cell.write("MODULE.bazel", "");
    cell.write("WORKSPACE", "");
    let server_pid = |cell: &Cell| -> u32 {
        let pid = cell.info("server_pid").parse();
        pid.expect("a numeric server pid")
    };

    let killed = server_pid(&cell);
    assert!(kill_hard(killed), "kill server {killed}");
    let deadline = Instant::now() + Duration::from_secs(30);
    while server::process_alive(killed) {
        assert!(
            Instant::now() < deadline,
            "server {killed} outlived SIGKILL"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // What the harness used to take for a live server. Without it this
    // test would pass having tested nothing.
    assert_eq!(
        cell.server_pid(),
        Some(killed),
        "a killed server leaves its pid file"
    );

    cell.shutdown();
    assert_eq!(cell.server_pid(), None, "the stale pid file is cleared");
    // The output base is still usable: the next command starts a server.
    let next = server_pid(&cell);
    assert_ne!(next, killed);
    assert_eq!(cell.server_pid(), Some(next));

    let report = cell.close();
    outside.assert_untouched("after the cell closed");
    report.ran();
}

const DATA: &[u8] = b"socket-patch probe canary\n";

/// A rule that makes a tree artifact with no shell: Bazel creates the
/// declared directory, and `cp` copies one file into it.
const TREE_BZL: &str = r#"def _tree_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name + ".dir")
    ctx.actions.run(
        executable = "/bin/cp",
        arguments = [ctx.file.src.path, out.path],
        inputs = [ctx.file.src],
        outputs = [out],
        mnemonic = "SocketTree",
    )
    return [DefaultInfo(files = depset([out]))]

tree = rule(
    implementation = _tree_impl,
    attrs = {"src": attr.label(allow_single_file = True, mandatory = True)},
)
"#;

const BUILD: &str = r#"load("//:probe.bzl", "socket_probe")
load("//:tree.bzl", "tree")

tree(
    name = "tree",
    src = "data.txt",
)

socket_probe(
    name = "socket_probe",
    srcs = [
        "data.txt",
        ":tree",
    ],
)
"#;

/// The package the toy cell probes the rule in: beside the fixture's own
/// `//:socket_probe`, so nothing of the fixture changes.
const PROBE_PACKAGE: &str = "probe_rule";

/// What a `socket_probe` over [`BUILD`] must yield: the file input's bytes
/// and a directory that holds exactly the tree artifact's one file.
fn assert_probe_outputs(cell: &Cell, target: &str, server: &str) {
    let output = |name: &str| cell.probe_output(&cell.options, target, name);
    let file = std::fs::read(output("data.txt")).expect("read the probe's file output");
    assert_eq!(file, DATA, "{server} server: file input");
    let tree = output("tree.dir");
    assert!(
        tree.is_dir(),
        "{server} server: {} is not a directory",
        tree.display()
    );
    assert_eq!(
        entries(&tree),
        ["data.txt"],
        "{server} server: tree contents"
    );
    let copied = std::fs::read(tree.join("data.txt")).expect("read the tree's file");
    assert_eq!(copied, DATA, "{server} server: tree-artifact input");
}

/// `common/probe.bzl` takes a tree-artifact input (the shape rules_js
/// hands it) on the toy cell, where nothing leaves the machine on a line
/// that commits its module archives: Bazel's own modules come from the
/// committed registry and archives, and the fixture's one package from the
/// loopback fixture server. Tier 1 holds for the file and for the tree on
/// a warm and on a restarted server, and the lock the baseline wrote is
/// the lock a restarted server writes again (`lock_after_rebaseline`: what
/// a lane compares after a rollback), also on 6.6.0, 7.0.2 and 7.1.2,
/// whose lock is of the older family that names the registry it was made
/// against. The standing check of the rule in the `bazel_core_` row, on
/// every release of the core cells that has the Bzlmod fixture
/// (`core/MATRIX.json`; like any test of the toy group it reports `SKIP
/// (n/a)` on a release its row does not list).
/// `bazel_canary_probe_rule_tree_artifact` is the same probe on any line,
/// through the real registry; it is planned on the pinned releases this
/// test does not claim.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_probe_rule_takes_a_tree_artifact() {
    const TEST: &str = "bazel_core_probe_rule_takes_a_tree_artifact";
    if cfg!(windows) {
        probe_report::skip_na(&Report::new(TEST), "the tree-artifact maker runs /bin/cp");
        return;
    }
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    let target = format!("//{PROBE_PACKAGE}:socket_probe");
    cell.write("tree.bzl", TREE_BZL);
    cell.write(&format!("{PROBE_PACKAGE}/data.txt"), DATA);
    cell.write(&format!("{PROBE_PACKAGE}/BUILD.bazel"), BUILD);

    // `//...` and not the probe alone: the fixture's own targets evaluate
    // the toy extension, so the lock has something to record on every line
    // (under the committed `file://` registry a 9.3.2 build that evaluates
    // no extension writes no lock at all).
    cell.baseline(&["//..."], false);
    let lock = cell.module_lock();
    assert!(lock.is_some(), "{TEST}: the baseline wrote no lock");
    assert_probe_outputs(cell, &target, "warm");

    let again = cell.lock_after_rebaseline(&["//..."], false);
    assert_probe_outputs(cell, &target, "restarted");
    assert!(
        again == lock,
        "{TEST}: a restarted server wrote another lock for the same commands"
    );

    // Whatever the fixture server was asked for (the fixture's own toy
    // package, and the registry where it plays one), it answered.
    let unanswered: Vec<String> = toy
        .server
        .requests()
        .into_iter()
        .filter(|request| request.status != 200)
        .map(|request| request.url)
        .collect();
    assert_eq!(unanswered, Vec::<String>::new(), "{TEST}: unanswered");
    toy.finish();
}

/// The canary's workspace on a line where `socket_probe` cannot take a
/// directory input: the file input alone.
const BUILD_FILE_ONLY: &str = r#"load("//:probe.bzl", "socket_probe")

socket_probe(
    name = "socket_probe",
    srcs = ["data.txt"],
)
"#;

/// `common/probe.bzl` on this Bazel: tier 0 lists the source file with its
/// digest, and tier 1 yields the same bytes for a file input and for a
/// tree-artifact input (the shape rules_js hands the probe, which a rule
/// that only declares files fails on), on a warm and on a restarted
/// server. Before Bazel 6 the rule cannot take a directory input (on 5.4.1
/// the symlink action fails with `File exists`): the file input alone is
/// built there, and the report says so. Record-only: on a Bzlmod line
/// Bazel resolves its builtin modules from the real registry, so the cell
/// says nothing about hermeticity.
#[test]
#[ignore = "real Bazel and the network; run with --ignored"]
fn bazel_canary_probe_rule_tree_artifact() {
    const TEST: &str = "bazel_canary_probe_rule_tree_artifact";
    if cfg!(windows) {
        probe_report::skip_na(&Report::new(TEST), "the tree-artifact maker runs /bin/cp");
        return;
    }
    let outside = OutsideState::capture();
    let Some(mut cell) = Cell::open(TEST, Group::Core, None) else {
        return;
    };
    if env::offline() {
        // No fixture server and no downloader rewrite here: the build
        // would reach the real registry in the phase that forbids it.
        let why = "the canary resolves Bazel's own modules from the real registry; the offline \
                   phase has bazel_core_probe_rule_takes_a_tree_artifact";
        probe_report::skip_na(&cell.report, why);
        return;
    }
    cell.write("MODULE.bazel", "module(name = \"socket_probe_canary\")\n");
    cell.write("WORKSPACE", "workspace(name = \"socket_probe_canary\")\n");
    cell.write("data.txt", DATA);
    // No planned fixture hands the probe a directory on a 5.x line.
    let tree_input = cell.bazel.version.at_least(6, 0, 0);
    if tree_input {
        cell.write("tree.bzl", TREE_BZL);
        cell.write("BUILD.bazel", BUILD);
    } else {
        cell.write("BUILD.bazel", BUILD_FILE_ONLY);
    }
    cell.install_probe_rule();

    let fetch = cell.bazel("build", &["--nobuild", PROBE]);
    if fetch.origin_unreachable() {
        let why = format!("an origin is unreachable:\n{}", fetch.stderr());
        probe_report::skip(&cell.report, &why);
        return;
    }
    assert!(fetch.ok(), "{}", fetch.dump());

    let sha256 = hex::encode(Sha256::digest(DATA));
    let listed = cell.tier0(Anchor::Sha256 {
        label: ":data.txt",
        sha256: &sha256,
    });
    assert_eq!(
        resolved(&listed),
        resolved(cell.scratch.workspace.join("data.txt"))
    );

    for server in ["warm", "restarted"] {
        assert_eq!(
            cell.tier1_file("data.txt"),
            DATA,
            "{server} server: file input"
        );
        if tree_input {
            let tree = cell.tier1_output("tree.dir");
            assert!(
                tree.is_dir(),
                "{server} server: {} is not a directory",
                tree.display()
            );
            assert_eq!(
                entries(&tree),
                ["data.txt"],
                "{server} server: tree contents"
            );
            let copied = std::fs::read(tree.join("data.txt")).expect("read the tree's file");
            assert_eq!(copied, DATA, "{server} server: tree-artifact input");
        }
        cell.shutdown();
    }
    outside.assert_untouched("after the builds");

    let jvm_tmp = entries(&cell.scratch.tmp);
    let tree_artifact = if tree_input {
        "built"
    } else {
        "unsupported before Bazel 6"
    };
    cell.report.direct_network = true;
    cell.report
        .detail("jvm_tmp_entries", jvm_tmp)
        .detail("tree_artifact", tree_artifact);
    let report = cell.close();
    outside.assert_untouched("after the cell closed");
    report.ran();
}
