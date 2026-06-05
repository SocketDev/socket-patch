//! setup-matrix: golang ecosystem (go modules). `setup` wires a project-local
//! fail-closed guard (`internal/socketpatchguard` + a blank import in each
//! `package main` dir) via the go.mod-redirect backend (#104). The Docker
//! matrix `go()` case is still an EXPECTED BASELINE GAP (its image carries an
//! older binary and `matrix.json` marks go `baseline_supported=false`); the
//! real configure→check→remove contract is pinned by the host guard below.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("golang", "go")` routes go through the shared Docker matrix
//! harness, which (a) *soft-skips and silently passes* whenever Docker or the
//! `golang` image is absent (the common case locally and in this eval), and
//! (b) is NOT npm-family (`is_npm_family` is false for go — see the harness),
//! so the check/remove behavioral round-trip is skipped entirely. go's
//! `baseline_supported` is also false in matrix.json, so the only verdict the
//! matrix could ever produce is the coarse `actual_applied == expect_applied`
//! — and on a crashed / never-run case `actual_applied` defaults to the same
//! `false` that satisfies every negative-control scenario. Net effect: the
//! matrix call can never turn red for a genuine go `setup` regression. On its
//! own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::go_setup_configures_and_removes_guard_host`] runs
//! unconditionally (no Docker, no network, no go toolchain) and pins go
//! `setup`'s *actual current contract*: `--check` on an un-wired project
//! reports `needs_configuration` (exit 1); `setup` wires the guard package +
//! blank import (status `success`, `updated=2`) without mutating the go
//! sources; `--check` then reports `configured` (exit 0); and `--remove` tears
//! it back out, restoring the byte-for-byte original tree. It verifies on-disk
//! state with an *independent* recursive directory snapshot (not any production
//! helper) so the oracle can disagree with a broken implementation. It fails
//! loudly if go `setup` regresses to a no-op, mis-reports state, leaks files,
//! or aborts.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_golang`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the go negative
/// controls when Docker + the `golang` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The real
/// teeth live in [`host_guard`] below.
#[test]
fn go() {
    smc::run_pm("golang", "go");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for go `setup`.
//
// Since #104's go.mod-redirect backend, `setup` wires a project-local
// fail-closed guard (`internal/socketpatchguard` + a blank import per
// `package main` dir) and `--remove` tears it back out. This guard pins that
// configure→check→remove round-trip — the assertion the Docker matrix can
// never make for go — and would fail loudly if a regression dropped the
// wiring, mis-reported state, leaked files, or aborted.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::process::Command;

    /// A faithful single-module go project mirroring the matrix `golang`
    /// target (`github.com/gin-gonic/gin@v1.9.1`): a `go.mod`, a `go.sum`, and
    /// a `main.go`. None of these is a surface `setup` configures, so the whole
    /// tree must come back byte-for-byte unchanged.
    const GO_MOD: &str = "module example.com/sm-go-proj\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n";
    const GO_SUM: &str = "github.com/gin-gonic/gin v1.9.1 h1:placeholderhashplaceholderhashplace= \ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:placeholdermodhashplaceholderhash=\n";
    const MAIN_GO: &str = "package main\n\nimport \"github.com/gin-gonic/gin\"\n\nfunc main() {\n\t_ = gin.New()\n}\n";

    /// Absolute path to the binary under test, via cargo's `CARGO_BIN_EXE_*`.
    fn binary() -> std::path::PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Every `SOCKET_*` env var clap consults for the surface this test drives.
    /// They are stripped from the child so behaviour reflects ONLY the explicit
    /// flags (`--cwd`, `--yes`, `--check`, `--remove`, `--json`). Without this,
    /// an ambient `SOCKET_CWD` could point setup at a *different* directory than
    /// the go fixture (e.g. a real package.json elsewhere), masking a regression
    /// by making the run report on something other than the go project.
    const SOCKET_ENV_VARS: &[&str] = &[
        "SOCKET_CWD",
        "SOCKET_MANIFEST_PATH",
        "SOCKET_API_URL",
        "SOCKET_API_TOKEN",
        "SOCKET_ORG_SLUG",
        "SOCKET_PROXY_URL",
        "SOCKET_ECOSYSTEMS",
        "SOCKET_DOWNLOAD_MODE",
        "SOCKET_OFFLINE",
        "SOCKET_GLOBAL",
        "SOCKET_GLOBAL_PREFIX",
        "SOCKET_JSON",
        "SOCKET_VERBOSE",
        "SOCKET_SILENT",
        "SOCKET_DRY_RUN",
        "SOCKET_YES",
        "SOCKET_LOCK_TIMEOUT",
        "SOCKET_BREAK_LOCK",
        "SOCKET_DEBUG",
        "SOCKET_TELEMETRY_DISABLED",
        "SOCKET_SAVE_ONLY",
        "SOCKET_ONE_OFF",
        "SOCKET_ALL_RELEASES",
        "SOCKET_PATCH_ROOT",
        "SOCKET_PATCH_GUARD",
    ];

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// The whole `SOCKET_*` surface is stripped so behaviour reflects the
    /// explicit flags alone and nothing reaches authed endpoints.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(binary());
        cmd.args(args).current_dir(cwd);
        for var in SOCKET_ENV_VARS {
            cmd.env_remove(var);
        }
        let out = cmd.output().expect("failed to execute socket-patch binary");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Parse the CLI's `--json` stdout into a single JSON object. Panics
    /// (loudly) if stdout is not the single JSON object the command promises —
    /// a non-JSON / multi-line dump means the command did not run the path we
    /// think it did.
    fn parse_json(stdout: &str, who: &str) -> serde_json::Value {
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}")
        })
    }

    fn json_str_field(v: &serde_json::Value, key: &str, who: &str) -> String {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{who}: JSON has no string `{key}` field:\n{v}"))
            .to_string()
    }

    fn json_i64_field(v: &serde_json::Value, key: &str, who: &str) -> i64 {
        v.get(key)
            .and_then(|n| n.as_i64())
            .unwrap_or_else(|| panic!("{who}: JSON has no integer `{key}` field:\n{v}"))
    }

    /// Independent oracle: a recursive `relative-path -> bytes` snapshot of the
    /// project tree. Deliberately does NOT reuse any production discovery /
    /// detection helper, so it can disagree with a broken `setup` that litters
    /// or mutates the go project. Used to prove the tree is byte-for-byte
    /// identical before and after every sub-command.
    fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut map = BTreeMap::new();
        fn walk(dir: &Path, base: &Path, map: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                let ft = entry.file_type().expect("file_type");
                if ft.is_dir() {
                    walk(&path, base, map);
                } else {
                    let rel = path
                        .strip_prefix(base)
                        .expect("strip base")
                        .to_string_lossy()
                        .into_owned();
                    map.insert(rel, std::fs::read(&path).expect("read file"));
                }
            }
        }
        walk(root, root, &mut map);
        map
    }

    /// Assert the snapshot is exactly the three go fixture files (unchanged),
    /// proving `setup` neither littered the tree with a hook file
    /// (package.json / .cargo/config.toml / *.pth) nor mutated the go sources.
    fn assert_pristine_go_tree(root: &Path, who: &str) {
        let snap = snapshot(root);
        let names: Vec<&str> = snap.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            vec!["go.mod", "go.sum", "main.go"],
            "{who}: go project tree must contain ONLY the original go files \
             (setup must not write a hook into a go project); found: {names:?}"
        );
        assert_eq!(snap["go.mod"], GO_MOD.as_bytes(), "{who}: go.mod must be unchanged");
        assert_eq!(snap["go.sum"], GO_SUM.as_bytes(), "{who}: go.sum must be unchanged");
        assert_eq!(snap["main.go"], MAIN_GO.as_bytes(), "{who}: main.go must be unchanged");
    }

    #[test]
    fn go_setup_configures_and_removes_guard_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("go.mod"), GO_MOD).unwrap();
        std::fs::write(root.join("go.sum"), GO_SUM).unwrap();
        std::fs::write(root.join("main.go"), MAIN_GO).unwrap();
        let root_s = root.to_str().unwrap();

        // Pin the BEFORE state: exactly the three go files, no hook artifacts.
        assert_pristine_go_tree(root, "fixture (pristine)");

        // The fail-closed guard surfaces setup wires into a `package main` dir:
        // a guard package under `internal/socketpatchguard/` and a blank import
        // beside the `package main` file (here, the repo root).
        let guard_dir = root.join("internal").join("socketpatchguard");
        let guard_go = guard_dir.join("guard.go");
        let guard_test = guard_dir.join("guard_test.go");
        let import_go = root.join("socket_patch_guard_import.go");

        // ── check (pristine): since #104's go.mod-redirect guard backend, go IS
        // a configurable surface — an un-wired project reports
        // `needs_configuration` and exits 1 (NOT `no_files`/exit 0). ──────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check on an un-wired go project must exit 1 (guard not configured).\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (pristine)");
        assert_eq!(
            json_str_field(&v, "status", "check (pristine)"),
            "needs_configuration",
            "an un-wired go project must report needs_configuration.\nstderr:\n{err}"
        );
        let kinds: Vec<&str> = v["files"]
            .as_array()
            .expect("check must report a files array")
            .iter()
            .filter_map(|f| f["kind"].as_str())
            .collect();
        assert!(
            kinds.contains(&"go_guard") && kinds.contains(&"go_import"),
            "check must surface the go_guard + go_import targets; got kinds={kinds:?}\n{out}"
        );
        // --check must not write anything.
        assert_pristine_go_tree(root, "after check");

        // ── setup: wires the guard package + the blank import. ───────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup on a go project must exit 0.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "setup");
        assert_eq!(
            json_str_field(&v, "status", "setup"),
            "success",
            "setup must report success now that go is a configurable surface.\nstderr:\n{err}"
        );
        assert_eq!(
            json_i64_field(&v, "updated", "setup"),
            2,
            "setup wires exactly the guard package + the blank import.\n{out}"
        );
        assert_eq!(json_i64_field(&v, "errors", "setup"), 0, "setup must report zero errors.\n{out}");
        // Independent on-disk oracle: the guard package + blank import now exist,
        // and the original go sources are byte-for-byte untouched. (Use path
        // joins, not snapshot string keys, so this is separator-correct on
        // Windows.)
        assert!(guard_go.exists(), "setup must write internal/socketpatchguard/guard.go");
        assert!(guard_test.exists(), "setup must write internal/socketpatchguard/guard_test.go");
        assert!(import_go.exists(), "setup must write the blank socket_patch_guard_import.go");
        assert_eq!(std::fs::read(root.join("go.mod")).unwrap(), GO_MOD.as_bytes(), "go.mod must be unchanged");
        assert_eq!(std::fs::read(root.join("main.go")).unwrap(), MAIN_GO.as_bytes(), "main.go must be unchanged");

        // ── check (post-setup): now configured, exit 0. ──────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check must exit 0 once the guard is wired.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_eq!(
            json_str_field(&parse_json(&out, "check (post-setup)"), "status", "check (post-setup)"),
            "configured",
            "go must report configured after setup wired the guard.\nstderr:\n{err}"
        );

        // ── remove: tears down the guard + import (pruning internal/) and
        // restores the exact pre-setup tree. ────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup --remove on a configured go project must exit 0.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_eq!(
            json_str_field(&parse_json(&out, "remove"), "status", "remove"),
            "success",
            "remove must report success when it tears the guard back out.\nstderr:\n{err}"
        );
        // Decisive anti-leak check: the tree is byte-for-byte the original three
        // files — the guard package + blank import are gone and internal/ pruned.
        assert_pristine_go_tree(root, "after remove");

        // ── check (post-remove): back to needs_configuration, exit 1. ────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must exit 1 again once the guard is removed.\nstdout:\n{out}\nstderr:\n{err}"
        );
    }
}
