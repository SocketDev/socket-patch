//! The upward lookups bounded by [`super::upward_bound`]: inside a git
//! checkout none reads a file above the repository root, and each one
//! that would have found something there refuses or withholds; outside
//! any checkout each walks on as before. Every test here fails with the
//! bound disabled (`upward_bound` answering `None`).

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// `<base>/outer/repo` is the checkout (with `.git` unless `git` is
/// false) and `<base>/outer/repo/app` the project; `<base>/outer` lies
/// above the repository root.
struct Layout {
    _tmp: tempfile::TempDir,
    outer: PathBuf,
    repo: PathBuf,
    app: PathBuf,
}

fn layout(git: bool) -> Layout {
    let tmp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let outer = base.join("outer");
    let repo = outer.join("repo");
    let app = repo.join("app");
    fs::create_dir_all(&app).unwrap();
    if git {
        fs::create_dir_all(repo.join(".git")).unwrap();
    }
    Layout {
        _tmp: tmp,
        outer,
        repo,
        app,
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn marker_above_is_stat_only_and_starts_above_the_checkout() {
    let l = layout(true);
    let bound = upward_bound(ReadScope::Workspace, &l.app).unwrap();
    assert_eq!(bound.root(), Some(l.repo.as_path()));
    assert_eq!(bound.marker_above(&["package.json"]), None);
    write(&l.repo.join("package.json"), "{}");
    assert_eq!(bound.marker_above(&["package.json"]), None, "inside");
    write(&l.outer.join("package.json"), "not json");
    assert_eq!(
        bound.marker_above(&["package.json"]),
        Some(l.outer.join("package.json"))
    );
    assert!(upward_readable(
        ReadScope::Workspace,
        &l.app,
        &l.repo.join("package.json")
    ));
    assert!(!upward_readable(
        ReadScope::Workspace,
        &l.app,
        &l.outer.join("package.json")
    ));
    // No checkout: no bound, every ancestor stays readable.
    let plain = layout(false);
    assert_eq!(upward_bound(ReadScope::Workspace, &plain.app), None);
    assert!(upward_readable(
        ReadScope::Workspace,
        &plain.app,
        &plain.outer.join("package.json")
    ));
}

/// npm / yarn / Bun `package.json` workspaces (and the pnpm and vlt
/// files) above the repository: a lockless member is refused naming the
/// unread file, never read as the workspace root.
#[tokio::test]
async fn npm_family_workspace_root_above_the_repository() {
    for git in [true, false] {
        let l = layout(git);
        write(&l.app.join("package.json"), r#"{"name":"app"}"#);
        write(
            &l.outer.join("package.json"),
            r#"{"name":"ws","workspaces":["repo/app"]}"#,
        );
        write(&l.outer.join("package-lock.json"), "{}");
        let found = crate::hosted::governing_root::npm_lock_elsewhere(&l.app)
            .await
            .unwrap();
        assert_eq!(found.dir, l.outer, "git: {git}");
        assert_eq!(
            found.detail.contains("outside the repository"),
            git,
            "git: {git}: {}",
            found.detail
        );
    }
}

/// A member's own lock under a workspace root above the repository.
#[tokio::test]
async fn member_stray_lock_above_the_repository() {
    for git in [true, false] {
        let l = layout(git);
        write(&l.app.join("package.json"), r#"{"name":"app"}"#);
        write(&l.app.join("package-lock.json"), "{}");
        write(
            &l.outer.join("package.json"),
            r#"{"name":"ws","workspaces":["repo/app"]}"#,
        );
        write(&l.outer.join("package-lock.json"), "{}");
        let stray = crate::hosted::governing_root::member_stray_lock(&l.app)
            .await
            .unwrap();
        assert_eq!(stray.root, l.outer);
        assert_eq!(
            stray.detail.contains("outside the repository"),
            git,
            "{}",
            stray.detail
        );
    }
}

/// The nearest `pnpm-workspace.yaml` above the repository fails closed
/// as governing, even one that would not list the member when read.
#[test]
fn pnpm_workspace_file_above_the_repository_fails_closed() {
    let l = layout(true);
    let file = l.outer.join("pnpm-workspace.yaml");
    write(&file, "packages:\n  - other\n");
    assert_eq!(
        crate::utils::pnpm_workspace::governing_workspace_file(&l.app),
        Some(file)
    );
    let plain = layout(false);
    write(
        &plain.outer.join("pnpm-workspace.yaml"),
        "packages:\n  - other\n",
    );
    assert_eq!(
        crate::utils::pnpm_workspace::governing_workspace_file(&plain.app),
        None,
        "read as before"
    );
}

#[tokio::test]
async fn uv_workspace_root_above_the_repository() {
    for git in [true, false] {
        let l = layout(git);
        write(&l.app.join("pyproject.toml"), "[project]\nname = \"app\"\n");
        write(
            &l.outer.join("pyproject.toml"),
            "[tool.uv.workspace]\nmembers = [\"repo/app\"]\n",
        );
        let why = crate::utils::uv_workspace::governing_uv_refusal(&l.app)
            .await
            .unwrap();
        assert_eq!(why.contains("outside the repository"), git, "{why}");
        assert_eq!(why.contains("is a member of the uv workspace"), !git);
    }
}

#[test]
fn uv_settings_above_the_repository() {
    use crate::utils::python_script::{find_ancestor_uv_config, uv_config_above_repo};
    for git in [true, false] {
        let l = layout(git);
        write(&l.outer.join("uv.toml"), "[pip]\nno-binary = [\"six\"]\n");
        assert_eq!(find_ancestor_uv_config(&l.app).is_some(), !git);
        let ancestor = find_ancestor_uv_config(&l.app);
        assert_eq!(
            uv_config_above_repo(&l.app, ancestor.as_ref()).is_some(),
            git
        );
    }
}

#[tokio::test]
async fn cargo_workspace_and_configs_above_the_repository() {
    for git in [true, false] {
        let l = layout(git);
        write(
            &l.app.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        );
        write(
            &l.outer.join("Cargo.toml"),
            "[workspace]\nmembers = [\"repo/app\"]\n",
        );
        let doc = crate::vendor::cargo_manifest::parse_manifest(
            &fs::read_to_string(l.app.join("Cargo.toml")).unwrap(),
        )
        .unwrap();
        let why = crate::vendor::cargo::workspace_root_refusal(&l.app, &doc, "hint")
            .await
            .unwrap();
        assert_eq!(why.contains("outside the repository"), git, "{why}");

        write(
            &l.outer.join(".cargo/config.toml"),
            "[patch.crates-io]\nserde = { path = \"x\" }\n",
        );
        let chain = crate::vendor::cargo_config::read_config_chain_with(&l.app, None).await;
        assert_eq!(chain.is_empty(), git, "{chain:?}");
        assert_eq!(
            crate::vendor::cargo_config::config_above_repo(&l.app).is_some(),
            git
        );
        let layers = crate::formats::cargo::source_replacement::config_layer_paths(
            ReadScope::Workspace,
            &l.app,
            None,
            |p| p.is_file(),
        );
        assert_eq!(layers.is_empty(), git, "{layers:?}");
    }
}

#[test]
fn gradle_settings_above_the_repository() {
    for git in [true, false] {
        let l = layout(git);
        write(&l.app.join("build.gradle"), "");
        write(&l.outer.join("settings.gradle"), "include 'repo:app'\n");
        let roots = crate::crawlers::gradle_cache::build_roots(ReadScope::Workspace, &l.app);
        assert_eq!(roots.contains(&l.outer), !git, "{roots:?}");
    }
}

fn yarn_env() -> crate::crawlers::pkg_managers::YarnEnv {
    crate::crawlers::pkg_managers::YarnEnv {
        node_linker: None,
        pnpm_store_folder: None,
        rc_filename: ".yarnrc.yml".to_string(),
        home: None,
        vars: Some(Default::default()),
        env_files: Default::default(),
        scope: ReadScope::Workspace,
    }
}

#[test]
fn yarnrc_yml_above_the_repository() {
    use crate::crawlers::pkg_managers::{yarn_node_linker_in, yarn_pnpm_store_folder_in};
    for git in [true, false] {
        let l = layout(git);
        write(
            &l.outer.join(".yarnrc.yml"),
            "nodeLinker: node-modules\npnpmStoreFolder: store\n\
             injectEnvironmentFiles: [vars.env]\n",
        );
        write(&l.outer.join("vars.env"), "INJECTED=1\n");
        let linker = yarn_node_linker_in(&l.app, &yarn_env()).unwrap();
        assert_eq!(linker == "node-modules", !git, "{linker}");
        assert_eq!(
            yarn_pnpm_store_folder_in(&l.app, &yarn_env()),
            (!git).then(|| l.outer.join("store"))
        );
        let env = yarn_env().with_env_files(&l.app, None);
        assert_eq!(env.var("INJECTED").is_some(), !git);
    }
}

/// yarn classic's `.yarnrc` / `.npmrc` above the repository: the outer
/// mirror fails closed (the hosted rewriter then refuses).
#[test]
fn yarn_classic_rc_above_the_repository() {
    use crate::patch::redirect::yarnrc::{resolve_outer_yarn_mirror, MirrorValue};
    let env = crate::patch::redirect::npmrc::NpmConfigEnv {
        vars: Vec::new(),
        home: None,
        node_exe: None,
        windows: false,
    };
    for git in [true, false] {
        let l = layout(git);
        write(&l.outer.join(".yarnrc"), "yarn-offline-mirror \"./m\"\n");
        let read = |p: &Path| fs::read_to_string(p).ok();
        let outer = resolve_outer_yarn_mirror(&env, false, &l.app, read);
        let file = outer.yarn.file.unwrap();
        if git {
            assert!(file.origin.contains("outside the repository"), "{file:?}");
        } else {
            assert_eq!(file.value, MirrorValue::Path("./m".to_string()));
        }
    }
}

/// A global run (`--global` / `--global-prefix`) is unbounded: every
/// lookup the CLI threads `ReadScope::Global` into reads above the
/// repository root, exactly as before the bound, while the same layout in
/// a workspace run stays bounded (the tests above).
#[test]
fn global_scope_reads_above_the_repository() {
    let l = layout(true);
    write(&l.outer.join("go.work"), "go 1.22\n");
    write(&l.outer.join(".cargo/config.toml"), "[build]\njobs = 1\n");
    write(&l.app.join("build.gradle"), "");
    write(&l.outer.join("settings.gradle"), "include 'repo:app'\n");
    write(
        &l.outer.join(".yarnrc.yml"),
        "nodeLinker: node-modules\npnpmStoreFolder: store\n",
    );

    assert_eq!(upward_bound(ReadScope::Global, &l.app), None);
    assert!(upward_readable(
        ReadScope::Global,
        &l.app,
        &l.outer.join("go.work")
    ));
    assert!(ReadBoundary::of(ReadScope::Global, &l.app).contains(&l.outer));
    assert!(bounded_project_path(ReadScope::Global, &l.app, "../../go.work").is_ok());
    assert!(bounded_project_path(ReadScope::Workspace, &l.app, "../../go.work").is_err());

    // `GOWORK` in the environment would decide instead.
    if std::env::var_os("GOWORK").is_none() {
        use crate::vendor::go_workspace::{resolve_in, GoWork};
        assert_eq!(
            resolve_in(ReadScope::Global, &l.app),
            GoWork::File(l.outer.join("go.work"))
        );
        assert!(matches!(
            resolve_in(ReadScope::Workspace, &l.app),
            GoWork::Invalid(_)
        ));
    }

    let layers = crate::formats::cargo::source_replacement::config_layer_paths(
        ReadScope::Global,
        &l.app,
        None,
        |p| p.is_file(),
    );
    assert!(
        layers.contains(&(l.outer.join(".cargo/config.toml"), l.outer.clone())),
        "{layers:?}"
    );

    let roots = crate::crawlers::gradle_cache::build_roots(ReadScope::Global, &l.app);
    assert!(roots.contains(&l.outer), "{roots:?}");

    use crate::crawlers::pkg_managers::{yarn_node_linker_in, yarn_pnpm_store_folder_in};
    let env = crate::crawlers::pkg_managers::YarnEnv {
        scope: ReadScope::Global,
        ..yarn_env()
    };
    assert_eq!(
        yarn_node_linker_in(&l.app, &env).as_deref(),
        Some("node-modules")
    );
    assert_eq!(
        yarn_pnpm_store_folder_in(&l.app, &env),
        Some(l.outer.join("store"))
    );
}

/// The crawler's scope comes from its CLI mode, never from the
/// filesystem: a `--global-prefix` crawl outside any repository finds its
/// packages while the working directory sits in a checkout.
#[tokio::test]
async fn global_crawl_reads_a_package_outside_the_repository() {
    use crate::crawlers::types::CrawlerOptions;
    let l = layout(true);
    let global = l.outer.join("global/node_modules");
    write(
        &global.join("left-pad/package.json"),
        r#"{"name":"left-pad","version":"1.3.0"}"#,
    );
    let options = CrawlerOptions {
        cwd: l.app.clone(),
        global: true,
        global_prefix: Some(global.clone()),
    };
    assert_eq!(options.read_scope(), ReadScope::Global);
    let local = CrawlerOptions {
        cwd: l.app.clone(),
        global: false,
        global_prefix: None,
    };
    assert_eq!(local.read_scope(), ReadScope::Workspace);
    let found = crate::crawlers::npm_crawler::NpmCrawler::for_options(&options)
        .crawl_all(&options)
        .await;
    assert!(
        found.iter().any(|p| p.purl == "pkg:npm/left-pad@1.3.0"),
        "{found:?}"
    );
}
