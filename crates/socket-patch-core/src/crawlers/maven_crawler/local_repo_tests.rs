//! The Maven local repository agent mode and `-g` work on must be the one
//! Maven itself uses (#423): `M2_HOME` is the Maven install, not a local
//! repository; `<localRepository>` in the user or global `settings.xml`
//! and `-Dmaven.repo.local` relocate it; on Windows `user.home` is the
//! profile directory, whatever `HOME` says. A project's `.mvn/maven.config`
//! can relocate it too, for the builds run in that project.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::JvmEnv;
use crate::gradle::Os;

fn env(pairs: &[(&str, &Path)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
        .collect()
}

fn m2_repo(env: &HashMap<String, String>, os: Os) -> Option<PathBuf> {
    JvmEnv::resolve(env, os, None).m2_repo
}

/// The local repository of a build run in `project`.
fn m2_repo_in(env: &HashMap<String, String>, project: &Path) -> Option<PathBuf> {
    JvmEnv::resolve_in(env, Os::current(), None, Some(project)).m2_repo
}

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn settings(local_repository: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<settings>\n  <!-- <localRepository>/commented</localRepository> -->\n  \
         <localRepository>{local_repository}</localRepository>\n</settings>\n"
    )
}

/// Trigger 1: `M2_HOME` names the Maven install. Maven keeps using
/// `~/.m2/repository`, and so must the crawler.
#[test]
fn m2_home_is_not_a_local_repository() {
    let home = tempfile::tempdir().unwrap();
    let install = tempfile::tempdir().unwrap();
    let e = env(&[("HOME", home.path()), ("M2_HOME", install.path())]);
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(home.path().join(".m2").join("repository"))
    );
}

/// Trigger 2: `<localRepository>` in `~/.m2/settings.xml`.
#[test]
fn user_settings_local_repository_is_honoured() {
    let home = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    write(
        &home.path().join(".m2").join("settings.xml"),
        &settings(&format!("  {}  ", data.path().display())),
    );
    let e = env(&[("HOME", home.path())]);
    assert_eq!(m2_repo(&e, Os::Unix), Some(data.path().to_path_buf()));
}

/// `${user.home}` and `${env.NAME}` interpolate in `<localRepository>`, as
/// Maven's settings builder does.
#[test]
fn settings_local_repository_interpolates_user_home_and_env() {
    let home = tempfile::tempdir().unwrap();
    let user_settings = home.path().join(".m2").join("settings.xml");
    write(&user_settings, &settings("${user.home}/caches/m2"));
    let e = env(&[("HOME", home.path())]);
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(PathBuf::from(format!(
            "{}/caches/m2",
            home.path().display()
        )))
    );

    let ci = tempfile::tempdir().unwrap();
    write(&user_settings, &settings("${env.CI_CACHE}/m2"));
    let e = env(&[("HOME", home.path()), ("CI_CACHE", ci.path())]);
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(PathBuf::from(format!("{}/m2", ci.path().display())))
    );

    // A placeholder nothing defines is no usable directory: the default.
    let e = env(&[("HOME", home.path())]);
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(home.path().join(".m2").join("repository"))
    );
}

/// The install's `conf/settings.xml` (under `MAVEN_HOME`, or `M2_HOME`)
/// applies when the user settings don't set `<localRepository>`, and the
/// user settings win when both do.
#[test]
fn global_settings_local_repository_is_honoured_below_user_settings() {
    let home = tempfile::tempdir().unwrap();
    let install = tempfile::tempdir().unwrap();
    let global = tempfile::tempdir().unwrap();
    let user = tempfile::tempdir().unwrap();
    write(
        &install.path().join("conf").join("settings.xml"),
        &settings(global.path().to_str().unwrap()),
    );
    for var in ["MAVEN_HOME", "M2_HOME"] {
        let e = env(&[("HOME", home.path()), (var, install.path())]);
        assert_eq!(
            m2_repo(&e, Os::Unix),
            Some(global.path().to_path_buf()),
            "{var}"
        );
    }

    // A user settings file without <localRepository> keeps the global one.
    let user_settings = home.path().join(".m2").join("settings.xml");
    write(
        &user_settings,
        "<settings><offline>false</offline></settings>",
    );
    let e = env(&[("HOME", home.path()), ("M2_HOME", install.path())]);
    assert_eq!(m2_repo(&e, Os::Unix), Some(global.path().to_path_buf()));

    write(&user_settings, &settings(user.path().to_str().unwrap()));
    assert_eq!(m2_repo(&e, Os::Unix), Some(user.path().to_path_buf()));
}

/// `-Dmaven.repo.local` in `MAVEN_OPTS` or `MAVEN_ARGS` beats every
/// settings file; `MAVEN_REPO_LOCAL` still beats everything.
#[test]
fn maven_repo_local_system_property_beats_settings() {
    let home = tempfile::tempdir().unwrap();
    let from_settings = tempfile::tempdir().unwrap();
    let from_opts = tempfile::tempdir().unwrap();
    let from_args = tempfile::tempdir().unwrap();
    let from_env = tempfile::tempdir().unwrap();
    write(
        &home.path().join(".m2").join("settings.xml"),
        &settings(from_settings.path().to_str().unwrap()),
    );
    let mut e = env(&[("HOME", home.path())]);
    e.insert(
        "MAVEN_OPTS".into(),
        format!("-Xmx1g -Dmaven.repo.local={}", from_opts.path().display()),
    );
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(from_opts.path().to_path_buf())
    );
    e.insert(
        "MAVEN_ARGS".into(),
        format!("-B -Dmaven.repo.local={}", from_args.path().display()),
    );
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(from_args.path().to_path_buf())
    );
    e.insert(
        "MAVEN_REPO_LOCAL".into(),
        from_env.path().to_str().unwrap().into(),
    );
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(from_env.path().to_path_buf())
    );
}

/// `-Duser.home` in `MAVEN_OPTS` moves `~/.m2` (settings and repository)
/// the way it moves Maven's.
#[test]
fn maven_opts_user_home_moves_the_m2_directory() {
    let home = tempfile::tempdir().unwrap();
    let jvm_home = tempfile::tempdir().unwrap();
    let mut e = env(&[("HOME", home.path())]);
    e.insert(
        "MAVEN_OPTS".into(),
        format!("-Duser.home={}", jvm_home.path().display()),
    );
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(jvm_home.path().join(".m2").join("repository"))
    );
}

/// Trigger 3: on Windows Java's `user.home` is the profile directory, so
/// a `HOME` that Git for Windows / MSYS or a network-drive mapping set
/// elsewhere is not where Maven keeps `.m2`.
#[test]
fn windows_user_home_is_the_profile_directory() {
    let home = tempfile::tempdir().unwrap();
    let profile = tempfile::tempdir().unwrap();
    let e = env(&[("HOME", home.path()), ("USERPROFILE", profile.path())]);
    assert_eq!(
        m2_repo(&e, Os::Windows),
        Some(profile.path().join(".m2").join("repository"))
    );
    // Unix keeps HOME first.
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(home.path().join(".m2").join("repository"))
    );
}

/// A relative `<localRepository>` or a settings file that isn't well
/// formed names no directory the crawler could trust: the default.
#[test]
fn unusable_settings_fall_through_to_the_default() {
    let home = tempfile::tempdir().unwrap();
    let user_settings = home.path().join(".m2").join("settings.xml");
    let default = Some(home.path().join(".m2").join("repository"));
    let e = env(&[("HOME", home.path())]);
    for text in [
        settings("relative/repo"),
        settings(""),
        "<settings><localRepository>/x".to_string(),
        "<settings><![CDATA[ unterminated".to_string(),
    ] {
        write(&user_settings, &text);
        assert_eq!(m2_repo(&e, Os::Unix), default, "{text}");
    }
}

/// `<localRepository>` is read as Maven's XML parser reads it: a CDATA
/// value is its character data, entities decode, and a profile property
/// of the same name is not the setting.
#[test]
fn settings_local_repository_is_read_as_xml() {
    let home = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let user_settings = home.path().join(".m2").join("settings.xml");
    let e = env(&[("HOME", home.path())]);
    let data_s = data.path().to_str().unwrap();

    write(&user_settings, &settings(&format!("<![CDATA[{data_s}]]>")));
    assert_eq!(m2_repo(&e, Os::Unix), Some(data.path().to_path_buf()));

    write(&user_settings, &settings(&format!("{data_s}/a&amp;b")));
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(PathBuf::from(format!("{data_s}/a&b")))
    );

    write(
        &user_settings,
        "<settings><profiles><profile><properties>\
         <localRepository>/opt/other</localRepository>\
         </properties></profile></profiles></settings>",
    );
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(home.path().join(".m2").join("repository"))
    );
    write(
        &user_settings,
        &format!(
            "<settings><profiles><profile><properties>\
             <localRepository>/opt/other</localRepository>\
             </properties></profile></profiles>\
             <localRepository>{data_s}</localRepository></settings>"
        ),
    );
    assert_eq!(m2_repo(&e, Os::Unix), Some(data.path().to_path_buf()));
}

/// A comment inside `<localRepository>` is not part of its value, as
/// Maven's parser skips it; text and CDATA around it join up.
#[test]
fn settings_local_repository_skips_comments() {
    let home = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let user_settings = home.path().join(".m2").join("settings.xml");
    let e = env(&[("HOME", home.path())]);
    let data_s = data.path().to_str().unwrap();

    write(
        &user_settings,
        &settings(&format!("<!-- moved -->{data_s}")),
    );
    assert_eq!(m2_repo(&e, Os::Unix), Some(data.path().to_path_buf()));

    write(
        &user_settings,
        &settings(&format!(
            "\n  {data_s}<!-- was /old -->/r&amp;<![CDATA[&x]]>\n"
        )),
    );
    assert_eq!(
        m2_repo(&e, Os::Unix),
        Some(PathBuf::from(format!("{data_s}/r&&x")))
    );
}

/// A command-line `-Duser.home` (MAVEN_ARGS) is set after Maven has
/// derived its `~/.m2` paths, so it does not move them.
#[test]
fn maven_args_user_home_does_not_move_the_m2_directory() {
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let mut e = env(&[("HOME", home.path())]);
    e.insert(
        "MAVEN_ARGS".into(),
        format!("-Duser.home={}", elsewhere.path().display()),
    );
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(home.path().join(".m2").join("repository"))
    );
}

/// `-Dmaven.repo.local` in the project's `.mvn/maven.config` is the local
/// repository of every build run there, in Maven's order: below
/// `MAVEN_REPO_LOCAL` and the command line (`MAVEN_ARGS`), above
/// `MAVEN_OPTS` and the settings files.
#[test]
fn maven_config_local_repository_is_honoured_in_mavens_order() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let from_settings = tempfile::tempdir().unwrap();
    let from_config = tempfile::tempdir().unwrap();
    let from_opts = tempfile::tempdir().unwrap();
    let from_args = tempfile::tempdir().unwrap();
    let from_env = tempfile::tempdir().unwrap();
    write(
        &home.path().join(".m2").join("settings.xml"),
        &settings(from_settings.path().to_str().unwrap()),
    );
    let config = project.path().join(".mvn").join("maven.config");
    write(
        &config,
        &format!(
            "# the team's shared cache\n-B\n-Dmaven.repo.local={}\n-T 4\n",
            from_config.path().display()
        ),
    );
    let mut e = env(&[("HOME", home.path())]);
    assert_eq!(
        m2_repo_in(&e, project.path()),
        Some(from_config.path().to_path_buf())
    );
    // Without the project the environment alone decides, as before.
    assert_eq!(
        m2_repo(&e, Os::current()),
        Some(from_settings.path().to_path_buf())
    );

    e.insert(
        "MAVEN_OPTS".into(),
        format!("-Dmaven.repo.local={}", from_opts.path().display()),
    );
    assert_eq!(
        m2_repo_in(&e, project.path()),
        Some(from_config.path().to_path_buf()),
        "a user property (maven.config) is read before a JVM one (MAVEN_OPTS)"
    );
    e.insert(
        "MAVEN_ARGS".into(),
        format!("-Dmaven.repo.local={}", from_args.path().display()),
    );
    assert_eq!(
        m2_repo_in(&e, project.path()),
        Some(from_args.path().to_path_buf()),
        "the command line is merged over maven.config"
    );
    e.insert(
        "MAVEN_REPO_LOCAL".into(),
        from_env.path().to_str().unwrap().into(),
    );
    assert_eq!(
        m2_repo_in(&e, project.path()),
        Some(from_env.path().to_path_buf())
    );
}

/// The config is the one Maven's launcher finds from a module directory:
/// in the nearest directory above that holds `.mvn`. A relative value is
/// taken from the directory Maven runs in, and Maven's own placeholders
/// resolve.
#[test]
fn maven_config_is_found_above_a_module_and_interpolated() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let module = root.path().join("services").join("api");
    std::fs::create_dir_all(&module).unwrap();
    let config = root.path().join(".mvn").join("maven.config");
    let e = env(&[("HOME", home.path())]);

    write(
        &config,
        "-Dmaven.repo.local=${session.rootDirectory}/.m2/repository\n",
    );
    let in_root = Some(root.path().join(".m2").join("repository"));
    assert_eq!(m2_repo_in(&e, &module), in_root);
    assert_eq!(m2_repo_in(&e, root.path()), in_root);

    write(&config, "-Dmaven.repo.local=${user.home}/cache/m2\n");
    assert_eq!(
        m2_repo_in(&e, &module),
        Some(home.path().join("cache").join("m2"))
    );

    // Maven before 3.9 split the whole file on whitespace; the last
    // occurrence wins either way.
    write(
        &config,
        "-B -Dmaven.repo.local=first -Dmaven.repo.local=.repo -q\n",
    );
    assert_eq!(m2_repo_in(&e, &module), Some(module.join(".repo")));
    assert_eq!(m2_repo_in(&e, root.path()), Some(root.path().join(".repo")));

    // A nearer `.mvn` is the one the launcher stops at, config or not.
    std::fs::create_dir_all(module.join(".mvn")).unwrap();
    assert_eq!(
        m2_repo_in(&e, &module),
        Some(home.path().join(".m2").join("repository"))
    );
}

/// A config that does not set the property, or is not a file, changes
/// nothing. One that sets it to a value not used here (empty, or with a
/// placeholder nothing defines) still decides, as it does in Maven.
#[test]
fn an_unusable_maven_config_changes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let from_opts = tempfile::tempdir().unwrap();
    let config = project.path().join(".mvn").join("maven.config");
    let mut e = env(&[("HOME", home.path())]);
    let default = Some(home.path().join(".m2").join("repository"));

    std::fs::create_dir_all(project.path().join(".mvn")).unwrap();
    assert_eq!(m2_repo_in(&e, project.path()), default, "no config");
    e.insert(
        "MAVEN_OPTS".into(),
        format!("-Dmaven.repo.local={}", from_opts.path().display()),
    );
    let opts = Some(from_opts.path().to_path_buf());
    for text in [
        "-B\n-Dmaven.repo.locale=/elsewhere\n",
        "-Dmaven.repo.local.tail=/a/tail\n",
        "# -Dmaven.repo.local=/commented\n",
    ] {
        write(&config, text);
        assert_eq!(m2_repo_in(&e, project.path()), opts, "{text:?}");
    }
    std::fs::remove_file(&config).unwrap();
    std::fs::create_dir(&config).unwrap();
    assert_eq!(m2_repo_in(&e, project.path()), opts, "a directory");
    std::fs::remove_dir(&config).unwrap();

    // Set, but not used here: Maven takes the config's value, so the
    // repository MAVEN_OPTS names (which Maven does not reach) is not it.
    for text in [
        "-Dmaven.repo.local=${some.build.property}/m2\n",
        "-Dmaven.repo.local=\n",
    ] {
        write(&config, text);
        assert_eq!(m2_repo_in(&e, project.path()), default, "{text:?}");
    }
}
