use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;

fn path(value: &str) -> Option<MirrorValue> {
    Some(MirrorValue::Path(value.to_string()))
}

/// #1078: yarn honours a `.yarnrc` / `.npmrc` saved with a UTF-8 BOM, so
/// the first line's key must not read as `\u{feff}yarn-offline-mirror`.
#[test]
fn rc_values_skip_a_leading_bom() {
    for text in [
        "\u{feff}yarn-offline-mirror \"./mirror\"\n",
        "\u{feff}yarn-offline-mirror \"./mirror\"\r\n",
        "\u{feff}\"yarn-offline-mirror\": ./mirror\n",
    ] {
        assert_eq!(yarnrc_value(text), path("./mirror"), "{text:?}");
    }
    for text in [
        "\u{feff}yarn-offline-mirror=./mirror\n",
        "\u{feff}yarn-offline-mirror = ./mirror\r\n",
    ] {
        assert_eq!(npmrc_value(text), path("./mirror"), "{text:?}");
    }
    assert_eq!(
        yarnrc_value("\u{feff}yarn-offline-mirror false\n"),
        Some(MirrorValue::Disabled)
    );
    // Only one BOM is encoding: a second one is part of the key.
    assert_eq!(
        yarnrc_value("\u{feff}\u{feff}yarn-offline-mirror ./m\n"),
        None
    );
}

fn outer_file(value: MirrorValue, origin: &str) -> OuterRegistryMirror {
    OuterRegistryMirror {
        env: None,
        file: Some(MirrorSetting {
            value,
            origin: origin.to_string(),
        }),
    }
}

fn outer_env(value: MirrorValue, origin: &str) -> OuterRegistryMirror {
    OuterRegistryMirror {
        env: Some(MirrorSetting {
            value,
            origin: origin.to_string(),
        }),
        file: None,
    }
}

fn mirror_of(setting: Option<MirrorSetting>) -> Option<(String, String)> {
    setting.map(|s| match s.value {
        MirrorValue::Path(p) => (p, s.origin),
        MirrorValue::Disabled => unreachable!("effective_mirror never returns Disabled"),
    })
}

/// Yarn's precedence: env beats the project file beats the outer files,
/// per registry; then npm's value is overridden by yarn's, and `false` in
/// either one means no mirror (`Config.getOfflineMirrorPath`).
#[test]
fn effective_mirror_layers_like_yarn() {
    let m = |p: &str| MirrorValue::Path(p.to_string());
    let none = OuterYarnMirror::default();
    // An outer file alone sets the mirror (#1013).
    let outer = OuterYarnMirror {
        yarn: outer_file(m("/m"), "/home/u/.yarnrc"),
        ..Default::default()
    };
    assert_eq!(
        mirror_of(effective_mirror(None, None, &outer)),
        Some(("/m".into(), "/home/u/.yarnrc".into()))
    );
    // A project `false` beats the outer file of its own registry...
    assert_eq!(
        effective_mirror(Some("yarn-offline-mirror false\n"), None, &outer),
        None
    );
    // ...and an `.npmrc` `false` turns off the yarn registry's mirror too.
    assert_eq!(
        effective_mirror(None, Some("yarn-offline-mirror=false\n"), &outer),
        None
    );
    // An env value beats the project file.
    let env = OuterYarnMirror {
        yarn: outer_env(m("/e"), "YARN_YARN_OFFLINE_MIRROR"),
        ..Default::default()
    };
    assert_eq!(
        mirror_of(effective_mirror(
            Some("yarn-offline-mirror false\n"),
            None,
            &env
        )),
        Some(("/e".into(), "YARN_YARN_OFFLINE_MIRROR".into()))
    );
    let env_off = OuterYarnMirror {
        npm: outer_env(MirrorValue::Disabled, "npm_config_yarn_offline_mirror"),
        ..Default::default()
    };
    assert_eq!(
        effective_mirror(Some("yarn-offline-mirror ./m\n"), None, &env_off),
        None
    );
    // The yarn value overrides the npm one.
    assert_eq!(
        mirror_of(effective_mirror(
            Some("yarn-offline-mirror ./y\n"),
            Some("yarn-offline-mirror=./n\n"),
            &none
        )),
        Some(("./y".into(), ".yarnrc".into()))
    );
    // An npm-only mirror counts.
    assert_eq!(
        mirror_of(effective_mirror(
            None,
            Some("yarn-offline-mirror=./n\n"),
            &none
        )),
        Some(("./n".into(), ".npmrc".into()))
    );
    // A project empty value shadows an outer mirror (first-found wins).
    assert_eq!(
        effective_mirror(Some("yarn-offline-mirror \"\"\n"), None, &outer),
        None
    );
}

/// A fake host: env vars, a home, a node binary and a set of rc files.
struct Host {
    vars: Vec<(String, String)>,
    files: BTreeMap<PathBuf, String>,
    root_user: bool,
}

impl Host {
    fn new() -> Self {
        Self {
            vars: vec![("HOME".into(), "/home/u".into())],
            files: BTreeMap::new(),
            root_user: false,
        }
    }
    fn var(mut self, k: &str, v: &str) -> Self {
        self.vars.push((k.into(), v.into()));
        self
    }
    fn file(mut self, p: &str, text: &str) -> Self {
        self.files.insert(PathBuf::from(p), text.into());
        self
    }
    fn root(mut self) -> Self {
        self.root_user = true;
        self
    }
    fn outer(&self, project: &str) -> OuterYarnMirror {
        let env = NpmConfigEnv::from_parts(
            self.vars.clone(),
            Some(PathBuf::from("/opt/node/bin/node")),
            false,
        );
        resolve_outer_yarn_mirror(&env, self.root_user, Path::new(project), |p| {
            self.files.get(p).cloned()
        })
    }
    /// The effective mirror for `/work/root/proj` with no project rc files.
    /// The origin is spelled with `/` so the expectations hold on Windows,
    /// where the resolver joins the rc name with `\`.
    fn mirror(&self) -> Option<(String, String)> {
        mirror_of(effective_mirror(None, None, &self.outer("/work/root/proj")))
            .map(|(p, origin)| (p, origin.replace('\\', "/")))
    }
}

/// #1013: every location yarn 1 reads a mirror from outside the project.
#[test]
fn outer_layers_cover_every_yarn_config_location() {
    let some = |p: &str, o: &str| Some((p.to_string(), o.to_string()));
    // Parent and grandparent directories.
    let h = Host::new().file("/work/root/.yarnrc", "yarn-offline-mirror \"/w/mirror\"\n");
    assert_eq!(h.mirror(), some("/w/mirror", "/work/root/.yarnrc"));
    let h = Host::new().file("/work/.npmrc", "yarn-offline-mirror=/w/mirror\n");
    assert_eq!(h.mirror(), some("/w/mirror", "/work/.npmrc"));
    // `~/.yarnrc` (where `yarn config set` writes) and `~/.npmrc`.
    let h = Host::new().file(
        "/home/u/.yarnrc",
        "yarn-offline-mirror ./npm-packages-offline-cache\n",
    );
    assert_eq!(
        h.mirror(),
        some("./npm-packages-offline-cache", "/home/u/.yarnrc")
    );
    let h = Host::new().file("/home/u/.npmrc", "\u{feff}yarn-offline-mirror=/m\n");
    assert_eq!(h.mirror(), some("/m", "/home/u/.npmrc"));
    // `<prefix>/etc/yarnrc` / `npmrc`, the prefix from the node binary or
    // `PREFIX`.
    let h = Host::new().file("/opt/node/etc/yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.mirror(), some("/m", "/opt/node/etc/yarnrc"));
    let h = Host::new()
        .var("PREFIX", "/pfx")
        .file("/pfx/etc/npmrc", "yarn-offline-mirror=/m\n");
    assert_eq!(h.mirror(), some("/m", "/pfx/etc/npmrc"));
    // Env variables, any case of the prefix.
    let h = Host::new().var("YARN_YARN_OFFLINE_MIRROR", "/e");
    assert_eq!(h.mirror(), some("/e", "YARN_YARN_OFFLINE_MIRROR"));
    let h = Host::new().var("npm_config_yarn_offline_mirror", "/e");
    assert_eq!(h.mirror(), some("/e", "npm_config_yarn_offline_mirror"));
    let h = Host::new().var("yarn_yarn_offline_mirror", "/e");
    assert_eq!(h.mirror(), some("/e", "yarn_yarn_offline_mirror"));
    // A relocated user config (`YARN_USERCONFIG` / `npm_config_userconfig`).
    let h = Host::new()
        .var("npm_config_userconfig", "/cfg/npmrc")
        .file("/cfg/npmrc", "yarn-offline-mirror=/m\n")
        .file("/home/u/.npmrc", "yarn-offline-mirror=false\n");
    assert_eq!(h.mirror(), some("/m", "/cfg/npmrc"));
    // As root the user rc is `/usr/local/share/.yarnrc`, and `~/.yarnrc`
    // is still read after the global one.
    let h = Host::new()
        .root()
        .file("/usr/local/share/.yarnrc", "yarn-offline-mirror /r\n");
    assert_eq!(h.mirror(), some("/r", "/usr/local/share/.yarnrc"));
    let h = Host::new()
        .root()
        .file("/home/u/.yarnrc", "yarn-offline-mirror /h\n");
    assert_eq!(h.mirror(), some("/h", "/home/u/.yarnrc"));
    // ...but not under fakeroot.
    let h = Host::new()
        .root()
        .var("FAKEROOTKEY", "1")
        .file("/usr/local/share/.yarnrc", "yarn-offline-mirror /r\n");
    assert_eq!(h.mirror(), None);
}

/// The first file that sets the key wins (user before global before
/// ancestors), and the filesystem root's rc is never read (yarn stops
/// one short of it).
#[test]
fn outer_files_first_found_wins_and_skip_the_filesystem_root() {
    let h = Host::new()
        .file("/home/u/.yarnrc", "yarn-offline-mirror false\n")
        .file("/work/root/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.mirror(), None);
    let h = Host::new()
        .file("/work/root/.yarnrc", "yarn-offline-mirror /near\n")
        .file("/work/.yarnrc", "yarn-offline-mirror /far\n");
    assert_eq!(
        h.mirror(),
        Some(("/near".into(), "/work/root/.yarnrc".into()))
    );
    let h = Host::new().file("/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.mirror(), None);
    // The project's own rc is the project layer, not an outer one.
    let h = Host::new().file("/work/root/proj/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.outer("/work/root/proj"), OuterYarnMirror::default());
    // No config anywhere: no mirror.
    assert_eq!(Host::new().mirror(), None);
    // Unrelated keys and a look-alike key set nothing.
    let h = Host::new().file(
        "/home/u/.yarnrc",
        "yarn-offline-mirror-pruning true\n# yarn-offline-mirror /m\n",
    );
    assert_eq!(h.mirror(), None);
}

/// Env parsing follows yarn's `mergeEnv`: `npm_config_*` overrides
/// `YARN_*` for the npm registry, `false` disables, and an empty value
/// is set-but-no-mirror.
#[test]
fn outer_env_layers() {
    let h = Host::new()
        .var("YARN_YARN_OFFLINE_MIRROR", "/y")
        .var("NPM_CONFIG_YARN_OFFLINE_MIRROR", "false");
    // npm's registry: npm_config_ (false) over YARN_; that false wins.
    assert_eq!(h.mirror(), None);
    let h = Host::new()
        .var("YARN_YARN_OFFLINE_MIRROR", "false")
        .file("/home/u/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.mirror(), None);
    let h = Host::new()
        .var("YARN_YARN_OFFLINE_MIRROR", "")
        .file("/home/u/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.mirror(), None);
    // A look-alike variable is not the key.
    let h = Host::new().var("YARN_YARN_OFFLINE_MIRROR_PRUNING", "true");
    assert_eq!(h.mirror(), None);
}

impl Host {
    fn member(&self, members: &[&str]) -> Option<(String, String)> {
        let env = NpmConfigEnv::from_parts(
            self.vars.clone(),
            Some(PathBuf::from("/opt/node/bin/node")),
            false,
        );
        let members: Vec<PathBuf> = members.iter().map(PathBuf::from).collect();
        mirror_of(resolve_member_yarn_mirror(
            &env,
            self.root_user,
            &members,
            |p| self.files.get(p).cloned(),
        ))
        .map(|(p, origin)| {
            let origin = origin.replace('\\', "/");
            let (file, member) = origin
                .split_once(", as read by yarn run in the workspace member ")
                .expect("the origin names the member");
            assert!(members.contains(&PathBuf::from(member)), "{origin}");
            (p, file.to_string())
        })
    }
}

/// #1115: yarn 1 run in a workspace member reads the member's own
/// `.yarnrc` / `.npmrc` as the project files, which the root's layers
/// never read.
#[test]
fn member_layers_read_the_members_own_rc_files() {
    let some = |p: &str, o: &str| Some((p.to_string(), o.to_string()));
    let members = ["/w/root/packages/a", "/w/root/packages/b"];
    // A member `.yarnrc` (the issue's repro) and a member `.npmrc` (its
    // follow-up comment) each set the mirror.
    let h = Host::new().file("/w/root/packages/b/.yarnrc", "yarn-offline-mirror \"/m\"\n");
    assert_eq!(h.member(&members), some("/m", "/w/root/packages/b/.yarnrc"));
    let h = Host::new().file(
        "/w/root/packages/a/.npmrc",
        "yarn-offline-mirror=./mirror\n",
    );
    assert_eq!(
        h.member(&members),
        some("./mirror", "/w/root/packages/a/.npmrc")
    );
    // A member run reads the root's rc only as an ancestor's, below the
    // user rc: a root `false` does not hide a user mirror there.
    let h = Host::new()
        .file("/w/root/.yarnrc", "yarn-offline-mirror false\n")
        .file("/home/u/.yarnrc", "yarn-offline-mirror /u\n");
    assert_eq!(h.member(&members), some("/u", "/home/u/.yarnrc"));
    // A member's own `false` turns off what it would inherit.
    let h = Host::new()
        .file("/w/root/.yarnrc", "yarn-offline-mirror /r\n")
        .file("/w/root/packages/a/.yarnrc", "yarn-offline-mirror false\n");
    assert_eq!(
        h.member(&members[..1]),
        None,
        "a member that turns the mirror off uses none"
    );
    // No member rc, no other layer: no mirror; no members: none.
    assert_eq!(Host::new().member(&members), None);
    let h = Host::new().file("/w/root/packages/a/.yarnrc", "yarn-offline-mirror /m\n");
    assert_eq!(h.member(&[]), None);
}

/// #1115: the members are the root `package.json` `workspaces` matches
/// that hold a `package.json`, only for a classic `yarn.lock`.
#[test]
fn yarn_classic_workspace_members_follow_the_root_globs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let write = |rel: &str, text: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    };
    write("yarn.lock", "# yarn lockfile v1\n\n");
    write(
        "package.json",
        r#"{"private":true,"workspaces":{"packages":["packages/*","tools/x"]}}"#,
    );
    write("packages/a/package.json", "{}");
    write("packages/b/README", "not a package");
    write("packages/a/node_modules/dep/package.json", "{}");
    write("tools/x/package.json", "{}");
    write("tools/y/package.json", "{}");
    write("node_modules/packages/z/package.json", "{}");
    assert_eq!(
        yarn_classic_workspace_members(root),
        vec![root.join("packages/a"), root.join("tools/x")]
    );
    // A literal pattern is searched as deep as it goes.
    write(
        "package.json",
        r#"{"private":true,"workspaces":["a/b/c/d/e/f/g/h/i"]}"#,
    );
    write("a/b/c/d/e/f/g/h/i/package.json", "{}");
    assert_eq!(
        yarn_classic_workspace_members(root),
        vec![root.join("a/b/c/d/e/f/g/h/i")]
    );
    // A member reached through a directory link counts, as yarn's globber
    // follows it.
    #[cfg(unix)]
    {
        write(
            "package.json",
            r#"{"private":true,"workspaces":["linked/*"]}"#,
        );
        write("shared/s/package.json", "{}");
        std::fs::create_dir_all(root.join("linked")).unwrap();
        std::os::unix::fs::symlink(root.join("shared/s"), root.join("linked/s")).unwrap();
        assert_eq!(
            yarn_classic_workspace_members(root),
            vec![root.join("linked/s")]
        );
    }
    // `**` searches deeper.
    write(
        "package.json",
        r#"{"private":true,"workspaces":["apps/**"]}"#,
    );
    write("apps/web/site/package.json", "{}");
    assert_eq!(
        yarn_classic_workspace_members(root),
        vec![root.join("apps/web/site")]
    );
    // A berry lock, or no workspaces: none.
    write("yarn.lock", "__metadata:\n  version: 8\n");
    assert!(yarn_classic_workspace_members(root).is_empty());
    write("yarn.lock", "# yarn lockfile v1\n\n");
    write("package.json", r#"{"private":true}"#);
    assert!(yarn_classic_workspace_members(root).is_empty());
}

impl Host {
    /// [`configured_yarn_global_folders`] for yarn run in `cwd`.
    fn global_folders(&self, cwd: &str) -> Vec<PathBuf> {
        let env = NpmConfigEnv::from_parts(
            self.vars.clone(),
            Some(PathBuf::from("/opt/node/bin/node")),
            false,
        );
        configured_yarn_global_folders(&env, self.root_user, Path::new(cwd), |p| {
            self.files.get(p).cloned()
        })
    }
}

fn paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

/// #1629: every layer yarn 1 reads `global-folder` from names a global
/// folder. Each expectation matches `yarn global dir` on yarn 1.22.22.
#[test]
fn global_folder_layers_match_yarn() {
    // Env, any prefix spelling yarn's `mergeEnv` accepts.
    for var in [
        "YARN_GLOBAL_FOLDER",
        "yarn_global_folder",
        "npm_config_global_folder",
    ] {
        assert_eq!(
            Host::new().var(var, "/opt/yg").global_folders("/w"),
            paths(&["/opt/yg"]),
            "{var}"
        );
    }
    // The project's own rc, the user's, the global prefix's and an
    // ancestor's.
    for (file, text) in [
        ("/w/.yarnrc", "global-folder \"/opt/yg\"\n"),
        ("/home/u/.yarnrc", "global-folder /opt/yg\n"),
        ("/home/u/.yarnrc", "\"global-folder\": '/opt/yg'\n"),
        ("/opt/node/etc/yarnrc", "global-folder /opt/yg\n"),
        ("/w/.npmrc", "global-folder=/opt/yg\n"),
        ("/home/u/.npmrc", "global-folder = \"/opt/yg\"\n"),
        ("/opt/node/etc/npmrc", "global-folder=/opt/yg\n"),
    ] {
        assert_eq!(
            Host::new().file(file, text).global_folders("/w"),
            paths(&["/opt/yg"]),
            "{file}: {text:?}"
        );
    }
    assert_eq!(
        Host::new()
            .file("/w/.yarnrc", "global-folder /opt/yg\n")
            .global_folders("/w/sub"),
        paths(&["/opt/yg"]),
        "an ancestor's .yarnrc"
    );
    // Every layer counts, env first.
    assert_eq!(
        Host::new()
            .var("YARN_GLOBAL_FOLDER", "/opt/a")
            .var("npm_config_global_folder", "/opt/b")
            .file("/home/u/.yarnrc", "global-folder /opt/c\n")
            .file("/home/u/.npmrc", "global-folder=/opt/d\n")
            .global_folders("/w"),
        paths(&["/opt/a", "/opt/b", "/opt/c", "/opt/d"])
    );
    // Unset, empty, commented out or under an `.npmrc` section: nothing.
    for host in [
        Host::new(),
        Host::new().var("YARN_GLOBAL_FOLDER", ""),
        Host::new().file("/home/u/.yarnrc", "# global-folder /opt/yg\n"),
        Host::new().file("/home/u/.yarnrc", "global-folder \"\"\n"),
        Host::new().file("/home/u/.npmrc", "[x]\nglobal-folder=/opt/yg\n"),
        Host::new().file("/home/u/.yarnrc", "global-folders /opt/yg\n"),
    ] {
        assert_eq!(host.global_folders("/w"), Vec::<PathBuf>::new());
    }
}

/// #1629: yarn resolves a `.yarnrc` `global-folder` against that file's
/// folder (no `~` expansion), and an env or `.npmrc` value through
/// `resolveWithHome`: `~/` is yarn's user home (`/usr/local/share` for
/// root), anything else is taken against the cwd.
#[test]
fn global_folder_paths_resolve_like_yarn() {
    let home = Host::new().file("/home/u/.yarnrc", "global-folder gf\n");
    assert_eq!(home.global_folders("/w"), paths(&["/home/u/gf"]));
    let tilde = Host::new().file("/home/u/.yarnrc", "global-folder \"~/gf\"\n");
    assert_eq!(tilde.global_folders("/w"), paths(&["/home/u/~/gf"]));
    let ancestor = Host::new().file("/w/.yarnrc", "global-folder ../gf\n");
    assert_eq!(ancestor.global_folders("/w/sub"), paths(&["/w/../gf"]));

    for host in [
        Host::new().var("YARN_GLOBAL_FOLDER", "gf"),
        Host::new().file("/home/u/.npmrc", "global-folder=gf\n"),
    ] {
        assert_eq!(host.global_folders("/w"), paths(&["/w/gf"]));
    }
    for host in [
        Host::new().var("YARN_GLOBAL_FOLDER", "~/gf"),
        Host::new().file("/home/u/.npmrc", "global-folder=~/gf\n"),
    ] {
        assert_eq!(host.global_folders("/w"), paths(&["/home/u/gf"]));
        assert_eq!(
            host.root().global_folders("/w"),
            paths(&["/usr/local/share/gf"]),
            "root's userHome"
        );
    }
}

/// #1629: `global-folder` values decode as yarn 1.22.22 decodes them
/// (each expectation checked with `yarn global dir`).
#[test]
fn global_folder_values_read_like_yarn() {
    let yarnrc = |text: &str| {
        Host::new()
            .file("/home/u/.yarnrc", text)
            .global_folders("/w")
    };
    // A default `--global-folder` flag.
    assert_eq!(yarnrc("--global-folder \"/opt/rc\"\n"), paths(&["/opt/rc"]));
    assert_eq!(yarnrc("--global-folder /opt/rc\n"), paths(&["/opt/rc"]));
    // A trailing comment is its own token.
    assert_eq!(
        yarnrc("global-folder /opt/yg # moved\n"),
        paths(&["/opt/yg"])
    );
    // A double-quoted value is JSON.
    assert_eq!(
        yarnrc("global-folder \"/opt/a\\\\b\"\n"),
        paths(&["/opt/a\\b"])
    );
    // yarn's YAML fallback reads a single-quoted value.
    assert_eq!(
        yarnrc("\"global-folder\": '/opt/yg'\n"),
        paths(&["/opt/yg"])
    );
    // `~` can't start a bare word: yarn ignores the line.
    assert_eq!(yarnrc("global-folder ~/yg\n"), Vec::<PathBuf>::new());

    let npmrc = |host: Host, text: &str| host.file("/home/u/.npmrc", text).global_folders("/w");
    // `${NAME}` expands; an unset name makes yarn drop its config.
    assert_eq!(
        npmrc(Host::new(), "global-folder=${HOME}/x\n"),
        paths(&["/home/u/x"])
    );
    assert_eq!(
        npmrc(Host::new().var("YG", "/opt/yg"), "global-folder=${YG}\n"),
        paths(&["/opt/yg"])
    );
    assert_eq!(
        npmrc(Host::new(), "global-folder=${NOPE}/x\n"),
        Vec::<PathBuf>::new()
    );
    // An escaped expression stays verbatim (`ini` reads `\\` as `\`
    // first). On Windows the leading `\` makes it root-relative: it keeps
    // the cwd's drive and replaces the rest, as `path.resolve` does
    // (`/w` has no drive, so nothing of it is kept).
    let escaped = if cfg!(windows) {
        "\\${HOME}/x"
    } else {
        "/w/\\${HOME}/x"
    };
    for text in [
        "global-folder=\\${HOME}/x\n",
        "global-folder=\\\\${HOME}/x\n",
    ] {
        assert_eq!(npmrc(Host::new(), text), paths(&[escaped]), "{text:?}");
    }
    // `ini` ends an unquoted value at a comment and unquotes a quoted one.
    assert_eq!(
        npmrc(Host::new(), "global-folder=/opt/n ; moved\n"),
        paths(&["/opt/n"])
    );
    assert_eq!(
        npmrc(Host::new(), "global-folder=\"/opt/nq\"\n"),
        paths(&["/opt/nq"])
    );
}

/// #437: yarn 1.0.x can't report its global folder, so it is derived the
/// way yarn 1.0.2's `constants.js` does: `<userHome>/.config/yarn/global`
/// (`userHome` is `/usr/local/share` for a root user that isn't under
/// fakeroot), or `%LOCALAPPDATA%\Yarn\config\global` on Windows.
#[test]
fn yarn_1_0_default_global_folder_follows_yarn_1_0_2() {
    let vars = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let unix = NpmConfigEnv::from_parts(vars(&[("HOME", "/home/u")]), None, false);
    assert_eq!(
        yarn_1_0_default_global_folder(&unix, false),
        Some(PathBuf::from("/home/u/.config/yarn/global"))
    );
    assert_eq!(
        yarn_1_0_default_global_folder(&unix, true),
        Some(PathBuf::from("/usr/local/share/.config/yarn/global"))
    );
    let fakeroot = NpmConfigEnv::from_parts(
        vars(&[("HOME", "/home/u"), ("FAKEROOTKEY", "1")]),
        None,
        false,
    );
    assert_eq!(
        yarn_1_0_default_global_folder(&fakeroot, true),
        Some(PathBuf::from("/home/u/.config/yarn/global"))
    );
    assert_eq!(
        yarn_1_0_default_global_folder(&NpmConfigEnv::from_parts(Vec::new(), None, false), false),
        None,
        "no home, no folder"
    );

    let windows = NpmConfigEnv::from_parts(
        vars(&[
            ("USERPROFILE", r"C:\Users\u"),
            ("LOCALAPPDATA", r"C:\Users\u\AppData\Local"),
        ]),
        None,
        true,
    );
    assert_eq!(
        yarn_1_0_default_global_folder(&windows, false),
        Some(
            Path::new(r"C:\Users\u\AppData\Local")
                .join("Yarn")
                .join("config")
                .join("global")
        )
    );
    // Without LOCALAPPDATA yarn 1.0.x falls back to the home layout.
    let windows = NpmConfigEnv::from_parts(vars(&[("USERPROFILE", r"C:\Users\u")]), None, true);
    assert_eq!(
        yarn_1_0_default_global_folder(&windows, false),
        Some(
            Path::new(r"C:\Users\u")
                .join(".config")
                .join("yarn")
                .join("global")
        )
    );
}
