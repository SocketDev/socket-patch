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
