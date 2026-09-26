//! The project fixture every real-vlt capstone builds on: a project
//! installed by the vlt under test against the harness registry, the mock
//! patch service publishing patches built from the registry bytes, and the
//! assertions the suites share.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::*;

pub const LP: (&str, &str) = ("left-pad", "1.3.0");
pub const MS: (&str, &str) = ("ms", "2.1.3");
pub const SCOPED: (&str, &str) = ("@isaacs/string-locale-compare", "1.1.0");
pub const FSEVENTS: (&str, &str) = ("fsevents", "2.3.3");
pub const UUID: &str = "a1a1a1a1-1111-4111-8111-111111111111";
pub const UUID_MS: &str = "b2b2b2b2-2222-4222-8222-222222222222";
pub const UUID_SCOPED: &str = "c3c3c3c3-3333-4333-8333-333333333333";
pub const UUID_USX: &str = "d4d4d4d4-4444-4444-8444-444444444444";
pub const UUID_FSEVENTS: &str = "e5e5e5e5-5555-4555-8555-555555555555";

pub const ADVISORY: &str = "redirect_vlt_reinstall_required";
pub const UNVERIFIABLE: &str = "redirect_vlt_artifact_unverifiable";
pub const OPTIONAL_KEPT: &str = "socket-patch does not remove them because `vlt install` does not \
     reinstall a removed optional dependency. Run `vlt ci` (or delete node_modules and run `vlt \
     install`). vlt releases before 1.0.5 install no optional dependency from the lock of a \
     project that declares only optional dependencies, so there both commands remove the \
     installed copy: upgrade vlt to 1.0.5 or later first.";
pub const VLT_UPDATE_NOTE: &str =
    " Note: `vlt update` re-resolves from the registry and drops these redirects.";

pub fn invalidated_head(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages; socket-patch removed {n} stale installed \
         copies (node_modules/.vlt-lock.json and node_modules/.vlt entries), so node_modules is \
         incomplete until you run `vlt install` (or `vlt ci`), which installs the patched \
         packages."
    )
}

pub fn advisory_invalidated(n: usize) -> String {
    format!("{}{VLT_UPDATE_NOTE}", invalidated_head(n))
}

pub fn advisory_cleanup_skipped(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but node_modules still holds {n} unpatched \
         copies and `vlt install` will not refresh them; run `vlt ci` (or re-run without \
         --no-vlt-install-cleanup)."
    )
}

pub fn advisory_nothing_stale() -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages; fresh checkouts install them with `vlt ci` \
         or `vlt install --frozen-lockfile`.{VLT_UPDATE_NOTE}"
    )
}

pub fn advisory_rolled_back(n: usize) -> String {
    format!(
        "restored registry pins for {n} packages; removed the patched installed copies, so \
         node_modules is incomplete until you run `vlt install` (or `vlt ci`)"
    )
}

// ── fixtures ──────────────────────────────────────────────────────────────

/// A leg's own vlt.json for (vlt version, default registry URL).
pub type VltJsonFn = std::sync::Arc<dyn Fn(VltVersion, &str) -> Value + Send + Sync>;

/// A project shape for [`Fixture::build`].
#[derive(Clone)]
pub struct Shape {
    pub deps: Vec<(&'static str, &'static str)>,
    pub dev: Vec<(&'static str, &'static str)>,
    pub optional: Vec<(&'static str, &'static str)>,
    /// Every registry pin (targets and transitive dependencies).
    pub pins: Vec<(&'static str, &'static str)>,
    /// `(name, version, uuid, patched file)`.
    pub targets: Vec<(&'static str, &'static str, &'static str, &'static str)>,
    pub vlt_json: VltJson,
    /// Keep the fixture install's tree (a warm project).
    pub warm: bool,
    /// Extra files written before the fixture install.
    pub files: Vec<(String, String)>,
    /// Extra env for every vlt run of the fixture (registry from env).
    pub vlt_env: Vec<(String, String)>,
    /// A vlt.json of the leg's own for (version, default registry URL).
    pub custom_vlt_json: Option<VltJsonFn>,
    /// Profiles whose user config (`$XDG_CONFIG_HOME/vlt/vlt.json`) holds
    /// the era's registry configuration.
    pub user_config: Vec<&'static str>,
    /// Harness-built packages the registry serves beside the npmjs pins.
    pub synthetic: Vec<CachedPkg>,
}

impl Shape {
    pub fn left_pad() -> Shape {
        Shape {
            deps: vec![LP],
            dev: vec![],
            optional: vec![],
            pins: vec![LP],
            targets: vec![(LP.0, LP.1, UUID, "index.js")],
            vlt_json: VltJson::default(),
            warm: false,
            files: vec![],
            vlt_env: vec![],
            custom_vlt_json: None,
            user_config: vec![],
            synthetic: vec![],
        }
    }

    pub fn vlt_json_fn(
        mut self,
        f: impl Fn(VltVersion, &str) -> Value + Send + Sync + 'static,
    ) -> Shape {
        self.custom_vlt_json = Some(std::sync::Arc::new(f));
        self
    }

    /// left-pad (patched) beside ms (not patched): the heal and rollback
    /// legs prove ms's store entry is never touched.
    pub fn with_bystander() -> Shape {
        let mut s = Shape::left_pad();
        s.deps.push(MS);
        s.pins.push(MS);
        s
    }

    pub fn warm(mut self) -> Shape {
        self.warm = true;
        self
    }
}

/// An installed project, its registry and the patch service.
pub struct Fixture {
    pub leg: Leg,
    pub reg: Registry,
    pub svc: PatchService,
    pub proj: PathBuf,
    /// vlt-lock.json as vlt wrote it (the rollback target).
    pub lock_before: Vec<u8>,
    pub run: VltRun,
}

impl Fixture {
    pub async fn build(leg: Leg, shape: Shape) -> Fixture {
        Fixture::build_with(leg, shape, &[]).await
    }

    /// [`Fixture::build`]; patch targets may come from `extra` registries.
    pub async fn build_with(leg: Leg, shape: Shape, extra: &[&Registry]) -> Fixture {
        let reg = Registry::start_with(&shape.pins, shape.synthetic.clone()).await;
        let proj = leg.dir("proj");
        let mut fields: Vec<(&str, &[(&str, &str)])> = Vec::new();
        if !shape.deps.is_empty() {
            fields.push(("dependencies", &shape.deps));
        }
        if !shape.dev.is_empty() {
            fields.push(("devDependencies", &shape.dev));
        }
        if !shape.optional.is_empty() {
            fields.push(("optionalDependencies", &shape.optional));
        }
        write(
            &proj.join("package.json"),
            package_json_fields("vlt-e2e-app", &fields),
        );
        match &shape.custom_vlt_json {
            Some(f) => write(
                &proj.join("vlt.json"),
                serde_json::to_string_pretty(&f(leg.version(), &reg.url())).unwrap() + "\n",
            ),
            None => write_vlt_json(&proj, leg.version(), &reg.url(), &shape.vlt_json),
        }
        for (rel, body) in &shape.files {
            write(&proj.join(rel), body.replace("{R}", &reg.url()));
        }
        for profile in &shape.user_config {
            let user = vlt_json(leg.version(), &reg.url(), &VltJson::default());
            write(
                &leg.xdg(profile).config.join("vlt/vlt.json"),
                serde_json::to_string_pretty(&user).unwrap(),
            );
        }
        let mut run = VltRun::default();
        for (k, v) in &shape.vlt_env {
            run = run.with_env(k, &v.replace("{R}", &reg.url()));
        }
        leg.vlt_ok_with(&proj, &["install"], &run);
        assert_lock_era(&leg, &proj);
        let lock_before = lock_bytes(&proj);
        let mut targets = Vec::new();
        for (name, version, uuid, file) in &shape.targets {
            let pkg = reg
                .pkgs
                .iter()
                .chain(extra.iter().flat_map(|r| r.pkgs.iter()))
                .find(|p| p.name == *name && p.version == *version)
                .unwrap_or_else(|| panic!("{name}@{version} is pinned nowhere"));
            targets.push(PatchTarget::from_pkg(pkg, uuid, file));
        }
        for t in &targets {
            if let Some(bytes) = installed(&proj, &t.name, &t.file) {
                assert_eq!(bytes, t.before, "{} installs pristine", t.name);
            }
        }
        let svc = PatchService::start(targets).await;
        if !shape.warm {
            remove_tree(&proj);
        }
        Fixture {
            leg,
            reg,
            svc,
            proj,
            lock_before,
            run,
        }
    }

    pub fn t(&self) -> &PatchTarget {
        &self.svc.targets[0]
    }

    pub fn scan(&self, extra: &[&str]) -> Value {
        scan_hosted(&self.proj, &self.svc, extra)
    }

    /// `scan --mode hosted --vex out.vex.json`; exit 1 is the omission
    /// exit (asserted by [`Fixture::assert_in_run_vex`]).
    pub fn scan_vex(&self, extra: &[&str]) -> SocketOut {
        let mut args = vec!["--vex", "out.vex.json", "--vex-product", PRODUCT];
        args.extend_from_slice(extra);
        socket_api(&self.proj, &self.svc, &["scan", "--mode", "hosted"], &args)
    }

    pub fn checkout(&self, name: &str) -> PathBuf {
        fresh_checkout(&self.proj, &self.leg.root.join(name))
    }

    pub fn vlt_ok(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        self.leg.vlt_ok_with(cwd, args, &self.run)
    }

    pub fn vlt_ok_profile(&self, cwd: &Path, args: &[&str], profile: &str) -> std::process::Output {
        let mut run = self.run.clone();
        run.profile = Some(profile.to_string());
        self.leg.vlt_ok_with(cwd, args, &run)
    }

    pub fn vlt_profile(&self, cwd: &Path, args: &[&str], profile: &str) -> std::process::Output {
        let mut run = self.run.clone();
        run.profile = Some(profile.to_string());
        self.leg.vlt_with(cwd, args, &run)
    }

    /// A fresh checkout's locked install (`vlt ci`) into the cold profile
    /// `name`: every target patched, the lock byte-stable.
    pub fn assert_fresh_locked_install(&self, name: &str) -> PathBuf {
        let co = self.checkout(name);
        let before = lock_bytes(&co);
        self.vlt_ok_profile(&co, &self.leg.locked_install_args(), name);
        for t in &self.svc.targets {
            assert_eq!(state(&co, t), State::Patched, "{} in {name}", t.name);
        }
        assert_eq!(
            String::from_utf8_lossy(&lock_bytes(&co)),
            String::from_utf8_lossy(&before),
            "the locked install must keep vlt-lock.json byte-stable"
        );
        co
    }

    /// The lock-level warnings DESIGN §3.8 predicts for the lock vlt wrote.
    pub fn lock_warnings(&self) -> Vec<&'static str> {
        expected_lock_warnings(&self.lock_before, &self.proj)
    }

    /// Whether an in-run `--vex` may attest (no lock-level warning).
    pub fn in_run_vex_attests(&self) -> bool {
        self.lock_warnings().is_empty()
    }

    pub fn assert_lock_warnings(&self, doc: &Value) {
        for code in self.lock_warnings() {
            assert!(has_warning(doc, code), "expected {code}: {doc:#}");
        }
    }

    /// The in-run VEX outcome for `t`: attested (exit 0) unless a
    /// lock-level warning or `stale` withholds it (exit 1, `vex_omitted`).
    pub fn assert_in_run_vex(&self, out: &SocketOut, t: &PatchTarget, attest: bool) {
        let doc = out.json();
        if attest {
            assert_eq!(out.code, 0, "{out}");
            assert!(
                self.vex_attested(t),
                "in-run VEX must attest {}: {out}",
                t.name
            );
        } else {
            assert!(
                !self.vex_attested(t),
                "in-run VEX must not attest {}: {out}",
                t.name
            );
            assert!(
                doc.to_string().contains("vex_omitted") || out.code == 0,
                "the omission is reported: {out}"
            );
        }
    }

    pub fn assert_advisory(&self, doc: &Value, want: &str) {
        assert_eq!(warning_detail(doc, ADVISORY), want, "{doc:#}");
    }

    pub fn vex_attested(&self, t: &PatchTarget) -> bool {
        vex_doc_attests(&self.proj.join("out.vex.json"), t)
    }

    pub fn ledger(&self) -> Option<Vec<u8>> {
        std::fs::read(self.proj.join(".socket/vendor/redirect-state.json")).ok()
    }

    pub fn store_ids(&self, t: &PatchTarget) -> Vec<String> {
        node_ids(&read_lock(&self.proj), &t.name, &t.version)
    }

    /// The other `.vlt` entries and (1.2.0) the global store.
    pub fn snapshot(&self, dir: &Path, exclude: &[String]) -> Snapshot {
        let store = self.leg.global_store("default");
        let store = if self.leg.at_least(STORE_LINKER_FROM) && store.exists() {
            Some(store)
        } else {
            None
        };
        Snapshot::take(dir, exclude, store.as_deref())
    }
}

pub fn vex_doc_attests(path: &Path, t: &PatchTarget) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let doc: Value = serde_json::from_str(&text).unwrap();
    let canonical = t.purl().replace("%40", "@");
    doc["statements"].as_array().into_iter().flatten().any(|s| {
        s["products"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| p["subcomponents"].as_array().into_iter().flatten())
            .any(|c| c["@id"] == t.purl() || c["@id"] == canonical)
    })
}

/// The `reason` of the envelope event carrying `code`.
pub fn event_reason(doc: &Value, code: &str) -> String {
    [&doc["events"], &doc["vendor"]["events"]]
        .into_iter()
        .filter_map(|e| e.as_array())
        .flatten()
        .find(|e| e["errorCode"] == code)
        .and_then(|e| e["reason"].as_str())
        .unwrap_or_else(|| panic!("expected a `{code}` event: {doc:#}"))
        .to_string()
}

pub fn remove_tree(proj: &Path) {
    let nm = proj.join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }
}

pub fn slash(u: &str) -> String {
    if u.ends_with('/') {
        u.to_string()
    } else {
        format!("{u}/")
    }
}

/// DESIGN §3.8 over the lock vlt wrote and the project's vlt.json.
pub fn expected_lock_warnings(lock_bytes: &[u8], proj: &Path) -> Vec<&'static str> {
    let lock: Value = serde_json::from_slice(lock_bytes).unwrap();
    let mut out = Vec::new();
    let absent = lock.get("lockfileVersion").is_none();
    let legacy = absent || lock["lockfileVersion"] == 0;
    if absent {
        out.push("redirect_vlt_lockfile_version_missing");
    }
    let registry = lock["options"]["registry"].as_str();
    if legacy {
        let default_non_npm = lock["nodes"]
            .as_object()
            .into_iter()
            .flatten()
            .any(|(id, _)| {
                let Some(rest) = id.strip_prefix('·') else {
                    return false;
                };
                let seg = rest.split('·').next().unwrap_or_default();
                if seg.is_empty() {
                    return true;
                }
                match (legacy_decode(seg), registry) {
                    (Some(url), Some(r)) => {
                        (url.starts_with("http://") || url.starts_with("https://"))
                            && slash(&url) == slash(r)
                    }
                    _ => false,
                }
            });
        let modifiers = std::fs::read(proj.join("vlt.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some_and(|v| v.get("modifiers").is_some());
        if default_non_npm && !modifiers {
            out.push("redirect_vlt_old_lockfile_ignored");
        }
    }
    if registry.is_some() && (legacy || !lock["options"]["registries"]["npm"].is_string()) {
        out.push("redirect_vlt_scalar_registry_ignored");
    }
    out
}

/// The vlt.json for `registries` (an alias map) on top of the era's
/// default-registry keys.
pub fn with_registries(v: VltVersion, r: &str, aliases: Value, extra: &[(&str, Value)]) -> Value {
    let mut doc = vlt_json(v, r, &VltJson::default());
    let config = if flat_vlt_json(v) {
        &mut doc
    } else {
        doc.as_object_mut()
            .unwrap()
            .entry("config")
            .or_insert_with(|| json!({}))
    };
    let regs = config
        .as_object_mut()
        .unwrap()
        .entry("registries")
        .or_insert_with(|| json!({}));
    for (k, val) in aliases.as_object().unwrap() {
        regs[k] = val.clone();
    }
    for (k, val) in extra {
        config[*k] = val.clone();
    }
    doc
}

pub fn standalone_vex(fx: &Fixture) -> SocketOut {
    let _ = std::fs::remove_file(fx.proj.join("out.vex.json"));
    let uri = fx.svc.uri();
    socket_api(
        &fx.proj,
        &fx.svc,
        &["vex"],
        &[
            "--output",
            "out.vex.json",
            "--product",
            PRODUCT,
            "--patch-server-url",
            &uri,
        ],
    )
}

/// `.socket/manifest.json` + after blobs for `targets` (agent mode and
/// the `vendor` driver read them).
pub fn stage_manifest(proj: &Path, targets: &[&PatchTarget]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut patches = serde_json::Map::new();
    for t in targets {
        let mut files = serde_json::Map::new();
        for (rel, before, after) in t.all_files() {
            files.insert(
                format!("package/{rel}"),
                json!({ "beforeHash": git_sha256(&before), "afterHash": git_sha256(&after) }),
            );
            std::fs::write(socket.join("blobs").join(git_sha256(&after)), &after).unwrap();
            std::fs::write(socket.join("blobs").join(git_sha256(&before)), &before).unwrap();
        }
        patches.insert(
            t.purl(),
            json!({
                "uuid": t.uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": files,
                "vulnerabilities": { t.ghsa.clone(): {
                    "cves": [t.cve], "summary": "s", "severity": "high", "description": "d"
                }},
                "description": "migration", "license": "MIT", "tier": "free"
            }),
        );
    }
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}
