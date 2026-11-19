//! Maven `~/.m2` checksum sidecars (`<file>.sha1` / `<file>.md5`) through
//! the real CLI: a pom-only patch of a plain Maven project. Present and
//! matching the pre-patch bytes, they follow the patched bytes on apply
//! and are put back exactly on rollback; absent, none is created; one that
//! never described the file is left alone. Every rollback is byte-exact.
//!
//! Also here, as the plain-Maven agent flows that need no build: the local
//! repository a project's `.mvn/maven.config` names is the one patched, and
//! a jar a second project finds already patched in the shared repository is
//! rolled back from the registry's verified copy.

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha1::Digest as _;

const PURL: &str = "pkg:maven/com.example/lib@2.0";
const UUID: &str = "7c1e0c2d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const POM: &str = "lib-2.0.pom";
const PRISTINE: &[u8] =
    b"<project><groupId>com.example</groupId><artifactId>lib</artifactId><version>2.0</version></project>\n";
const PATCHED: &[u8] =
    b"<project><groupId>com.example</groupId><artifactId>lib</artifactId><version>2.0</version><!-- socket --></project>\n";

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(bytes))
}

/// RFC 1321 MD5 (no md5 crate among the dev-dependencies).
fn md5_hex(input: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    state
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A plain Maven project depending on the lib, its `~/.m2` copy holding
/// `sidecars` beside the pom, and a manifest patching the pom.
struct Fx {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    m2: PathBuf,
    dir: PathBuf,
}

fn fx(sidecars: &[(&str, String)]) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(
        proj.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.x</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>com.example</groupId><artifactId>lib</artifactId><version>2.0</version>\
         </dependency></dependencies></project>\n",
    )
    .unwrap();
    let m2 = root.join("m2");
    let dir = m2.join("com/example/lib/2.0");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(POM), PRISTINE).unwrap();
    for (name, text) in sidecars {
        std::fs::write(dir.join(name), text).unwrap();
    }
    for bytes in [PRISTINE, PATCHED] {
        std::fs::write(proj.join(".socket/blobs").join(git_sha256(bytes)), bytes).unwrap();
    }
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": { PURL: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { format!("package/{POM}"): {
                "beforeHash": git_sha256(PRISTINE),
                "afterHash": git_sha256(PATCHED),
            } },
            "vulnerabilities": {},
            "description": "pom sidecar fixture",
            "license": "MIT",
            "tier": "free",
        } } }))
        .unwrap(),
    )
    .unwrap();
    Fx {
        _tmp: tmp,
        proj,
        m2,
        dir,
    }
}

impl Fx {
    fn run(&self, args: &[&str]) -> serde_json::Value {
        let mut cmd = hermetic::command(Path::new(env!("CARGO_BIN_EXE_socket-patch")));
        prebuilt_common::jvm_env::isolate_cli(&mut cmd);
        let out = cmd
            .args(args)
            .args(["--json", "--offline", "--cwd", self.proj.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("MAVEN_REPO_LOCAL", &self.m2)
            .env_remove("M2_HOME")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(stdout.trim()).unwrap()
    }

    /// Every file of the m2 version dir.
    fn m2_files(&self) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(&self.dir)
            .unwrap()
            .flatten()
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap()
    }
}

/// Both checksum files matched the pristine pom: rewritten to the patched
/// pom on apply (format kept: digest + file name, and an upper-case md5),
/// reported in `sidecars[]`, and put back byte for byte by rollback.
#[test]
fn matching_sidecars_follow_apply_and_rollback_exactly() {
    let f = fx(&[
        (
            &format!("{POM}.sha1"),
            format!("{}  {POM}\n", sha1_hex(PRISTINE)),
        ),
        (
            &format!("{POM}.md5"),
            md5_hex(PRISTINE).to_ascii_uppercase(),
        ),
    ]);
    let before = f.m2_files();

    let env = f.run(&["apply"]);
    assert_eq!(std::fs::read(f.dir.join(POM)).unwrap(), PATCHED);
    assert_eq!(
        f.read(&format!("{POM}.sha1")),
        format!("{}  {POM}\n", sha1_hex(PATCHED))
    );
    assert_eq!(
        f.read(&format!("{POM}.md5")),
        md5_hex(PATCHED).to_ascii_uppercase()
    );
    let sidecars = env["sidecars"].to_string();
    assert!(
        sidecars.contains(&format!("{POM}.sha1")) && sidecars.contains(&format!("{POM}.md5")),
        "{env}"
    );

    f.run(&["rollback"]);
    assert_eq!(f.m2_files(), before, "rollback must be byte-exact");
}

/// No checksum files: apply and rollback create none, and rollback is
/// byte-exact.
#[test]
fn absent_sidecars_are_not_created() {
    let f = fx(&[]);
    let before = f.m2_files();
    f.run(&["apply"]);
    assert_eq!(std::fs::read(f.dir.join(POM)).unwrap(), PATCHED);
    assert_eq!(f.m2_files().len(), 1, "{:?}", f.m2_files().keys());
    f.run(&["rollback"]);
    assert_eq!(f.m2_files(), before);
}

/// A checksum file that never described the pom is left exactly as it is,
/// by apply and by rollback.
#[test]
fn mismatched_sidecar_is_untouched() {
    let stale = format!("{}\n", "0".repeat(40));
    let f = fx(&[(&format!("{POM}.sha1"), stale.clone())]);
    let before = f.m2_files();
    f.run(&["apply"]);
    assert_eq!(f.read(&format!("{POM}.sha1")), stale);
    f.run(&["rollback"]);
    assert_eq!(f.m2_files(), before);
}

/// `socket-patch <args> --json --cwd <proj>` with `env` and no
/// `MAVEN_REPO_LOCAL`: `(exit status, envelope, stderr)`.
fn run_plain(
    proj: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = hermetic::command(Path::new(env!("CARGO_BIN_EXE_socket-patch")));
    prebuilt_common::jvm_env::isolate_cli(&mut cmd);
    cmd.args(args)
        .args(["--json", "--cwd", proj.to_str().unwrap()])
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env_remove("MAVEN_REPO_LOCAL")
        .env_remove("M2_HOME");
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let json = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e})\n{stdout}\n{stderr}"));
    (out.status.code(), json, stderr)
}

/// `-Dmaven.repo.local` in the project's `.mvn/maven.config` names the
/// repository its builds use: that is the one patched and rolled back,
/// from the project and from a module below it, and the one `MAVEN_OPTS`
/// names (which Maven reads after the config) is left alone. Without the
/// config the `MAVEN_OPTS` repository is the one patched, so the config is
/// what moved it.
#[test]
fn maven_config_local_repository_is_the_one_patched() {
    let f = fx(&[]);
    let decoy = f.proj.parent().unwrap().join("decoy");
    let decoy_pom = decoy.join("com/example/lib/2.0").join(POM);
    std::fs::create_dir_all(decoy_pom.parent().unwrap()).unwrap();
    std::fs::write(&decoy_pom, PRISTINE).unwrap();
    let config = f.proj.join(".mvn/maven.config");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        format!(
            "# shared cache\n-B\n-Dmaven.repo.local={}\n",
            f.m2.display()
        ),
    )
    .unwrap();
    let opts = format!("-Dmaven.repo.local={}", decoy.display());
    let env = [("MAVEN_OPTS", opts.as_str())];
    // `--preserve-state`: a rollback otherwise drops the record it restored.
    let run = |cwd: &Path, command: &str| {
        let args: &[&str] = match command {
            "rollback" => &["rollback", "--offline", "--preserve-state"],
            _ => &[command, "--offline"],
        };
        let (code, json, stderr) = run_plain(cwd, args, &env);
        assert_eq!(code, Some(0), "{command}: {json}\n{stderr}");
    };
    let poms = || {
        (
            std::fs::read(f.dir.join(POM)).unwrap(),
            std::fs::read(&decoy_pom).unwrap(),
        )
    };

    run(&f.proj, "apply");
    assert_eq!(poms(), (PATCHED.to_vec(), PRISTINE.to_vec()));
    run(&f.proj, "rollback");
    assert_eq!(poms(), (PRISTINE.to_vec(), PRISTINE.to_vec()));

    // Maven's launcher finds the config from a module directory too.
    let module = f.proj.join("module");
    std::fs::create_dir_all(&module).unwrap();
    for entry in ["pom.xml", ".socket"] {
        std::fs::rename(f.proj.join(entry), module.join(entry)).unwrap();
    }
    run(&module, "apply");
    assert_eq!(poms(), (PATCHED.to_vec(), PRISTINE.to_vec()));
    run(&module, "rollback");
    assert_eq!(poms(), (PRISTINE.to_vec(), PRISTINE.to_vec()));

    std::fs::remove_file(&config).unwrap();
    run(&module, "apply");
    assert_eq!(poms(), (PRISTINE.to_vec(), PATCHED.to_vec()));
}

/// A config that names one repository to Maven before 3.9 and another to
/// later Mavens, with both on disk and no Maven Wrapper to say which Maven
/// builds the project: neither is patched, and the run says why.
#[test]
fn an_ambiguous_maven_config_patches_nothing_and_says_so() {
    let f = fx(&[]);
    let later = PathBuf::from(format!("{} -B", f.m2.display()));
    let later_pom = later.join("com/example/lib/2.0").join(POM);
    std::fs::create_dir_all(later_pom.parent().unwrap()).unwrap();
    std::fs::write(&later_pom, PRISTINE).unwrap();
    std::fs::create_dir_all(f.proj.join(".mvn")).unwrap();
    std::fs::write(
        f.proj.join(".mvn/maven.config"),
        format!("-Dmaven.repo.local={} -B\n", f.m2.display()),
    )
    .unwrap();
    let (_, json, stderr) = run_plain(&f.proj, &["apply", "--offline"], &[]);
    let warnings = json["warnings"].to_string();
    assert!(
        warnings.contains("maven_local_repository_undetermined")
            && warnings.contains("to Maven before 3.9"),
        "{json}\n{stderr}"
    );
    assert_eq!(std::fs::read(f.dir.join(POM)).unwrap(), PRISTINE);
    assert_eq!(std::fs::read(&later_pom).unwrap(), PRISTINE);

    // The wrapper settles it.
    std::fs::create_dir_all(f.proj.join(".mvn/wrapper")).unwrap();
    std::fs::write(
        f.proj.join(".mvn/wrapper/maven-wrapper.properties"),
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.8.9/apache-maven-3.8.9-bin.zip\n",
    )
    .unwrap();
    let (code, json, stderr) = run_plain(&f.proj, &["apply", "--offline"], &[]);
    assert_eq!(code, Some(0), "{json}\n{stderr}");
    assert_eq!(std::fs::read(f.dir.join(POM)).unwrap(), PATCHED);
    assert_eq!(std::fs::read(&later_pom).unwrap(), PRISTINE);
}

/// A stored jar of `members`.
fn jar(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in members {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// Two projects share one `~/.m2`. The first applies a jar patch and keeps
/// the original under its own `.socket/`; the second finds the copy already
/// patched and has no backup. The second project's rollback restores the
/// jar from the registry (the download matches the registry's checksum and
/// is the jar the copy was patched from) and puts its `.sha1` back. With no
/// such copy to be had it fails, says what happened and how to recover, and
/// leaves the jar as it is; the first project can still roll it back.
#[test]
fn a_second_project_rolls_back_a_shared_m2_jar_from_verified_upstream() {
    const JAR: &str = "lib-2.0.jar";
    const NOTICE: &str = "META-INF/NOTICE.txt";
    let class: (&str, &[u8]) = ("com/example/Lib.class", b"\xca\xfe\xba\xbe");
    let original = jar(&[(NOTICE, b"pristine\n"), class]);
    let patched = jar(&[(NOTICE, b"patched\n"), class]);

    let f = fx(&[]);
    let root = f.proj.parent().unwrap().to_path_buf();
    let sha1 = format!("{}\n", sha1_hex(&original));
    std::fs::write(f.dir.join(JAR), &original).unwrap();
    std::fs::write(f.dir.join(format!("{JAR}.sha1")), &sha1).unwrap();
    let before = f.m2_files();
    let project = |name: &str| {
        let proj = root.join(name);
        std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
        std::fs::copy(f.proj.join("pom.xml"), proj.join("pom.xml")).unwrap();
        for bytes in [&b"pristine\n"[..], b"patched\n"] {
            std::fs::write(proj.join(".socket/blobs").join(git_sha256(bytes)), bytes).unwrap();
        }
        std::fs::write(
            proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": { PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { NOTICE: {
                    "beforeHash": git_sha256(b"pristine\n"),
                    "afterHash": git_sha256(b"patched\n"),
                } },
                "vulnerabilities": {},
                "description": "shared jar fixture",
                "license": "MIT",
                "tier": "free",
            } } }))
            .unwrap(),
        )
        .unwrap();
        proj
    };
    let (one, two) = (project("one"), project("two"));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (server, no_registry) = rt.block_on(async {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        prebuilt_common::mount_download(&server, PURL, UUID, JAR, &patched).await;
        let route = format!("/com/example/lib/2.0/{JAR}");
        Mock::given(method("GET"))
            .and(path(&route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(original.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{route}.sha1")))
            .respond_with(ResponseTemplate::new(200).set_body_string(sha1_hex(&original)))
            .mount(&server)
            .await;
        (server, MockServer::start().await)
    });
    let m2 = f.m2.to_str().unwrap();
    let apply = |proj: &Path| {
        let (code, json, stderr) = run_plain(
            proj,
            &["apply", "--vendor-url", &server.uri()],
            &[("MAVEN_REPO_LOCAL", m2)],
        );
        assert_eq!(code, Some(0), "{json}\n{stderr}");
        assert_eq!(std::fs::read(f.dir.join(JAR)).unwrap(), patched);
    };
    // `--preserve-state`: a rollback otherwise drops the record it restored.
    let rollback = |proj: &Path, extra: &[&str], registry: &str| {
        let args = [&["rollback", "--preserve-state"][..], extra].concat();
        run_plain(
            proj,
            &args,
            &[
                ("MAVEN_REPO_LOCAL", m2),
                ("SOCKET_MAVEN_REGISTRY", registry),
            ],
        )
    };

    apply(&one);
    assert!(one.join(".socket/jvm-originals").is_dir());
    apply(&two);
    assert!(!two.join(".socket/jvm-originals").exists());

    let (code, json, stderr) = rollback(&two, &[], &server.uri());
    assert_eq!(code, Some(0), "{json}\n{stderr}");
    assert_eq!(f.m2_files(), before, "the jar and its .sha1 come back");
    assert!(!two.join(".socket/jvm-originals").exists());

    // No verified upstream copy: the failure says what to do, and the jar
    // is left for the project that holds the original.
    apply(&one);
    apply(&two);
    for (extra, registry, why) in [
        (&[][..], no_registry.uri(), "the registry did not serve it"),
        (
            &["--offline"][..],
            server.uri(),
            "--offline prevents downloading it again",
        ),
    ] {
        let (code, json, stderr) = rollback(&two, extra, &registry);
        assert_eq!(code, Some(1), "{json}\n{stderr}");
        let text = format!("{json}\n{stderr}");
        for part in [
            "jvm_jar_backup_missing: ",
            "has no backup of the original (another project or an earlier workspace applied it)",
            why,
            "To recover, run the rollback from the project that applied the patch",
            "so the build downloads the jar again",
        ] {
            assert!(text.contains(part), "missing {part:?}: {text}");
        }
        assert_eq!(std::fs::read(f.dir.join(JAR)).unwrap(), patched);
    }
    let (code, json, stderr) = rollback(&one, &["--offline"], &server.uri());
    assert_eq!(code, Some(0), "{json}\n{stderr}");
    assert_eq!(f.m2_files(), before);
}

#[test]
fn md5_fixture_matches_rfc1321() {
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
}
