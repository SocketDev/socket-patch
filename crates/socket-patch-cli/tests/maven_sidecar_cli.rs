//! Maven `~/.m2` checksum sidecars (`<file>.sha1` / `<file>.md5`) through
//! the real CLI: a pom-only patch of a plain Maven project. Present and
//! matching the pre-patch bytes, they follow the patched bytes on apply
//! and are put back exactly on rollback; absent, none is created; one that
//! never described the file is left alone. Every rollback is byte-exact.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use sha1::Digest as _;

const PURL: &str = "pkg:maven/com.example/lib@2.0";
const UUID: &str = "7c1e0c2d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const POM: &str = "lib-2.0.pom";
const PRISTINE: &[u8] =
    b"<project><groupId>com.example</groupId><artifactId>lib</artifactId><version>2.0</version></project>\n";
const PATCHED: &[u8] =
    b"<project><groupId>com.example</groupId><artifactId>lib</artifactId><version>2.0</version><!-- socket --></project>\n";

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("SOCKET_") {
                cmd.env_remove(&k);
            }
        }
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

#[test]
fn md5_fixture_matches_rfc1321() {
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
}
