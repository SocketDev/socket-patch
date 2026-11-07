//! Self-tests for the shared test-support modules in `tests/common`.
//!
//! They live in this one binary rather than in `common/mod.rs`,
//! `common/cache_env.rs` and `common/jvm_env.rs` themselves: every
//! integration test that declares `mod common` would otherwise compile and
//! run all of them again (118 binaries, about 2,600 redundant runs per
//! `cargo test`), and each failure would be reported once per binary.

#[path = "common/mod.rs"]
mod common;

// ── Self-tests for the shared oracle ──────────────────────────────────
//
// This module is the trust anchor for every safety suite: consuming
// tests call `git_sha256` BOTH to populate `after_hash` in their
// synthetic manifests AND to verify the bytes apply leaves on disk.
// That makes `git_sha256` a single point of failure — if it ever
// drifted from the canonical Git-blob hash (drop the `\0`, drop the
// length header, uppercase the hex, …), both sides of every consumer's
// round-trip would drift together and the suites would stay green while
// guarding nothing.
//
// These self-tests pin the oracle so it can never be silently weakened:
//   * golden constants derived independently (Python `hashlib`), NOT by
//     re-running the helper against itself, and
//   * an equality check against the *production* hash
//     (`compute_git_sha256_from_bytes`) that apply actually verifies
//     against — so the harness and production can never disagree
//     unnoticed.
mod oracle_selftests {
    use crate::common::*;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

    // Independently computed: sha256(b"blob <len>\0" + content).
    const GIT_BLOB_EMPTY: &str = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";
    const GIT_BLOB_HELLO: &str = "8aec4e4876f854f688d0ebfc8f37598f38e5fd6903cccc850ca36591175aeb60";
    // Independently computed: bare sha256(content), no Git framing.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn git_sha256_matches_independent_golden() {
        assert_eq!(
            git_sha256(b""),
            GIT_BLOB_EMPTY,
            "git_sha256 oracle drifted from the canonical Git-blob hash of empty content"
        );
        assert_eq!(
            git_sha256(b"hello"),
            GIT_BLOB_HELLO,
            "git_sha256 oracle drifted from the canonical Git-blob hash of b\"hello\""
        );
    }

    #[test]
    fn git_sha256_agrees_with_production_hash() {
        // The harness oracle MUST equal the hash apply actually verifies
        // against; otherwise the circular round-trip in every consumer
        // can agree with a broken implementation. Cover empty, ASCII,
        // multi-byte (so the length header is exercised in bytes not
        // chars), and raw binary.
        for content in [
            &b""[..],
            b"hello",
            b"socket-patch test\n",
            "é multibyte".as_bytes(),
            &[0u8, 1, 2, 255, 254, 0, 42],
        ] {
            assert_eq!(
                git_sha256(content),
                compute_git_sha256_from_bytes(content),
                "harness git_sha256 disagrees with production compute_git_sha256_from_bytes \
                 for {content:?}"
            );
        }
    }

    #[test]
    fn git_framing_is_actually_applied() {
        // Guard against the framing being silently stripped: the Git
        // blob hash must differ from a bare sha256, must be lowercase
        // hex, and must depend on content length (the `<len>` header),
        // not just the bytes.
        assert_ne!(
            git_sha256(b"hello"),
            sha256_hex(b"hello"),
            "git_sha256 must include the `blob <len>\\0` framing, not bare sha256"
        );

        // Reconstruct the framing independently (manual byte concatenation
        // fed through the un-framed `sha256_hex`) and pin git_sha256 to it.
        // This proves the EXACT framing — `blob ` + decimal length + NUL +
        // content — without re-deriving it from `git_sha256` itself.
        //
        // The previous check here (`git_sha256(b"ab") != git_sha256(b"a\0b")`)
        // was confounded: those inputs differ in *content* as well as length,
        // so it passed even for an impl that dropped the length header
        // entirely. We instead compare against framing that omits the length,
        // which differs in nothing BUT the length digits.
        let content = b"socket-patch length-header probe";
        let mut framed_with_len = Vec::new();
        framed_with_len.extend_from_slice(format!("blob {}\0", content.len()).as_bytes());
        framed_with_len.extend_from_slice(content);
        assert_eq!(
            git_sha256(content),
            sha256_hex(&framed_with_len),
            "git_sha256 must equal the bare sha256 of `blob <len>\\0` ++ content"
        );
        let mut framed_no_len = Vec::new();
        framed_no_len.extend_from_slice(b"blob \0");
        framed_no_len.extend_from_slice(content);
        assert_ne!(
            git_sha256(content),
            sha256_hex(&framed_no_len),
            "git_sha256 must hash the content LENGTH in the header, not a fixed `blob \\0`"
        );
        // Belt-and-braces: changing only the length (same trailing bytes) must
        // change the hash. `b"a"` and `b"aa"` share the same first byte but
        // frame at lengths 1 and 2.
        assert_ne!(
            git_sha256(b"a"),
            git_sha256(b"aa"),
            "git_sha256 of distinct-length inputs must differ"
        );

        let h = git_sha256(b"hello");
        assert_eq!(h.len(), 64, "hash must be 32 bytes of hex");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "hash must be lowercase hex, got {h}"
        );
    }

    #[test]
    fn sha256_hex_matches_independent_golden() {
        assert_eq!(sha256_hex(b""), SHA256_EMPTY);
        assert_eq!(sha256_hex(b"hello"), SHA256_HELLO);
        // Must be the un-framed digest, distinct from the Git-blob form.
        assert_ne!(sha256_hex(b"hello"), git_sha256(b"hello"));
    }

    #[test]
    fn git_sha256_file_hashes_real_bytes() {
        // `git_sha256_file` must hash exactly what is on disk — read it
        // back and confirm it equals hashing the same bytes in memory,
        // and that distinct contents produce distinct hashes (i.e. it
        // isn't returning a constant or hashing the path).
        let dir = tempfile::tempdir().expect("temp dir");
        let p1 = dir.path().join("a.bin");
        let p2 = dir.path().join("b.bin");
        let content_a = b"alpha-content\n";
        let content_b = b"beta-content\n";
        std::fs::write(&p1, content_a).expect("write temp a");
        std::fs::write(&p2, content_b).expect("write temp b");

        assert_eq!(git_sha256_file(&p1), git_sha256(content_a));
        assert_eq!(git_sha256_file(&p2), git_sha256(content_b));
        assert_ne!(
            git_sha256_file(&p1),
            git_sha256_file(&p2),
            "git_sha256_file must reflect file contents"
        );
    }

    #[test]
    fn write_minimal_manifest_emits_apply_compatible_shape() {
        // `write_minimal_manifest` is the fixture builder behind every safety
        // suite — if its emitted schema silently drifted (snake_case keys,
        // wrong nesting, missing uuid/files), apply would stop matching and
        // the suites would pass while exercising nothing. Pin the exact shape
        // apply consumes: `patches.<purl>.{uuid,files.<file>.{beforeHash,
        // afterHash}}`, all camelCase.
        let root = tempfile::tempdir().expect("temp dir");
        let socket_dir = root.path().join(".socket");
        let purl = "pkg:npm/dummy@1.0.0";
        let uuid = "11111111-1111-4111-8111-111111111111";
        let path = write_minimal_manifest(
            &socket_dir,
            purl,
            uuid,
            &[PatchEntry {
                file_name: "package/index.js",
                before_hash: "beforehash000",
                after_hash: "afterhash111",
            }],
        );

        assert_eq!(
            path,
            socket_dir.join("manifest.json"),
            "manifest must land at <socket_dir>/manifest.json"
        );
        let raw = std::fs::read_to_string(&path).expect("manifest written");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest must be valid JSON");

        let patch = v
            .get("patches")
            .and_then(|p| p.get(purl))
            .unwrap_or_else(|| panic!("manifest must key the patch by purl\n{raw}"));
        assert_eq!(
            patch.get("uuid").and_then(|x| x.as_str()),
            Some(uuid),
            "patch must carry the supplied uuid"
        );
        let file = patch
            .get("files")
            .and_then(|f| f.get("package/index.js"))
            .unwrap_or_else(|| panic!("files must be keyed by file_name\n{raw}"));
        assert_eq!(
            file.get("beforeHash").and_then(|x| x.as_str()),
            Some("beforehash000"),
            "file entry must use camelCase `beforeHash` (the key apply reads)"
        );
        assert_eq!(
            file.get("afterHash").and_then(|x| x.as_str()),
            Some("afterhash111"),
            "file entry must use camelCase `afterHash` (the key apply reads)"
        );
        // The builder documents that it does NOT stage the after blob — that
        // is `write_blob`'s job, and several tests rely on the blob being
        // absent to force an offline-apply failure.
        assert!(
            !socket_dir.join("blobs").join("afterhash111").exists(),
            "write_minimal_manifest must not stage after_hash blobs"
        );
    }

    #[test]
    fn write_blob_stages_exact_bytes_at_hash_path() {
        // The companion fixture builder: apply resolves `after_hash` blobs at
        // `<socket_dir>/blobs/<hash>` and verifies their bytes. If write_blob
        // wrote the wrong path or mangled the bytes, "offline apply succeeds"
        // tests would silently fall back to a network path or fail to match.
        let root = tempfile::tempdir().expect("temp dir");
        let socket_dir = root.path().join(".socket");
        let hash = "deadbeefcafef00d";
        let payload = &[0u8, 1, 2, 255, b'p', b'a', b't', b'c', b'h', 0, 42];
        write_blob(&socket_dir, hash, payload);

        let blob_path = socket_dir.join("blobs").join(hash);
        assert!(
            blob_path.is_file(),
            "blob must be written at <socket_dir>/blobs/<hash>: {}",
            blob_path.display()
        );
        assert_eq!(
            std::fs::read(&blob_path).expect("blob readable"),
            payload,
            "write_blob must stage the exact bytes, byte-for-byte"
        );
    }

    #[test]
    fn envelope_helpers_read_the_v3_shapes() {
        // The envelope accessors are how every safety suite reads apply's
        // `--json` output. Pin them to the real v3 shapes: `error.code` /
        // `error.message` nested under a top-level `error` object, top-level
        // string fields via `json_string`, and graceful `None` (never a
        // panic or a wrong-key hit) on absent / non-string / non-object
        // fields — so a consumer's negative assertion can't pass vacuously.
        let env = parse_json_envelope(
            r#"{"status":"error","command":"apply","count":3,
                "error":{"code":"lock_held","message":"another run holds the lock"}}"#,
        );
        assert_eq!(json_string(&env, "status"), Some("error"));
        assert_eq!(json_string(&env, "command"), Some("apply"));
        // Non-string and absent top-level fields must yield None, not a coerced
        // value — otherwise `assert_eq!(json_string(..), Some(..))` could be
        // dodged or a missing field read as empty.
        assert_eq!(
            json_string(&env, "count"),
            None,
            "numeric field is not a string"
        );
        assert_eq!(json_string(&env, "missing"), None);
        assert_eq!(envelope_error_code(&env), Some("lock_held"));
        assert_eq!(
            envelope_error_message(&env),
            Some("another run holds the lock")
        );

        // No `error` object → both error accessors return None (not a panic,
        // not a stale hit), so success-path consumers asserting `None` stay
        // honest.
        let ok = parse_json_envelope(r#"{"status":"success","command":"list"}"#);
        assert_eq!(envelope_error_code(&ok), None);
        assert_eq!(envelope_error_message(&ok), None);

        // The accessors must look under the nested `error` object, NOT at a
        // flat top-level `code`/`message`. A flat-keyed envelope must read as
        // absent so the helper can't accidentally satisfy a nested-shape
        // assertion against the wrong layout.
        let flat = parse_json_envelope(r#"{"code":"nope","message":"flat"}"#);
        assert_eq!(
            envelope_error_code(&flat),
            None,
            "error.code must be nested under `error`, not read from top-level `code`"
        );
        assert_eq!(envelope_error_message(&flat), None);
    }
}

// ── cache_env ──────────────────────────────────────────────────────────
mod cache_env_selftests {
    use crate::common::cache_env::*;
    use std::path::PathBuf;
    use std::process::Command;

    /// The names the bun suites' hermeticity depends on — the registry
    /// overrides that reproduced the false negative, bun's auth and cache
    /// knobs, the CLI's own surface — are covered; the hermetic switch, the
    /// toolchain vars and look-alike prefixes (`BUNDLE_*`) survive.
    #[test]
    fn ambient_bun_scrub_covers_the_registry_and_config_overrides() {
        for name in [
            "BUN_CONFIG_REGISTRY",
            "BUN_CONFIG_TOKEN",
            "BUN_INSTALL",
            "BUN_INSTALL_CACHE_DIR",
            "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
            "npm_config_registry",
            "NPM_CONFIG_REGISTRY",
            "Npm_Config_Registry",
            "npm_config__auth",
            "npm_config_cache",
            "SOCKET_API_TOKEN",
            "SOCKET_DRY_RUN",
            "VIRTUAL_ENV",
        ] {
            assert!(is_ambient_bun_var(name), "{name} must be scrubbed");
        }
        for name in [
            "SOCKET_NO_CONFIG",
            "PATH",
            "HOME",
            "BUNDLE_PATH",
            "BUNDLE_USER_HOME",
            "npm_lifecycle_event",
            "XDG_CONFIG_HOME",
            "RUSTUP_HOME",
        ] {
            assert!(!is_ambient_bun_var(name), "{name} must survive the scrub");
        }
    }

    /// The scrub removes exactly the parent variables the predicate names:
    /// nothing else is touched, and no matching parent variable is missed.
    #[test]
    fn ambient_bun_scrub_removes_only_matching_parent_vars() {
        let parent = parent_var_names();
        let mut cmd = Command::new("true");
        scrub_parent_vars(&mut cmd, parent.clone(), is_ambient_bun_var);
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        for name in &removed {
            assert!(
                is_ambient_bun_var(name),
                "{name} was removed but is not an ambient bun var"
            );
        }
        for name in &parent {
            let name = name.to_string_lossy();
            if is_ambient_bun_var(&name) {
                assert!(
                    removed.iter().any(|r| *r == name),
                    "{name} is set in the parent env but was not scrubbed"
                );
            }
        }
        assert!(
            cmd.get_envs().all(|(_, value)| value.is_none()),
            "the scrub only removes; it seeds nothing"
        );
    }

    #[test]
    fn ambient_vlt_scrub_covers_vlt_config_and_keeps_the_harness_gates() {
        for name in [
            "VLT_REGISTRY",
            "VLT_REGISTRIES",
            "VLT_CACHE",
            "VLT_STORE_LINKER",
            "VLT_TELEMETRY",
            "npm_config_registry",
            "NPM_CONFIG_REGISTRY",
            "SOCKET_API_TOKEN",
            "SOCKET_NO_VLT_INSTALL_CLEANUP",
            "SOCKET_PATCH_BUN_E2E_JS",
            "VIRTUAL_ENV",
        ] {
            assert!(is_ambient_vlt_var(name), "{name} must be scrubbed");
        }
        for name in [
            "SOCKET_NO_CONFIG",
            "SOCKET_PATCH_VLT_E2E_JS",
            "SOCKET_PATCH_VLT_E2E_VERSION",
            "SOCKET_PATCH_VLT_E2E_REQUIRED",
            "SOCKET_PATCH_VLT_E2E_STORE_LINKER",
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "NODE_OPTIONS_X",
        ] {
            assert!(!is_ambient_vlt_var(name), "{name} must survive the scrub");
        }
    }

    /// The CLI-child variant keeps every `SOCKET_*`, so it never undoes
    /// the opt-outs `hermetic::command` forces on, and still strips the
    /// vlt, npm and Python config.
    #[test]
    fn ambient_vlt_tool_scrub_leaves_socket_vars_to_the_hermetic_builder() {
        for name in [
            "SOCKET_TELEMETRY_DISABLED",
            "SOCKET_NO_UPDATE_CHECK",
            "SOCKET_NO_CONFIG",
            "SOCKET_API_TOKEN",
        ] {
            assert!(!is_ambient_vlt_tool_var(name), "{name} must survive");
        }
        for name in ["VLT_REGISTRY", "npm_config_registry", "VIRTUAL_ENV"] {
            assert!(is_ambient_vlt_tool_var(name), "{name} must be scrubbed");
        }
    }

    #[test]
    fn ambient_vlt_scrub_removes_only_matching_parent_vars() {
        let parent = parent_var_names();
        let mut cmd = Command::new("true");
        scrub_parent_vars(&mut cmd, parent.clone(), is_ambient_vlt_var);
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        for name in &removed {
            assert!(is_ambient_vlt_var(name), "{name} was removed");
        }
        for name in &parent {
            let name = name.to_string_lossy();
            if is_ambient_vlt_var(&name) {
                assert!(removed.iter().any(|r| *r == name), "{name} kept");
            }
        }
    }

    /// The variables whose whole point is that they outrank `HOME`. A future
    /// edit that drops one would silently restore the leak this module
    /// exists to close, and nothing else in the suite would notice.
    const MUST_PIN: &[&str] = &[
        "HOME",
        "GOCACHE",
        "GOMODCACHE",
        "GOPATH",
        "COREPACK_HOME",
        "PNPM_HOME",
        "CARGO_HOME",
        "npm_config_cache",
        "YARN_CACHE_FOLDER",
        "BUN_INSTALL_CACHE_DIR",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "GEM_SPEC_CACHE",
        "NUGET_PACKAGES",
    ];

    #[test]
    fn every_leak_prone_var_is_pinned() {
        let pinned = overrides();
        for want in MUST_PIN {
            assert!(
                pinned.iter().any(|(var, _)| var == want),
                "{want} is no longer pinned by cache_env::overrides(); package-manager \
                 caches will leak into the home directory of whoever runs the suite"
            );
        }
    }

    #[test]
    fn every_override_lands_inside_the_sandbox() {
        let root = cache_root();
        for (var, path) in overrides() {
            assert!(
                path.starts_with(&root),
                "{var} points outside the cache sandbox: {} is not under {}",
                path.display(),
                root.display()
            );
        }
    }

    #[test]
    fn no_override_points_into_the_real_home() {
        let Some(real) = real_home() else {
            return;
        };
        // A machine whose TMPDIR is itself inside the home directory has no
        // way to satisfy this; the sandbox is still a dedicated directory, so
        // skip rather than fail.
        if cache_root().starts_with(&real) {
            return;
        }
        for (var, path) in overrides() {
            assert!(
                !path.starts_with(&real),
                "{var} still resolves inside the real home: {}",
                path.display()
            );
        }
    }

    #[test]
    fn isolate_applies_the_overrides_to_a_command() {
        let mut cmd = Command::new("true");
        isolate(&mut cmd);
        let applied: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (var, path) in overrides() {
            let seen = applied
                .iter()
                .find(|(name, _)| name == var)
                .unwrap_or_else(|| panic!("isolate() did not set {var}"));
            assert_eq!(
                seen.1.as_deref(),
                Some(path.to_string_lossy().as_ref()),
                "isolate() set {var} to the wrong path"
            );
        }
        assert!(
            sandbox_home().is_dir(),
            "isolate() must create the sandbox home so tools that require \
             an existing $HOME can start"
        );
    }

    #[test]
    fn toolchain_roots_are_only_seeded_when_they_exist() {
        // The preservation pass must never invent a path. Whatever it seeds
        // has to be a directory that is really there under the real home,
        // and it must leave a variable the caller already exported alone.
        let Some(real) = real_home() else {
            return;
        };
        let mut cmd = Command::new("true");
        isolate(&mut cmd);
        let applied: Vec<(String, Option<PathBuf>)> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(PathBuf::from)))
            .collect();
        for (var, relative) in TOOLCHAIN_ROOTS {
            let Some((_, value)) = applied.iter().find(|(name, _)| name == var) else {
                continue;
            };
            if std::env::var_os(var).is_some() {
                // Already exported by the caller: inherited untouched, so it
                // must not appear in the command's explicit env at all.
                panic!("{var} was already set in the parent env; isolate() must not override it");
            }
            let value = value.as_ref().expect("seeded roots always have a value");
            assert_eq!(
                value,
                &real.join(relative),
                "{var} was seeded to something other than its default under the real home"
            );
            assert!(
                value.is_dir(),
                "{var} was seeded to a path that does not exist: {}",
                value.display()
            );
        }
    }
}

// ── jvm_env ────────────────────────────────────────────────────────────
mod jvm_env_selftests {
    use crate::common::jvm_env::*;
    use std::path::PathBuf;
    use std::process::Command;

    /// A stray GRADLE_OPTS (and every other ambient JVM knob) never reaches
    /// the child, the home is the stand-in, and an explicit cache applied
    /// afterwards wins.
    #[test]
    fn isolate_cli_scrubs_ambient_jvm_env_and_pins_home() {
        let mut cmd = Command::new("socket-patch");
        cmd.env("GRADLE_OPTS", "-Dgradle.user.home=/real/.gradle")
            .env("JAVA_OPTS", "-Dgradle.user.home=/real/.gradle")
            .env("GRADLE_RO_DEP_CACHE", "/real/ro");
        isolate_cli(&mut cmd);
        cmd.env("GRADLE_USER_HOME", "/explicit/gradle-home");
        let envs: std::collections::HashMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for key in [
            "GRADLE_OPTS",
            "JAVA_OPTS",
            "GRADLE_RO_DEP_CACHE",
            "GRADLE_HOME",
        ] {
            assert_eq!(envs.get(key), Some(&None), "{key} must be scrubbed");
        }
        let home = stand_in_home().to_string_lossy().into_owned();
        assert_eq!(envs["HOME"].as_deref(), Some(home.as_str()));
        assert_eq!(envs["USERPROFILE"].as_deref(), Some(home.as_str()));
        assert_eq!(
            envs["GRADLE_USER_HOME"].as_deref(),
            Some("/explicit/gradle-home")
        );
        assert!(std::path::Path::new(&home).is_dir());
    }

    /// Without an explicit cache the Gradle user home is the stand-in's
    /// `.gradle`: the CLI resolves Gradle's home from the passwd entry on
    /// Unix, so pinning `HOME` alone would leak the real `~/.gradle`.
    #[test]
    fn isolate_cli_pins_the_gradle_user_home() {
        let mut cmd = Command::new("socket-patch");
        cmd.env("GRADLE_USER_HOME", "/real/.gradle");
        isolate_cli(&mut cmd);
        let home = cmd
            .get_envs()
            .find(|(k, _)| *k == "GRADLE_USER_HOME")
            .and_then(|(_, v)| v)
            .map(PathBuf::from);
        assert_eq!(home, Some(stand_in_home().join(".gradle")));
    }
}
