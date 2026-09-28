use super::*;

fn mem(files: &[(&str, &str)]) -> MemoryPolicyFs {
    let mut fs = MemoryPolicyFs::default();
    for (name, text) in files {
        fs.files.insert(
            name.to_string(),
            RootFile::Present(text.as_bytes().to_vec()),
        );
        fs.root_names.push(name.to_string());
    }
    fs
}

fn load(files: &[(&str, &str)]) -> SelectionPolicy {
    SelectionPolicy::load(&mem(files), &PolicyOverrides::default())
        .expect("valid policy")
        .0
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn root<'a>(rel_dir: &'a str, markers: &'a [String], explicit: bool) -> Root<'a> {
    Root {
        rel_dir,
        markers,
        explicit,
    }
}

#[test]
fn no_file_is_unrestricted_with_default_ignores() {
    let (policy, warnings) =
        SelectionPolicy::load(&MemoryPolicyFs::default(), &PolicyOverrides::default()).unwrap();
    assert_eq!(policy.source(), &PolicySource::None);
    assert!(warnings.is_empty());
    assert!(policy.enabled());
    assert_eq!(policy.max_new_patches(), None);
    let lock = strings(&["package-lock.json"]);
    assert!(policy.admits_root(&root("", &lock, false)).is_ok());
    let err = policy
        .admits_root(&root("packages/a/test", &lock, false))
        .unwrap_err();
    assert_eq!(err.code(), "policy_path_excluded");
    assert_eq!(err.detail(), "test/ (built-in default)");
    // Case-insensitive defaults, unlike the old hard-coded segment list.
    assert!(policy
        .admits_root(&root("Tests/app", &lock, false))
        .is_err());
    // Explicit roots never see the defaults.
    assert!(policy
        .admits_root(&root("packages/a/test", &lock, true))
        .is_ok());
}

#[test]
fn empty_file_is_source_none() {
    let policy = load(&[("socket.yml", "# nothing\n")]);
    assert_eq!(policy.source(), &PolicySource::None);
}

#[test]
fn file_source_carries_path_and_hash() {
    let text = "version: 2\npatches:\n  maxNewPatches: 3\n";
    let policy = load(&[("socket.yml", text)]);
    match policy.source() {
        PolicySource::File { path, sha256 } => {
            assert_eq!(path, "socket.yml");
            assert_eq!(sha256, &hex::encode(Sha256::digest(text.as_bytes())));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(policy.max_new_patches(), Some(3));
    let yaml = load(&[("socket.yaml", text)]);
    assert!(matches!(yaml.source(), PolicySource::File { path, .. } if path == "socket.yaml"));
}

#[test]
fn bypass_ignores_the_file_but_keeps_defaults_and_flag_floor() {
    let overrides = PolicyOverrides {
        bypass: true,
        min_severity: Some((Some(1), OverrideSource::Flag)),
    };
    let fs = mem(&[(
        "socket.yml",
        "version: 2\npatches:\n  enabled: false\n  maxNewPatches: 1\n",
    )]);
    let (policy, _) = SelectionPolicy::load(&fs, &overrides).unwrap();
    assert_eq!(policy.source(), &PolicySource::Bypassed);
    assert!(policy.enabled());
    assert_eq!(policy.max_new_patches(), None);
    assert_eq!(policy.min_severity(), (Some(1), SeveritySource::Flag));
    let lock = strings(&["yarn.lock"]);
    assert!(policy
        .admits_root(&root("fixtures/x", &lock, false))
        .is_err());
    // An invalid file is not even read when bypassed.
    let broken = mem(&[("socket.yml", "version: 2\npatches: [\n")]);
    assert!(SelectionPolicy::load(&broken, &overrides).is_ok());
}

#[test]
fn severity_precedence_flag_env_file_default() {
    let fs = mem(&[("socket.yml", "version: 2\npatches:\n  minSeverity: high\n")]);
    let (p, _) = SelectionPolicy::load(&fs, &PolicyOverrides::default()).unwrap();
    assert_eq!(p.min_severity(), (Some(1), SeveritySource::File));
    let env = PolicyOverrides {
        bypass: false,
        min_severity: Some((Some(0), OverrideSource::Env)),
    };
    assert_eq!(
        SelectionPolicy::load(&fs, &env).unwrap().0.min_severity(),
        (Some(0), SeveritySource::Env)
    );
    let none = PolicyOverrides {
        bypass: false,
        min_severity: Some((None, OverrideSource::Flag)),
    };
    assert_eq!(
        SelectionPolicy::load(&fs, &none).unwrap().0.min_severity(),
        (None, SeveritySource::Flag)
    );
    assert_eq!(
        SelectionPolicy::unrestricted().min_severity(),
        (None, SeveritySource::Default)
    );
}

#[test]
fn severity_floor_filters_unknown_and_below() {
    let policy = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  minSeverity: moderate\n",
    )]);
    assert!(policy.admits_severity(0).is_ok());
    assert!(policy.admits_severity(2).is_ok());
    let low = policy.admits_severity(3).unwrap_err();
    assert_eq!(low.code(), "policy_severity");
    assert_eq!(low.detail(), "low < medium");
    assert_eq!(
        policy.admits_severity(4).unwrap_err().detail(),
        "unknown < medium"
    );
    let lowest = load(&[("socket.yml", "version: 2\npatches:\n  minSeverity: low\n")]);
    assert!(lowest.admits_severity(3).is_ok());
    assert!(
        lowest.admits_severity(4).is_err(),
        "low still drops unknown severity"
    );
    assert!(SelectionPolicy::unrestricted().admits_severity(4).is_ok());
}

#[test]
fn floor_filter_uses_max_advisory_severity() {
    use crate::api::types::VulnerabilityResponse;
    use std::collections::HashMap;
    let patch = |uuid: &str, severities: &[&str]| PatchSearchResult {
        uuid: uuid.to_string(),
        purl: "pkg:npm/a@1.0.0".to_string(),
        published_at: String::new(),
        description: String::new(),
        license: String::new(),
        tier: "free".to_string(),
        vulnerabilities: severities
            .iter()
            .enumerate()
            .map(|(i, s)| {
                (
                    format!("GHSA-{i}"),
                    VulnerabilityResponse {
                        cves: vec![],
                        summary: String::new(),
                        severity: s.to_string(),
                        description: String::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>(),
    };
    let policy = load(&[("socket.yml", "version: 2\npatches:\n  minSeverity: high\n")]);
    let (kept, dropped) = policy.floor_filter(vec![
        patch("merged", &["LOW", "CRITICAL"]),
        patch("low", &["LOW"]),
        patch("none", &[]),
    ]);
    assert_eq!(
        kept.iter().map(|p| p.uuid.as_str()).collect::<Vec<_>>(),
        ["merged"]
    );
    assert_eq!(dropped.len(), 2);
}

#[test]
fn both_files_equal_different_and_one_invalid() {
    let a = "version: 2\npatches:\n  maxNewPatches: 2\n";
    let same = "# different bytes, same policy\nversion: \"2\"\npatches: {maxNewPatches: 2}\n";
    let policy = load(&[("socket.yml", a), ("socket.yaml", same)]);
    assert!(matches!(policy.source(), PolicySource::File { path, .. } if path == "socket.yml"));

    let other = "version: 2\npatches:\n  maxNewPatches: 3\n";
    let err = SelectionPolicy::load(
        &mem(&[("socket.yml", a), ("socket.yaml", other)]),
        &PolicyOverrides::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "socket_yml_ambiguous");

    let broken = "version: 2\npatches: [\n";
    let err = SelectionPolicy::load(
        &mem(&[("socket.yml", a), ("socket.yaml", broken)]),
        &PolicyOverrides::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "socket_yml_invalid");
    assert!(err.detail().starts_with("socket.yaml:"), "{}", err.detail());
}

#[test]
fn present_without_content_is_invalid_not_absent() {
    let mut fs = MemoryPolicyFs::default();
    fs.files
        .insert("socket.yml".to_string(), RootFile::PresentWithoutContent);
    let err = SelectionPolicy::load(&fs, &PolicyOverrides::default()).unwrap_err();
    assert_eq!(err.code(), "socket_yml_invalid");
}

#[test]
fn oversize_memory_file_is_invalid() {
    let mut fs = MemoryPolicyFs::default();
    fs.files.insert(
        "socket.yml".to_string(),
        RootFile::Present(vec![b' '; MAX_FILE_BYTES + 1]),
    );
    assert!(SelectionPolicy::load(&fs, &PolicyOverrides::default()).is_err());
}

#[test]
fn case_variant_is_not_read_and_warns() {
    let mut fs = mem(&[]);
    fs.root_names.push("Socket.yml".to_string());
    let (policy, warnings) = SelectionPolicy::load(&fs, &PolicyOverrides::default()).unwrap();
    assert_eq!(policy.source(), &PolicySource::None);
    assert_eq!(warnings[0].code, "socket_yml_name_case");
}

#[test]
fn error_display_names_file_key_and_remedy() {
    let err = SelectionPolicy::load(
        &mem(&[(
            "socket.yml",
            "version: 2\npatches:\n  minSeverity: severe\n",
        )]),
        &PolicyOverrides::default(),
    )
    .unwrap_err();
    let text = err.to_string();
    assert!(
        text.starts_with("socket.yml: patches.minSeverity: unknown severity `severe`"),
        "{text}"
    );
    assert!(text.contains("--no-socket-yml"), "{text}");
}

#[test]
fn marker_rule_all_ignored_or_any_included() {
    let policy = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  ignorePaths: [\"**/yarn.lock\"]\n  includePaths: [\"/services/payments/\"]\n",
    )]);
    let both = strings(&["package.json", "yarn.lock"]);
    let yarn = strings(&["yarn.lock"]);
    // Not every marker ignored: the root stays.
    assert!(policy
        .admits_root(&root("services/payments", &both, false))
        .is_ok());
    assert_eq!(
        policy
            .admits_root(&root("services/payments", &yarn, false))
            .unwrap_err()
            .code(),
        "policy_path_excluded"
    );
    assert_eq!(
        policy
            .admits_root(&root("services/api", &both, false))
            .unwrap_err(),
        FilterReason::PathNotIncluded
    );
    // The repo-root project alone: `/*` plus `!/*/`.
    let only_root = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  includePaths: [\"/*\", \"!/*/\"]\n",
    )]);
    let lock = strings(&["package-lock.json"]);
    assert!(only_root.admits_root(&root("", &lock, true)).is_ok());
    assert!(only_root.admits_root(&root("a", &lock, false)).is_err());
}

#[test]
fn deny_wins_over_include() {
    let policy = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  includePaths: [\"/services/\"]\n  ignorePaths: [\"/services/legacy/\"]\n",
    )]);
    let lock = strings(&["package-lock.json"]);
    let err = policy
        .admits_root(&root("services/legacy", &lock, true))
        .unwrap_err();
    assert_eq!(err.detail(), "/services/legacy/ (patches.ignorePaths)");
}

#[test]
fn defaults_negation_and_project_ignore_paths() {
    let policy = load(&[(
        "socket.yml",
        "version: 2\nprojectIgnorePaths: [\"examples/**\"]\npatches:\n  ignorePaths: [\"!/e2e/tests/\"]\n",
    )]);
    let lock = strings(&["package-lock.json"]);
    assert!(policy.admits_root(&root("e2e/tests", &lock, false)).is_ok());
    assert!(policy
        .admits_root(&root("other/tests", &lock, false))
        .is_err());
    let err = policy
        .admits_root(&root("examples/demo", &lock, true))
        .unwrap_err();
    assert_eq!(err.detail(), "examples/** (projectIgnorePaths)");
    // An unrelated ignore never re-enables fixtures.
    let unrelated = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  ignorePaths: [\"/legacy/\"]\n",
    )]);
    assert!(unrelated
        .admits_root(&root("a/fixtures", &lock, false))
        .is_err());
    // projectIgnorePaths without a patches block is honored too.
    let scanner_only = load(&[(
        "socket.yml",
        "version: 2\nprojectIgnorePaths:\n  - \"crates/*/tests/fixtures/**\"\n",
    )]);
    let cargo = strings(&["Cargo.lock"]);
    assert!(scanner_only
        .admits_root(&root("crates/x/tests/fixtures/app", &cargo, true))
        .is_err());
}

#[test]
fn ecosystems_and_packages() {
    let policy = load(&[(
        "socket.yml",
        "version: 2\npatches:\n  ecosystems: [npm, deno]\n  packages: [\"pkg:npm/lodash\", \"left-pad\", \"@std/path\"]\n  ignorePackages: [\"pkg:npm/left-pad@1.0.0\"]\n",
    )]);
    assert!(policy.admits_purl("pkg:npm/lodash@4.17.20").is_ok());
    assert!(policy.admits_purl("pkg:jsr/@std/path@1.0.0").is_ok());
    assert_eq!(
        policy.admits_purl("pkg:pypi/requests@2.0.0").unwrap_err(),
        FilterReason::Ecosystem
    );
    assert_eq!(
        policy.admits_purl("pkg:npm/qs@6.5.2").unwrap_err(),
        FilterReason::PackageNotListed
    );
    let err = policy.admits_purl("pkg:npm/left-pad@1.0.0").unwrap_err();
    assert_eq!(err.code(), "policy_package_ignored");
    assert_eq!(
        err.detail(),
        "pkg:npm/left-pad@1.0.0 (patches.ignorePackages)"
    );
    assert!(policy.admits_purl("pkg:npm/left-pad@1.1.0").is_ok());
    assert_eq!(
        policy.admits_purl("pkg:unknown/x@1").unwrap_err(),
        FilterReason::Ecosystem
    );
}

#[test]
fn package_spec_matching_grammar() {
    assert!(package_spec_matches("lodash", "pkg:npm/lodash@4.17.20"));
    assert!(package_spec_matches("core", "pkg:npm/%40babel/core@7.0.0"));
    assert!(package_spec_matches(
        "@babel/core",
        "pkg:npm/@babel/core@7.0.0"
    ));
    assert!(package_spec_matches(
        "Requests",
        "pkg:pypi/requests@2.0.0?artifact_id=x"
    ));
    assert!(package_spec_matches(
        "pkg:npm/lodash",
        "pkg:npm/lodash@1.0.0"
    ));
    assert!(!package_spec_matches(
        "pkg:npm/lodash",
        "pkg:npm/lodash-es@1.0.0"
    ));
    assert!(!package_spec_matches(
        "pkg:npm/lodash@1.0.1",
        "pkg:npm/lodash@1.0.0"
    ));
    assert!(!package_spec_matches("", "pkg:npm/lodash@1.0.0"));
    assert!(!package_spec_matches("pkg:", "pkg:npm/lodash@1.0.0"));
    assert!(package_spec_matches(
        "org.example:lib",
        "pkg:maven/org.example/lib@1.0"
    ));
}

#[test]
fn enabled_false_is_reported_by_callers() {
    let policy = load(&[("socket.yml", "version: 2\npatches:\n  enabled: false\n")]);
    assert!(!policy.enabled());
    assert_eq!(FilterReason::Disabled.code(), "policy_disabled");
}

#[test]
fn min_severity_flag_values() {
    assert_eq!(parse_min_severity("none"), Ok(None));
    assert_eq!(parse_min_severity("NONE"), Ok(None));
    assert_eq!(parse_min_severity("Critical"), Ok(Some(0)));
    assert_eq!(parse_min_severity("moderate"), Ok(Some(2)));
    assert!(parse_min_severity("severe").is_err());
    assert!(parse_min_severity("").is_err());
}

#[test]
fn sanitize_strips_controls_and_truncates() {
    assert_eq!(sanitize("a\u{1b}[31mb\nc"), "a[31mbc");
    assert_eq!(sanitize(&"x".repeat(500)).chars().count(), 200);
}

#[test]
fn repo_relative_paths() {
    let root = Path::new("/r");
    assert_eq!(repo_relative(root, Path::new("/r")), "");
    assert_eq!(repo_relative(root, Path::new("/r/a/b")), "a/b");
    assert_eq!(repo_relative_checked(root, Path::new("/other")), None);
}

mod disk {
    use super::*;
    use std::fs;

    fn read(dir: &Path, name: &str) -> std::io::Result<RootFile> {
        DiskPolicyFs::new(dir).read_root_file(name, MAX_FILE_BYTES)
    }

    #[test]
    fn regular_file_absent_and_case_variant() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read(tmp.path(), "socket.yml").unwrap(), RootFile::Absent);
        fs::write(tmp.path().join("Socket.yml"), "version: 2\n").unwrap();
        // Even on case-insensitive disks the exact name must be listed.
        assert_eq!(read(tmp.path(), "socket.yml").unwrap(), RootFile::Absent);
        assert_eq!(
            DiskPolicyFs::new(tmp.path()).case_variants(),
            vec!["Socket.yml".to_string()]
        );
        fs::write(tmp.path().join("socket.yaml"), "version: 2\n").unwrap();
        assert_eq!(
            read(tmp.path(), "socket.yaml").unwrap(),
            RootFile::Present(b"version: 2\n".to_vec())
        );
    }

    #[test]
    fn directory_and_oversize_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("socket.yml")).unwrap();
        assert!(read(tmp.path(), "socket.yml").is_err());
        fs::write(
            tmp.path().join("socket.yaml"),
            vec![b'#'; MAX_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(read(tmp.path(), "socket.yaml").is_err());
        let err =
            SelectionPolicy::load(&DiskPolicyFs::new(tmp.path()), &PolicyOverrides::default())
                .unwrap_err();
        assert_eq!(err.code(), "socket_yml_invalid");
    }

    #[test]
    fn exactly_the_size_limit_is_fine() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("socket.yml"), vec![b'#'; MAX_FILE_BYTES]).unwrap();
        assert!(
            matches!(read(tmp.path(), "socket.yml").unwrap(), RootFile::Present(b) if b.len() == MAX_FILE_BYTES)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_is_followed_outside_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join("config")).unwrap();
        fs::write(repo.join("config/policy.yml"), "version: 2\n").unwrap();
        std::os::unix::fs::symlink("config/policy.yml", repo.join("socket.yml")).unwrap();
        assert!(matches!(
            read(&repo, "socket.yml").unwrap(),
            RootFile::Present(_)
        ));

        fs::write(tmp.path().join("outside.yml"), "version: 2\n").unwrap();
        std::os::unix::fs::symlink("../outside.yml", repo.join("socket.yaml")).unwrap();
        let err = read(&repo, "socket.yaml").unwrap_err();
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("socket.yml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = read(tmp.path(), "socket.yml").unwrap_err();
        assert!(err.to_string().contains("regular file"), "{err}");
    }

    #[test]
    fn repo_root_lookup_git_dir_git_file_and_none() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("a/b")).unwrap();
        assert_eq!(find_repo_root(&repo.join("a/b")), repo);
        assert_eq!(find_repo_root(&repo), repo);

        let worktree = base.join("wt");
        fs::create_dir_all(worktree.join("sub")).unwrap();
        fs::write(worktree.join(".git"), "gitdir: /elsewhere\n").unwrap();
        assert_eq!(find_repo_root(&worktree.join("sub")), worktree);

        let bare = base.join("plain/x");
        fs::create_dir_all(&bare).unwrap();
        assert_eq!(find_repo_root(&bare), bare);
    }

    #[test]
    #[serial_test::serial(git_ceiling_env)]
    fn repo_root_lookup_honors_ceiling_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(base.join(".git")).unwrap();
        let cwd = base.join("ceiling/cwd");
        fs::create_dir_all(&cwd).unwrap();
        std::env::set_var("GIT_CEILING_DIRECTORIES", base.join("ceiling"));
        let found = find_repo_root(&cwd);
        std::env::remove_var("GIT_CEILING_DIRECTORIES");
        assert_eq!(found, cwd);
        assert_eq!(find_repo_root(&cwd), base);
    }

    #[cfg(unix)]
    #[test]
    fn owner_rule() {
        assert!(owner_trusted(1000, 1000));
        assert!(owner_trusted(0, 1000));
        assert!(!owner_trusted(1001, 1000));
    }

    #[cfg(unix)]
    #[test]
    fn foreign_owned_git_stops_the_walk() {
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            // Only root can hand `.git` to another owner; `owner_rule`
            // covers the decision itself.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(base.join(".git")).unwrap();
        let cwd = base.join("sub");
        fs::create_dir_all(&cwd).unwrap();
        let git = std::ffi::CString::new(base.join(".git").to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::chown(git.as_ptr(), 4242, 4242) }, 0);
        let (found, warnings) = find_repo_root_with_warnings(&cwd);
        assert_eq!(found, cwd);
        assert_eq!(warnings[0].code, "socket_yml_repo_untrusted");
    }
}
