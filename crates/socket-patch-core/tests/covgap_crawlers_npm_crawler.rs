//! Coverage-gap integration tests for `crawlers::npm_crawler`: the audited
//! never-executed skip/fallback regions of the store walkers
//! (`collect_nested_node_modules`, `collect_nested_store_entries`,
//! `scan_scoped_packages`) and every reject/fallback gate of
//! `find_pnpm_peer_variant_copies`. Each test stages the real on-disk shape
//! that reaches its region and asserts resolver/scan OUTPUT, not just
//! survival. Companion to `crawler_npm_e2e.rs` (helpers mirrored from
//! there).

use std::path::Path;

use socket_patch_core::crawlers::npm_crawler::find_pnpm_peer_variant_copies;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::NpmCrawler;

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
    }
}

/// Stage a package inside node_modules. `name` may include a `@scope/`
/// prefix.
async fn stage_npm_pkg(node_modules: &Path, name: &str, version: &str) {
    let pkg_dir = node_modules.join(name);
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    tokio::fs::write(pkg_dir.join("package.json"), pkg_json)
        .await
        .unwrap();
}

// ── plain-FILE store markers at a node_modules root ────────────

/// A stray plain FILE named `.pnpm` or `.registry.npmjs.org` at a
/// `node_modules` root (trivially stageable; real trees carry such junk)
/// must be skipped by BOTH walks — the resolver's nested-nm BFS and the
/// scan pass — without erroring out and without being mistaken for a
/// virtual store.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_and_crawl_all_skip_plain_file_store_markers() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "foo", "1.0.0").await;
    // Plain files where the store DIRS would live.
    tokio::fs::write(nm.join(".pnpm"), b"junk").await.unwrap();
    tokio::fs::write(nm.join(".registry.npmjs.org"), b"junk")
        .await
        .unwrap();

    // Resolver walk: foo resolves at the root, the marker files are
    // skipped (no error, no phantom copies).
    let crawler = NpmCrawler::new();
    let purls = vec!["pkg:npm/foo@1.0.0".to_string()];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();
    assert_eq!(result.len(), 1, "only foo resolves; got {result:?}");
    let copies = result.get("pkg:npm/foo@1.0.0").unwrap();
    assert_eq!(copies.len(), 1, "exactly one physical copy of foo");
    assert_eq!(copies[0].path, nm.join("foo"));

    // Scan walk: exactly one package inventoried.
    let packages = crawler.crawl_all(&options_at(tmp.path())).await;
    assert_eq!(
        packages.len(),
        1,
        "marker files must not add or hide packages; got {:?}",
        packages.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(packages[0].purl, "pkg:npm/foo@1.0.0");
    assert_eq!(packages[0].path, nm.join("foo"));
}

// ── stray entries inside a `@scope` dir during the nested-nm BFS ─

/// The resolver's nested-node_modules walk descends `@scope/<pkg>` dirs
/// looking for deeper `node_modules`. Hidden entries (`.DS_Store`-style
/// junk is ubiquitous inside scope dirs on macOS) and plain files inside
/// the `@scope` dir must be skipped without breaking or polluting the
/// walk — the target below the real scoped package must still resolve.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_ignores_stray_entries_in_scope_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "@scope/pkg", "1.0.0").await;
    // The target lives ONLY inside the scoped package's nested
    // node_modules, so resolving it forces the walk through @scope.
    stage_npm_pkg(&nm.join("@scope/pkg/node_modules"), "leaf", "2.0.0").await;
    // Stray entries inside the @scope dir itself: a hidden dir and a
    // plain file.
    tokio::fs::create_dir_all(nm.join("@scope/.cache"))
        .await
        .unwrap();
    tokio::fs::write(nm.join("@scope/notes.txt"), b"junk")
        .await
        .unwrap();

    let crawler = NpmCrawler::new();
    let purls = vec![
        "pkg:npm/leaf@2.0.0".to_string(),
        "pkg:npm/@scope/pkg@1.0.0".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    assert_eq!(result.len(), 2, "both packages resolve; got {result:?}");
    assert_eq!(
        result.get("pkg:npm/leaf@2.0.0").unwrap()[0].path,
        nm.join("@scope/pkg/node_modules/leaf"),
        "leaf resolves only by descending @scope/pkg's nested node_modules"
    );
    assert_eq!(
        result.get("pkg:npm/@scope/pkg@1.0.0").unwrap()[0].path,
        nm.join("@scope/pkg")
    );
}

// ── scoped root-linked pnpm direct dep: dedup + no symlink descend ─

/// Scoped twin of the unscoped `identity_seen` dedup: a SCOPED pnpm
/// direct dep is root-linked (`node_modules/@scope/leaf` → store copy),
/// so the importer pass inventories it first and the store pass must
/// skip the redundant re-read — while STILL descending the store copy,
/// because a bundled dep is a real dir physically present only there.
/// The importer pass must inventory the symlinked scoped package without
/// descending through the symlink (descending would surface the bundled
/// dep at its symlink-relative path instead of its physical store home).
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_dedups_scoped_root_linked_pnpm_direct_dep_and_skips_symlink_descend() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    // Store copy of the scoped package…
    stage_npm_pkg(
        &store.join("@scope+leaf@2.0.0").join("node_modules"),
        "@scope/leaf",
        "2.0.0",
    )
    .await;
    let store_leaf = store.join("@scope+leaf@2.0.0/node_modules/@scope/leaf");
    // …with a bundled dep as a REAL dir below it (its only physical home).
    stage_npm_pkg(&store_leaf.join("node_modules"), "bundled", "1.0.0").await;

    // Importer root: the scoped direct dep is a symlink into the store.
    tokio::fs::create_dir_all(nm.join("@scope")).await.unwrap();
    symlink(&store_leaf, nm.join("@scope/leaf")).unwrap();

    let crawler = NpmCrawler::new();
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        result.len(),
        2,
        "exactly @scope/leaf (once) + bundled; got {purls:?}"
    );
    let leaf_copies: Vec<_> = result
        .iter()
        .filter(|p| p.purl == "pkg:npm/@scope/leaf@2.0.0")
        .collect();
    assert_eq!(
        leaf_copies.len(),
        1,
        "the root-linked scoped dep must be inventoried exactly once"
    );
    assert_eq!(
        leaf_copies[0].path,
        nm.join("@scope/leaf"),
        "the importer-root path wins over the store copy"
    );
    let bundled = result
        .iter()
        .find(|p| p.purl == "pkg:npm/bundled@1.0.0")
        .unwrap_or_else(|| panic!("bundled dep must be inventoried; got {purls:?}"));
    assert_eq!(
        bundled.path,
        store_leaf.join("node_modules/bundled"),
        "bundled dep surfaces at its physical store home — reached by \
         descending the store entry (dedup skip must not stop the \
         descent), never through the importer symlink"
    );
}

// ── find_pnpm_peer_variant_copies: probe gates ─────────────────

/// All four reject/fallback gates of the peer-variant store probe, in one
/// staged store:
/// - an UNDECODABLE entry name stays probeable and its real matching copy
///   IS returned (a regression here silently skips a physical copy,
///   leaving a live vulnerable file after apply reports success);
/// - an entry whose candidate dir is absent is skipped;
/// - a candidate that is a SYMLINK to another entry's copy is skipped
///   (that copy is already yielded via its own entry — no double count);
/// - an imposter whose package.json disagrees with the decoded name is
///   rejected by the authority probe.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn find_pnpm_peer_variant_copies_probe_gates() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    // (a) The primary peer-variant copy.
    stage_npm_pkg(
        &store.join("foo@1.0.0(react@17.0.2)").join("node_modules"),
        "foo",
        "1.0.0",
    )
    .await;
    let primary = store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");

    // (b) A real twin under another peer combination — must be returned.
    stage_npm_pkg(
        &store.join("foo@1.0.0(react@18.2.0)").join("node_modules"),
        "foo",
        "1.0.0",
    )
    .await;
    let twin = store.join("foo@1.0.0(react@18.2.0)/node_modules/foo");

    // (c) An UNDECODABLE entry name (`_` reads as a legacy peer suffix,
    // so decode yields None) holding a real matching copy — must be
    // returned: undecodable stays probeable.
    stage_npm_pkg(
        &store.join("foo_bar@1.0.0").join("node_modules"),
        "foo",
        "1.0.0",
    )
    .await;
    let undecodable_copy = store.join("foo_bar@1.0.0/node_modules/foo");

    // (d) A matching-decoded entry whose node_modules holds no `foo` dir.
    tokio::fs::create_dir_all(store.join("foo@1.0.0(vue@3.2.0)").join("node_modules"))
        .await
        .unwrap();

    // (e) A matching-decoded entry whose `foo` is a SYMLINK to twin (b).
    let sym_nm = store.join("foo@1.0.0(sym@1.0.0)").join("node_modules");
    tokio::fs::create_dir_all(&sym_nm).await.unwrap();
    symlink(&twin, sym_nm.join("foo")).unwrap();

    // (f) An imposter: the entry NAME decodes to foo@1.0.0 (passes the
    // advertisement filter) but the package.json inside says 1.0.1.
    stage_npm_pkg(
        &store.join("foo@1.0.0(baz@1.0.0)").join("node_modules"),
        "foo",
        "1.0.1",
    )
    .await;

    let copies = find_pnpm_peer_variant_copies(&primary).await;

    let got: std::collections::HashSet<_> = copies.iter().cloned().collect();
    let want: std::collections::HashSet<_> = [twin.clone(), undecodable_copy.clone()]
        .into_iter()
        .collect();
    assert_eq!(
        got, want,
        "exactly the real twin and the undecodable-entry copy — no \
         primary, no symlink duplicate, no absent candidate, no imposter"
    );
}

/// Fail-safe gate: when the PRIMARY's package.json is unreadable there is
/// no safe way to identify twins, so NONE are reported — even though a
/// perfectly probeable twin exists in the store (the primary itself is
/// still handled by the caller).
#[tokio::test]
#[serial_test::parallel]
async fn find_pnpm_peer_variant_copies_unreadable_primary_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    // Primary: a bare dir with NO package.json.
    let primary = store.join("foo@1.0.0(react@17.0.2)/node_modules/foo");
    tokio::fs::create_dir_all(&primary).await.unwrap();

    // A fully-formed twin that WOULD match if the primary were readable.
    stage_npm_pkg(
        &store.join("foo@1.0.0(react@18.2.0)").join("node_modules"),
        "foo",
        "1.0.0",
    )
    .await;

    let copies = find_pnpm_peer_variant_copies(&primary).await;
    assert!(
        copies.is_empty(),
        "unreadable primary identity ⇒ no twins reported; got {copies:?}"
    );
}

// ── pnpm<=3 legacy store: stray node_modules + depth-1 home ────

/// Two edge shapes of the nested legacy-store walk:
/// - a stray `node_modules` child inside the store host belongs to a
///   parent entry, never a name/version coordinate — a decoy package
///   staged below it must NOT be inventoried;
/// - a depth-1 package home (`<host>/<pkg>/node_modules/<pkg>`) has no
///   `/` in its host-relative path, so the raw component becomes an
///   undecodable-but-probed entry name and the package IS inventoried.
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_legacy_store_skips_stray_node_modules_and_probes_depth1_home() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".registry.npmjs.org");

    // Normal legacy shape: <name>/<version>/node_modules/<name>.
    stage_npm_pkg(&store.join("mkdirp/0.5.5/node_modules"), "mkdirp", "0.5.5").await;
    // Depth-1 home: <name>/node_modules/<name> (no version dir).
    stage_npm_pkg(&store.join("directpkg/node_modules"), "directpkg", "3.0.0").await;
    // Stray node_modules child of the host, shaped like a package home so
    // a skip regression would surface the decoy in the inventory.
    stage_npm_pkg(
        &store.join("node_modules/decoy/9.9.9/node_modules"),
        "decoy",
        "9.9.9",
    )
    .await;

    let crawler = NpmCrawler::new();
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        result.len(),
        2,
        "exactly mkdirp + directpkg, decoy stays out; got {purls:?}"
    );
    let by_purl = |purl: &str| {
        result
            .iter()
            .find(|p| p.purl == purl)
            .unwrap_or_else(|| panic!("{purl} must be inventoried; got {purls:?}"))
    };
    assert_eq!(
        by_purl("pkg:npm/mkdirp@0.5.5").path,
        store.join("mkdirp/0.5.5/node_modules/mkdirp")
    );
    assert_eq!(
        by_purl("pkg:npm/directpkg@3.0.0").path,
        store.join("directpkg/node_modules/directpkg"),
        "a depth-1 package home must be probed (undecodable entry name)"
    );
    assert!(
        !purls.contains(&"pkg:npm/decoy@9.9.9"),
        "a stray node_modules child of the store host must be skipped"
    );
}
