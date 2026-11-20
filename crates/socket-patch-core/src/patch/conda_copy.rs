//! When a patch made from a PyPI release may be applied to a copy conda
//! built.
//!
//! A PyPI patch records, for each file it replaces, the hash that file has
//! in the PyPI release. conda packages repackage PyPI releases, and
//! conda-forge builds most pure-Python ones from the same sources, so
//! their files are usually the release's byte for byte. Usually is not
//! always. Compared file by file with the PyPI wheels, the 51 pure-Python
//! conda packages of one real project held 45 identical builds and 6 that
//! differ somewhere (a build-generated version file in three, a recipe
//! that patches one module in `setuptools`), and every compiled package
//! differed: its extension modules are built separately for conda and
//! link conda's own libraries, and `pillow` carried a patched Python
//! source as well.
//!
//! So a copy conda built is patched only when it is the PyPI release as
//! far as this machine can tell:
//!
//! - the patch is not for a platform wheel, and the copy holds no compiled
//!   code: its `WHEEL` metadata says so, or, for an install without one,
//!   no extension module is among its files. A compiled conda package is
//!   never the PyPI wheel, whatever its Python files hash to;
//! - every file the patch replaces has the release's bytes (or the bytes a
//!   Socket patch wrote), and the patch replaces at least one file, so
//!   something shows the copy is that release.
//!
//! No flag overrides this: `--force` and `--allow-patch-conflicts` consent
//! to overwriting local changes to the distribution a patch was made for,
//! not to writing one distribution's files into another.
//!
//! What is not compared: the files the patch leaves alone. Their hashes in
//! the PyPI release are not in a patch record, so a conda recipe that
//! changes another module of an otherwise identical build is not seen.
//!
//! A copy pip or uv installed into a conda prefix from PyPI is the PyPI
//! release and takes the usual rules; its `INSTALLER` says who put it
//! there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crawlers::pixi_env::conda_prefix_of;
use crate::crawlers::python_crawler::{
    canonicalize_pypi_name, read_egg_info_metadata, read_python_metadata,
};
use crate::crawlers::Ecosystem;
use crate::manifest::schema::PatchFileInfo;
use crate::utils::fs::{list_dir_entries, read_regular_to_string};
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};

/// The stable code every refusal starts with.
pub const REFUSAL_CODE: &str = "conda_build_not_pypi_release";

/// What a copy conda built shows about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondaBuild {
    /// Whether the copy holds compiled code. From its `WHEEL` metadata
    /// (`Root-Is-Purelib`) when it has one; for an install without one
    /// (`.egg-info`), from whether an extension module is among its
    /// files. `None` when the copy's metadata was not found, so nothing
    /// could be read.
    pub compiled: Option<bool>,
    /// What says so, for the refusal text.
    evidence: &'static str,
}

/// The conda build behind the installed copy of `purl` in `site_packages`,
/// or `None` when the copy is not one: not a PyPI package, not in a conda
/// prefix, or installed by pip or uv (its `INSTALLER` names something
/// other than conda). Only that positive record takes a copy in a conda
/// prefix out of the rule. One with no `INSTALLER` (pip and uv always
/// write one), or whose metadata cannot be found or read at all, is taken
/// for conda's.
pub async fn conda_build(purl: &str, site_packages: &Path) -> Option<CondaBuild> {
    if Ecosystem::from_purl(purl) != Some(Ecosystem::Pypi) {
        return None;
    }
    conda_prefix_of(site_packages)?;
    let unknown = Some(CondaBuild {
        compiled: None,
        evidence: "its metadata was not found",
    });
    let Some((name, version)) = parse_pypi_purl(strip_purl_qualifiers(purl)) else {
        return unknown;
    };
    let Some(metadata) = metadata_dir(site_packages, &name, &version).await else {
        return unknown;
    };
    let installer = read_regular_to_string(&metadata.join("INSTALLER"))
        .await
        .ok()
        .map(|text| text.trim().to_ascii_lowercase());
    if installer.as_deref().is_some_and(|by| by != "conda") {
        return None;
    }
    let purelib = read_regular_to_string(&metadata.join("WHEEL"))
        .await
        .ok()
        .and_then(|wheel| root_is_purelib(&wheel));
    Some(match purelib {
        Some(purelib) => CondaBuild {
            compiled: Some(!purelib),
            evidence: "its WHEEL metadata says Root-Is-Purelib: false",
        },
        None => CondaBuild {
            compiled: Some(holds_extension_modules(site_packages, &metadata, &name).await),
            evidence: "it holds extension modules",
        },
    })
}

/// [`static_refusal_for`] the copy of `purl` in `site_packages`; `None`
/// when that copy is not a conda build.
pub async fn static_refusal(purl: &str, site_packages: &Path) -> Option<String> {
    let build = conda_build(purl, site_packages).await?;
    static_refusal_for(&build, purl, site_packages)
}

/// Why the patch `purl` names is not applied to the conda build `build`
/// in `site_packages`, judged without the patch's files: the patch is for
/// a platform wheel, or the copy holds compiled code, or nothing shows
/// what the copy holds and the patch does not name a pure-Python wheel.
/// `None` when nothing rules the patch out yet (see [`refusal_for`] for
/// the file rule).
pub fn static_refusal_for(build: &CondaBuild, purl: &str, site_packages: &Path) -> Option<String> {
    let where_ = site_packages.display();
    let variant = Variant::of(purl);
    if let Variant::PlatformWheel(wheel) = variant {
        return Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_}, and this patch is for the \
             platform wheel `{wheel}`: a compiled conda package is built separately from \
             the PyPI wheel, so the patch was not applied to it"
        ));
    }
    match build.compiled {
        Some(true) => Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_} with compiled code ({}), \
             which is not the pure-Python PyPI release the patch was made for, so the \
             patch was not applied to it",
            build.evidence
        )),
        // A patch made from a pure-Python wheel says the release is pure
        // Python; a source distribution's, or a record that names no
        // artifact, does not, so the copy itself has to show it.
        None if variant != Variant::PureWheel => Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_}, and nothing shows it is the \
             pure-Python PyPI release ({}, and the patch names no pure-Python wheel), so \
             the patch was not applied to it",
            build.evidence
        )),
        _ => None,
    }
}

/// [`static_refusal_for`], plus the one file rule that needs no hashing: a
/// patch that replaces no existing file gives nothing to compare a conda
/// build with. Whether each replaced file has the release's bytes is the
/// apply engine's own check, which for a conda build no flag relaxes (see
/// `patch::apply`).
pub fn refusal_for(
    build: &CondaBuild,
    purl: &str,
    site_packages: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Option<String> {
    if let Some(refused) = static_refusal_for(build, purl, site_packages) {
        return Some(refused);
    }
    if files.values().all(|file| file.before_hash.is_empty()) {
        return Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {}, and the patch replaces no file \
             of it, so nothing shows the copy is the PyPI release; nothing was changed",
            site_packages.display()
        ));
    }
    None
}

/// The release artifact a patch purl says it was made from.
#[derive(Debug, PartialEq, Eq)]
enum Variant<'a> {
    /// A wheel with no compiled code: ABI `none`, platform `any`.
    PureWheel,
    /// Any other wheel.
    PlatformWheel(&'a str),
    /// A source distribution (`tar-gz`), or a record keyed by the bare
    /// purl: it does not say whether the release is pure Python.
    Other,
}

impl<'a> Variant<'a> {
    fn of(purl: &'a str) -> Self {
        match artifact_id(purl) {
            Some(id) if id.ends_with("-none-any-whl") => Variant::PureWheel,
            Some(id) if id.ends_with("-whl") => Variant::PlatformWheel(id),
            _ => Variant::Other,
        }
    }
}

/// The `artifact_id` qualifier of a patch purl: the release artifact the
/// patch was made from (`py3-none-any-whl`).
fn artifact_id(purl: &str) -> Option<&str> {
    let (_, query) = purl.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("artifact_id="))
        .filter(|id| !id.is_empty())
}

/// `Root-Is-Purelib` from `WHEEL` metadata text.
fn root_is_purelib(wheel: &str) -> Option<bool> {
    wheel.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("Root-Is-Purelib")
            .then(|| value.trim().eq_ignore_ascii_case("true"))
    })
}

/// Whether a distribution with no `WHEEL` metadata holds an extension
/// module: a shared library named after one of its top-level modules
/// (`_cffi_backend.cpython-313-darwin.so`), or anywhere in one of its
/// top-level packages. The top-level names are the metadata's
/// `top_level.txt`, else the distribution's own name.
async fn holds_extension_modules(site_packages: &Path, metadata: &Path, name: &str) -> bool {
    let listed = read_regular_to_string(&metadata.join("top_level.txt"))
        .await
        .unwrap_or_default();
    let mut tops: Vec<String> = listed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if tops.is_empty() {
        tops.push(canonicalize_pypi_name(name).replace('-', "_"));
    }
    for entry in list_dir_entries(site_packages).await {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        for top in &tops {
            let module_file = file_name
                .strip_prefix(top.as_str())
                .is_some_and(|rest| rest.starts_with('.') && is_shared_library(rest));
            if module_file
                || (*file_name == **top && dir_holds_shared_library(&site_packages.join(top)).await)
            {
                return true;
            }
        }
    }
    false
}

fn is_shared_library(file_name: &str) -> bool {
    [".so", ".pyd", ".dylib"]
        .iter()
        .any(|extension| file_name.ends_with(extension))
}

/// Whether a shared library is anywhere under `dir`. Symbolic links are
/// not followed. A tree too large to finish looking through counts as
/// holding one: the answer decides whether a patch is withheld.
async fn dir_holds_shared_library(dir: &Path) -> bool {
    const MOST_ENTRIES: usize = 50_000;
    let mut seen = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in list_dir_entries(&dir).await {
            seen += 1;
            if seen > MOST_ENTRIES {
                return true;
            }
            let Ok(kind) = entry.file_type().await else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && is_shared_library(&entry.file_name().to_string_lossy()) {
                return true;
            }
        }
    }
    false
}

/// The `.dist-info` or `.egg-info` directory of `name` at `version` in
/// `site_packages`.
async fn metadata_dir(site_packages: &Path, name: &str, version: &str) -> Option<PathBuf> {
    let wanted = canonicalize_pypi_name(name);
    for entry in list_dir_entries(site_packages).await {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let dist_info = file_name.ends_with(".dist-info");
        if !dist_info && !file_name.ends_with(".egg-info") {
            continue;
        }
        // The directory is named after the distribution: skip the others
        // without opening their metadata.
        if !canonicalize_pypi_name(&file_name).starts_with(&wanted) {
            continue;
        }
        let dir = site_packages.join(&*file_name);
        let found = if dist_info {
            read_python_metadata(&dir).await
        } else {
            read_egg_info_metadata(&dir).await
        };
        if found.is_some_and(|(found_name, found_version)| {
            canonicalize_pypi_name(&found_name) == wanted && found_version == version
        }) {
            return Some(dir);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PURE: &str = "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl";
    const PLATFORM: &str =
        "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";

    /// `<root>/lib/python3.13/site-packages` of a conda prefix at `root`.
    fn conda_site(root: &Path) -> PathBuf {
        std::fs::create_dir_all(root.join("conda-meta")).unwrap();
        let site = root.join("lib").join("python3.13").join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        site
    }

    /// A `.dist-info` for `name` at `version`, with the given `INSTALLER`
    /// and `WHEEL` purity (each left out when `None`).
    fn dist_info(
        site: &Path,
        name: &str,
        version: &str,
        installer: Option<&str>,
        purelib: Option<bool>,
    ) {
        let dir = site.join(format!("{name}-{version}.dist-info"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("METADATA"),
            format!("Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
        if let Some(installer) = installer {
            std::fs::write(dir.join("INSTALLER"), format!("{installer}\n")).unwrap();
        }
        if let Some(purelib) = purelib {
            std::fs::write(
                dir.join("WHEEL"),
                format!("Wheel-Version: 1.0\nRoot-Is-Purelib: {purelib}\nTag: x\n"),
            )
            .unwrap();
        }
    }

    /// An `.egg-info` install of `name` at `version` (no `INSTALLER`, no
    /// `WHEEL`), as conda-forge's setuptools is, with its top-level names.
    fn egg_info(site: &Path, name: &str, version: &str, top_level: &str) {
        let dir = site.join(format!("{name}-{version}-py3.13.egg-info"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("PKG-INFO"),
            format!("Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
        std::fs::write(dir.join("top_level.txt"), top_level).unwrap();
    }

    fn replaces(file: &str) -> HashMap<String, PatchFileInfo> {
        HashMap::from([(
            file.to_string(),
            PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: "a".repeat(64),
            },
        )])
    }

    async fn compiled(purl: &str, site: &Path) -> Option<Option<bool>> {
        conda_build(purl, site).await.map(|build| build.compiled)
    }

    #[tokio::test]
    async fn a_pure_python_conda_build_takes_a_pure_python_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "certifi", "2026.7.22", Some("conda"), Some(true));
        assert_eq!(compiled(PURE, &site).await, Some(Some(false)));
        assert_eq!(static_refusal(PURE, &site).await, None);
        let build = conda_build(PURE, &site).await.unwrap();
        assert_eq!(
            refusal_for(&build, PURE, &site, &replaces("certifi/cacert.pem")),
            None
        );
    }

    /// A manifest can hold the source distribution's record beside the
    /// wheel's, and one keyed by the bare purl: neither says the release is
    /// pure Python, so the copy's own metadata decides, and a pure-Python
    /// conda build takes them like the wheel's.
    #[tokio::test]
    async fn a_pure_python_conda_build_takes_an_sdist_or_unnamed_record() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "certifi", "2026.7.22", Some("conda"), Some(true));
        for purl in [
            "pkg:pypi/certifi@2026.7.22?artifact_id=tar-gz",
            "pkg:pypi/certifi@2026.7.22",
        ] {
            assert_eq!(static_refusal(purl, &site).await, None, "{purl}");
        }
    }

    /// A compiled conda package is never the PyPI wheel: refused for a
    /// platform wheel's patch, and for any other record when the copy
    /// itself says it holds compiled code.
    #[tokio::test]
    async fn a_compiled_conda_build_takes_no_pypi_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "pillow", "12.3.0", Some("conda"), Some(false));
        let refused = static_refusal(PLATFORM, &site).await.expect("refused");
        assert!(
            refused.starts_with(REFUSAL_CODE) && refused.contains("cp313-cp313-manylinux"),
            "{refused}"
        );
        for purl in [
            "pkg:pypi/pillow@12.3.0?artifact_id=py3-none-any-whl",
            "pkg:pypi/pillow@12.3.0?artifact_id=tar-gz",
            "pkg:pypi/pillow@12.3.0",
            // The names match however the purl or the directory spells them.
            "pkg:pypi/Pillow@12.3.0?artifact_id=py3-none-any-whl",
        ] {
            let refused = static_refusal(purl, &site).await.expect(purl);
            assert!(refused.contains("Root-Is-Purelib: false"), "{refused}");
        }
    }

    /// conda-forge's setuptools is an `.egg-info` install: no `INSTALLER`,
    /// no `WHEEL`. What it holds is read from its files: with no extension
    /// module among them it is pure Python and takes any record of the
    /// release; with one it is compiled and takes none.
    #[tokio::test]
    async fn an_egg_info_conda_build_is_judged_by_the_files_it_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        egg_info(
            &site,
            "setuptools",
            "80.10.2",
            "setuptools\npkg_resources\n",
        );
        std::fs::create_dir_all(site.join("setuptools").join("_vendor")).unwrap();
        std::fs::write(site.join("setuptools").join("wheel.py"), "").unwrap();
        // A Windows launcher is not an extension module.
        std::fs::write(site.join("setuptools").join("cli-64.exe"), "").unwrap();
        for purl in [
            "pkg:pypi/setuptools@80.10.2?artifact_id=py3-none-any-whl",
            "pkg:pypi/setuptools@80.10.2?artifact_id=tar-gz",
            "pkg:pypi/setuptools@80.10.2",
        ] {
            assert_eq!(compiled(purl, &site).await, Some(Some(false)), "{purl}");
            assert_eq!(static_refusal(purl, &site).await, None, "{purl}");
        }

        // An extension module in a package, or as a top-level module.
        egg_info(&site, "pysam", "0.24.0", "pysam\n");
        std::fs::create_dir_all(site.join("pysam")).unwrap();
        std::fs::write(
            site.join("pysam").join("libchtslib.cpython-313-darwin.so"),
            "",
        )
        .unwrap();
        egg_info(&site, "cffi", "2.0.0", "_cffi_backend\ncffi\n");
        std::fs::write(site.join("_cffi_backend.cpython-313-darwin.so"), "").unwrap();
        for purl in [
            "pkg:pypi/pysam@0.24.0?artifact_id=py3-none-any-whl",
            "pkg:pypi/cffi@2.0.0?artifact_id=tar-gz",
        ] {
            assert_eq!(compiled(purl, &site).await, Some(Some(true)), "{purl}");
            let refused = static_refusal(purl, &site).await.expect(purl);
            assert!(refused.contains("it holds extension modules"), "{refused}");
        }
    }

    /// A patch that only adds files gives nothing to compare the conda
    /// build with.
    #[tokio::test]
    async fn a_patch_that_replaces_no_file_is_not_applied_to_a_conda_build() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "certifi", "2026.7.22", Some("conda"), Some(true));
        let added = HashMap::from([(
            "certifi/new.py".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "a".repeat(64),
            },
        )]);
        let build = conda_build(PURE, &site).await.unwrap();
        let refused = refusal_for(&build, PURE, &site, &added).expect("refused");
        assert!(refused.contains("replaces no file"), "{refused}");
    }

    /// pip and uv install the PyPI wheel itself into a conda prefix, a venv
    /// is not a conda prefix, and another ecosystem's package is not this
    /// rule's: each takes the usual rules, compiled or not.
    #[tokio::test]
    async fn copies_conda_did_not_build_are_not_judged() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(&tmp.path().join("env"));
        for installer in ["pip", "uv", "uv-pixi"] {
            dist_info(&site, "pillow", "12.3.0", Some(installer), Some(false));
            assert_eq!(conda_build(PLATFORM, &site).await, None, "{installer}");
            assert_eq!(static_refusal(PLATFORM, &site).await, None, "{installer}");
        }

        let venv = tmp
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.13")
            .join("site-packages");
        std::fs::create_dir_all(&venv).unwrap();
        dist_info(&venv, "pillow", "12.3.0", None, Some(false));
        assert_eq!(static_refusal(PLATFORM, &venv).await, None);

        // Another ecosystem's package is not this rule's.
        assert_eq!(conda_build("pkg:gem/pillow@12.3.0", &site).await, None);
    }

    /// Only an `INSTALLER` naming pip or uv takes a copy in a conda prefix
    /// out of the rule. A copy whose metadata is not found there (another
    /// version's, or none) cannot show who installed it or what it holds:
    /// it is judged as a conda build, and takes only a patch that names a
    /// pure-Python wheel, which then goes on to the file check.
    #[tokio::test]
    async fn a_copy_whose_metadata_is_not_found_is_judged_as_a_conda_build() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "pillow", "12.3.0", Some("pip"), Some(false));
        let other_version =
            "pkg:pypi/pillow@12.2.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
        assert_eq!(compiled(other_version, &site).await, Some(None));
        assert!(static_refusal(other_version, &site).await.is_some());
        let absent = "pkg:pypi/numpy@2.4.4?artifact_id=py3-none-any-whl";
        assert_eq!(compiled(absent, &site).await, Some(None));
        assert_eq!(static_refusal(absent, &site).await, None);
        for purl in [
            "pkg:pypi/numpy@2.4.4",
            "pkg:pypi/numpy@2.4.4?artifact_id=tar-gz",
        ] {
            let refused = static_refusal(purl, &site).await.expect(purl);
            assert!(refused.contains("its metadata was not found"), "{refused}");
        }
    }

    #[test]
    fn the_artifact_id_names_the_artifact_the_patch_was_made_from() {
        assert_eq!(artifact_id(PURE), Some("py3-none-any-whl"));
        assert_eq!(
            artifact_id("pkg:pypi/a@1?x=y&artifact_id=py2-py3-none-any-whl#sub"),
            Some("py2-py3-none-any-whl")
        );
        assert_eq!(artifact_id("pkg:pypi/a@1"), None);
        assert_eq!(artifact_id("pkg:pypi/a@1?artifact_id="), None);
        assert_eq!(Variant::of(PURE), Variant::PureWheel);
        assert_eq!(
            Variant::of("pkg:pypi/a@1?artifact_id=py2-py3-none-any-whl"),
            Variant::PureWheel
        );
        assert_eq!(
            Variant::of(PLATFORM),
            Variant::PlatformWheel("cp313-cp313-manylinux_2_28_x86_64-whl")
        );
        assert_eq!(
            Variant::of("pkg:pypi/a@1?artifact_id=cp39-abi3-any-whl"),
            Variant::PlatformWheel("cp39-abi3-any-whl")
        );
        assert_eq!(
            Variant::of("pkg:pypi/a@1?artifact_id=tar-gz"),
            Variant::Other
        );
        assert_eq!(Variant::of("pkg:pypi/a@1"), Variant::Other);
        assert_eq!(root_is_purelib("Root-Is-Purelib: true\n"), Some(true));
        assert_eq!(root_is_purelib("root-is-purelib:FALSE\n"), Some(false));
        assert_eq!(root_is_purelib("Tag: py3-none-any\n"), None);
    }
}
