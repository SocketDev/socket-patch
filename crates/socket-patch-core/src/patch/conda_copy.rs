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
//! - the patch is for a pure-Python wheel (`…-none-any`), and the copy does
//!   not say it holds compiled code. A compiled conda package is never the
//!   PyPI wheel, whatever its Python files hash to;
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

/// What a copy conda built says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondaBuild {
    /// `Root-Is-Purelib` of the copy's `WHEEL` metadata: `Some(false)` for
    /// a build with compiled code. `None` when the copy has no `WHEEL` (an
    /// `.egg-info` install).
    pub purelib: Option<bool>,
}

/// The conda build behind the installed copy of `purl` in `site_packages`,
/// or `None` when the copy is not one: not a PyPI package, not in a conda
/// prefix, or installed by pip or uv (its `INSTALLER` names something
/// other than conda). Only that positive record takes a copy in a conda
/// prefix out of the rule. One with no `INSTALLER` (pip and uv always
/// write one), or whose metadata cannot be found or read at all, is taken
/// for conda's, with nothing known about its purity.
pub async fn conda_build(purl: &str, site_packages: &Path) -> Option<CondaBuild> {
    if Ecosystem::from_purl(purl) != Some(Ecosystem::Pypi) {
        return None;
    }
    conda_prefix_of(site_packages)?;
    let unknown = Some(CondaBuild { purelib: None });
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
    Some(CondaBuild { purelib })
}

/// Why the patch `purl` names is not applied to the copy in
/// `site_packages`, judged without the patch's files: the copy is a conda
/// build, and the patch is for a platform wheel, or the copy holds
/// compiled code, or nothing says the copy is pure Python. `None` when the
/// copy is not a conda build or nothing rules the patch out yet (see
/// [`refusal`] for the file check).
pub async fn static_refusal(purl: &str, site_packages: &Path) -> Option<String> {
    let build = conda_build(purl, site_packages).await?;
    let where_ = site_packages.display();
    let variant = artifact_id(purl);
    if let Some(variant) = variant.filter(|variant| !is_pure_python_wheel(variant)) {
        return Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_}, and this patch is for the \
             PyPI artifact `{variant}`: a compiled conda package is built separately from \
             the PyPI wheel, so the patch was not applied to it"
        ));
    }
    match build.purelib {
        Some(false) => Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_} with compiled code (its \
             WHEEL metadata says Root-Is-Purelib: false), which is not the pure-Python \
             PyPI release the patch was made for, so the patch was not applied to it"
        )),
        None if variant.is_none() => Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {where_}, and nothing says it is the \
             pure-Python PyPI release (the patch names no wheel and the copy has no WHEEL \
             metadata), so the patch was not applied to it"
        )),
        _ => None,
    }
}

/// [`static_refusal`], plus the one file rule that needs no hashing: a
/// patch that replaces no existing file gives nothing to compare a conda
/// build with. Whether each replaced file has the release's bytes is the
/// apply engine's own check, which for a conda build no policy relaxes
/// (see `patch::apply`).
pub async fn refusal(
    purl: &str,
    site_packages: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Option<String> {
    if let Some(refused) = static_refusal(purl, site_packages).await {
        return Some(refused);
    }
    conda_build(purl, site_packages).await?;
    if files.values().all(|file| file.before_hash.is_empty()) {
        return Some(format!(
            "{REFUSAL_CODE}: conda built the copy in {}, and the patch replaces no file \
             of it, so nothing shows the copy is the PyPI release; nothing was changed",
            site_packages.display()
        ));
    }
    None
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

/// Whether an `artifact_id` names a wheel with no compiled code: ABI
/// `none`, platform `any`.
fn is_pure_python_wheel(artifact_id: &str) -> bool {
    artifact_id.ends_with("-none-any-whl")
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

    fn replaces(file: &str) -> HashMap<String, PatchFileInfo> {
        HashMap::from([(
            file.to_string(),
            PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: "a".repeat(64),
            },
        )])
    }

    #[tokio::test]
    async fn a_pure_python_conda_build_takes_a_pure_python_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "certifi", "2026.7.22", Some("conda"), Some(true));
        assert_eq!(
            conda_build(PURE, &site).await,
            Some(CondaBuild {
                purelib: Some(true)
            })
        );
        assert_eq!(static_refusal(PURE, &site).await, None);
        assert_eq!(
            refusal(PURE, &site, &replaces("certifi/cacert.pem")).await,
            None
        );
    }

    /// A compiled conda package is never the PyPI wheel: refused for a
    /// platform wheel's patch, and for a pure wheel's patch when the copy
    /// itself says it holds compiled code.
    #[tokio::test]
    async fn a_compiled_conda_build_takes_no_pypi_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "pillow", "12.3.0", Some("conda"), Some(false));
        let platform = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
        let refused = static_refusal(platform, &site).await.expect("refused");
        assert!(
            refused.starts_with(REFUSAL_CODE) && refused.contains("cp313-cp313-manylinux"),
            "{refused}"
        );
        let pure = "pkg:pypi/pillow@12.3.0?artifact_id=py3-none-any-whl";
        let refused = static_refusal(pure, &site).await.expect("refused");
        assert!(refused.contains("Root-Is-Purelib: false"), "{refused}");
        // The names match however the purl or the directory spells them.
        let spelled = "pkg:pypi/Pillow@12.3.0?artifact_id=py3-none-any-whl";
        assert!(static_refusal(spelled, &site).await.is_some());
    }

    /// conda-forge's setuptools is an `.egg-info` install: no `INSTALLER`,
    /// no `WHEEL`. The patch's own wheel tag says it is pure Python. With
    /// neither, nothing does.
    #[tokio::test]
    async fn an_egg_info_conda_build_needs_the_patch_to_name_a_pure_wheel() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        let egg = site.join("setuptools-80.10.2-py3.10.egg-info");
        std::fs::create_dir_all(&egg).unwrap();
        std::fs::write(
            egg.join("PKG-INFO"),
            "Metadata-Version: 2.4\nName: setuptools\nVersion: 80.10.2\n",
        )
        .unwrap();
        let named = "pkg:pypi/setuptools@80.10.2?artifact_id=py3-none-any-whl";
        assert_eq!(
            conda_build(named, &site).await,
            Some(CondaBuild { purelib: None })
        );
        assert_eq!(static_refusal(named, &site).await, None);
        let bare = "pkg:pypi/setuptools@80.10.2";
        let refused = static_refusal(bare, &site).await.expect("refused");
        assert!(
            refused.contains("nothing says it is the pure-Python"),
            "{refused}"
        );
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
        let refused = refusal(PURE, &site, &added).await.expect("refused");
        assert!(refused.contains("replaces no file"), "{refused}");
    }

    /// pip and uv install the PyPI wheel itself into a conda prefix, a venv
    /// is not a conda prefix, and another ecosystem's package is not this
    /// rule's: each takes the usual rules, compiled or not.
    #[tokio::test]
    async fn copies_conda_did_not_build_are_not_judged() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(&tmp.path().join("env"));
        let platform = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
        for installer in ["pip", "uv", "uv-pixi"] {
            dist_info(&site, "pillow", "12.3.0", Some(installer), Some(false));
            assert_eq!(conda_build(platform, &site).await, None, "{installer}");
            assert_eq!(static_refusal(platform, &site).await, None, "{installer}");
        }

        let venv = tmp
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.13")
            .join("site-packages");
        std::fs::create_dir_all(&venv).unwrap();
        dist_info(&venv, "pillow", "12.3.0", None, Some(false));
        assert_eq!(static_refusal(platform, &venv).await, None);

        // Another ecosystem's package is not this rule's.
        assert_eq!(conda_build("pkg:gem/pillow@12.3.0", &site).await, None);
    }

    /// Only an `INSTALLER` naming pip or uv takes a copy in a conda prefix
    /// out of the rule. A copy whose metadata is not found there (another
    /// version's, or none) cannot show who installed it, so it is judged
    /// as a conda build of unknown purity: a platform wheel's patch is
    /// refused, a pure wheel's goes on to the file check.
    #[tokio::test]
    async fn a_copy_whose_metadata_is_not_found_is_judged_as_a_conda_build() {
        let tmp = tempfile::tempdir().unwrap();
        let site = conda_site(tmp.path());
        dist_info(&site, "pillow", "12.3.0", Some("pip"), Some(false));
        let unknown = Some(CondaBuild { purelib: None });
        let other_version =
            "pkg:pypi/pillow@12.2.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
        assert_eq!(conda_build(other_version, &site).await, unknown);
        assert!(static_refusal(other_version, &site).await.is_some());
        let absent = "pkg:pypi/numpy@2.4.4?artifact_id=py3-none-any-whl";
        assert_eq!(conda_build(absent, &site).await, unknown);
        assert_eq!(static_refusal(absent, &site).await, None);
        assert!(static_refusal("pkg:pypi/numpy@2.4.4", &site)
            .await
            .is_some());
    }

    #[test]
    fn the_artifact_id_names_the_wheel_the_patch_was_made_from() {
        assert_eq!(artifact_id(PURE), Some("py3-none-any-whl"));
        assert_eq!(
            artifact_id("pkg:pypi/a@1?x=y&artifact_id=py2-py3-none-any-whl#sub"),
            Some("py2-py3-none-any-whl")
        );
        assert_eq!(artifact_id("pkg:pypi/a@1"), None);
        assert_eq!(artifact_id("pkg:pypi/a@1?artifact_id="), None);
        assert!(is_pure_python_wheel("py3-none-any-whl"));
        assert!(is_pure_python_wheel("py2-py3-none-any-whl"));
        assert!(!is_pure_python_wheel(
            "cp313-cp313-manylinux_2_28_x86_64-whl"
        ));
        assert!(!is_pure_python_wheel("cp39-abi3-any-whl"));
        assert!(!is_pure_python_wheel("tar-gz"));
        assert_eq!(root_is_purelib("Root-Is-Purelib: true\n"), Some(true));
        assert_eq!(root_is_purelib("root-is-purelib:FALSE\n"), Some(false));
        assert_eq!(root_is_purelib("Tag: py3-none-any\n"), None);
    }
}
