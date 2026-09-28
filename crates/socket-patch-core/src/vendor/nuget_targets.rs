//! The generated MSBuild side of the NuGet fallback layout
//! ([`super::nuget_fallback`]): `socket-patch.targets`, the `.gitattributes`
//! / `.gitignore` of `.socket/vendor/nuget/`, and the `Directory.Build.props`
//! block that imports the targets.
//!
//! Everything here is a pure render of the fallback seeds' markers, sorted
//! by uuid, with LF line endings — the same seeds always render the same
//! bytes. The template was validated against real `dotnet` (SDK 8):
//!
//! * the targets are imported through `CustomAfterDirectoryBuildTargets`,
//!   i.e. after the whole `Directory.Build.targets` chain, so the
//!   `PackageReference` / `PackageVersion` `Update`s see every item the
//!   project declares;
//! * `SocketPatchNuGetSeedCheck` runs before `CollectPackageReferences` (the
//!   hook that fires in every restore mode, static graph included) and fails
//!   `SOCKETPATCH001` (missing / unexpected seed files) or `SOCKETPATCH002`
//!   (a seed file whose sha256 changed);
//! * `SocketPatchNuGetGuard` runs after `ResolvePackageAssets` and fails
//!   `SOCKETPATCH005` when any asset still resolves from the UNPATCHED
//!   upstream version; `SocketPatchNuGetGuard` is assigned unconditionally,
//!   so only a global `-p:SocketPatchNuGetGuard=false` disables it.
//!
//! No generated comment may contain `--` (an XML comment cannot, and a
//! `Directory.Build.props` that fails to load is SILENTLY ignored by
//! restore).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::nuget_feed::is_plain_nuget_token;

/// The generated targets file, relative to `.socket/vendor/nuget/`.
pub(crate) const TARGETS_FILE: &str = "socket-patch.targets";
pub(crate) const GITATTRIBUTES_FILE: &str = ".gitattributes";
pub(crate) const GITIGNORE_FILE: &str = ".gitignore";

/// The first line of the `Directory.Build.props` block.
pub(crate) const DBP_BEGIN: &str = "<!-- socket-patch:begin";
/// The last line of the `Directory.Build.props` block.
pub(crate) const DBP_END: &str = "<!-- socket-patch:end -->";

/// The begin-line tag of a block in a `Directory.Build.props` socket-patch
/// CREATED: only such a file is deleted once its block is excised.
const DBP_CREATED_TAG: &str = "<!-- socket-patch:begin created";

/// A `Directory.Build.props` socket-patch created: the block and nothing else.
/// Once the block is excised it reads [`CREATED_DBP_EMPTY`].
pub(crate) const CREATED_DBP_EMPTY: &str = "<Project>\n</Project>\n";

/// Blank XML comments (keeping byte offsets) so commented-out elements are
/// never read.
pub(crate) fn blank_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find("-->").map_or(tail.len(), |e| e + 3);
        out.extend(
            tail[..end]
                .chars()
                .map(|c| if c == '\n' { '\n' } else { ' ' }),
        );
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// A token rendered into MSBuild (and into a generated comment): a plain
/// NuGet token that is a safe path segment and holds no `--`.
fn is_renderable_token(s: &str) -> bool {
    is_plain_nuget_token(s)
        && crate::patch::path_safety::is_safe_single_segment(s)
        && !s.contains("--")
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

/// The fallback-seed section of a uuid dir's `socket-patch.vendor.json`:
/// everything the shared render needs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NugetSeedMarker {
    /// Package id, as the patch names it.
    pub(crate) id: String,
    /// Normalized upstream version V.
    pub(crate) version: String,
    /// The Socket version V′.
    pub(crate) socket_version: String,
    /// The seed's contentHash (also in its `.nupkg.metadata`).
    pub(crate) content_hash: String,
    /// Extra literal spellings of V found in the project files (V and
    /// `V.0` are always matched).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) spellings: Vec<String>,
    /// The seed files relative to `<idlower>/<V′>/` → sha256 hex, recorded at
    /// vendor time (the render never re-baselines from disk).
    pub(crate) inventory: BTreeMap<String, String>,
    /// False after a `--preserve-state` revert: the seed stays on disk but is
    /// no longer rendered.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub(crate) wired: bool,
}

impl NugetSeedMarker {
    /// Everything rendered into MSBuild is a plain NuGet token or a
    /// validated seed path; anything else never renders.
    pub(crate) fn is_renderable(&self) -> bool {
        is_renderable_token(&self.id)
            && is_renderable_token(&self.version)
            && is_renderable_token(&self.socket_version)
            && self.spellings.iter().all(|s| is_renderable_token(s))
            && !self.inventory.is_empty()
            && self.inventory.keys().all(|k| {
                crate::patch::apply::is_safe_relative_subpath(k)
                    && super::common::is_plain_archive_name(k)
            })
            && self
                .inventory
                .values()
                .all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// The seed dir relative to the uuid dir.
    pub(crate) fn seed_rel(&self) -> String {
        format!("{}/{}", self.id.to_ascii_lowercase(), self.socket_version)
    }

    /// Every literal version spelling the `Update`s match, sorted.
    pub(crate) fn all_spellings(&self) -> Vec<String> {
        let mut out = vec![self.version.clone(), format!("{}.0", self.version)];
        out.extend(self.spellings.iter().cloned());
        out.sort();
        out.dedup();
        out
    }
}

/// MSBuild-escape (`% $ @ ; ' * ?` → `%XX`) and then XML-escape `s`.
pub(crate) fn msbuild_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' | '$' | '@' | ';' | '\'' | '*' | '?' => out.push_str(&format!("%{:02X}", c as u32)),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Render `socket-patch.targets` for `seeds` (`(uuid, marker)`, any order).
pub(crate) fn render_targets(seeds: &[(String, NugetSeedMarker)]) -> String {
    let mut seeds: Vec<&(String, NugetSeedMarker)> = seeds.iter().collect();
    seeds.sort_by(|a, b| a.0.cmp(&b.0));
    let q = msbuild_text;
    let mut l: Vec<String> = vec![
        "<Project>".into(),
        "  <!-- Generated by socket-patch from .socket/vendor/nuget/*/socket-patch.vendor.json. \
         Do not edit. -->"
            .into(),
        "  <PropertyGroup>".into(),
        "    <SocketPatchNuGetTargetsImported>true</SocketPatchNuGetTargetsImported>".into(),
        "    <SocketPatchNuGetGuard>true</SocketPatchNuGetGuard>".into(),
        "    <SocketPatchNuGetDir>$([MSBuild]::NormalizeDirectory('$(MSBuildThisFileDirectory)'))\
         </SocketPatchNuGetDir>"
            .into(),
    ];
    let folders: String = seeds
        .iter()
        .map(|(u, _)| format!(";$(SocketPatchNuGetDir){}", q(u)))
        .collect();
    l.push(format!(
        "    <RestoreAdditionalProjectFallbackFolders>$(RestoreAdditionalProjectFallbackFolders)\
         {folders}</RestoreAdditionalProjectFallbackFolders>"
    ));
    l.push("  </PropertyGroup>".into());
    for (u, m) in &seeds {
        let (id, vp) = (q(&m.id), q(&m.socket_version));
        l.push(String::new());
        l.push(format!(
            "  <!-- {}: {id} {} -> {vp} -->",
            q(u),
            q(&m.version)
        ));
        let cond = |item: &str| {
            m.all_spellings()
                .iter()
                .map(|s| {
                    format!(
                        "'@({item}->WithMetadataValue('Identity','{id}')->WithMetadataValue(\
                         'Version','{}'))' != ''",
                        q(s)
                    )
                })
                .collect::<Vec<_>>()
                .join(" or ")
        };
        l.push(format!(
            "  <ItemGroup Condition=\"{}\">",
            cond("PackageReference")
        ));
        l.push(format!(
            "    <PackageReference Update=\"{id}\" Version=\"[{vp}, )\" />"
        ));
        l.push("  </ItemGroup>".into());
        l.push(format!(
            "  <ItemGroup Condition=\"'$(ManagePackageVersionsCentrally)' == 'true' and ({})\">",
            cond("PackageVersion")
        ));
        l.push(format!(
            "    <PackageVersion Update=\"{id}\" Version=\"[{vp}, )\" />"
        ));
        l.push("  </ItemGroup>".into());
    }
    l.push(String::new());
    l.push("  <ItemGroup>".into());
    for (u, m) in &seeds {
        let seed = m.seed_rel();
        for (rel, sha) in &m.inventory {
            l.push(format!(
                "    <SocketPatchSeedFile Include=\"$(SocketPatchNuGetDir){}/{}/{}\" Sha256=\"{}\" />",
                q(u),
                q(&seed),
                q(rel),
                sha.to_ascii_uppercase()
            ));
        }
    }
    l.push("  </ItemGroup>".into());
    l.push(String::new());
    let include = seeds
        .iter()
        .map(|(u, _)| format!("$(SocketPatchNuGetDir){}/**", q(u)))
        .collect::<Vec<_>>()
        .join(";");
    let exclude = seeds
        .iter()
        .map(|(u, _)| {
            format!(
                "$(SocketPatchNuGetDir){}/{}",
                q(u),
                super::state::VENDOR_MARKER_FILE
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    l.push(
        "  <Target Name=\"SocketPatchNuGetSeedCheck\" \
         BeforeTargets=\"_GenerateRestoreGraph;CollectPackageReferences\" \
         Condition=\"'$(SocketPatchNuGetGuard)' != 'false' and '$(_SpSeedChecked)' != 'true'\">"
            .into(),
    );
    l.push("    <ItemGroup>".into());
    l.push(format!(
        "      <_SpOnDisk Include=\"{include}\" Exclude=\"{exclude}\" />"
    ));
    l.push("      <_SpExtra Include=\"@(_SpOnDisk)\" Exclude=\"@(SocketPatchSeedFile)\" />".into());
    l.push(
        "      <_SpMissing Include=\"@(SocketPatchSeedFile)\" Condition=\"!Exists('%(FullPath)')\" />"
            .into(),
    );
    l.push("    </ItemGroup>".into());
    l.push(
        "    <Error Condition=\"'@(_SpMissing)@(_SpExtra)' != ''\" Code=\"SOCKETPATCH001\" \
         Text=\"socket-patch: vendored NuGet seed does not match its inventory (missing: \
         @(_SpMissing); unexpected: @(_SpExtra)). Run 'git checkout -- .socket/vendor/nuget' or \
         'socket-patch vendor'.\" />"
            .into(),
    );
    l.push("    <GetFileHash Files=\"@(SocketPatchSeedFile)\" Algorithm=\"SHA256\">".into());
    l.push("      <Output TaskParameter=\"Items\" ItemName=\"_SpSeedHashed\" />".into());
    l.push("    </GetFileHash>".into());
    l.push(
        "    <Error Condition=\"'%(_SpSeedHashed.FileHash)' != '%(_SpSeedHashed.Sha256)'\" \
         Code=\"SOCKETPATCH002\" Text=\"socket-patch: vendored NuGet seed file modified: \
         %(_SpSeedHashed.Identity).\" />"
            .into(),
    );
    l.push("    <PropertyGroup>".into());
    l.push("      <_SpSeedChecked>true</_SpSeedChecked>".into());
    l.push("    </PropertyGroup>".into());
    l.push("  </Target>".into());
    l.push(String::new());
    l.push(
        "  <Target Name=\"SocketPatchNuGetGuard\" AfterTargets=\"ResolvePackageAssets\" \
         Condition=\"'$(SocketPatchNuGetGuard)' != 'false' and '$(DesignTimeBuild)' != 'true'\">"
            .into(),
    );
    l.push("    <ItemGroup>".into());
    l.push(
        "      <_SpCand Include=\"@(RuntimeCopyLocalItems);@(ResolvedCompileFileDefinitions);\
         @(RuntimeTargetsCopyLocalItems);@(NativeCopyLocalItems);@(ResourceCopyLocalItems);\
         @(Analyzer)\" />"
            .into(),
    );
    for (_, m) in &seeds {
        l.push(format!(
            "      <_SpUnpatched Include=\"@(_SpCand)\" Condition=\"'%(_SpCand.NuGetPackageId)' \
             == '{}' and '%(_SpCand.NuGetPackageVersion)' == '{}'\" />",
            q(&m.id),
            q(&m.version)
        ));
    }
    l.push("    </ItemGroup>".into());
    l.push(
        "    <Error Condition=\"'@(_SpUnpatched)' != ''\" Code=\"SOCKETPATCH005\" \
         Text=\"socket-patch: $(MSBuildProjectName) resolved UNPATCHED \
         %(_SpUnpatched.NuGetPackageId) %(_SpUnpatched.NuGetPackageVersion), which is \
         vendored-patched in this repo. Run 'socket-patch vendor'.\" />"
            .into(),
    );
    l.push("  </Target>".into());
    l.push("</Project>".into());
    let mut out = l.join("\n");
    out.push('\n');
    out
}

/// `.socket/vendor/nuget/.gitattributes`: the seeds are opaque bytes (no EOL
/// conversion, no filters such as LFS), the generated text files diffable.
/// The seed markers are diffable too: they carry the hashes the targets are
/// rendered from, so a change to one shows in review.
pub(crate) fn render_gitattributes() -> String {
    "* -text -diff -merge -filter\n/socket-patch.targets -text diff\n/.gitignore -text diff\n\
     /.gitattributes -text diff\n/*/socket-patch.vendor.json -text diff\n"
        .to_string()
}

/// `.socket/vendor/nuget/.gitignore`: negations so a root ignore rule
/// (`*.dll`, `bin/`, …) can never drop a seed file from the commit.
pub(crate) fn render_gitignore(uuids: &[String]) -> String {
    let mut uuids: Vec<&String> = uuids.iter().collect();
    uuids.sort();
    let mut out = String::new();
    for u in uuids {
        out.push_str(&format!("!/{u}/\n!/{u}/**\n"));
    }
    out.push_str("!/socket-patch.targets\n!/.gitattributes\n!/.gitignore\n");
    out
}

/// The block lines for a `Directory.Build.props` `rel` levels below the
/// root (`rel` is `""` or `../` repeated, always with its trailing slash).
/// `created` tags the block of a props file socket-patch created.
///
/// `SocketPatchNuGetImportCheck` is the restore-time fail-closed for a
/// checkout without `.socket/vendor/nuget` (restore ignores the missing
/// import): the vendored folder itself is deliberately NOT a fallback
/// folder, so nothing planted beside the uuid dirs can ever be restored.
fn dbp_block(rel: &str, eol: &str, created: bool) -> String {
    let begin = if created { DBP_CREATED_TAG } else { DBP_BEGIN };
    [
        format!("  {begin} (generated; remove with: socket-patch vendor revert) -->"),
        "  <PropertyGroup Label=\"socket-patch\">".to_string(),
        format!(
            "    <CustomAfterDirectoryBuildTargets Condition=\"!$(CustomAfterDirectoryBuildTargets.\
             Contains('socket-patch.targets'))\">$(CustomAfterDirectoryBuildTargets);\
             $(MSBuildThisFileDirectory){rel}.socket/vendor/nuget/socket-patch.targets\
             </CustomAfterDirectoryBuildTargets>"
        ),
        "  </PropertyGroup>".to_string(),
        "  <Target Name=\"SocketPatchNuGetImportCheck\" \
         BeforeTargets=\"_GenerateRestoreGraph;CollectPackageReferences\" \
         Condition=\"'$(SocketPatchNuGetTargetsImported)' != 'true' and \
         '$(SocketPatchNuGetGuard)' != 'false'\">"
            .to_string(),
        "    <Error Code=\"SOCKETPATCH007\" Text=\"socket-patch: \
         .socket/vendor/nuget/socket-patch.targets was not imported, so the vendored NuGet \
         patches of this repo are missing from this checkout. Check out .socket/vendor/nuget \
         (git sparse-checkout add .socket/vendor/nuget) or run 'socket-patch vendor'.\" />"
            .to_string(),
        "  </Target>".to_string(),
        format!("  {DBP_END}"),
    ]
    .iter()
    .map(|line| format!("{line}{eol}"))
    .collect()
}

/// The `Directory.Build.props` socket-patch creates at `rel` (for a project
/// with no props file): the tagged block in an otherwise empty `<Project>`.
pub(crate) fn created_dbp(rel: &str) -> String {
    format!("<Project>\n{}</Project>\n", dbp_block(rel, "\n", true))
}

/// `text` with every socket-patch block removed (each from the start of its
/// begin line through the end of its end line), or `None` when it has none.
#[cfg(test)]
pub(crate) fn excise_dbp_block(text: &str) -> Option<String> {
    excise_dbp_blocks(text).map(|(out, _)| out)
}

/// [`excise_dbp_block`], plus whether any excised block was tagged as
/// socket-patch having created the file.
fn excise_dbp_blocks(text: &str) -> Option<(String, bool)> {
    let mut out = text.to_string();
    let mut found = false;
    let mut created = false;
    while let Some(begin) = out.find(DBP_BEGIN) {
        let line_start = out[..begin].rfind('\n').map_or(0, |i| i + 1);
        let Some(end_rel) = out[begin..].find(DBP_END) else {
            break;
        };
        created |= out[begin..].starts_with(DBP_CREATED_TAG);
        let mut line_end = begin + end_rel + DBP_END.len();
        if out[line_end..].starts_with("\r\n") {
            line_end += 2;
        } else if out[line_end..].starts_with('\n') {
            line_end += 1;
        }
        out.replace_range(line_start..line_end, "");
        found = true;
    }
    found.then_some((out, created))
}

/// What the last revert leaves of a props file: `None` to delete it (a
/// file socket-patch created, nothing but the block added since, in any EOL
/// style), else its text with the block excised. `text` without a block is
/// `Some(text)`.
pub(crate) fn unwire_dbp(text: &str) -> Option<String> {
    let Some((excised, created)) = excise_dbp_blocks(text) else {
        return Some(text.to_string());
    };
    let bare = excised.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    (!(created && bare == CREATED_DBP_EMPTY)).then_some(excised)
}

/// `text` with the block for `rel` in place of any existing one, inserted
/// before the closing `</Project>` (a self-closing `<Project/>` is expanded).
/// The file's EOL style and BOM are kept, and so is a `created` tag of the
/// block it replaces. `Err` when `text` has no project element to insert
/// into (outside comments).
pub(crate) fn inject_dbp_block(text: &str, rel: &str) -> Result<String, String> {
    let (base, was_created) = excise_dbp_blocks(text).unwrap_or_else(|| (text.to_string(), false));
    inject_block(&base, rel, was_created)
}

fn inject_block(base: &str, rel: &str, created: bool) -> Result<String, String> {
    let eol = if base.contains("\r\n") { "\r\n" } else { "\n" };
    let block = dbp_block(rel, eol, created);
    let visible = blank_comments(base);
    if let Some(close) = visible.rfind("</Project>") {
        let line_start = base[..close].rfind('\n').map_or(0, |i| i + 1);
        let mut out = base.to_string();
        if base[line_start..close].trim().is_empty() {
            out.insert_str(line_start, &block);
        } else {
            out.insert_str(close, &format!("{eol}{block}"));
        }
        return Ok(out);
    }
    // Self-closing root: `<Project ... />`.
    let mut search = 0;
    while let Some(rel_at) = visible[search..].find("<Project") {
        let start = search + rel_at;
        let after = &visible[start + "<Project".len()..];
        if after.starts_with(|c: char| c.is_whitespace() || c == '/' || c == '>') {
            let Some(gt) = after.find('>') else { break };
            let tag_end = start + "<Project".len() + gt;
            let head = base[..tag_end].trim_end_matches('/').trim_end();
            if base[..tag_end].ends_with('/') {
                let mut out = String::new();
                out.push_str(head);
                out.push('>');
                out.push_str(eol);
                out.push_str(&block);
                out.push_str("</Project>");
                out.push_str(&base[tag_end + 1..]);
                return Ok(out);
            }
            break;
        }
        search = start + 1;
    }
    Err("no <Project> element to insert the socket-patch block into".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/nuget-fallback");
    const UUID: &str = "3f9a01bc-1111-4222-8333-444455556666";

    fn read(rel: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{rel}")).unwrap()
    }

    /// The marker behind the validated targets: its seed rows, parsed back.
    fn fixture_marker(golden: &str) -> NugetSeedMarker {
        let prefix = format!(
            "<SocketPatchSeedFile Include=\"$(SocketPatchNuGetDir){UUID}/newtonsoft.json/\
             13.0.1.1340506223/"
        );
        let mut inventory = BTreeMap::new();
        for line in golden.lines() {
            let Some(rest) = line.trim().strip_prefix(&prefix) else {
                continue;
            };
            let (rel, tail) = rest.split_once("\" Sha256=\"").unwrap();
            let sha = tail.trim_end_matches("\" />");
            inventory.insert(rel.to_string(), sha.to_ascii_lowercase());
        }
        assert_eq!(inventory.len(), 19);
        NugetSeedMarker {
            id: "Newtonsoft.Json".into(),
            version: "13.0.1".into(),
            socket_version: "13.0.1.1340506223".into(),
            content_hash: "x".into(),
            spellings: Vec::new(),
            inventory,
            wired: true,
        }
    }

    #[test]
    fn targets_render_matches_the_dotnet_validated_golden() {
        let golden = read("sln/socket-patch.targets");
        let marker = fixture_marker(&golden);
        assert!(marker.is_renderable());
        assert_eq!(render_targets(&[(UUID.to_string(), marker)]), golden);
    }

    #[test]
    fn targets_render_is_sorted_and_deterministic_for_two_seeds() {
        let golden = read("sln/socket-patch.targets");
        let a = fixture_marker(&golden);
        let mut b = a.clone();
        b.id = "Humanizer.Core".into();
        b.version = "2.14.1".into();
        b.socket_version = "2.14.1.1073741824".into();
        b.spellings = vec!["2.14.01".into()];
        let ua = UUID.to_string();
        let ub = "00000000-1111-4222-8333-444455556666".to_string();
        let one = render_targets(&[(ua.clone(), a.clone()), (ub.clone(), b.clone())]);
        let two = render_targets(&[(ub.clone(), b), (ua.clone(), a)]);
        assert_eq!(one, two);
        assert!(one.find(&ub).unwrap() < one.find(&ua).unwrap());
        assert!(one.contains(&format!(
            "$(SocketPatchNuGetDir){ub};$(SocketPatchNuGetDir){ua}</Restore"
        )));
        assert!(one.contains("WithMetadataValue('Version','2.14.01')"));
        assert!(one.contains("'%(_SpCand.NuGetPackageVersion)' == '2.14.1'"));
        for line in one.lines().filter(|l| l.contains("<!--")) {
            assert!(!line.replace("<!--", "").replace("-->", "").contains("--"));
        }
    }

    #[test]
    fn unrenderable_markers_are_detected() {
        let golden = read("sln/socket-patch.targets");
        let mut m = fixture_marker(&golden);
        m.id = "Evil\"$(x)".into();
        assert!(!m.is_renderable());
        let mut m = fixture_marker(&golden);
        m.inventory.insert("../x".into(), "0".repeat(64));
        assert!(!m.is_renderable());
        let mut m = fixture_marker(&golden);
        m.inventory.insert("x".into(), "zz".into());
        assert!(!m.is_renderable());
        for bad in ["..", ".", "A--B"] {
            let mut m = fixture_marker(&golden);
            m.id = bad.into();
            assert!(!m.is_renderable(), "{bad}");
        }
    }

    #[test]
    fn escaping() {
        assert_eq!(msbuild_text("a%$@;'*?b"), "a%25%24%40%3B%27%2A%3Fb");
        assert_eq!(msbuild_text("<&\">"), "&lt;&amp;&quot;&gt;");
    }

    #[test]
    fn shared_files_match_the_validated_templates() {
        assert_eq!(
            render_gitattributes(),
            "* -text -diff -merge -filter\n/socket-patch.targets -text diff\n/.gitignore -text \
             diff\n/.gitattributes -text diff\n/*/socket-patch.vendor.json -text diff\n"
        );
        assert_eq!(
            render_gitignore(&[UUID.to_string()]),
            format!(
                "!/{UUID}/\n!/{UUID}/**\n!/socket-patch.targets\n!/.gitattributes\n!/.gitignore\n"
            )
        );
    }

    #[test]
    fn created_dbp_matches_the_validated_fixture_and_excises_to_empty() {
        let fixture = read("sln/after/Directory.Build.props");
        assert_eq!(created_dbp(""), fixture);
        assert_eq!(excise_dbp_block(&fixture).unwrap(), CREATED_DBP_EMPTY);
        assert!(created_dbp("../")
            .contains("$(MSBuildThisFileDirectory)../.socket/vendor/nuget/socket-patch.targets<"));
        // The vendored folder itself is never a fallback folder.
        assert!(!fixture.contains("RestoreAdditionalProjectFallbackFolders"));
        // Re-rendering keeps the created tag; a CRLF checkout still deletes.
        assert_eq!(inject_dbp_block(&fixture, "").unwrap(), fixture);
        assert_eq!(unwire_dbp(&fixture), None);
        assert_eq!(unwire_dbp(&fixture.replace('\n', "\r\n")), None);
        assert_eq!(unwire_dbp(&format!("\u{feff}{fixture}")), None);
    }

    #[test]
    fn a_users_own_empty_dbp_is_never_deleted() {
        for user in [CREATED_DBP_EMPTY, "<Project>\r\n</Project>\r\n"] {
            let wired = inject_dbp_block(user, "").unwrap();
            assert!(!wired.contains(DBP_CREATED_TAG));
            assert_eq!(unwire_dbp(&wired).as_deref(), Some(user));
        }
        // A created file the user added to since is kept, minus the block.
        let edited = created_dbp("").replace("<Project>\n", "<Project>\n  <X/>\n");
        assert_eq!(
            unwire_dbp(&edited).as_deref(),
            Some("<Project>\n  <X/>\n</Project>\n")
        );
        assert_eq!(unwire_dbp("<Project/>").as_deref(), Some("<Project/>"));
    }

    #[test]
    fn a_close_tag_inside_a_comment_is_not_the_insertion_point() {
        let text = "<Project>\n  <X/>\n</Project>\n<!-- old: </Project> -->\n";
        let wired = inject_dbp_block(text, "").unwrap();
        let block_at = wired.find(DBP_BEGIN).unwrap();
        assert!(block_at < wired.find("</Project>\n<!--").unwrap());
        assert_eq!(excise_dbp_block(&wired).unwrap(), text);
        let self_closing = "<!-- <Project> </Project> -->\n<Project />\n";
        let wired = inject_dbp_block(self_closing, "").unwrap();
        assert!(wired.starts_with("<!-- <Project> </Project> -->\n<Project>"));
    }

    #[test]
    fn dbp_inject_keeps_eol_and_bom_and_round_trips() {
        let lf = "<Project>\n  <PropertyGroup>\n    <X>1</X>\n  </PropertyGroup>\n</Project>\n";
        for original in [
            lf.to_string(),
            lf.replace('\n', "\r\n"),
            format!("\u{feff}{}", lf.replace('\n', "\r\n")),
            lf.trim_end().to_string(),
        ] {
            let wired = inject_dbp_block(&original, "").unwrap();
            assert!(wired.contains(DBP_BEGIN));
            if original.contains("\r\n") {
                assert_eq!(
                    wired.matches('\n').count(),
                    wired.matches("\r\n").count(),
                    "CRLF kept"
                );
            }
            assert_eq!(
                wired.starts_with('\u{feff}'),
                original.starts_with('\u{feff}')
            );
            // Re-injecting is a no-op; excising restores the original bytes.
            assert_eq!(inject_dbp_block(&wired, "").unwrap(), wired);
            assert_eq!(excise_dbp_block(&wired).unwrap(), original);
        }
        assert!(excise_dbp_block(lf).is_none());
        // Re-injecting with another rel replaces the block.
        let wired = inject_dbp_block(lf, "").unwrap();
        let moved = inject_dbp_block(&wired, "../").unwrap();
        assert_eq!(moved.matches(DBP_BEGIN).count(), 1);
        assert!(moved.contains("../.socket"));
    }

    #[test]
    fn dbp_inject_handles_indented_and_same_line_close_and_self_closing() {
        let indented = "<Project>\n  <PropertyGroup/>\n  </Project>\n";
        let wired = inject_dbp_block(indented, "").unwrap();
        assert_eq!(excise_dbp_block(&wired).unwrap(), indented);

        let same_line = "<Project><PropertyGroup/></Project>";
        let wired = inject_dbp_block(same_line, "").unwrap();
        assert!(wired.ends_with("  <!-- socket-patch:end -->\n</Project>"));

        for self_closing in ["<Project/>\n", "<Project />\n", "<Project Sdk=\"x\" />"] {
            let wired = inject_dbp_block(self_closing, "").unwrap();
            assert!(wired.contains(DBP_BEGIN), "{self_closing}");
            assert!(wired.contains("</Project>"), "{self_closing}");
            assert!(!wired.contains("/>\n  <!-- socket-patch:begin"));
            let excised = excise_dbp_block(&wired).unwrap();
            assert!(excised.contains("</Project>"));
        }
        assert!(inject_dbp_block("<Other/>", "").is_err());
    }
}
