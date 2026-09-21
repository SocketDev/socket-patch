//! Native, lossless surgery for Bun's binary lockfile.
//!
//! The wire format is Bun's `Lockfile.Serializer` / `Package.Serializer`:
//! https://github.com/oven-sh/bun/blob/bun-v1.2.0/src/install/lockfile.zig
//! https://github.com/oven-sh/bun/blob/bun-v1.4.2/src/install/lockfile/bun.lockb.rs
//! Format 1 (before 0.1.7) has a semver-only npm resolution; format 2 adds
//! its tarball URL. Format 3 widens semver components to u64. 0.6.8 added the eighth package column (scripts). The six
//! buffer arrays and optional tagged extension arrays use absolute offsets.
//! We retain every unrelated byte, including padding and unknown trailers; unknown extensions refuse edits.
//! Strings are appended without relocating existing string references.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha512_256};
use std::cmp::Ordering;
use std::ops::Range;

const HEADER: &[u8] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n";
const TOTAL_AT: usize = HEADER.len() + 4 + 32;
const PACKAGES_AT: usize = TOTAL_AT + 8;
const INTEGRITY_LEN: usize = 65;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BinaryPackage {
    pub(crate) id: usize,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) resolution: String,
    pub(crate) integrity: Option<String>,
}

#[derive(Clone, Debug)]
struct Array {
    descriptor: usize,
    data: Range<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct BunLockb {
    data: Vec<u8>,
    format: u32,
    count: usize,
    fields: usize,
    package_start: usize,
    resolution_size: usize,
    strings: Array,
    /// Absolute-offset array descriptors after the string buffer.
    extensions: Vec<Array>,
    total: usize,
    unknown_extension: bool,
}

impl BunLockb {
    pub(crate) fn parse(input: &[u8]) -> Result<Self, String> {
        if !input.starts_with(HEADER) {
            return Err("bun.lockb: invalid binary lockfile header".into());
        }
        let format = u32_at(input, HEADER.len())?;
        let resolution_size = match format {
            1 => 56,
            2 => 64,
            3 => 72,
            _ => {
                return Err(format!(
                    "bun.lockb: unsupported binary format {format} (supported: 1, 2, 3)"
                ))
            }
        };
        let total = usize_at(input, TOTAL_AT)?;
        if total > input.len() || total < PACKAGES_AT + 40 {
            return Err("bun.lockb: invalid total byte length".into());
        }
        let count = usize_at(input, PACKAGES_AT)?;
        let alignment = usize_at(input, PACKAGES_AT + 8)?;
        let fields = usize_at(input, PACKAGES_AT + 16)?;
        if alignment != 8 || !matches!(fields, 7 | 8) {
            return Err(format!(
                "bun.lockb: unsupported package layout (alignment {alignment}, fields {fields})"
            ));
        }
        let package_start = usize_at(input, PACKAGES_AT + 24)?;
        let package_end = usize_at(input, PACKAGES_AT + 32)?;
        let record_size =
            8 + 8 + resolution_size + 8 + 8 + 88 + 20 + if fields == 8 { 49 } else { 0 };
        let size = count
            .checked_mul(record_size)
            .ok_or("bun.lockb: package count overflow")?;
        if count >= u32::MAX as usize
            || package_start < PACKAGES_AT + 40
            || package_start % 8 != 0
            || package_end > total
            || package_start.checked_add(size) != Some(package_end)
        {
            return Err("bun.lockb: invalid package column range".into());
        }
        let mut pos = package_end;
        let mut arrays = Vec::with_capacity(6);
        for _ in 0..6 {
            let array = read_array(input, pos, total)?;
            pos = array.data.end;
            arrays.push(array);
        }
        // Fixed-width tree, dependency IDs, resolved package IDs, external
        // dependencies (26 bytes), and hashed strings precede string bytes.
        for (array, width) in arrays.iter().zip([20, 4, 4, 26, 16, 1]) {
            if array.data.len() % width != 0 {
                return Err("bun.lockb: invalid buffer element width".into());
            }
        }
        if u64_at(input, pos)? != 0 || pos + 8 > total {
            return Err("bun.lockb: missing buffer terminator".into());
        }
        pos += 8;
        let mut extensions = Vec::new();
        // These are the append-only extension tags understood by Bun 1.x.
        // Unknown suffixes are retained verbatim instead of being discarded.
        while pos.checked_add(8).is_some_and(|end| end <= total) {
            let n = match &input[pos..pos + 8] {
                b"wOrKsPaC" => 4,
                b"tRuStEDd" => 1,
                b"eMpTrUsT" => 0,
                b"oVeRriDs" | b"pAtChEdD" => 2,
                b"sCoPdOvR" => 3,
                b"cNfGvRsN" => {
                    if pos + 16 > total {
                        return Err("bun.lockb: truncated config extension".into());
                    }
                    pos += 16;
                    continue;
                }
                b"cAtAlOgS" => {
                    pos += 8;
                    let mut groups = 0;
                    for i in 0..3 {
                        let array = read_array(input, pos, total)?;
                        pos = array.data.end;
                        if i == 2 {
                            if array.data.len() % 8 != 0 {
                                return Err("bun.lockb: invalid catalog group array".into());
                            }
                            groups = array.data.len() / 8;
                        }
                        extensions.push(array);
                    }
                    for _ in 0..groups {
                        for _ in 0..2 {
                            let array = read_array(input, pos, total)?;
                            pos = array.data.end;
                            extensions.push(array);
                        }
                    }
                    continue;
                }
                _ => break,
            };
            pos += 8;
            for _ in 0..n {
                let array = read_array(input, pos, total)?;
                pos = array.data.end;
                extensions.push(array);
            }
        }
        let lock = Self {
            data: input.to_vec(),
            format,
            count,
            fields,
            package_start,
            resolution_size,
            strings: arrays.pop().expect("six arrays"),
            extensions,
            total,
            unknown_extension: pos < total,
        };
        // All strings exposed to inventory/editing must be valid before a
        // caller can stage any changes to the lockfile.
        lock.packages()?;
        Ok(lock)
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub(crate) fn packages(&self) -> Result<Vec<BinaryPackage>, String> {
        (0..self.count).map(|id| self.package(id)).collect()
    }

    /// Workspace roots are relative to the lockfile root. Callers validate
    /// filesystem confinement before creating per-workspace tarball mirrors.
    pub(crate) fn workspace_paths(&self) -> Result<Vec<String>, String> {
        let mut paths = Vec::new();
        for id in 0..self.count {
            let at = self.resolution_at(id);
            if self.data[at] == 72 {
                paths.push(self.string_at(at + 8)?);
            }
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    fn package(&self, id: usize) -> Result<BinaryPackage, String> {
        self.check_id(id)?;
        let name = self.string_at(self.package_start + id * 8)?;
        let at = self.resolution_at(id);
        let tag = self.data[at];
        let (version, resolution) = match tag {
            2 => {
                let version = self.version_at(at + if self.format == 1 { 8 } else { 16 })?;
                let url = if self.format == 1 {
                    let leaf = name.rsplit('/').next().unwrap_or(&name);
                    format!("https://registry.npmjs.org/{name}/-/{leaf}-{version}.tgz")
                } else {
                    self.string_at(at + 8)?
                };
                (Some(version), url)
            }
            4 | 8 | 64 | 72 | 80 | 100 => (None, self.string_at(at + 8)?),
            // Git records contain several strings and hashes; they are not
            // registry packages and are deliberately opaque to this editor.
            0 | 1 | 16 | 24 | 32 | 33 | 40 | 48 | 56 | 96 => (None, String::new()),
            _ => return Err(format!("bun.lockb: unsupported resolution tag {tag}")),
        };
        let integrity_at = self.integrity_at(id);
        let integrity = decode_integrity(&self.data[integrity_at..integrity_at + INTEGRITY_LEN])?;
        Ok(BinaryPackage {
            id,
            name,
            version,
            resolution,
            integrity,
        })
    }

    /// Snapshot includes semantic values for inventory/ownership and binary
    /// values for byte-exact restoration. String values accompany pointers so
    /// restoration also works after Bun has compacted/re-saved its string pool.
    pub(crate) fn snapshot(&self, id: usize) -> Result<Value, String> {
        let pkg = self.package(id)?;
        let at = self.resolution_at(id);
        let raw = &self.data[at..at + self.resolution_size];
        let refs = self.resolution_strings(raw)?;
        let integrity = self.integrity_at(id);
        Ok(json!({
            "layout_original": if self.format == 1 || self.needs_workspace_normalization()? {Some(STANDARD.encode(&self.data))} else {None},
            "name": pkg.name,
            "version": pkg.version,
            "resolution": pkg.resolution,
            "integrity": pkg.integrity,
            "format": self.format,
            "raw_resolution": STANDARD.encode(raw),
            "raw_integrity": STANDARD.encode(&self.data[integrity..integrity + INTEGRITY_LEN]),
            "strings": refs,
            "string_buffer_len": self.strings.data.len(),
        }))
    }

    pub(crate) fn matches_snapshot(&self, id: usize, snapshot: &Value) -> Result<bool, String> {
        if id >= self.count {
            return Ok(false);
        }
        let pkg = self.package(id)?;
        Ok(
            snapshot.get("name").and_then(Value::as_str) == Some(&pkg.name)
                && snapshot.get("version").cloned().unwrap_or(Value::Null) == json!(pkg.version)
                && snapshot.get("resolution").and_then(Value::as_str) == Some(&pkg.resolution)
                && snapshot.get("integrity").cloned().unwrap_or(Value::Null)
                    == json!(pkg.integrity),
        )
    }

    /// Bun can reorder package IDs when it rewrites a lockfile. Prefer the
    /// recorded ID, then recover a uniquely matching semantic package.
    pub(crate) fn find_snapshot_id(
        &self,
        preferred: usize,
        snapshot: &Value,
    ) -> Result<Option<usize>, String> {
        if self.matches_snapshot(preferred, snapshot)? {
            return Ok(Some(preferred));
        }
        let mut found = None;
        for id in 0..self.count {
            if self.matches_snapshot(id, snapshot)? {
                if found.is_some() {
                    return Err(
                        "bun.lockb: package snapshot matches multiple reordered entries".into(),
                    );
                }
                found = Some(id);
            }
        }
        Ok(found)
    }

    pub(crate) fn set_package(
        &mut self,
        id: usize,
        target: &str,
        integrity: &str,
    ) -> Result<(), String> {
        let mut candidate = self.clone();
        candidate.set_package_inner(id, target, integrity)?;
        *self = candidate;
        Ok(())
    }

    fn set_package_inner(
        &mut self,
        id: usize,
        target: &str,
        integrity: &str,
    ) -> Result<(), String> {
        self.check_id(id)?;
        self.check_editable()?;
        let style = self.hash_style()?;
        self.promote_legacy_format()?;
        self.normalize_workspace_behaviors()?;
        if target.is_empty() || target.as_bytes().contains(&0) {
            return Err("bun.lockb: empty or NUL-containing tarball location".into());
        }
        let digest = encode_integrity(integrity)?;
        let at = self.resolution_at(id);
        let old_tag = self.data[at];
        if !matches!(old_tag, 2 | 8 | 80) {
            return Err("bun.lockb: only registry and tarball packages can be patched".into());
        }
        let remote = target.starts_with("https://") || target.starts_with("http://");
        let target = if remote {
            target
        } else {
            target.strip_prefix("file:").unwrap_or(target)
        };
        let pointer = self.intern(target)?;
        // Tarball variants have distinct cache identities. Keeping npm tag 2
        // would allow Bun to reuse an already-cached, unpatched name@version.
        self.data[at..at + self.resolution_size].fill(0);
        self.data[at] = if remote { 80 } else { 8 };
        self.data[at + 8..at + 16].copy_from_slice(&pointer);
        let integrity_at = self.integrity_at(id);
        self.data[integrity_at..integrity_at + INTEGRITY_LEN].copy_from_slice(&digest);
        self.update_hash(style)?;
        Ok(())
    }

    pub(crate) fn restore(&mut self, id: usize, snapshot: &Value) -> Result<(), String> {
        let mut candidate = self.clone();
        candidate.restore_inner(id, snapshot)?;
        if !candidate.matches_snapshot(id, snapshot)? {
            return Err("bun.lockb: snapshot binary and semantic values disagree".into());
        }
        *self = candidate;
        Ok(())
    }

    fn restore_inner(&mut self, id: usize, snapshot: &Value) -> Result<(), String> {
        self.check_editable()?;
        let style = self.hash_style()?;
        let pkg = self.package(id)?;
        if snapshot.get("name").and_then(Value::as_str) != Some(&pkg.name) {
            return Err("bun.lockb: snapshot package name does not match".into());
        }
        let original_format = snapshot
            .get("format")
            .and_then(Value::as_u64)
            .ok_or("bun.lockb: invalid snapshot format")?;
        let mut resolution = snapshot_bytes(snapshot, "raw_resolution")?;
        let integrity = snapshot_bytes(snapshot, "raw_integrity")?;
        let original_size = match original_format {
            1 => 56,
            2 => 64,
            3 => 72,
            _ => return Err("bun.lockb: invalid snapshot format".into()),
        };
        if resolution.len() != original_size || integrity.len() != INTEGRITY_LEN {
            return Err("bun.lockb: snapshot binary layout does not match lockfile".into());
        }
        let mut refs = snapshot
            .get("strings")
            .and_then(Value::as_array)
            .ok_or("bun.lockb: invalid snapshot strings")?
            .clone();
        if original_format != self.format as u64 {
            let old = resolution;
            resolution = vec![0; self.resolution_size];
            resolution[..8].copy_from_slice(&old[..8]);
            if old[0] == 2 {
                let old_version = if original_format == 1 { 8 } else { 16 };
                let new_version = if self.format == 1 { 8 } else { 16 };
                let old_tags = old_version + if original_format == 3 { 24 } else { 16 };
                let new_tags = new_version + if self.format == 3 { 24 } else { 16 };
                for i in 0..3 {
                    let number = if original_format == 3 {
                        u64_at(&old, old_version + i * 8)?
                    } else {
                        u32_at(&old, old_version + i * 4)? as u64
                    };
                    if self.format == 3 {
                        resolution[new_version + i * 8..new_version + i * 8 + 8]
                            .copy_from_slice(&number.to_le_bytes());
                    } else {
                        let number = u32::try_from(number).map_err(|_| {
                            "bun.lockb: snapshot version exceeds this binary format"
                        })?;
                        resolution[new_version + i * 4..new_version + i * 4 + 4]
                            .copy_from_slice(&number.to_le_bytes());
                    }
                }
                resolution[new_tags..new_tags + 32].copy_from_slice(&old[old_tags..old_tags + 32]);
                if self.format != 1 && original_format != 1 {
                    resolution[8..16].copy_from_slice(&old[8..16]);
                }
                for reference in &mut refs {
                    let offset = reference["offset"]
                        .as_u64()
                        .ok_or("bun.lockb: invalid snapshot string offset")?
                        as usize;
                    if offset == old_tags || offset == old_tags + 16 {
                        reference["offset"] = json!(new_tags + offset - old_tags);
                    }
                }
                if self.format == 1 {
                    refs.retain(|reference| reference["offset"] != json!(8));
                } else if original_format == 1 {
                    refs.push(json!({"offset":8,"value":snapshot["resolution"]}));
                }
            } else {
                let end = old.len().min(resolution.len());
                resolution[8..end].copy_from_slice(&old[8..end]);
            }
        }
        for reference in &refs {
            let offset = reference
                .get("offset")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or("bun.lockb: invalid snapshot string offset")?;
            let value = reference
                .get("value")
                .and_then(Value::as_str)
                .ok_or("bun.lockb: invalid snapshot string value")?;
            let end = offset
                .checked_add(8)
                .ok_or("bun.lockb: snapshot offset overflow")?;
            let old = resolution
                .get(offset..end)
                .ok_or("bun.lockb: snapshot string outside record")?;
            if self.decode_string(old).as_deref() != Ok(value) {
                resolution[offset..end].copy_from_slice(&self.intern(value)?);
            }
        }
        let at = self.resolution_at(id);
        self.data[at..at + self.resolution_size].copy_from_slice(&resolution);
        let at = self.integrity_at(id);
        self.data[at..at + INTEGRITY_LEN].copy_from_slice(&integrity);
        if let Some(len) = snapshot
            .get("string_buffer_len")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
        {
            self.trim_unreferenced_tail(len)?;
        }
        self.update_hash(style)?;
        if let Some(encoded) = snapshot.get("layout_original").and_then(Value::as_str) {
            let original = STANDARD
                .decode(encoded)
                .map_err(|_| "bun.lockb: invalid legacy snapshot")?;
            let mut expected = Self::parse(&original)?;
            let original_style = expected.hash_style()?;
            expected.promote_legacy_format()?;
            expected.normalize_workspace_behaviors()?;
            expected.update_hash(original_style)?;
            let mut compacted = self.clone();
            compacted.trim_unreferenced_tail(expected.strings.data.len())?;
            if compacted.bytes() == expected.bytes() {
                *self = Self::parse(&original)?;
            }
        }
        Ok(())
    }

    fn buffer_array(&self, wanted: usize) -> Result<Array, String> {
        let width =
            16 + self.resolution_size + 16 + 88 + 20 + if self.fields == 8 { 49 } else { 0 };
        let mut pos = self.package_start + self.count * width;
        for index in 0..6 {
            let array = read_array(&self.data, pos, self.total)?;
            if index == wanted {
                return Ok(array);
            }
            pos = array.data.end;
        }
        Err("bun.lockb: invalid buffer index".into())
    }

    fn dependency_array(&self) -> Result<Array, String> {
        self.buffer_array(3)
    }

    fn workspace_literal_changes(&self) -> Result<Vec<(usize, String)>, String> {
        let dependencies = self.dependency_array()?;
        let resolutions = self.buffer_array(2)?;
        if dependencies.data.len() / 26 != resolutions.data.len() / 4 {
            return Err("bun.lockb: dependency and resolution buffer lengths differ".into());
        }
        let mut changes = Vec::new();
        for index in 0..dependencies.data.len() / 26 {
            let at = dependencies.data.start + index * 26;
            if self.data[at + 17] != 6 {
                continue;
            }
            let id = u32_at(&self.data, resolutions.data.start + index * 4)? as usize;
            if id >= self.count {
                continue;
            }
            let resolution = self.resolution_at(id);
            if self.data[resolution] != 72 {
                continue;
            }
            let path = self.string_at(resolution + 8)?;
            if self.string_at(at + 18)? != path {
                changes.push((at + 18, path));
            }
        }
        Ok(changes)
    }

    fn needs_workspace_normalization(&self) -> Result<bool, String> {
        let dependencies = self.dependency_array()?;
        Ok(self.data[dependencies.data]
            .chunks_exact(26)
            .any(|dep| dep[16] & 0x20 != 0 && dep[16] & 0x1e != 0)
            || !self.workspace_literal_changes()?.is_empty())
    }

    // Bun <=1.2 wrote workspace|normal/dev/optional on member dependency
    // edges. Modern Bun compares every behavior bit against package.json and
    // otherwise re-resolves those packages, dropping tarball redirects. Older
    // Bun compares only workspace-only vs other edges, so clearing the redundant
    // workspace bit is compatible with both generations. Actual workspace-only
    // declarations (0x20) retain their original behavior.
    // Some writers also persist the unexpanded workspace:* literal while their
    // binary loader expects its resolved path. Canonical path literals (used by
    // older writers) compare correctly in every supported binary reader.
    fn normalize_workspace_behaviors(&mut self) -> Result<(), String> {
        let changes = self.workspace_literal_changes()?;
        let dependencies = self.dependency_array()?;
        for dep in self.data[dependencies.data].chunks_exact_mut(26) {
            if dep[16] & 0x20 != 0 && dep[16] & 0x1e != 0 {
                dep[16] &= !0x20;
            }
        }
        for (at, path) in changes {
            let pointer = self.intern(&path)?;
            self.data[at..at + 8].copy_from_slice(&pointer);
        }
        Ok(())
    }

    /// Bun versions capable of installing tarballs only accept binary format
    /// 2 or later. Promote the earliest binary layout in memory, retaining the
    /// binary filename and all dependency graph data. No Bun process runs.
    fn promote_legacy_format(&mut self) -> Result<(), String> {
        if self.format != 1 {
            return Ok(());
        }
        self.check_editable()?;
        let urls: Vec<_> = self
            .packages()?
            .into_iter()
            .filter(|p| p.version.is_some())
            .map(|p| (p.id, p.resolution))
            .collect();
        let old_resolution_start = self.package_start + self.count * 16;
        let old_resolution_end = old_resolution_start + self.count * 56;
        let old_package_end =
            self.package_start + self.count * (196 + if self.fields == 8 { 49 } else { 0 });
        let delta = self
            .count
            .checked_mul(8)
            .ok_or("bun.lockb: package size overflow")?;
        let mut arrays = Vec::new();
        let mut pos = old_package_end;
        for _ in 0..6 {
            let array = read_array(&self.data, pos, self.total)?;
            pos = array.data.end;
            arrays.push(array);
        }
        let mut data = Vec::with_capacity(self.data.len() + delta);
        data.extend_from_slice(&self.data[..old_resolution_start]);
        for id in 0..self.count {
            let old =
                &self.data[old_resolution_start + id * 56..old_resolution_start + (id + 1) * 56];
            let mut resolution = [0; 64];
            if old[0] == 2 {
                resolution[..8].copy_from_slice(&old[..8]);
                resolution[16..].copy_from_slice(&old[8..]);
            } else {
                resolution[..56].copy_from_slice(old);
            }
            data.extend_from_slice(&resolution);
        }
        data.extend_from_slice(&self.data[old_resolution_end..]);
        data[HEADER.len()..HEADER.len() + 4].copy_from_slice(&2u32.to_le_bytes());
        put_u64(&mut data, PACKAGES_AT + 32, old_package_end + delta);
        for array in arrays.iter_mut().chain(self.extensions.iter_mut()) {
            array.descriptor += delta;
            array.data = array.data.start + delta..array.data.end + delta;
            put_u64(&mut data, array.descriptor, array.data.start);
            put_u64(&mut data, array.descriptor + 8, array.data.end);
        }
        self.total += delta;
        put_u64(&mut data, TOTAL_AT, self.total);
        self.strings = arrays.pop().unwrap();
        self.data = data;
        self.format = 2;
        self.resolution_size = 64;
        for (id, url) in urls {
            let pointer = self.intern(&url)?;
            let at = self.resolution_at(id);
            self.data[at + 8..at + 16].copy_from_slice(&pointer);
        }
        Ok(())
    }

    fn update_hash(&mut self, style: (bool, bool)) -> Result<(), String> {
        let hash = self.meta_hash(style)?;
        self.data[HEADER.len() + 4..TOTAL_AT].copy_from_slice(&hash);
        Ok(())
    }

    // Bun's frozen install validates this hash even when package.json has not
    // changed. Historical releases differ in workspace/git rendering and in
    // whether root/workspace scripts participate. Select the dialect against
    // the existing hash before editing, instead of guessing the writer version.
    fn hash_style(&self) -> Result<(bool, bool), String> {
        let stored = &self.data[HEADER.len() + 4..TOTAL_AT];
        for style in [(false, true), (false, false), (true, false), (true, true)] {
            if self.meta_hash(style).is_ok_and(|hash| hash == stored) {
                return Ok(style);
            }
        }
        Err("bun.lockb: package metadata hash does not match the lockfile; run bun install to refresh it before patching".into())
    }

    fn meta_hash(&self, (legacy, scripts): (bool, bool)) -> Result<[u8; 32], String> {
        if self.count <= 1 {
            return Ok([0; 32]);
        }
        struct Entry {
            name: String,
            text: String,
            tag: u8,
            version: Option<(u64, u64, u64, String, String)>,
            repository: Vec<String>,
        }
        let mut entries = Vec::with_capacity(self.count - 1);
        for id in 1..self.count {
            let package = self.package(id)?;
            let at = self.resolution_at(id);
            let tag = self.data[at];
            let mut repository = Vec::new();
            let mut version = None;
            let text = match tag {
                2 => {
                    let value = package.version.unwrap();
                    let at = at + if self.format == 1 { 8 } else { 16 };
                    let (a, b, c, tags) = if self.format == 3 {
                        (
                            u64_at(&self.data, at)?,
                            u64_at(&self.data, at + 8)?,
                            u64_at(&self.data, at + 16)?,
                            24,
                        )
                    } else {
                        (
                            u32_at(&self.data, at)? as u64,
                            u32_at(&self.data, at + 4)? as u64,
                            u32_at(&self.data, at + 8)? as u64,
                            16,
                        )
                    };
                    version = Some((
                        a,
                        b,
                        c,
                        self.string_at(at + tags)?,
                        self.string_at(at + tags + 16)?,
                    ));
                    value
                }
                4 | 8 | 80 => package.resolution,
                64 => format!(
                    "link:{}{}",
                    if legacy { "//" } else { "" },
                    package.resolution
                ),
                72 => format!(
                    "workspace:{}{}",
                    if legacy { "//" } else { "" },
                    package.resolution
                ),
                100 => format!(
                    "{}{}",
                    if legacy { "link://" } else { "module:" },
                    package.resolution
                ),
                32 | 33 if legacy => format!(
                    "{}{}",
                    if tag == 32 { "git+ssh://" } else { "https://" },
                    self.string_at(at + 8)?
                ),
                16 | 24 | 32 => {
                    for offset in [8, 16, 24] {
                        repository.push(self.string_at(at + offset)?);
                    }
                    let owner = &repository[0];
                    let repo = &repository[1];
                    let committish = &repository[2];
                    let mut value = if legacy {
                        format!(
                            "{}:{owner}{repo}",
                            if tag == 16 { "github" } else { "gitlab" }
                        )
                    } else {
                        let label = if tag == 16 { "github:" } else { "git+" };
                        let prefix = if !owner.is_empty() {
                            format!("{owner}/")
                        } else if !repo.contains("://") && repo.contains('@') && repo.contains(':')
                        {
                            "ssh://".into()
                        } else {
                            String::new()
                        };
                        format!("{label}{prefix}{repo}")
                    };
                    let resolved = if legacy {
                        String::new()
                    } else {
                        self.string_at(at + 32)?
                    };
                    let revision = if resolved.is_empty() {
                        committish.as_str()
                    } else {
                        resolved.rsplit('-').next().unwrap_or(&resolved)
                    };
                    if !revision.is_empty() {
                        value.push('#');
                        value.push_str(revision);
                    }
                    value
                }
                0 | 1 => String::new(),
                _ => return Err("bun.lockb: unsupported resolution metadata hash".into()),
            };
            entries.push(Entry {
                name: package.name,
                text,
                tag,
                version,
                repository,
            });
        }
        entries.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.tag.cmp(&b.tag))
                .then_with(|| {
                    if let (Some(a), Some(b)) = (&a.version, &b.version) {
                        (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)).then_with(|| {
                            if !legacy && !a.3.is_empty() && !b.3.is_empty() {
                                compare_prerelease(&a.3, &b.3)
                            } else {
                                a.3.cmp(&b.3).then_with(|| a.4.cmp(&b.4))
                            }
                        })
                    } else if !a.repository.is_empty() {
                        a.repository.cmp(&b.repository)
                    } else {
                        a.text.cmp(&b.text)
                    }
                })
        });
        let mut source =
            String::from("\n-- BEGIN SHA512/256(`${alphabetize(name)}@${order(version)}`) --\n");
        for entry in entries {
            source.push_str(&entry.name);
            source.push('@');
            source.push_str(&entry.text);
            source.push('\n');
        }
        if scripts && self.fields == 8 {
            let start =
                self.package_start + self.count * (16 + self.resolution_size + 16 + 88 + 20);
            let mut block = String::new();
            for (i, name) in [
                "preinstall",
                "install",
                "postinstall",
                "preprepare",
                "prepare",
                "postprepare",
            ]
            .into_iter()
            .enumerate()
            {
                for id in 0..self.count {
                    let tag = self.data[self.resolution_at(id)];
                    if id != 0 && tag != 72 {
                        continue;
                    }
                    if id != 0 && self.data[self.integrity_at(id) + INTEGRITY_LEN] != 2 {
                        continue;
                    }
                    let script = self.string_at(start + id * 49 + i * 8)?;
                    if !script.is_empty() {
                        block.push_str(name);
                        block.push_str(": ");
                        block.push_str(&script);
                        block.push('\n');
                    }
                }
            }
            if !block.is_empty() {
                source.push_str("\n-- BEGIN SCRIPTS --\n");
                source.push_str(&block);
                source.push_str("\n-- END SCRIPTS --\n");
            }
        }
        source.push_str("-- END HASH--\n");
        Ok(Sha512_256::digest(source.as_bytes()).into())
    }

    pub(crate) fn validate_mutation(&self) -> Result<(), String> {
        self.check_editable()?;
        self.hash_style().map(|_| ())
    }

    fn check_editable(&self) -> Result<(), String> {
        if self.unknown_extension {
            Err("bun.lockb: unsupported binary extension; update socket-patch before editing this lockfile".into())
        } else {
            Ok(())
        }
    }

    fn check_id(&self, id: usize) -> Result<(), String> {
        if id < self.count {
            Ok(())
        } else {
            Err("bun.lockb: package ID out of range".into())
        }
    }

    fn resolution_at(&self, id: usize) -> usize {
        self.package_start + self.count * 16 + id * self.resolution_size
    }

    fn integrity_at(&self, id: usize) -> usize {
        self.package_start + self.count * (16 + self.resolution_size + 16) + id * 88 + 20
    }

    fn string_at(&self, at: usize) -> Result<String, String> {
        self.decode_string(take(&self.data, at, 8)?)
    }

    fn decode_string(&self, bytes: &[u8]) -> Result<String, String> {
        if bytes.len() != 8 {
            return Err("bun.lockb: invalid string representation".into());
        }
        let raw = if bytes[7] & 0x80 == 0 {
            &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(8)]
        } else {
            let start = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            let len = (u32::from_le_bytes(bytes[4..].try_into().unwrap()) & 0x7fff_ffff) as usize;
            let end = start
                .checked_add(len)
                .ok_or("bun.lockb: string length overflow")?;
            self.data[self.strings.data.clone()]
                .get(start..end)
                .ok_or("bun.lockb: string reference outside buffer")?
        };
        String::from_utf8(raw.to_vec()).map_err(|_| "bun.lockb: invalid UTF-8 string".into())
    }

    fn version_at(&self, at: usize) -> Result<String, String> {
        let (major, minor, patch, tags) = if self.format == 3 {
            (
                u64_at(&self.data, at)?,
                u64_at(&self.data, at + 8)?,
                u64_at(&self.data, at + 16)?,
                24,
            )
        } else {
            (
                u32_at(&self.data, at)? as u64,
                u32_at(&self.data, at + 4)? as u64,
                u32_at(&self.data, at + 8)? as u64,
                16,
            )
        };
        let mut version = format!("{major}.{minor}.{patch}");
        let pre = self.string_at(at + tags)?;
        let build = self.string_at(at + tags + 16)?;
        if !pre.is_empty() {
            version.push('-');
            version.push_str(&pre);
        }
        if !build.is_empty() {
            version.push('+');
            version.push_str(&build);
        }
        Ok(version)
    }

    fn resolution_strings(&self, raw: &[u8]) -> Result<Vec<Value>, String> {
        let offsets: Vec<usize> = match raw[0] {
            2 if self.format == 1 => vec![24, 40],
            2 if self.format == 3 => vec![8, 40, 56],
            2 => vec![8, 32, 48],
            4 | 8 | 64 | 72 | 80 | 100 => vec![8],
            _ => Vec::new(),
        };
        offsets
            .into_iter()
            .map(|offset| {
                Ok(json!({"offset":offset,"value":self.decode_string(&raw[offset..offset + 8])?}))
            })
            .collect()
    }

    fn intern(&mut self, value: &str) -> Result<[u8; 8], String> {
        let raw = value.as_bytes();
        if raw.len() < 8 || (raw.len() == 8 && raw[7] < 0x80) {
            let mut inline = [0; 8];
            inline[..raw.len()].copy_from_slice(raw);
            return Ok(inline);
        }
        let pool = &self.data[self.strings.data.clone()];
        let existing = if raw.len() <= pool.len() {
            pool.windows(raw.len()).position(|slice| slice == raw)
        } else {
            None
        };
        let offset = existing.unwrap_or(pool.len());
        let off = u32::try_from(offset).map_err(|_| "bun.lockb: string buffer exceeds 4 GiB")?;
        let len = u32::try_from(raw.len())
            .ok()
            .filter(|n| *n <= 0x7fff_ffff)
            .ok_or("bun.lockb: string exceeds format limit")?;
        if existing.is_none() {
            // A multiple of eight preserves alignment of every suffix array.
            let added = raw
                .len()
                .checked_add(7)
                .ok_or("bun.lockb: string size overflow")?
                & !7;
            let mut append = vec![0; added];
            append[..raw.len()].copy_from_slice(raw);
            self.resize_pool(self.strings.data.len() + added, &append)?;
        }
        let mut pointer = [0; 8];
        pointer[..4].copy_from_slice(&off.to_le_bytes());
        pointer[4..].copy_from_slice(&(len | 0x8000_0000).to_le_bytes());
        Ok(pointer)
    }

    fn resize_pool(&mut self, new_len: usize, append: &[u8]) -> Result<(), String> {
        let old_len = self.strings.data.len();
        let old_end = self.strings.data.end;
        let new_end = self
            .strings
            .data
            .start
            .checked_add(new_len)
            .ok_or("bun.lockb: string buffer overflow")?;
        let delta = new_len as i128 - old_len as i128;
        let shift = |value: usize| -> Result<usize, String> {
            usize::try_from(value as i128 + delta).map_err(|_| "bun.lockb: offset overflow".into())
        };
        let total = shift(self.total)?;
        if new_len >= old_len {
            if append.len() != new_len - old_len {
                return Err("bun.lockb: invalid string append".into());
            }
            self.data.splice(old_end..old_end, append.iter().copied());
        } else {
            self.data.drain(new_end..old_end);
        }
        self.strings.data.end = new_end;
        put_u64(&mut self.data, self.strings.descriptor + 8, new_end);
        self.total = total;
        put_u64(&mut self.data, TOTAL_AT, total);
        for array in &mut self.extensions {
            array.descriptor = shift(array.descriptor)?;
            array.data = shift(array.data.start)?..shift(array.data.end)?;
            put_u64(&mut self.data, array.descriptor, array.data.start);
            put_u64(&mut self.data, array.descriptor + 8, array.data.end);
        }
        Ok(())
    }

    /// Conservative compaction after restoration. Any eight bytes resembling
    /// a live out-of-line reference keep the tail alive; false positives merely
    /// retain unused bytes. Looking at all byte alignments also protects opaque
    /// extension records and old Bun fields with one-byte alignment.
    fn trim_unreferenced_tail(&mut self, len: usize) -> Result<(), String> {
        let current = self.strings.data.len();
        if len >= current || !(current - len).is_multiple_of(8) {
            return Ok(());
        }
        let keeps_tail = |candidate: &[u8]| {
            if candidate[7] & 0x80 == 0 {
                return false;
            }
            let start = u32::from_le_bytes(candidate[..4].try_into().unwrap()) as usize;
            let size =
                (u32::from_le_bytes(candidate[4..].try_into().unwrap()) & 0x7fff_ffff) as usize;
            start
                .checked_add(size)
                .is_some_and(|end| end <= current && end > len)
        };
        // Old releases wrote uninitialized padding in inactive resolution/bin
        // unions. Only active package string fields can keep pool bytes alive.
        let meta = self.package_start + self.count * (16 + self.resolution_size + 16);
        let bins = meta + self.count * 88;
        let scripts = bins + self.count * 20;
        let package_end = scripts + if self.fields == 8 { self.count * 49 } else { 0 };
        for id in 0..self.count {
            let mut pointers = vec![self.package_start + id * 8, meta + id * 88 + 12];
            let at = self.resolution_at(id);
            let offsets: Vec<usize> = match self.data[at] {
                2 if self.format == 1 => vec![24, 40],
                2 if self.format == 3 => vec![8, 40, 56],
                2 => vec![8, 32, 48],
                4 | 8 | 33 | 64 | 72 | 80 | 100 => vec![8],
                16 | 24 | 32 => vec![8, 16, 24, 32, 40],
                _ => Vec::new(),
            };
            pointers.extend(offsets.into_iter().map(|off| at + off));
            let bin = bins + id * 20;
            match self.data[bin] {
                1 | 3 => pointers.push(bin + 4),
                2 => {
                    pointers.push(bin + 4);
                    pointers.push(bin + 12);
                }
                _ => {}
            }
            if self.fields == 8 {
                pointers.extend((0..6).map(|i| scripts + id * 49 + i * 8));
            }
            if pointers
                .into_iter()
                .any(|at| keeps_tail(&self.data[at..at + 8]))
            {
                return Ok(());
            }
        }
        // Scan opaque array records conservatively; false positives retain
        // unused bytes and never discard live strings.
        for part in [
            &self.data[package_end..self.strings.data.start],
            &self.data[self.strings.data.end..self.total],
        ] {
            if part.windows(8).any(keeps_tail) {
                return Ok(());
            }
        }
        self.resize_pool(len, &[])
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut a = a.split('.');
    let mut b = b.split('.');
    loop {
        let order = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(a), Ok(b)) => a.cmp(&b),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            },
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

fn take(data: &[u8], at: usize, len: usize) -> Result<&[u8], String> {
    at.checked_add(len)
        .and_then(|end| data.get(at..end))
        .ok_or_else(|| "bun.lockb: truncated binary data".into())
}
fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(data, at, 4)?.try_into().unwrap()))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(take(data, at, 8)?.try_into().unwrap()))
}
fn usize_at(data: &[u8], at: usize) -> Result<usize, String> {
    usize::try_from(u64_at(data, at)?).map_err(|_| "bun.lockb: offset exceeds address space".into())
}
fn put_u64(data: &mut [u8], at: usize, value: usize) {
    data[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}
fn read_array(data: &[u8], descriptor: usize, total: usize) -> Result<Array, String> {
    let start = usize_at(data, descriptor)?;
    let end = usize_at(
        data,
        descriptor
            .checked_add(8)
            .ok_or("bun.lockb: array offset overflow")?,
    )?;
    if descriptor
        .checked_add(16)
        .is_none_or(|prefix_end| start < prefix_end)
        || start > end
        || end > total
    {
        return Err("bun.lockb: invalid array range".into());
    }
    Ok(Array {
        descriptor,
        data: start..end,
    })
}
fn snapshot_bytes(snapshot: &Value, key: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(
            snapshot
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("bun.lockb: missing snapshot {key}"))?,
        )
        .map_err(|_| format!("bun.lockb: invalid snapshot {key}"))
}
fn decode_integrity(raw: &[u8]) -> Result<Option<String>, String> {
    let (algorithm, len) = match raw[0] {
        0 => return Ok(None),
        1 => ("sha1", 20),
        2 => ("sha256", 32),
        3 => ("sha384", 48),
        4 => ("sha512", 64),
        tag => return Err(format!("bun.lockb: unsupported integrity tag {tag}")),
    };
    Ok(Some(format!(
        "{algorithm}-{}",
        STANDARD.encode(&raw[1..1 + len])
    )))
}
fn encode_integrity(sri: &str) -> Result<[u8; INTEGRITY_LEN], String> {
    let mut best: Option<(u8, Vec<u8>)> = None;
    for candidate in sri.split_ascii_whitespace() {
        let Some((algorithm, value)) = candidate.split_once('-') else {
            continue;
        };
        let (tag, len) = match algorithm {
            "sha1" => (1, 20),
            "sha256" => (2, 32),
            "sha384" => (3, 48),
            "sha512" => (4, 64),
            _ => continue,
        };
        let value = value.split('?').next().unwrap_or(value);
        let digest = STANDARD
            .decode(value)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value));
        if let Ok(digest) = digest {
            if digest.len() == len && best.as_ref().is_none_or(|(previous, _)| tag > *previous) {
                best = Some((tag, digest));
            }
        }
    }
    let (tag, digest) = best.ok_or("bun.lockb: invalid tarball integrity")?;
    let mut raw = [0; INTEGRITY_LEN];
    raw[0] = tag;
    raw[1..1 + digest.len()].copy_from_slice(&digest);
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: &[&str] = &[
        "0.1.1", "0.1.6", "0.1.7", "0.6.7", "0.6.8", "0.8.1", "1.0.0", "1.0.36", "1.1.0", "1.1.38",
        "1.1.45", "1.2.0", "1.2.23", "1.3.0", "1.3.14", "1.4.2",
    ];

    fn fixture(version: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bun-lockb")
                .join(version)
                .join("bun.lockb"),
        )
        .unwrap()
    }

    fn digest() -> String {
        format!("sha512-{}", STANDARD.encode([42; 64]))
    }

    #[test]
    fn every_historical_binary_layout_parses_losslessly() {
        for version in VERSIONS {
            let original = fixture(version);
            let lock = BunLockb::parse(&original).unwrap_or_else(|e| panic!("{version}: {e}"));
            let packages = lock.packages().unwrap();
            assert_eq!(lock.bytes(), original, "{version}");
            assert_eq!(packages.len(), 3, "{version}");
            let package = packages.iter().find(|p| p.name == "minimist").unwrap();
            assert_eq!(package.version.as_deref(), Some("1.2.2"), "{version}");
            assert_eq!(
                package.resolution, "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz",
                "{version}"
            );
            assert!(
                package.integrity.as_deref().unwrap().starts_with("sha512-"),
                "{version}"
            );
        }
    }

    #[test]
    fn native_local_hosted_migration_and_exact_restore_all_layouts() {
        for version in VERSIONS {
            let original = fixture(version);
            let mut lock = BunLockb::parse(&original).unwrap();
            let untouched = lock.snapshot(2).unwrap();
            let snapshot = lock.snapshot(1).unwrap();
            let path = ".socket/vendor/npm/12345678-1234-1234-1234-123456789abc/minimist-1.2.2.tgz";
            lock.set_package(1, path, &digest()).unwrap();
            let local = BunLockb::parse(&lock.bytes()).unwrap();
            assert_eq!(local.package(1).unwrap().resolution, path, "{version}");
            assert_eq!(local.package(1).unwrap().version, None, "{version}");
            assert!(local.matches_snapshot(2, &untouched).unwrap(), "{version}");
            let hosted = "https://patches.socket.dev/npm/minimist/1.2.2/patched.tgz";
            lock.set_package(1, hosted, &digest()).unwrap();
            let reopened = BunLockb::parse(&lock.bytes()).unwrap();
            assert_eq!(reopened.package(1).unwrap().resolution, hosted, "{version}");
            assert_eq!(
                reopened.package(1).unwrap().integrity,
                Some(digest()),
                "{version}"
            );
            assert_eq!(
                reopened.data[reopened.resolution_at(1)],
                80,
                "cache isolation: {version}"
            );
            lock.restore(1, &snapshot).unwrap();
            assert!(
                lock.bytes() == original,
                "exact restoration: {version} (length {} vs {})",
                lock.bytes().len(),
                original.len()
            );
        }
    }

    #[test]
    fn workspace_scripts_git_catalog_extensions_retain_valid_metahashes() {
        for version in ["1.1.45-extensions", "1.2.23-extensions", "1.4.2-extensions"] {
            let original = fixture(version);
            let mut lock = BunLockb::parse(&original).unwrap_or_else(|e| panic!("{version}: {e}"));
            lock.validate_mutation()
                .unwrap_or_else(|e| panic!("{version}: {e}"));
            let package = lock
                .packages()
                .unwrap()
                .into_iter()
                .find(|p| p.name == "minimist")
                .unwrap();
            let snapshot = lock.snapshot(package.id).unwrap();
            lock.set_package(package.id, "https://example.test/patched.tgz", &digest())
                .unwrap();
            let reopened = BunLockb::parse(&lock.bytes()).unwrap();
            reopened.validate_mutation().unwrap();
            assert!(reopened.workspace_literal_changes().unwrap().is_empty());
            assert_eq!(reopened.extensions.len(), lock.extensions.len());
            lock.restore(package.id, &snapshot).unwrap();
            assert!(lock.bytes() == original, "{version}");
        }
    }

    #[test]
    fn restore_survives_binary_format_upgrade_and_reordered_ids() {
        let old = BunLockb::parse(&fixture("1.1.38")).unwrap();
        let snapshot = old.snapshot(1).unwrap();
        let mut newer = BunLockb::parse(&fixture("1.4.2")).unwrap();
        newer
            .set_package(1, "https://example.test/patched.tgz", &digest())
            .unwrap();
        let rewritten = newer.snapshot(1).unwrap();
        // Swap the package columns as Bun does when re-resolving. Hash order
        // is semantic and is independent of the package table's IDs.
        let mut at = newer.package_start;
        for size in [8, 8, 72, 8, 8, 88, 20, 49] {
            for i in 0..size {
                newer.data.swap(at + size + i, at + size * 2 + i);
            }
            at += newer.count * size;
        }
        let id = newer.find_snapshot_id(1, &rewritten).unwrap().unwrap();
        assert_eq!(id, 2);
        newer.restore(id, &snapshot).unwrap();
        assert!(newer.matches_snapshot(id, &snapshot).unwrap());
        newer.validate_mutation().unwrap();
        assert_eq!(newer.format, 3);
    }

    #[test]
    fn malformed_snapshot_restore_is_transactional() {
        let mut lock = BunLockb::parse(&fixture("1.1.38")).unwrap();
        let mut snapshot = lock.snapshot(1).unwrap();
        lock.set_package(1, "https://example.test/patched.tgz", &digest())
            .unwrap();
        let before = lock.bytes();
        snapshot["version"] = json!("999.0.0");
        assert!(lock.restore(1, &snapshot).is_err());
        assert_eq!(lock.bytes(), before);
    }

    #[test]
    fn workspace_normalization_is_scoped_and_reverse_replay_is_exact() {
        let bytes = fixture("1.1.45-extensions");
        let mut lock = BunLockb::parse(&bytes).unwrap();
        let packages = lock.packages().unwrap();
        let first = packages.iter().find(|p| p.name == "minimist").unwrap().id;
        let second = packages.iter().find(|p| p.name == "left-pad").unwrap().id;
        let dependencies = lock.dependency_array().unwrap();
        let before: Vec<_> = lock.data[dependencies.data]
            .chunks_exact(26)
            .map(|dep| dep[16])
            .collect();
        let original_first = lock.snapshot(first).unwrap();
        lock.set_package(first, "https://example.test/minimist.tgz", &digest())
            .unwrap();
        let dependencies = lock.dependency_array().unwrap();
        let after: Vec<_> = lock.data[dependencies.data]
            .chunks_exact(26)
            .map(|dep| dep[16])
            .collect();
        for (old, new) in before.iter().zip(&after) {
            assert_eq!(
                *new,
                if old & 0x20 != 0 && old & 0x1e != 0 {
                    old & !0x20
                } else {
                    *old
                }
            );
        }
        assert!(before.contains(&0x20));
        assert!(after.contains(&0x20));
        let original_second = lock.snapshot(second).unwrap();
        lock.set_package(second, "https://example.test/left-pad.tgz", &digest())
            .unwrap();
        let rewritten_second = lock.snapshot(second).unwrap();
        let mut reverse = lock.clone();
        reverse.restore(second, &original_second).unwrap();
        reverse.restore(first, &original_first).unwrap();
        assert!(reverse.bytes() == bytes);
        // Removing the first patch while another remains must never restore
        // the whole-file structural snapshot over the surviving patch.
        lock.restore(first, &original_first).unwrap();
        assert!(lock.matches_snapshot(second, &rewritten_second).unwrap());
        assert!(!lock.needs_workspace_normalization().unwrap());
        lock.restore(second, &original_second).unwrap();
        assert!(lock.matches_snapshot(first, &original_first).unwrap());
        assert!(lock.matches_snapshot(second, &original_second).unwrap());
        // Scoped removal intentionally retains the harmless normalization.
        // Exact original bytes are guaranteed for normal reverse-order replay.
        assert!(!lock.needs_workspace_normalization().unwrap());
    }

    #[test]
    fn deterministic_malformed_byte_corpus_never_panics() {
        let original = fixture("1.4.2-extensions");
        let mut seed = 0x8e73_2bad_19c4_aa01u64;
        for iteration in 0..512 {
            let mut bytes = original.clone();
            for _ in 0..1 + iteration % 4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = seed as usize % bytes.len();
                bytes[at] ^= (seed >> 32) as u8 | 1;
            }
            let result = std::panic::catch_unwind(|| {
                if let Ok(mut lock) = BunLockb::parse(&bytes) {
                    let _ = lock.validate_mutation();
                    if let Ok(packages) = lock.packages() {
                        if let Some(package) = packages.iter().find(|p| p.version.is_some()) {
                            if let Ok(snapshot) = lock.snapshot(package.id) {
                                if lock
                                    .set_package(
                                        package.id,
                                        "https://example.test/corpus.tgz",
                                        &digest(),
                                    )
                                    .is_ok()
                                {
                                    let _ = lock.restore(package.id, &snapshot);
                                }
                            }
                        }
                    }
                }
            });
            assert!(result.is_ok(), "corpus iteration {iteration}");
        }
    }

    #[test]
    fn restoring_one_package_retains_another_packages_live_strings() {
        let mut lock = BunLockb::parse(&fixture("1.1.38")).unwrap();
        let first = lock.snapshot(1).unwrap();
        lock.set_package(1, "https://example.test/minimist.tgz", &digest())
            .unwrap();
        lock.set_package(2, "https://example.test/is-number.tgz", &digest())
            .unwrap();
        let second = lock.snapshot(2).unwrap();
        lock.restore(1, &first).unwrap();
        assert!(lock.matches_snapshot(1, &first).unwrap());
        assert!(BunLockb::parse(&lock.bytes())
            .unwrap()
            .matches_snapshot(2, &second)
            .unwrap());
    }

    #[test]
    fn restoration_remaps_strings_after_pool_changes() {
        let mut lock = BunLockb::parse(&fixture("1.1.38")).unwrap();
        let original = lock.snapshot(1).unwrap();
        lock.set_package(1, "https://example.test/minimist.tgz", &digest())
            .unwrap();
        // Simulate a re-save that overwrites the old, now-unused npm URL.
        let old_ref = STANDARD
            .decode(original["raw_resolution"].as_str().unwrap())
            .unwrap();
        let off = u32::from_le_bytes(old_ref[8..12].try_into().unwrap()) as usize;
        let len = (u32::from_le_bytes(old_ref[12..16].try_into().unwrap()) & 0x7fff_ffff) as usize;
        let start = lock.strings.data.start + off;
        lock.data[start..start + len].fill(b'x');
        lock.restore(1, &original).unwrap();
        assert!(BunLockb::parse(&lock.bytes())
            .unwrap()
            .matches_snapshot(1, &original)
            .unwrap());
    }

    #[test]
    fn unknown_suffix_and_known_absolute_offset_extensions_are_preserved() {
        let mut original = fixture("1.1.38");
        let total = usize_at(&original, TOTAL_AT).unwrap();
        original.truncate(total);
        original.extend_from_slice(b"tRuStEDd");
        let descriptor = original.len();
        let start = descriptor + 16;
        original.extend_from_slice(&(start as u64).to_le_bytes());
        original.extend_from_slice(&((start + 4) as u64).to_le_bytes());
        original.extend_from_slice(&0x12345678u32.to_le_bytes());
        let len = original.len();
        put_u64(&mut original, TOTAL_AT, len);
        original.extend_from_slice(b"unknown trailer retained verbatim");
        let mut lock = BunLockb::parse(&original).unwrap();
        let snapshot = lock.snapshot(1).unwrap();
        lock.set_package(
            1,
            "https://example.test/some-really-long-url.tgz",
            &digest(),
        )
        .unwrap();
        let reopened = BunLockb::parse(&lock.bytes()).unwrap();
        assert_eq!(reopened.extensions.len(), 1);
        assert_eq!(
            &reopened.data[reopened.extensions[0].data.clone()],
            &0x12345678u32.to_le_bytes()
        );
        assert!(reopened
            .bytes()
            .ends_with(b"unknown trailer retained verbatim"));
        lock.restore(1, &snapshot).unwrap();
        assert_eq!(lock.bytes(), original);
    }

    #[test]
    fn malformed_sizes_strings_integrities_and_versions_fail_closed() {
        let original = fixture("1.1.38");
        for at in [
            TOTAL_AT,
            PACKAGES_AT,
            PACKAGES_AT + 8,
            PACKAGES_AT + 16,
            PACKAGES_AT + 24,
            PACKAGES_AT + 32,
        ] {
            let mut bad = original.clone();
            bad[at..at + 8].fill(0xff);
            assert!(BunLockb::parse(&bad).is_err(), "offset {at}");
        }
        for len in 0..original.len() {
            let result = std::panic::catch_unwind(|| BunLockb::parse(&original[..len]));
            assert!(result.is_ok(), "panicked at prefix {len}");
            if len < usize_at(&original, TOTAL_AT).unwrap() {
                assert!(result.unwrap().is_err());
            }
        }
        let mut lock = BunLockb::parse(&original).unwrap();
        let at = lock.resolution_at(1) + 8;
        lock.data[at..at + 8].fill(0xff);
        assert!(BunLockb::parse(&lock.bytes()).is_err());
        let mut lock = BunLockb::parse(&original).unwrap();
        assert!(lock
            .set_package(1, "https://example.test/a.tgz", "sha512-bad")
            .is_err());
        assert_eq!(lock.bytes(), original);
        assert!(lock
            .set_package(999, "https://example.test/a.tgz", &digest())
            .is_err());
    }

    #[test]
    fn refuses_to_relocate_unknown_extension_offsets() {
        let mut bytes = fixture("1.1.38");
        let total = usize_at(&bytes, TOTAL_AT).unwrap();
        bytes.truncate(total);
        bytes.extend_from_slice(b"futureEXunknown data");
        let total = bytes.len();
        put_u64(&mut bytes, TOTAL_AT, total);
        let mut lock = BunLockb::parse(&bytes).unwrap();
        assert!(lock
            .set_package(1, "https://example.test/a.tgz", &digest())
            .unwrap_err()
            .contains("unsupported binary extension"));
        assert_eq!(lock.bytes(), bytes);
    }

    #[test]
    fn integrity_algorithms_and_inline_strings() {
        for (algorithm, len) in [("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64)] {
            let sri = format!("{algorithm}-{}", STANDARD.encode(vec![7; len]));
            assert_eq!(
                decode_integrity(&encode_integrity(&sri).unwrap()).unwrap(),
                Some(sri)
            );
        }
        let mut lock = BunLockb::parse(&fixture("1.1.38")).unwrap();
        let original_len = lock.bytes().len();
        lock.set_package(1, "a.tgz", &digest()).unwrap();
        assert_eq!(lock.package(1).unwrap().resolution, "a.tgz");
        assert_eq!(lock.bytes().len(), original_len);
    }
}
