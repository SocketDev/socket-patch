//! Go upstream restore: drop the hosted `replace M v => patch.socket.dev/
//! gopatch/<uuid> …` directive and the socket module's sum lines, and put
//! the upstream module's two sum lines back (re-derived from the module
//! proxy exactly as `go` hashes them) — the pair the hosted rewriter pruned.
//!
//! The directive lives in the go.mod or go.work that discovery read it
//! from (`files`): the root go.mod, an in-root workspace member's go.mod
//! (a go.work root without a module of its own), or the root go.work. Its
//! sum lines live where go verifies them: beside a go.mod its go.sum, and
//! in workspace mode `go.work.sum` (go writes there itself) and the
//! members' go.sum files. The upstream pair goes back into the go.sum
//! beside a go.mod directive (its pin pruned it there); for a go.work
//! directive, which prunes nothing, only when no sum file holds it, into
//! each that held the socket pair, else go.work.sum. A go.work.sum left
//! empty is removed: nothing records whether it existed before the pin,
//! and go never writes an empty one, so the pin almost always created it.
//!
//! A directive the hosted run took over from the user (a pre-existing
//! `replace` it superseded) is not recorded anywhere, so the restore always
//! lands on the plain upstream module; the refusal message of a formats the
//! restore cannot handle names the checkout remedy instead.

use std::collections::{BTreeMap, BTreeSet};

use super::{Ctx, FormatResult, HostedPin, View};
use crate::vendor::go_mod_edit::{
    hosted_module_uuid, normalize_for_read, parse_replace_entries, parse_use_dirs,
    remove_replace_entry, ReplaceOwner,
};
use crate::vendor::go_sum_edit::{go_sum_lines, reinsert_lines, remove_module_prefix_lines};
use crate::vendor::go_workspace::in_root_dir;

const GO_WORK: &str = "go.work";
const GO_WORK_SUM: &str = "go.work.sum";

/// One hosted directive to unwind.
struct Hit {
    uuid: String,
    module: String,
    version: String,
    socket_module: String,
    file: String,
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let mut wiring: Vec<String> = files.iter().filter(|f| is_wiring(f)).cloned().collect();
    if wiring.is_empty() {
        wiring.push("go.mod".to_string());
    }
    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    for file in &wiring {
        match view.read(file).await {
            Ok(Some(text)) => {
                texts.insert(file.clone(), text);
            }
            Ok(None) => {}
            Err(e) => {
                for pin in pins.iter().filter(|p| wires(p, file)) {
                    result.refuse(&pin.uuid, e.clone());
                }
            }
        }
    }
    if texts.is_empty() {
        for pin in pins {
            result.refuse(&pin.uuid, format!("{} no longer exists", wiring.join(", ")));
        }
        return result;
    }

    let mut hits: Vec<Hit> = Vec::new();
    for pin in pins {
        let Some((module, version)) = pin.name_version() else {
            result.refuse(&pin.uuid, format!("{} is not a golang purl", pin.purl));
            continue;
        };
        for (file, text) in texts.iter().filter(|(f, _)| wires(pin, f)) {
            let entries = parse_replace_entries(&normalize_for_read(text));
            let Some(directive) = entries.iter().find(|e| {
                e.module == module
                    && e.rhs_module
                        .as_deref()
                        .and_then(hosted_module_uuid)
                        .is_some_and(|u| u == pin.uuid)
            }) else {
                continue;
            };
            hits.push(Hit {
                uuid: pin.uuid.clone(),
                module: module.clone(),
                version: directive.version.clone().unwrap_or_else(|| version.clone()),
                socket_module: directive.rhs_module.clone().unwrap_or_default(),
                file: file.clone(),
            });
        }
    }
    if hits.is_empty() {
        return result;
    }
    // go.work last: the members' go.sum then hold what their own pins'
    // restores put back.
    hits.sort_by_key(|h| h.file == GO_WORK);
    let keys: BTreeSet<(String, String)> = hits
        .iter()
        .map(|h| (h.module.clone(), h.version.clone()))
        .collect();
    let lookups = keys.into_iter().map(|(module, version)| async move {
        let sums = ctx.client.go_sums(&module, &version).await;
        ((module, version), sums)
    });
    let sums: BTreeMap<(String, String), Result<super::client::GoSums, String>> =
        futures_util::future::join_all(lookups)
            .await
            .into_iter()
            .collect();

    let mut next = texts.clone();
    let mut removed: Vec<&Hit> = Vec::new();
    for hit in &hits {
        match sums.get(&(hit.module.clone(), hit.version.clone())) {
            Some(Ok(_)) => {}
            Some(Err(why)) => {
                result.refuse(&hit.uuid, format!("{}@{}: {why}", hit.module, hit.version));
                continue;
            }
            None => continue,
        }
        let text = next.get(&hit.file).cloned().unwrap_or_default();
        match remove_replace_entry(&text, &hit.module, ReplaceOwner::Hosted) {
            Ok(Some(edited)) => {
                next.insert(hit.file.clone(), edited);
            }
            Ok(None) => {}
            Err(e) => {
                result.refuse(&hit.uuid, format!("{}: {e}", hit.file));
                continue;
            }
        }
        removed.push(hit);
    }

    let go_work = match texts.get(GO_WORK) {
        Some(text) => Some(text.clone()),
        None => view.read(GO_WORK).await.ok().flatten(),
    };
    // A socket module another kept directive still targets keeps its lines.
    let still_targeted: BTreeSet<String> = next
        .values()
        .chain(go_work.iter().filter(|_| !next.contains_key(GO_WORK)))
        .flat_map(|text| parse_replace_entries(&normalize_for_read(text)))
        .filter_map(|e| e.rhs_module)
        .collect();
    let mut sum_texts: BTreeMap<String, Option<String>> = BTreeMap::new();
    for hit in &removed {
        let Some(Ok(go_sums)) = sums.get(&(hit.module.clone(), hit.version.clone())) else {
            continue;
        };
        let upstream = format!(
            "{m} {v} {}\n{m} {v}/go.mod {}\n",
            go_sums.zip_h1,
            go_sums.mod_h1,
            m = hit.module,
            v = hit.version
        );
        let candidates = sum_files_for(&hit.file, go_work.as_deref());
        let keep = still_targeted.contains(&hit.socket_module);
        let mut held = Vec::new();
        for sum in &candidates {
            if !sum_texts.contains_key(sum) {
                let text = view.read(sum).await.ok().flatten();
                sum_texts.insert(sum.clone(), text);
            }
            let Some(Some(text)) = sum_texts.get(sum).filter(|_| !keep) else {
                continue;
            };
            if let Some(stripped) = remove_module_prefix_lines(text, &hit.socket_module) {
                sum_texts.insert(sum.clone(), Some(stripped));
                held.push(sum.clone());
            }
        }
        // A go.mod pin pruned the pair from the go.sum beside it, which alone
        // needs it back (go.work.sum only held the socket pair for workspace
        // builds). A go.work pin prunes nothing: the members' go.sum keep the
        // pair for module-mode builds.
        let targets = if hit.file != GO_WORK {
            vec![candidates[0].clone()]
        } else if candidates.iter().any(|sum| {
            matches!(sum_texts.get(sum), Some(Some(text)) if go_sum_lines(text)
                .any(|l| l.zip_version_of(&hit.module) == Some(hit.version.as_str())))
        }) {
            Vec::new()
        } else if held.is_empty() {
            let own = candidates[0].clone();
            let existing = candidates
                .iter()
                .find(|s| matches!(sum_texts.get(*s), Some(Some(_))))
                .cloned();
            vec![existing.unwrap_or(own)]
        } else {
            held
        };
        for sum in targets {
            let text = sum_texts.get(&sum).cloned().flatten().unwrap_or_default();
            if let Some(reinserted) = reinsert_lines(&text, &upstream) {
                sum_texts.insert(sum, Some(reinserted));
            }
        }
        result.handled.insert(hit.uuid.clone());
    }

    for (file, text) in next {
        if texts.get(&file) != Some(&text) {
            view.write(&file, text);
        }
    }
    for (file, text) in sum_texts {
        let Some(text) = text else {
            continue;
        };
        if view.read(&file).await.ok().flatten().as_deref() == Some(text.as_str()) {
            continue;
        }
        // go never writes an empty go.work.sum: the pin created it.
        if file == GO_WORK_SUM && text.is_empty() {
            view.remove(&file);
        } else {
            view.write(&file, text);
        }
    }
    result
}

fn is_wiring(file: &str) -> bool {
    let leaf = file.rsplit('/').next().unwrap_or(file);
    leaf == "go.mod" || (leaf == GO_WORK && !file.contains('/'))
}

/// Whether `pin` is wired in `file` (a pin listing no files is looked for
/// everywhere).
fn wires(pin: &HostedPin, file: &str) -> bool {
    pin.files.is_empty() || pin.files.iter().any(|f| f == file)
}

/// The sum files that may hold the pin of a directive in `file`, the one
/// beside it first: a go.mod's go.sum, then go.work.sum; for go.work,
/// go.work.sum then each in-root member's go.sum.
fn sum_files_for(file: &str, go_work: Option<&str>) -> Vec<String> {
    let sibling = |dir: &str, name: &str| match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    };
    if file == GO_WORK {
        let mut out = vec![GO_WORK_SUM.to_string()];
        let uses = go_work
            .map(|text| parse_use_dirs(&normalize_for_read(text)))
            .unwrap_or_default();
        for dir in uses.iter().filter_map(|d| in_root_dir(d)) {
            let sum = sibling(&dir, "go.sum");
            if !out.contains(&sum) {
                out.push(sum);
            }
        }
        return out;
    }
    let dir = file.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut out = vec![sibling(dir, "go.sum")];
    if go_work.is_some() {
        out.push(GO_WORK_SUM.to_string());
    }
    out
}
