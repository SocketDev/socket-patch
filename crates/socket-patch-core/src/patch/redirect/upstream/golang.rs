//! Go upstream restore: drop the hosted `replace M v => patch.socket.dev/
//! gopatch/<uuid> …` directive and the socket module's go.sum lines, and put
//! the upstream module's two go.sum lines back (re-derived from the module
//! proxy exactly as `go` hashes them) — the pair the hosted rewriter pruned.
//!
//! A directive the hosted run took over from the user (a pre-existing
//! `replace` it superseded) is not recorded anywhere, so the restore always
//! lands on the plain upstream module; the refusal message of a formats the
//! restore cannot handle names the checkout remedy instead.

use super::{Ctx, FormatResult, HostedPin, View};
use crate::vendor::go_mod_edit::{
    hosted_module_uuid, parse_replace_entries, remove_replace_entry, ReplaceOwner,
};
use crate::vendor::go_sum_edit::{reinsert_lines, remove_module_prefix_lines};

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    _files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let go_mod = match view.read("go.mod").await {
        Ok(Some(text)) => text,
        Ok(None) => {
            for pin in pins {
                result.refuse(&pin.uuid, "go.mod no longer exists");
            }
            return result;
        }
        Err(e) => {
            for pin in pins {
                result.refuse(&pin.uuid, e.clone());
            }
            return result;
        }
    };
    let entries = parse_replace_entries(&go_mod);
    // (uuid, module, version, socket module path) per hosted directive.
    let mut hits: Vec<(String, String, String, String)> = Vec::new();
    for pin in pins {
        let Some((module, version)) = pin.name_version() else {
            result.refuse(&pin.uuid, format!("{} is not a golang purl", pin.purl));
            continue;
        };
        let directive = entries.iter().find(|e| {
            e.module == module
                && e.rhs_module
                    .as_deref()
                    .and_then(hosted_module_uuid)
                    .is_some_and(|u| u == pin.uuid)
        });
        let Some(directive) = directive else {
            continue;
        };
        let version = directive.version.clone().unwrap_or(version);
        let socket_module = directive.rhs_module.clone().unwrap_or_default();
        hits.push((pin.uuid.clone(), module, version, socket_module));
    }
    if hits.is_empty() {
        return result;
    }
    let lookups = hits.iter().map(|(uuid, module, version, _)| async move {
        (uuid.clone(), ctx.client.go_sums(module, version).await)
    });
    let sums: std::collections::BTreeMap<String, Result<super::client::GoSums, String>> =
        futures_util::future::join_all(lookups)
            .await
            .into_iter()
            .collect();

    let mut go_mod_next = go_mod.clone();
    let mut go_sum = view.read("go.sum").await.ok().flatten();
    let go_sum_original = go_sum.clone();
    for (uuid, module, version, socket_module) in &hits {
        let sums = match sums.get(uuid) {
            Some(Ok(s)) => s,
            Some(Err(why)) => {
                result.refuse(uuid, format!("{module}@{version}: {why}"));
                continue;
            }
            None => continue,
        };
        match remove_replace_entry(&go_mod_next, module, ReplaceOwner::Hosted) {
            Ok(Some(next)) => go_mod_next = next,
            Ok(None) => {}
            Err(e) => {
                result.refuse(uuid, format!("go.mod: {e}"));
                continue;
            }
        }
        if let Some(text) = go_sum.as_deref() {
            let mut next =
                remove_module_prefix_lines(text, socket_module).unwrap_or_else(|| text.to_string());
            let upstream = format!(
                "{module} {version} {}\n{module} {version}/go.mod {}\n",
                sums.zip_h1, sums.mod_h1
            );
            if let Some(reinserted) = reinsert_lines(&next, &upstream) {
                next = reinserted;
            }
            go_sum = Some(next);
        }
        result.handled.insert(uuid.clone());
    }
    if go_mod_next != go_mod {
        view.write("go.mod", go_mod_next);
    }
    if go_sum != go_sum_original {
        if let Some(text) = go_sum {
            view.write("go.sum", text);
        }
    }
    result
}
