//! Deno — deliberately always empty.
//!
//! Neither mode exists for Deno: there is no hosted rewriter
//! (`commands/scan/hosted.rs:78-80` refuses the ecosystem) and no vendored
//! backend (`vendor::path::ecosystem_dir_for_purl` maps `pkg:jsr/…` to
//! `None` — there is no `.socket/vendor/jsr/`). A `deno.lock` can therefore
//! never carry a Socket patch reference, and a Socket-looking url in one is
//! a user's own import. The extractor exists so the per-ecosystem coverage is
//! explicit and a future backend has an obvious home; Deno patches attest
//! only through the manifest + installed tree (agent mode, `setup.manual`).

use super::{DiscoverCtx, Discovery};

pub(crate) async fn extract(_ctx: &DiscoverCtx<'_>, _out: &mut Discovery) {}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    /// Even a lock that names a patch-server url yields nothing.
    #[tokio::test]
    async fn deno_lock_never_yields_refs() {
        let p = Project::new();
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        p.write(
            "deno.lock",
            format!(r#"{{"version":"4","remote":{{"{url}":"abc"}}}}"#),
        );
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
        // And the full orchestrator agrees (no other extractor claims it).
        let all = p.discover().await;
        assert!(all.refs.is_empty(), "{:?}", all.refs);
    }
}
