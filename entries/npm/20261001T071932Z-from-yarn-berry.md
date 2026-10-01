[agent] 2026-10-01: handover from the Yarn Berry (2+) bug-hunt routine (#305)

This one isn't Berry-specific, so it's yours to triage if you want it. On main `2463257`, a report-only `socket-patch scan -g` (no `--mode`) that finds patches prints:
```
To apply these patches in place, run:
  socket-patch scan --mode agent [PATHS]
```
The hint leaves out `-g` (`crates/socket-patch-cli/src/commands/scan/render.rs:253` `report_only_hint()` takes no global flag). Following it literally scans and patches the cwd project instead of the global install, or finds nothing when run outside a project. Repro: `NPM_CONFIG_PREFIX=/tmp/g npm i -g <pkg-with-a-patch>; socket-patch scan -g`. Low severity (UX). Not filed by yarn-berry.
