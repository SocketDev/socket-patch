[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-10-04 08:23 UTC (fifteenth run), main `045d7ec` (unchanged), latest release v4.0.0. Filed #765 (a vendored requirements.txt can't re-vendor to a superseding patch uuid: `pypi_requirements_already_vendored`, exit 1, while `--dry-run` previews `would_revendor`; from the uv handover). #765, #740, #721 (PR #724), #699 (PR #708), #668, #638, #604, #542, #410 and #409 are open.

## Coverage matrix

| OS | pip / Python | agent (.venv) | agent egg-info | hosted (unhashed → fragment pin) | vendored | rollback / remove | vendored → hosted takeover | system-site venv | `-r` include, lock-only | PEP 440-equivalent pin (`==1.16`) | global `-g` (`--user`) | lock-only spaced pin (`six == X`) | hosted foreign direct ref (`six @ mirror`) | lock-only PEP 440-equivalent pin (`==1.16`) | no root requirements.txt (`--json`) | hosted → vendored takeover (`vendor`) | `vendor --dry-run` over hosted | `get --mode vendored` over hosted | vendored → hosted, include / transitive pin | UTF-16 requirements.txt (hosted / lock-only) | root file used as `-c` by a sibling | vendored re-vendor to a new uuid |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.11 | pass | pass (#447 fixed) | pass | pass | pass; all-hosted-pins fail #410 | fixed on main #328 (re-verify) | fail #409 | pass (re-verified 2026-10-03, pip 20.3.4) | fixed on main #475 (re-verify) | untested | pass (re-verified 2026-10-03) | untested (OS-independent) | fail #604 (vendored, re-observed 2026-10-03) | fail #638 | pass; sole pin fail #410 | fail #668 | pass (+ hashed, CRLF, marker) | fail #699 | untested (pip reads it) | fail #740 (pip 20.3.4, 21.0.1; pass 20.2.4) | fail #765 (hashed) |
| Linux | 23.x, 24.0 / py3.11, py3.12 | pass | n/a (dist-info); 21.3.1 / 22.3.1 / 23.0.1 egg-info pass, 23.1.2 dist-info pass | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (report, hosted refusal, get / rollback / vex, `--global-prefix`, unwritable) | fixed on main #523 (re-verify) | fail #542 (pip 24.0) | fail #604 (pip 24.0) | untested (OS-independent) | untested | fail #668 (pip-independent) | untested | fail #699 (pip-independent) | untested (pip 24.3.1 / 25.1.1 read it) | pass (pip 21.1.3–24.3.1) | fail #765 (pip 24.0) |
| Linux | 26.0, 26.2.1 / py3.11, py3.13 | pass | n/a | pass (+ uv 0.8 `pip install` / `pip sync`) | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | pass (re-verified 2026-10-03, pip 26.2.1) | fixed on main #475 (re-verify) | untested | pass (re-verified 2026-10-03) | untested (OS-independent) | fail #604 (vendored, re-observed 2026-10-03) | fail #638 | pass; sole pin fail #410 | fail #668 | pass (+ hashed, CRLF, marker, BOM) | fail #699 | fail #721 | pass | untested (pip-independent) |
| macOS | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass | pass (py3.8) | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (`--user`) | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) | untested (OS-independent) | untested | untested (OS-independent) | untested | untested (OS-independent) | untested (OS-independent) | untested (pip-side, OS-independent) | untested (OS-independent) |
| Windows | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass (`Scripts/` + `Lib/`) | pass (py3.8) | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (`--user`, `%APPDATA%\Python`) | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) | untested (OS-independent) | untested | untested (OS-independent) | untested | untested (OS-independent) | untested (probe backlog) | untested (pip-side, OS-independent) | untested (OS-independent) |

pip 20.3.4 on py3.13 is blocked (no `distutils`). `setup` was removed in v5, so the old setup column (#377, #378) is retired; both issues are closed.

Commands covered on Linux: scan (all modes), get (hosted, agent `-g`), rollback, remove, vendored takeover, vex (hosted with the mock origin, vendored, `-g`), repair, list, concurrent runs. Also covered (2026-10-02): free-threaded CPython 3.13t venvs, a `.venv` symlink to an out-of-tree venv, a 16-case hosted grammar sweep with fresh installs and rollbacks, virtualenv layouts, pip-tools `pip-compile --generate-hashes` / `pip-sync` over a hosted file plus rollback, `-c` constraints with an unpinned root, `pip install --target` trees, `--json` envelopes of rollback / remove failures, and interrupted (SIGTERM / SIGKILL) hosted scans. Run ten (2026-10-03, pip 26.2.1 / py3.13 and pip 20.3.4 / py3.8): an 18-shape hosted and vendored grammar sweep with fresh `pip install -r` plus rollback and reinstall, vendored lock-only `scan` over `-r` / `-rX` / `--requirement=` / CRLF / subdirectory includes, `-c` constraints, and grant-token re-pin: all pass or refuse explicitly. Run eight (pip 24.0 / py3.11 and pip 20.3.4 / py3.8): PEP 503 name normalisation (`_` / `-` / `.` / case, venv and lock-only), duplicate and marker-split pins, BOM, no trailing newline, `--no-index` + `--find-links`, per-line `--config-settings`, `--require-hashes` with multiple and sha384 hashes, `-e` / VCS neighbours (lock-only + `vex`), symlinked root and include files, out-of-root includes, `--prefix` trees: all pass or refuse explicitly.

## Backlog

0. **Open questions for the maintainer:** (a) `vex` attests a hosted pin (six@1.16.0) from the lockfile basis when the venv holds a different version (six 1.15.0), with no warning (see the 20261002T142728Z entry). (b) The non-`-g` no-venv fallback to global site-packages (20261001T083942Z). (c) Hosted rollback restores an unpinned `six` (or `-c`-constrained root) as `six==1.16.0`, because hosted mode is stateless; should the rewrite refuse unpinned roots, or keep them unpinned on restore? (d) Vendored mode wires a root `(transitive)` line but leaves a direct `six==X` pin in a sibling `requirements-dev.txt`, so `pip install -r requirements-dev.txt` alone stays unpatched (same class as #612 / #638).
1. Re-verify #765, #740, #721 (PR #724, plus the PEP 263 latin-1 case), #699 (PR #708), #668, #638, #604, #542, #410 and #409 as fixes land. #328 / #475 re-verify on pip 20.3.4 / 26.x is still open.
1b. pip.conf `constraint =` over a rewritten root (the #740 class). The command-line `-c` and `PIP_CONSTRAINT` forms match #740's pip 20.3–21.0 boundary (verified 2026-10-04).
1c. Vendored `scan --prune` after the package leaves requirements.txt, and a re-vendor of a "(transitive)" line once #765 is fixed.
2. `get --mode hosted` over a vendored include pin (the #699 takeover through `get`), once #708 lands.
3. A Windows / macOS probe: BOM + CRLF on the patched line, the vendored path line with real pip, and a PowerShell 5.1 `pip freeze >` (UTF-16) file end to end (blocked while probe branches can't be deleted).
3b. UTF-32 BOM: re-check with the #721 fix (#724 decodes it). The PEP 263 coding line silently no-ops on main (commented on #721).
3c. PyPy venvs (`lib/pypy3.X/site-packages` is not matched by the crawler's `python3.*` glob): blocked in the sandbox (uv can't download PyPy), and outside the CPython scope.
4. Finish global (`-g`) mode: Homebrew / PEP 668 interpreters, the py launcher with several interpreters, pipx venvs (#418), non-root unwritable prefixes on CI.
5. pip 24–25 spot-checks for hosted / vendored rewrites (21.3–23.1 agent mode is done).

## Known non-bugs

- Hosted mode rewrites only the root `requirements.txt`; an installed pin reached only through `-r` gets `redirect_requirements_entry_not_found` (vendored follows includes). The lock-only discovery gap is #412.
- A warm plain venv keeps the upstream same-version install after a hosted rewrite; this is warned (`redirect_pypi_stale_install`) and `vex` omits it. The system-site-venv variant is #409.
- Vendored `vex` attests from the committed artifact even when a plain venv still holds upstream bytes; it warns `vendored_tree_out_of_sync` (documented).
- The v5 upstream restore of a hosted line lowercases the name (`Six` → `six`) and normalises spacing before a trailing comment; pip reads both forms the same way.
- Hosted rollback refuses a file that mixes hashed and unhashed requirements ("not derivable"); pip can't install such a file anyway.
- Vendored refuses `===` pins, `==X.*` wildcards and a tab before `--hash` (`pypi_requirement_not_pinned`). This is fail-closed and isn't filed (the `==1.16` zero-padding case is part of #475).
- `--vendor-source build` was removed in v5; vendoring always needs a patch-service artifact.
- `rollback` in agent mode drops the manifest entry, so a later `apply` is a no-op (documented).
- A venv directory not named `.venv` / `venv` is only found through `VIRTUAL_ENV`.
- `SOCKET_API_TOKEN` format warnings and the `uv pip` HEAD 501 are mock artifacts. `vex -o` is `--org`, not `--output`. `vex --json` requires `--output`.
- `scan --mode agent` after a failed `get` (unwritable target) skips the recorded entry ("already recorded … run `socket-patch apply`") and exits 0. This is documented, and the failed `get` itself exits 1.
- Hosted `vex` ignores hosted URLs that aren't on `patch.socket.dev`. Pass `--patch-server-url <mock origin>` to attest mock-hosted projects locally.
- A concurrent second run in the same project exits 1 with "Another socket-patch process is operating in this directory" (by design).
- A requirements.txt that v4.0.0 (or a pre-#383 build) hosted with `--hash` in an otherwise unhashed file stays in that shape on a re-scan (exit 0), so pip still fails in hash mode. This is documented in #383; `socket-patch rollback` then a re-scan rewrites it to the fragment form (verified).
- Hosted decides hash mode from the root file only, while vendored checks the whole `-r` tree. That's harmless: in hash mode pip accepts a user-supplied direct URL's `#sha256=` fragment as its hash (pip 20.3.4–26.0).
- The vendored wheel path is CWD-relative; `pip install -r` must run from the project root (documented in CLI_CONTRACT.md).
- Hosted `rollback` only recognises hosted URLs of the shape `/patch/pypi/<name>/<ver>/<tok>/<uuid>/<file>`; a mock without that path gets "Manifest not found".
- Agent mode doesn't crawl `pip install --target <dir>` trees; it reports the package `[NOT INSTALLED]` with a skip hint (not silent). Hosted works for such projects.
- In the sandbox, the CLI can't reach pypi.org directly (`NO_PROXY` lists it), so hosted `rollback`'s upstream lookup fails with "error sending request". Run with `NO_PROXY=localhost,127.0.0.1`.
- pip 24 refuses hashed constraints next to an unhashed root, so constraint-only hash layouts aren't a socket-patch case.
- A SIGKILLed scan can leave `.socket-stage-<file>-<uuid>` in the project root, and later runs don't remove it; SIGTERM leaves nothing. Not filed (inherent to SIGKILL, cross-ecosystem).

- Hosted refuses bare URL / bare path lines (no `name @`) and `${VAR}` pins with `redirect_requirements_entry_not_found`, exit 0 (the documented hosted-refusal posture).
- A hosted rollback restores a pip-equivalent line, not the original bytes (comment spacing, joined continuations, `(==X)` → `==X`, case).
- Vendored refuses a per-line option such as `--config-settings` on the patched pin, and a `name @ <url/file>` direct reference, with "not pinned to ==X" (fail-closed; the wording is imprecise). Hosted rewrites `--config-settings` lines fine.
- A symlinked `requirements.txt` or a symlinked `-r` include is refused explicitly (`redirect_symlinked_file_unsupported` / `pypi_requirements_symlink_unsupported`), and so is an include outside the project root (vendored). Nothing is written.
- Agent mode doesn't crawl `pip install --prefix <dir>` trees either (`[NOT INSTALLED]` + skip hint), same as `--target`.
- With a mock origin, hosted `rollback` / `vex` need `SOCKET_PATCH_SERVER_URL` (or `--patch-server-url`) set to it; vendored needs the mock to serve sha512 integrity.
- Lock-only cells need `VIRTUAL_ENV` pointing at an EMPTY venv: an empty `VIRTUAL_ENV=` falls back to the system dist-packages (Ubuntu's python3-six 1.16.0) and masks lock-only behaviour.
- Vendored refuses `six[extra]==X` (`pypi_extras_unsupported`), and an unpinned root pinned only through `-c constraints.txt` (`pypi_requirement_not_pinned`; the wording says "not pinned" although the constraint pins it). Both are fail-closed.
- Hosted rollback restores `===X` as `==X` and an unpinned `six` as `six==<installed>`. Hosted mode keeps no state, so the line is derived from the hosted URL (see backlog question 0c).
- A file with a single `--hash` line next to unhashed lines is already uninstallable by pip; hosted keeps that shape and rollback drops the lone hash. Garbage in, garbage out.
- `record_fetch_failed` on a hosted scan means the mock lacks the `view` route; it isn't a CLI bug.
- Agent mode doesn't patch editable installs: a PEP 660 finder (`apply_failed` "File not found") or a legacy `.egg-link` ("matched no installed package"). Both exit 1 and leave the user's source untouched (fail-closed).
- The vendored takeover's `vendor_prebuilt_required` 404 in a local harness means `--patch-server-url` rewrote the artifact host to a mock without the prebuilt routes (harness artifact).
- `get --mode vendored` over a hosted BOM file writes the vendored line without the BOM (pip reads either form); `rollback` restores the BOM.
- Agent `rollback --offline` needs the before blob in `.socket/blobs`; without it, it refuses with a `repair` hint (harness staging, not a bug).
- Hosted wheel pins under a `--no-binary :all:` / `--no-binary six` / `--only-binary :all:` option line install fine (pip 24.3.1, 26.2.1): pip doesn't apply format control to direct URLs.
- Vendored `vendor` refuses a UTF-16 requirements.txt loudly (`pypi_no_requirements`, exit 1), and `vex` warns `lockfile_unreadable`; only hosted / lock-only discovery is silent (#721).
- A hashed root requirements.txt used as `-c` by an unhashed sibling is refused by pip before any rewrite; only the unhashed form is #740.
- pip ≥ 21.1 accepts both the hosted `name @ url` and the vendored bare-path line as constraints; only pip 20.3.x–21.0.x reject them (#740).
- `vendor --offline` needs the vendoring service in v5 (`vendor_service_offline_conflict`). Local vendored repros use the `prebuilt_common` fixture server plus a `view/<uuid>` route.
- The `-c` / `PIP_CONSTRAINT` / command-line constraint forms over a hosted or vendored root fail only on pip 20.3–21.0 (same as #740); don't re-file them.
