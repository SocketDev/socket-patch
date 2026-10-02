[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-10-02 (ninth run), main `045d7ec`, latest release v4.0.0 (`96df6ae`). Filed #604 (lock-only PEP 440-equivalent pins). #328, #412, #475 and #523 were fixed on main (#503 / #530 / #478); #410 and #542 still reproduce.

## Coverage matrix

| OS | pip / Python | agent (.venv) | agent egg-info | hosted (unhashed → fragment pin) | vendored | rollback / remove | vendored → hosted takeover | system-site venv | `-r` include, lock-only | PEP 440-equivalent pin (`==1.16`) | global `-g` (`--user`) | lock-only spaced pin (`six == X`) | hosted foreign direct ref (`six @ mirror`) | lock-only PEP 440-equivalent pin (`==1.16`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.11 | pass | pass (#447 fixed) | pass | pass | pass; all-hosted-pins fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | untested | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) |
| Linux | 23.x, 24.0 / py3.11, py3.12 | pass | n/a (dist-info) | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (report, hosted refusal, get / rollback / vex, `--global-prefix`, unwritable) | fixed on main #523 (re-verify) | fail #542 (pip 24.0) | fail #604 (pip 24.0) |
| Linux | 26.0, 26.2.1 / py3.11, py3.13 | pass | n/a | pass (+ uv 0.8 `pip install` / `pip sync`) | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | untested | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) |
| macOS | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass | pass (py3.8) | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (`--user`) | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) |
| Windows | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass (`Scripts/` + `Lib/`) | pass (py3.8) | pass | pass | pass; fail #410 | fixed on main #328 (re-verify) | fail #409 | fixed on main #412 (re-verify) | fixed on main #475 (re-verify) | pass (`--user`, `%APPDATA%\Python`) | fixed on main #523 (re-verify) | untested (OS-independent) | untested (OS-independent) |

pip 20.3.4 on py3.13 is blocked (no `distutils`). `setup` was removed in v5, so the old setup column (#377, #378) is retired; both issues are closed.

Commands covered on Linux: scan (all modes), get (hosted, agent `-g`), rollback, remove, vendored takeover, vex (hosted with the mock origin, vendored, `-g`), repair, list, concurrent runs. Also covered (2026-10-02): free-threaded CPython 3.13t venvs, a `.venv` symlink to an out-of-tree venv, a 16-case hosted grammar sweep with fresh installs and rollbacks, virtualenv layouts, pip-tools `pip-compile --generate-hashes` / `pip-sync` over a hosted file plus rollback, `-c` constraints with an unpinned root, `pip install --target` trees, `--json` envelopes of rollback / remove failures, and interrupted (SIGTERM / SIGKILL) hosted scans. Run eight (pip 24.0 / py3.11 and pip 20.3.4 / py3.8): PEP 503 name normalisation (`_` / `-` / `.` / case, venv and lock-only), duplicate and marker-split pins, BOM, no trailing newline, `--no-index` + `--find-links`, per-line `--config-settings`, `--require-hashes` with multiple and sha384 hashes, `-e` / VCS neighbours (lock-only + `vex`), symlinked root and include files, out-of-root includes, `--prefix` trees: all pass or refuse explicitly.

## Backlog

0. **Open question for the maintainer:** `vex` attests a hosted pin (six@1.16.0) from the lockfile basis when the venv holds a different version (six 1.15.0), with no warning. The copy lookup is keyed by name@version, so the drifted copy reads as "not installed". Likely cross-ecosystem (see the 20261002T142728Z entry). Also the non-`-g` no-venv fallback to global site-packages (20261001T083942Z).
1. Re-verify #604, #542, #410 and #409 as fixes land. The fixed columns (#328, #412, #475, #523) were checked on Linux only (repo tests plus the venv cells); re-run them on pip 20.3.4 / 26.x.
2. Rebuild the mock with `view` / `blob` routes; vendored lock-only PEP 440 pins; vendored → hosted takeover with real pip.
3. pip 26.x / 20.3.4 grammar sweep against the #572 shared grammar.
4. Finish global (`-g`) mode: Homebrew / PEP 668 interpreters, the py launcher with several interpreters, pipx venvs (#418), non-root unwritable prefixes on CI.
5. A Windows / macOS probe for BOM + CRLF on the patched line.

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
