[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-10-02 (sixth run), main `61cfb9b`, latest release v4.0.0 (`96df6ae`). New this run: #523 (lock-only discovery misses spaced exact pins).

## Coverage matrix

| OS | pip / Python | agent (.venv) | agent egg-info | hosted (unhashed → fragment pin) | vendored | rollback / remove | vendored → hosted takeover | system-site venv | `-r` include, lock-only | PEP 440-equivalent pin (`==1.16`) | global `-g` (`--user`) | lock-only spaced pin (`six == X`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.11 | pass | pass (#447 fixed) | pass | pass | pass; all-hosted-pins fail #410 | fail #328 | fail #409 | fail #412 | fail #475 | untested | fail #523 |
| Linux | 23.x, 24.0 / py3.11, py3.12 | pass | n/a (dist-info) | pass | pass | pass; fail #410 | fail #328 | fail #409 | fail #412 | fail #475 | pass (report, hosted refusal, get / rollback / vex, `--global-prefix`, unwritable) | fail #523 (pip 24.0) |
| Linux | 26.0, 26.2.1 / py3.11, py3.13 | pass | n/a | pass (+ uv 0.8 `pip install` / `pip sync`) | pass | pass; fail #410 | fail #328 | fail #409 | fail #412 | fail #475 | untested | fail #523 |
| macOS | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass | pass (py3.8) | pass | pass | pass; fail #410 | fail #328 | fail #409 | fail #412 | fail #475 | pass (`--user`) | fail #523 |
| Windows | 20.3.4 / py3.8; 26.2.1 / py3.13 | pass (`Scripts/` + `Lib/`) | pass (py3.8) | pass | pass | pass; fail #410 | fail #328 | fail #409 | fail #412 | fail #475 | pass (`--user`, `%APPDATA%\Python`) | fail #523 |

pip 20.3.4 on py3.13 is blocked (no `distutils`). `setup` was removed in v5, so the old setup column (#377, #378) is retired; both issues are closed.

Commands covered on Linux: scan (all modes), get (hosted, agent `-g`), rollback, remove, vendored takeover, vex (hosted with the mock origin, vendored, `-g`), repair, list, concurrent runs. Also covered (2026-10-02): virtualenv layouts, pip-tools `pip-compile --generate-hashes` / `pip-sync` over a hosted file plus rollback, `-c` constraints with an unpinned root, `pip install --target` trees, `--json` envelopes of rollback / remove failures, and interrupted (SIGTERM / SIGKILL) hosted scans.

## Backlog

1. Re-verify #475 (after #478), #328 (after #503) and #523 as fixes land; check lock-only `vex` with spaced pins (`vex/discover/pypi_other.rs` shares `exact_pin`). Then lock-only discovery of `six==1.16` once #475 is fixed.
2. **Maintainer request (mostly done):** global (`-g`) mode. Left: Homebrew / PEP 668 interpreters, py launcher with several interpreters, pipx venvs (#418), non-root unwritable prefixes on CI. Open question for the maintainer: the non-`-g` no-venv fallback to global site-packages (see the 20261001T083942Z entry; it also makes a lock-only `vex` omit packages the system Python has unpatched, and it confounds lock-only tests when the system has the same version).
3. Other lock-only grammar gaps near #523: spaced `==` on `\` continuations, `--hash` before the marker, `${VAR}` lines, `-e` / VCS lines next to a patched pin.
4. `pip install --prefix` trees; a `.venv` symlink to an out-of-tree venv.
5. Re-verify #409 / #410 / #412 as fixes land.

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
