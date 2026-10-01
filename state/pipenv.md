[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

The routine runs every 6 hours. Each run adds one comment here with the socket-patch commit it tested, the OS × Pipenv-version × mode cells it covered, the issues it filed, updated or closed, and what it plans to probe next. The routine treats this thread as its only memory.

Last run: 2026-10-01 15:41Z, main `6e7ef74` (v5 + #330 Poetry venv reorder; CLI 4.0.0).

## Coverage matrix

Cells marked v5 were re-run on `2463257` (v5: no hosted ledger, upstream-restore rollback, service-artifact vendoring).

| OS | Pipenv | agent (OOT venv) | agent (stray venv/ or .venv+IN_PROJECT=0) | hosted (all categories, sync, --deploy, rollback) | hosted + OOT venv stale warning / VEX | hosted live-lock conflict + requirements.txt | vendored (lock-only, repair, revert) | hosted → vendored | vendored → hosted | VIRTUAL_ENV w/ IGNORE_VIRTUALENVS / PIPENV_ACTIVE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 2018.11.26 | untested | fail #334 (venv/) | pass v5 (+CRLF) | untested | fail #333 | pass v5 | untested | untested | fail #384 |
| Linux | 2022.12.19 | untested | untested | pass v5 (+relock) | untested | fail #333 | untested | untested | untested | untested |
| Linux | 2023.12.1 | pass | fail #334 | pass v5 (+relock) | pass; fail #334/#384 shapes (false VEX) | fail #333 | untested | untested | untested | fail #384 (agent + hosted VEX) |
| Linux | 2026.8.0 | pass v5 | fail #334 v5 | pass v5 (+CRLF) | pass; fail #334/#384 shapes (false VEX) | fail #333 v5 | pass v5 | pass v5 | fail #328 v5 | fail #384 (agent + hosted VEX) |
| macOS | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| macOS | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Linux | 2018.11.26 `-g` (`install --system`) | scan -g report pass; `-g --mode hosted` refused exit 2 pass; `-g --apply` / vex / rollback pass | | | | | | | | |
| Linux | 2023.12.1 `-g` (`install --system`) | scan -g report (in/out of project), hosted refused exit 2, `-g --apply` / vex / rollback, SOCKET_GLOBAL, `--global-prefix` pass; `rollback -g` / `remove -g` / `get -g --mode hosted\|vendored` unwind or rewire the cwd project's Pipfile.lock (#445 / #436) | | | | | | | | |
| Linux | 2026.8.0 `-g` (`install --system`) | scan -g report (in/out of project), SOCKET_GLOBAL, `--global-prefix` pass; hosted refused exit 2 pass; `-g --apply` / `get -g` / vex / rollback pass | no-`-g` agent scan in a venv-less project patches the global interpreter (needs a maintainer decision, see Known non-bugs) | | | | | | | |
| Linux | 9.1.0 / 11.10.4 (py3.8) | untested | untested | pass v5 (`path` ref, `--deploy`, rollback; 11 byte-exact) | pass on 11 (stale warning, VEX `not_applied`) | untested | refused (documented) | n/a | n/a | untested |
| macOS / Windows | 7–11 | untested | untested | untested | untested | untested | refused (documented) | n/a | n/a | untested |
| any | 0–6 | untested | n/a | refused (documented) | n/a | n/a | refused (documented) | n/a | n/a | untested |

Policy (socket.yml) cells, Linux 2026.8.0 hosted monorepo: every filter passes; `get <uuid>` skips the `policy_bypassed` warning (fail #453, re-checked on `6e7ef74`). socket.yml × `--package` / `--min-severity` / `--max-new-patches` intersections: pass (`6e7ef74`). Concurrent hosted scans: pass. SIGKILL mid hosted / vendored run: pass. Mirror / env-var source rollback refusal: pass (documented).

Named category (`[docs]`) hosted + `sync --categories` / `install --deploy --categories` / vex / rollback: pass on 2022.12.19, 2023.12.1 and 2026.8.0; vendored: pass on 2022.12.19 and 2023.12.1 (`6e7ef74`). Non-registry entries (`path`, `file` URL, `git`): hosted refuses with `redirect_pipenv_refused`, vendored with `pypi_pipenv_source_already_exists`, vex attests nothing: pass on 2026.8.0.

`-g` / agent on an unwritable prefix or a root-owned `.venv`, as a non-root user (2026.8.0): human mode fails loudly (pass); the `--json` envelope drops the failure (#424); a rerun exits 0 unpatched (#454).

macOS/Windows rows are from the 2026-09-30 probes on `f6b7fb9`. No probe ran on v5 because branch deletion through the git proxy still fails (re-checked 2026-10-01 09:30Z); `bughunt/pipenv/20260930-venv-discovery` and `bughunt/pipenv/20260930-virtualenv` still need a maintainer to delete them.

## Backlog

1. **Maintainer request (global `-g` mode):** Linux is covered on 2018.11.26, 2023.12.1 and 2026.8.0, and the unwritable prefix as a non-root user is done (#424 / #454). Still to do: macOS and Windows (blocked: no probe), 2022.12.19 (use `pipenv --python <py3.10>`, not `PIPENV_PYTHON`), and a `--global-prefix` with spaces or unicode. Full checklist in the 20261001T040000Z entry.
2. A macOS/Windows probe for hosted + VEX under the #334 / #384 shapes, and hosted / vendored on 2018 / 2022 there (CRLF on Windows).
3. Pipenv 7–11 agent mode with an out-of-tree venv (py3.8), and the `PIPENV_PYTHON` venv-name suffix on 11.
4. A non-normalized `PIPENV_PIPFILE` (`./Pipfile`, `sub/../Pipfile`, another directory): Pipenv hashes `os.path.abspath`, while the crawler hashes `cwd.join(raw)` (`python_crawler.rs:990`).
5. `pipenv requirements` / `pipenv verify` after a hosted redirect, on 2023.12.1 and 2026.8.0.

## Known non-bugs

- Pipfile.lock with `pipfile-spec` < 6 (Pipenv 0–6): hosted is refused (`redirect_pipenv_skipped`) and vendored is refused (`pypi_pipenv_spec_unsupported`). Documented.
- Vendored on Pipenv 7–11 is refused (`pypi_pipenv_installer_unsupported`). Documented.
- A warm venv is never reinstalled by `pipenv install` / `sync` / `--deploy`; the stale-install warning is the designed remedy. Documented.
- `pipenv lock` / `update` drops the redirected reference (silent unpatch until re-scan). Documented.
- Pipenv 2023+ don't hash-check local wheels, so vendored carries `vendor_integrity_unverified`. Documented.
- The CLI doesn't walk up to a parent Pipfile or follow `PIPENV_PIPFILE`. Documented.
- `rollback` drops manifest entries, so a later `apply` is a no-op. Documented.
- Pipenv 2026.8.0 crashes on `$VAR` inside `WORKON_HOME`. That's Pipenv's bug.
- `vendor_fetch_failed` against pypi.org in the sandbox is rustls vs the proxy CA; use a `SOCKET_PYPI_JSON_API` forwarder.
- `VIRTUAL_ENV` set with no `PIPENV_IGNORE_VIRTUALENVS` / `PIPENV_ACTIVE`: Pipenv uses the activated venv too, so socket-patch patching it is correct.
- `.venv` file pointer: a relative path is joined to the project directory and an empty file means the default placement. Matches Pipenv 2026.8.0.
- v5 `rollback` on a project with no manifest, ledger or hosted pin exits 1 "Manifest not found". Documented (CLI_CONTRACT, truly-empty project).
- v5 hosted rollback refuses when the entry's index isn't PyPI, or when offline. Documented (the upstream-restore refusals).
- Vendored drops the Pipfile.lock entry's `index` key. Harmless for a local wheel, and rollback restores it.
- `rollback <path>` targets select installed copies, not hosted project directories; use `--cwd`. Documented, and cross-PM anyway.
- Mock-API notes: vendoring needs `integrity.sha512` on the `tarball` artifact; the view needs `files`; agent mode needs `/patches/blob/<afterHash>`.
- **Open question for maintainers (not filed):** with no venv found and a Python project marker present, the crawler deliberately falls back to the global interpreter (`python_crawler.rs` `get_site_packages_paths`). So an agent-mode `scan` without `-g`, in a Pipenv project whose venv isn't created yet (or is `install --system`), patches the global site-packages in place. That's right for Docker `--system`, but it contradicts the `-g` checklist ("a scan without `-g` must never touch it"). Filing waits on a maintainer decision.
- A Pipenv 9.1.0 lock written with `"hashes": []` (seen in the sandbox) comes back from hosted rollback with PyPI's full hash list: not byte-exact, but a valid and stricter registry entry. The upstream restore re-derives hashes by design.
- Hosted rollback refuses a `_meta.sources` URL written as `${PIP_INDEX_URL}`, even when the variable points at pypi.org; env vars aren't expanded. Documented and fail-closed, with the `git checkout` remedy.
- `scan -g` counts every ecosystem plus the well-known system Python paths (`/usr/lib/python3*`, `/usr/local/lib/python3*`, `~/.local`). That's by design; Pipenv's WORKON_HOME venvs aren't included.
- `--prune` warns that it has no effect with `--mode hosted`. Documented.
- Non-registry Pipfile.lock entries (`path`, `file` URL, `git`) are refused in hosted (warning, exit 0) and vendored (`pypi_pipenv_source_already_exists`, exit 1). By design; the "no Pipfile beside the lock" wording in the hosted detail is #333.
- Mock-API note: the batch mock must filter by the requested purls, and `by-package` must carry `vulnerabilities[*].severity`, or `--package` / `--min-severity` cells give false failures.
