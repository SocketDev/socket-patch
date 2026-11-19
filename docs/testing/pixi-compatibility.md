# pixi compatibility backtests

`socket-patch` patches the Python packages of a [pixi](https://pixi.sh) project in
place (agent mode), in every environment pixi installs under `.pixi/envs`. Hosted and
vendored mode change nothing in a pixi project; see
[PyPI: pixi projects](../ecosystems.md#pypi-pixi-projects) for why and for the
commands.

The backtest uses real pixi releases, real conda-forge and PyPI artifacts and the
public Socket patch service. A scan that reports a patch is not an installation
result: the harness compares the bytes in the environment with the published patch.

## What is checked

`scripts/backtest-pixi.py` downloads each pinned pixi release (GitHub release asset,
SHA-256 pinned in the script), installs a one-dependency project (urllib3 1.26.18,
which has a public free-tier patch) and runs `socket-patch` from the project root
with no `pixi run` or `pixi shell` around it, as a CI step after `pixi install`
does.

| Mode | Checks |
| --- | --- |
| agent | `scan --mode agent` exits 0 and records the patch; the patched files of every environment hash to the patch's `afterHash`; no project file changes; pixi's package cache still holds the upstream bytes (an environment's files are hard links into it on Linux); `apply` is idempotent; `pixi install` and `pixi run` keep the patch and the environment's Python imports the package; `vex` attests it; rebuilt environments hold the upstream bytes again and `apply` restores the patch; `rollback` restores every byte |
| hosted | `scan` (default mode) exits 0, finds the package, changes no project file and warns `redirect_pypi_pixi_project` |
| vendored | `scan --mode vendored` finds the package, refuses it (`pypi_no_requirements` or `pypi_pyproject_only`, exit 1) and writes nothing |
| fresh | With pixi's files, a `pyproject.toml` and no environment installed, a decoy interpreter holding one package is first on `PATH`: nothing is read from it. With a `requirements.txt` added, which pip installs from, it is read (dry runs only) |

| Shape | Project |
| --- | --- |
| `conda` | `pixi.toml`, the package from conda-forge (how most Python packages of a pixi project arrive) |
| `pypi` | The same release from PyPI through `[pypi-dependencies]`, installed by pixi's uv |
| `pyproject` | The pixi manifest in `pyproject.toml` (`[tool.pixi.*]`) |
| `multi-env` | Two environments; both hold the package and both are patched |
| `detached` | `detached-environments = true`: the environments live under pixi's cache and `.pixi/envs` is a link (pixi 0.30 and later) |

## Matrix

| Tier | Where | Cells |
| --- | --- | --- |
| Path-filtered PRs, push to main, manual | [`pixi-compatibility.yml`](../../.github/workflows/pixi-compatibility.yml) | Linux × pixi {0.20.1, 0.39.5, 0.63.2, 0.84.2} × every shape and mode; macOS arm64 × {0.20.1, 0.84.2} on push to main |

pixi 0.20.1 is the oldest release the harness drives (it needs `pixi install -e
<environment>` and a `pyproject.toml` manifest). Every release from 0.20.1 on keeps
environments at `.pixi/envs/<name>`.

Hermetic coverage, with no pixi and no network, runs in every PR: the crawler's unit
tests (`crawlers::pixi_env`, `crawlers::python_crawler`), the in-process scan tests
(`in_process_python_envs`) and the apply tests (`apply::e2e_safety_advisories`).

## Running it

```sh
cargo build -p socket-patch-cli
scripts/backtest-pixi.py --socket-patch target/debug/socket-patch \
    --socket-patch-revision "$(git rev-parse HEAD)" --output /tmp/pixi-backtest
```

`--versions`, `--shapes` and `--modes` narrow the run, and `--pixi-dir` takes
prefetched binaries (`<dir>/<version>/pixi`). Each cell writes its logs and a
`result.json` under `<output>/cases/`; `summary.md` is the table of all of them. The
run needs network access (conda-forge, PyPI, GitHub releases, `patch.socket.dev`)
and no Socket token. POSIX only.

## Limits

- **Conda builds that differ from the PyPI release.** A patch applies to a conda
  package when the files it replaces are the PyPI release's bytes. That holds for
  conda-forge's pure-Python builds; a compiled extension module is built separately
  for conda and never matches. The backtest covers a pure-Python package.
- **conda packages that are not Python distributions** (OpenSSL, libxml2, the
  `ca-certificates` bundle) are outside what socket-patch patches.
- **Windows** is not in the matrix. Discovery uses the conda layout there
  (`Lib\site-packages`), covered by the unit tests; a detached environment has no
  `.pixi/envs` link on Windows and is found only under `pixi run`.
