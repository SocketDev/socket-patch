"""Offline regressions for Poetry case retries, including the real case flow."""

import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error


spec = importlib.util.spec_from_file_location(
    "backtest_poetry_retry", Path(__file__).parents[1] / "backtest-poetry.py")
poetry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poetry)

TRANSPORT = "requests.exceptions.ConnectionError: Connection reset by peer"


def operation(rc=1, out="", err=TRANSPORT):
    run = object.__new__(poetry.Run)
    run.cmd, run.rc, run.out, run.err = ["fixture-command"], rc, out, err
    return run


def exercise_case(transport_site):
    # Exercise the production nested backtest/check/require/pass-reduction
    # functions without running main's native-tool bootstrap or worker pool.
    # Only command effects, environment setup and byte oracles are stubbed.
    source = Path(poetry.__file__)
    main = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    functions = [n for n in main.body if isinstance(n, ast.FunctionDef)]
    ns = dict(vars(poetry))
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), ns)
    oot = transport_site.startswith("oot_")
    job = ("2.4.3", "direct", "agent-oot" if oot else "hosted")
    pristine = b"# pristine lock\n"
    patched = (b'type = "url"\nurl = "https://patch.socket.dev/fixture"\n'
               b'hash = "sha256:' + b"a" * 64 + b'"\n')
    churn = transport_site in {
        "informational_relock", "expected_tamper_failure", "successful_install_warning",
        "later_transport_exception", "rescan_churn_transport", "rescan_churn_json_transport",
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = root / "original"
        original.mkdir()
        (original / "poetry.lock").write_bytes(pristine)
        (original / "pyproject.toml").write_text("[tool.poetry]\nname='fixture'\n")
        ns.update(root=root, cli=Path("/mock/socket-patch"), env={}, upstream_files=[])
        after, before = {"urllib3/util/retry.py": "after"}, {"urllib3/util/retry.py": "before"}
        ns["native_lock"] = lambda *args: original
        ns["make_venv"] = lambda tool, venv, *args, **kwargs: venv.mkdir(parents=True, exist_ok=True)
        ns["record_hashes"] = lambda *args: (after, before, "fixture-uuid")
        calls, rows, command_logs = [], [], []

        def manifestless_vex(case, fresh, mode, uuid, lock, check, info):
            # A failed fresh install cannot establish the installed bytes
            # required by subsequent attestation. This must not run after
            # that terminal transport failure and invent another cause.
            installed = not (len(calls) == 1 and transport_site == "required_fresh_transport")
            check("vexManifestDeleted", installed)
            check("vexLedgerOffline", installed)

        ns["manifestless_vex"] = manifestless_vex

        def oracle(python, names, project, log):
            if oot and Path(log).name == "oracle-4.log":
                return before.copy()
            if len(calls) == 1:
                if transport_site == "required_install_transport" and Path(log).name == "oracle-1.log":
                    return {}  # The failed installer left the package absent.
                if transport_site == "required_fresh_transport" and Path(log).name == "fresh-oracle.log":
                    return {}
            return after.copy()

        ns["oracle"] = oracle

        class FakeRun(poetry.Run):
            def __init__(self, cmd, cwd, env, log, timeout=None):
                self.cmd = list(map(str, cmd))
                self.rc, self.out, self.err = 0, "{}", ""
                log, project = Path(log), Path(cwd)
                command_logs.append(log.name)
                first = len(calls) == 1
                if log.name == "env-info.log":
                    venv = root / "oot-venv"
                    (venv / "bin").mkdir(parents=True, exist_ok=True)
                    (venv / "bin/python").touch()
                    self.out = str(venv)
                elif log.name == "scan-bare-dryrun.log":
                    self.out = json.dumps({"packages": [{"purl": ns["PURL_BASE"]}], "apply": {"found": 1}})
                    if first and transport_site == "oot_prior_functional_failure":
                        self.out = "{}"
                elif log.name == "scan-apply.log":
                    if first:
                        self.out = json.dumps({"error": TRANSPORT})
                    else:
                        manifest = project / ".socket/manifest.json"
                        manifest.parent.mkdir(parents=True, exist_ok=True)
                        manifest.write_text('{"patches": {"fixture": {}}}')
                        self.out = json.dumps({"apply": {"applied": 1}})
                elif log.name == "scan.log":
                    if first and transport_site == "required_scan_json_transport":
                        self.out = json.dumps({"status": "error", "error": {"message": TRANSPORT}})
                    else:
                        (project / "poetry.lock").write_bytes(patched)
                        self.out = json.dumps({"status": "success", "redirect": {"redirected": 1, "warnings": []}})
                elif log.name == "rescan.log":
                    self.out = json.dumps({"status": "success", "redirect": {"redirected": 0, "warnings": []}})
                    if first and churn:
                        (project / "poetry.lock").write_bytes(patched + b"# unwanted churn\n")
                    if first and transport_site == "rescan_churn_transport":
                        self.rc, self.err = 1, TRANSPORT
                    if first and transport_site == "rescan_churn_json_transport":
                        self.out = json.dumps({"error": TRANSPORT})
                elif log.name == "install-warm.log":
                    (project / "poetry.lock").write_bytes(patched)
                    if first and transport_site == "successful_install_warning":
                        self.err = "WARNING: Retrying after " + TRANSPORT + "\nSuccessfully installed urllib3"
                elif first and ((log.name == "install.log" and transport_site == "required_install_transport")
                                or (log.name == "fresh-install.log" and transport_site == "required_fresh_transport")):
                    self.rc, self.err = 1, TRANSPORT
                elif log.name == "tamper-install.log":
                    self.rc = 1
                    self.err = TRANSPORT if first and transport_site == "expected_tamper_failure" else "Hash mismatch"
                elif log.name == "relock.log" and first and transport_site == "informational_relock":
                    self.rc, self.err = 1, TRANSPORT
                elif log.name == "reinstall.log" and first and transport_site in {"later_transport_exception", "required_reinstall_transport"}:
                    self.rc, self.err = 1, TRANSPORT
                elif log.name == "rollback.log":
                    if first and transport_site == "required_rollback_transport":
                        self.rc, self.err = 1, "API request failed with status 503: unavailable"
                    elif first and transport_site == "required_rollback_json_transport":
                        self.out = json.dumps({"error": "API request failed with status 503: unavailable"})
                    else:
                        (project / "poetry.lock").write_bytes(pristine)
                        (project / ".socket/manifest.json").unlink(missing_ok=True)
                        self.out = json.dumps({"hosted": {"reverted": [ns["PURL_BASE"]]}})
                log.write_text(f"$ {' '.join(self.cmd)}\n# exit {self.rc}\n--- stdout\n{self.out}\n--- stderr\n{self.err}")

        ns["Run"] = FakeRun

        def run_case(the_job):
            calls.append(the_job)
            row = ns["backtest"](the_job)
            rows.append(json.loads(json.dumps(row)))
            return row

        sleeps = []
        kind, payload = ns["retry_transport"](
            run_case, job, ns["case_dir"](job), root, sleep=sleeps.append)
        return {"kind": kind, "payload": payload, "attempts": len(calls),
                "rows": rows, "sleeps": sleeps, "commands": command_logs}


class PoetryRetryFlowTests(unittest.TestCase):
    def test_unrelated_transport_cannot_hide_a_required_failure(self):
        for site in ("informational_relock", "expected_tamper_failure",
                     "successful_install_warning", "later_transport_exception"):
            with self.subTest(site=site):
                result = exercise_case(site)
                self.assertEqual((result["attempts"], result["sleeps"]), (1, []), result)
                self.assertIs(result["payload"].get("passed"), False, result)
                self.assertIs(result["payload"]["checks"]["rescanIdempotent"], False, result)

    def test_rescan_transport_does_not_excuse_changed_files(self):
        for site in ("rescan_churn_transport", "rescan_churn_json_transport"):
            with self.subTest(site=site):
                result = exercise_case(site)
                self.assertEqual((result["attempts"], result["sleeps"]), (1, []), result)
                self.assertFalse(result["payload"]["checks"]["rescanIdempotent"], result)

    def test_required_transport_retries_including_dependent_oracles(self):
        for site in ("required_install_transport", "required_fresh_transport", "required_reinstall_transport",
                     "required_rollback_transport", "required_scan_json_transport", "required_rollback_json_transport"):
            with self.subTest(site=site):
                result = exercise_case(site)
                self.assertEqual((result["kind"], result["attempts"], result["payload"].get("passed")),
                                 ("row", 2, True), result)
                self.assertEqual(result["sleeps"], [10], result)
                if site == "required_install_transport":
                    self.assertFalse(result["rows"][0]["checks"]["installedBytesPatched"], result)
                if site == "required_fresh_transport":
                    self.assertNotIn("vexManifestDeleted", result["rows"][0]["checks"], result)
                if site.startswith("required_rollback"):
                    self.assertFalse(result["rows"][0]["checks"]["rollbackRestoresLockBytes"], result)

    def test_out_of_tree_apply_transport_retries_without_a_manifest(self):
        result = exercise_case("oot_apply_transport")
        self.assertEqual((result["kind"], result["attempts"], result["payload"].get("passed")),
                         ("row", 2, True), result)
        self.assertNotIn("survivesRepeatInstall", result["rows"][0]["checks"], result)

    def test_out_of_tree_transport_preserves_prior_discovery_failure(self):
        result = exercise_case("oot_prior_functional_failure")
        self.assertEqual((result["attempts"], result["sleeps"]), (1, []), result)
        self.assertFalse(result["payload"]["checks"]["bareScanSeesPoetryVenv"], result)


class PoetryRetryClassificationTests(unittest.TestCase):
    def test_successful_installer_retry_warnings_are_not_terminal(self):
        self.assertIsNone(poetry.operation_transport_failure(operation(rc=0)))
        recovered = "WARNING: Retrying after " + TRANSPORT + "\nDependency resolution failed"
        self.assertIsNone(poetry.operation_transport_failure(operation(err=recovered)))

    def test_zero_exit_cli_errors_are_structured_and_terminal(self):
        for envelope in ({"error": {"message": TRANSPORT}},
                         {"warnings": [{"code": "api_batch_failed", "detail": TRANSPORT}]},
                         {"vendor": {"events": [{"action": "skipped", "errorCode": "download_failed", "reason": TRANSPORT}]}}):
            with self.subTest(envelope=envelope):
                self.assertTrue(poetry.operation_transport_failure(operation(rc=0, out=json.dumps(envelope), err="")))
        for envelope in ({"status": "success", "detail": TRANSPORT},
                         {"warnings": [{"code": "unrelated", "detail": TRANSPORT}]},
                         {"action": {"unexpected": "shape"}}):
            with self.subTest(envelope=envelope):
                self.assertIsNone(poetry.operation_transport_failure(operation(rc=0, out=json.dumps(envelope))))
        self.assertIsNone(poetry.operation_transport_failure(operation(rc=0, out="not JSON")))

    def test_http_exceptions_retry_only_transient_statuses(self):
        for code in (400, 401, 403, 404, 429, 500, 503):
            with self.subTest(code=code):
                error = urllib.error.HTTPError("https://example.test", code, "fixture", {}, None)
                self.assertEqual(bool(poetry.exception_transport_failure(error)), code == 429 or code >= 500)
        self.assertTrue(poetry.exception_transport_failure(urllib.error.URLError(ConnectionResetError("reset"))))
        self.assertIsNone(poetry.exception_transport_failure(RuntimeError(TRANSPORT)))

    def test_no_failed_required_checks_cannot_trigger_a_row_retry(self):
        for checks in ({}, {"warmInstallReplacesUpstream": False}, {"lockOnlyVendorApplies": False}):
            with self.subTest(checks=checks), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                row = {"passed": False, "checks": checks, "transportFailures": dict.fromkeys(checks, TRANSPORT)}
                calls = []
                kind, payload = poetry.retry_transport(lambda job: calls.append(job) or row,
                                                       ("2.4.3", "direct", "hosted"), root / "case", root,
                                                       sleep=lambda seconds: self.fail("unexpected retry"))
                self.assertEqual((kind, len(calls)), ("row", 1))
                self.assertIs(payload, row)


if __name__ == "__main__":
    unittest.main()
