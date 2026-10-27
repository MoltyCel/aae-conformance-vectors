"""Tests for the Python runner (and, where Node and a built TypeScript runner are present,
for its parity with the TypeScript runner).

Run from the repository root:

    pip install cryptography jcs pytest
    python3 -m pytest runner/python/tests/
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
RUNNER_PATH = os.path.join(ROOT, "runner", "python")
REFERENCE = os.path.join(ROOT, "adapters", "python-reference", "adapter.py")
FAULTY = os.path.join(ROOT, "runner", "test-adapters", "faulty.py")
SKELETON_PY = os.path.join(ROOT, "adapters", "skeleton-python", "adapter.py")
SKELETON_JS = os.path.join(ROOT, "adapters", "skeleton-js", "adapter.mjs")
TS_CLI = os.path.join(ROOT, "runner", "ts", "dist", "cli.js")

PY = shlex.quote(sys.executable)


def run(impl: str, *args: str, timeout: float = 300):
    env = dict(os.environ, PYTHONPATH=RUNNER_PATH)
    proc = subprocess.run([sys.executable, "-m", "aae_conformance", "--impl", impl, *args],
                          capture_output=True, text=True, env=env, cwd=ROOT, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def faulty(mode: str) -> str:
    return f"{PY} {shlex.quote(FAULTY)} {mode}"


def summary(stdout: str) -> str:
    return stdout.strip().splitlines()[-1]


# --------------------------------------------------------------------- the passing case

def test_reference_adapter_passes_all_83(tmp_path):
    report = tmp_path / "report.json"
    code, out, _ = run(f"{PY} {shlex.quote(REFERENCE)}", "--json", str(report))
    assert code == 0, out
    assert summary(out) == "83/83 passed"
    assert "native   15/15 passed" in out
    assert "enforce  26/26 passed" in out
    assert "resume   42/42 passed" in out
    data = json.loads(report.read_text())
    assert data["ok"] is True
    assert data["families"] == {"native": {"passed": 15, "total": 15},
                                "enforce": {"passed": 26, "total": 26},
                                "resume": {"passed": 42, "total": 42}}
    assert all(r["status"] == "PASS" for r in data["results"])


@pytest.mark.parametrize("family,count", [("native", 15), ("enforce", 26), ("resume", 42)])
def test_family_filter(family, count):
    code, out, _ = run(f"{PY} {shlex.quote(REFERENCE)}", "--family", family)
    assert code == 0
    assert summary(out) == f"{count}/{count} passed"


# --------------------------------------------------------------------- wrong answers

def test_wrong_result_fails_every_vector(tmp_path):
    report = tmp_path / "report.json"
    code, out, _ = run(faulty("wrong-result"), "--json", str(report))
    assert code == 1
    assert summary(out) == "0/83 passed"
    assert 'result "REJECT", expected "ACCEPT"' in out
    assert 'verdict "DENY", expected "PERMIT"' in out
    data = json.loads(report.read_text())
    assert data["ok"] is False and data["passed"] == 0


def test_resume_vectors_go_out_as_native_and_enforce_requests():
    # Resume vectors reuse the two request shapes: the R05 cells carry a kernel and are
    # sent as enforce_check, the other 39 as native requests. Both kinds must fail when
    # the answer is wrong.
    code, out, _ = run(faulty("wrong-result"), "--family", "resume")
    assert code == 1
    assert summary(out) == "0/42 passed"
    assert 'verdict "PERMIT", expected "DENY"' in out
    assert 'result "ACCEPT", expected "REJECT"' in out
    code, out, _ = run(faulty("wrong-step"), "--family", "resume")
    assert summary(out) == "3/42 passed"


def test_wrong_step_fails_native():
    code, out, _ = run(faulty("wrong-step"), "--family", "native")
    assert code == 1
    assert summary(out) == "0/15 passed"
    assert "verification_step 8, expected 7" in out


def test_wrong_digest_fails_every_record():
    code, out, _ = run(faulty("wrong-digest"), "--family", "enforce")
    assert code == 1
    # 24 and 25 expect a caller error and produce no digest, so they still pass.
    assert summary(out) == "2/26 passed"
    assert 'core_digest "sha256:' + "0" * 64 + '", expected "sha256:' in out


def test_key_order_dependence_is_caught():
    code, out, _ = run(faulty("key-order"), "--family", "enforce")
    assert code == 1
    assert "canonicalization is not RFC 8785" in out
    # Every enforce_check vector (01-21) fails, the five ratify vectors pass.
    assert summary(out) == "5/26 passed"


# --------------------------------------------------------------------- broken protocol

ONE_OF_EACH = ("--vector", "aae-vector-01", "--vector", "aae-enforce-vector-01")


@pytest.mark.parametrize("mode,message", [
    ("malformed", "stdout is not a single JSON value: this is not JSON"),
    ("empty", "stdout is empty"),
    ("not-object", "response is not a JSON object"),
    ("crash", "exited with status 3 (stderr: adapter blew up on purpose)"),
    ("error", "implementation returned an error: not implemented"),
])
def test_protocol_violations_fail_clearly(mode, message):
    code, out, _ = run(faulty(mode), *ONE_OF_EACH)
    assert code == 1
    assert out.count(message) == 2
    assert summary(out) == "0/2 passed"


def test_generic_error_is_not_a_caller_error():
    # Vectors 24 and 25 expect a caller error; a blanket `error` must not satisfy them.
    code, out, _ = run(faulty("error"), "--vector", "24-", "--vector", "25-")
    assert code == 1
    assert summary(out) == "0/2 passed"


@pytest.mark.parametrize("vector,message", [
    ("aae-vector-01", "response.verification_step missing"),
    ("aae-enforce-vector-01", "response.core_digest missing"),
    ("aae-enforce-vector-22", "response.core_digest missing"),
])
def test_missing_required_member(vector, message):
    code, out, _ = run(faulty("missing-field"), "--vector", vector)
    assert code == 1
    assert message in out


def test_step_must_be_an_integer():
    code, out, _ = run(faulty("string-step"), "--vector", "aae-vector-01")
    assert code == 1
    assert 'response.verification_step must be an integer, got "7"' in out


def test_timeout():
    start = time.monotonic()
    code, out, _ = run(faulty("timeout"), "--vector", "aae-vector-01", "--timeout", "1")
    assert time.monotonic() - start < 20
    assert code == 1
    assert "timed out after 1s" in out


def test_missing_executable():
    code, out, _ = run("/nonexistent/aae-impl", "--vector", "aae-vector-01")
    assert code == 1
    assert "could not start the implementation" in out


# --------------------------------------------------------------------- usage errors

@pytest.mark.parametrize("args,message", [
    (("--vector", "no-such-vector"), "no vectors selected"),
    (("--timeout", "0"), "--timeout must be positive"),
    (("--vectors-root", "/nonexistent"), "--vectors-root"),
])
def test_usage_errors_exit_2(args, message):
    code, _, err = run(f"{PY} {shlex.quote(REFERENCE)}", *args)
    assert code == 2
    assert message in err


def test_unterminated_quote_is_a_usage_error():
    code, _, err = run("python3 'unterminated", "--vector", "aae-vector-01")
    assert code == 2
    assert "--impl" in err


# --------------------------------------------------------------------- skeletons

def test_python_skeleton_fails_cleanly():
    code, out, _ = run(f"{PY} {shlex.quote(SKELETON_PY)}")
    assert code == 1
    assert summary(out) == "0/83 passed"
    assert "implementation returned an error: not implemented" in out
    assert "exited with status" not in out


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_skeleton_fails_cleanly():
    code, out, _ = run(f"node {shlex.quote(SKELETON_JS)}")
    assert code == 1
    assert summary(out) == "0/83 passed"
    assert "implementation returned an error: not implemented" in out
    assert "exited with status" not in out


# --------------------------------------------------------------------- parity with TS

def body(stdout: str) -> list:
    """Everything after the header block (the first line names the runner)."""
    lines = stdout.splitlines()
    return lines[lines.index("") + 1:]


TS_AVAILABLE = shutil.which("node") is not None and os.path.exists(TS_CLI)


def test_ts_runner_present_when_required():
    # CI sets AAE_REQUIRE_TS_RUNNER so the parity tests below cannot be skipped silently.
    if os.environ.get("AAE_REQUIRE_TS_RUNNER"):
        assert TS_AVAILABLE, "node or runner/ts/dist/cli.js missing; build the TS runner first"


@pytest.mark.skipif(not TS_AVAILABLE,
                    reason="node or the built TypeScript runner (runner/ts/dist) missing")
@pytest.mark.parametrize("impl", [f"{PY} {shlex.quote(REFERENCE)}", faulty("wrong-result"),
                                  faulty("wrong-digest"), faulty("key-order")])
def test_both_runners_print_the_same_result(impl):
    code_py, out_py, _ = run(impl)
    ts = subprocess.run(["node", TS_CLI, "--impl", impl], capture_output=True, text=True,
                        cwd=ROOT, timeout=300)
    assert ts.returncode == code_py
    assert body(ts.stdout) == body(out_py)
