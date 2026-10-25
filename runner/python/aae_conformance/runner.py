"""Python runner for the AAE conformance vectors.

The protocol is specified in docs/RUNNER-PROTOCOL.md. In short: for every vector the runner
starts the implementation under test once, writes one JSON request to its stdin, reads one
JSON response from its stdout, and compares the fields the protocol names against the
vector's `expected` object. Output and exit codes are identical to the TypeScript runner
under runner/ts/.

Standard library only.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shlex
import signal
import subprocess
import sys

from . import PROTOCOL, RUNNER_VERSION

RUNNER_NAME = "python"
DEFAULT_TIMEOUT = 10.0
NAME_WIDTH = 58

NATIVE_RESULTS = ("ACCEPT", "REJECT")
VERDICTS = ("PERMIT", "DENY", "PENDING")
STATUSES = ("RATIFIED", "REJECTED")

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


class UsageError(Exception):
    pass


# ------------------------------------------------------------------------- JSON helpers

def j(value) -> str:
    """Compact JSON rendering for messages. Matches JSON.stringify for the values used."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def is_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def json_equal(a, b) -> bool:
    """Strict JSON equality: true is not 1, numbers compare by value, key order is ignored."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) or is_number(b):
        return is_number(a) and is_number(b) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, list) or isinstance(b, list):
        return (isinstance(a, list) and isinstance(b, list) and len(a) == len(b)
                and all(json_equal(x, y) for x, y in zip(a, b)))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return False


def keys_reversed(obj):
    """The same JSON value with every object's keys in reverse order (as the reference
    verifier's `reordered`). An RFC 8785 implementation computes the same digest from it."""
    if isinstance(obj, dict):
        return {k: keys_reversed(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [keys_reversed(v) for v in obj]
    return obj


# ------------------------------------------------------------------------- vector loading

def find_root(explicit: str | None) -> str:
    def is_root(d: str) -> bool:
        return (os.path.isdir(os.path.join(d, "vectors", "enforce"))
                and os.path.isdir(os.path.join(d, "testkeys", "did-documents")))

    if explicit:
        if not is_root(explicit):
            raise UsageError(f"--vectors-root {explicit}: no vectors/enforce/ and "
                             f"testkeys/did-documents/ there")
        return os.path.realpath(explicit)
    for start in (os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        d = os.path.realpath(start)
        while True:
            if is_root(d):
                return d
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    raise UsageError("cannot find the vector set; pass --vectors-root")


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_did_documents(root: str) -> dict:
    docs = {}
    for path in sorted(glob.glob(os.path.join(root, "testkeys", "did-documents", "*.json"))):
        doc = load_json(path)
        docs[doc["id"]] = doc
    return docs


def load_vectors(root: str, family: str) -> list:
    out = []
    if family in ("native", "all"):
        for path in sorted(glob.glob(os.path.join(root, "vectors", "*.json"))):
            out.append(("native", path, load_json(path)))
    if family in ("enforce", "all"):
        for path in sorted(glob.glob(os.path.join(root, "vectors", "enforce", "*.json"))):
            out.append(("enforce", path, load_json(path)))
    return out


def selected(path: str, vector: dict, patterns: list) -> bool:
    if not patterns:
        return True
    name = os.path.basename(path)
    return any(p == vector.get("id") or p in name for p in patterns)


# ------------------------------------------------------------------------- requests

def native_request(root: str, path: str, vector: dict, did_docs: dict) -> dict:
    return {
        "protocol": PROTOCOL,
        "family": "native",
        "vector_id": vector["id"],
        "vector_file": os.path.relpath(path, root).replace(os.sep, "/"),
        "section_ref": vector["section_ref"],
        "input": vector["input"],
        "did_documents": did_docs,
        "did_documents_dir": os.path.join(root, "testkeys", "did-documents"),
    }


def enforce_request(root: str, path: str, vector: dict, variant: str) -> dict:
    inp = vector["input"]
    if variant == "keys-reversed":
        inp = dict(inp)
        for key in ("mandate", "transaction"):
            if key in inp:
                inp[key] = keys_reversed(inp[key])
    return {
        "protocol": PROTOCOL,
        "family": "enforce",
        "vector_id": vector["id"],
        "vector_file": os.path.relpath(path, root).replace(os.sep, "/"),
        "section_ref": vector["section_ref"],
        "kernel": vector["kernel"],
        "kernel_version": vector["kernel_version"],
        "domain_tags": vector.get("domain_tags", {}),
        "variant": variant,
        "input": inp,
    }


# ------------------------------------------------------------------------- invocation

def stderr_tail(stderr: str) -> str:
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    return " | ".join(lines[-3:])


def excerpt(text: str) -> str:
    first = text.strip().split("\n", 1)[0]
    return first[:80] + ("..." if len(first) > 80 else "")


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def invoke(argv: list, request: dict, timeout: float):
    """Run the implementation once. Returns (response, error_message)."""
    data = (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=(os.name == "posix"))
    except OSError as exc:
        return None, f"could not start the implementation: {exc.strerror or exc}"
    try:
        out, err = proc.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        proc.communicate()
        return None, f"timed out after {timeout:g}s"
    stdout = out.decode("utf-8", errors="replace")
    stderr = err.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        tail = stderr_tail(stderr)
        return None, (f"exited with status {proc.returncode}"
                      + (f" (stderr: {tail})" if tail else ""))
    if not stdout.strip():
        tail = stderr_tail(stderr)
        return None, "stdout is empty" + (f" (stderr: {tail})" if tail else "")
    try:
        response = json.loads(stdout)
    except ValueError:
        return None, f"stdout is not a single JSON value: {excerpt(stdout)}"
    if not isinstance(response, dict):
        return None, "response is not a JSON object"
    return response, None


# ------------------------------------------------------------------------- comparison

def need(resp: dict, key: str, allowed=None, kind=None) -> str | None:
    if key not in resp:
        return f"response.{key} missing"
    value = resp[key]
    if allowed is not None and value not in allowed:
        return f"response.{key} must be one of {', '.join(allowed)}, got {j(value)}"
    if kind == "string" and not isinstance(value, str):
        return f"response.{key} must be a string, got {j(value)}"
    if kind == "step" and not (is_number(value) and (isinstance(value, int)
                                                     or value.is_integer())):
        return f"response.{key} must be an integer, got {j(value)}"
    return None


def compare(resp: dict, key: str, expected) -> str | None:
    if not json_equal(resp.get(key), expected):
        return f"{key} {j(resp.get(key))}, expected {j(expected)}"
    return None


def check_trace(expected_entries: list, produced) -> str | None:
    """Every named predicate must appear, in order, with the same result (and field, value,
    bound where the vector states them). `reason_contains` is not compared."""
    if not isinstance(produced, list):
        return "response.trace must be an array"
    cursor = 0
    for want in expected_entries:
        while cursor < len(produced):
            got = produced[cursor]
            cursor += 1
            if not isinstance(got, dict) or got.get("predicate") != want["predicate"]:
                continue
            if got.get("result") != want["result"]:
                return (f"trace: predicate {want['predicate']} result {j(got.get('result'))}, "
                        f"expected {j(want['result'])}")
            for key in ("field", "value", "bound"):
                if key in want and not json_equal(got.get(key), want[key]):
                    return (f"trace: predicate {want['predicate']} {key} {j(got.get(key))}, "
                            f"expected {j(want[key])}")
            break
        else:
            return f"trace: predicate {want['predicate']} ({want['result']}) not in the trace"
    return None


def reported_error(resp: dict) -> str | None:
    if "error" in resp and resp["error"] is not None:
        e = resp["error"]
        return f"implementation returned an error: {e if isinstance(e, str) else j(e)}"
    return None


def check_native(resp: dict, exp: dict) -> list:
    problem = reported_error(resp)
    if problem:
        return [problem]
    fails = [p for p in (need(resp, "result", NATIVE_RESULTS),
                         need(resp, "verification_step", kind="step")) if p]
    if fails:
        return fails
    return [p for p in (compare(resp, "result", exp["result"]),
                        compare(resp, "verification_step", exp.get("verification_step")))
            if p]


def check_enforce_check(resp: dict, exp: dict) -> list:
    problem = reported_error(resp)
    if problem:
        return [problem]
    fails = [p for p in (need(resp, "verdict", VERDICTS),
                         need(resp, "core_digest", kind="string")) if p]
    if "grant_index" in exp and "grant_index" not in resp:
        fails.append("response.grant_index missing")
    if fails:
        return fails
    fails = [p for p in (compare(resp, "verdict", exp["verdict"]),
                         compare(resp, "core_digest", exp["core_digest"])) if p]
    if "grant_index" in exp:
        p = compare(resp, "grant_index", exp["grant_index"])
        if p:
            fails.append(p)
    if exp.get("trace") and "trace" in resp:
        p = check_trace(exp["trace"], resp["trace"])
        if p:
            fails.append(p)
    return fails


def check_ratify(resp: dict, exp: dict) -> list:
    # A generic `error` means the implementation could not answer; it never stands in for
    # the caller error that vectors 24 and 25 expect, which has its own member.
    problem = reported_error(resp)
    if problem:
        return [problem]
    has_caller_error = "caller_error" in resp and resp["caller_error"] is not None
    if "error" in exp:
        if not has_caller_error:
            return [f"expected a caller error (no record), got status {j(resp.get('status'))}"]
        if not isinstance(resp["caller_error"], str) or not resp["caller_error"]:
            return ["response.caller_error must be a non-empty string"]
        if resp.get("status") is not None:
            return ["response carries both caller_error and status"]
        return []
    if has_caller_error:
        return [f"caller error {j(resp['caller_error'])}, expected status {j(exp['status'])}"]
    fails = [p for p in (need(resp, "status", STATUSES),
                         need(resp, "core_digest", kind="string"),
                         need(resp, "ratifies", kind="string")) if p]
    if "authority" in exp and "authority" not in resp:
        fails.append("response.authority missing")
    if fails:
        return fails
    fails = [p for p in (compare(resp, "status", exp["status"]),
                         compare(resp, "core_digest", exp["core_digest"]),
                         compare(resp, "ratifies", exp["ratifies"])) if p]
    if "authority" in exp:
        p = compare(resp, "authority", exp["authority"])
        if p:
            fails.append(p)
    if exp.get("trace") and "trace" in resp:
        p = check_trace(exp["trace"], resp["trace"])
        if p:
            fails.append(p)
    return fails


def outcome_text(family: str, vector: dict, resp: dict) -> str:
    if family == "native":
        text = f"{resp['result']} @ step {resp['verification_step']}"
        reason = resp.get("rejection_reason")
        return text + (f" ({reason})" if isinstance(reason, str) and reason else "")
    if vector["kernel"] == "enforce_check":
        return resp["verdict"]
    if "error" in vector["expected"]:
        return "caller error"
    return resp["status"]


def run_vector(argv, root, family, path, vector, did_docs, timeout) -> dict:
    exp = vector["expected"]
    entry = {
        "family": family,
        "file": os.path.relpath(path, root).replace(os.sep, "/"),
        "vector_id": vector["id"],
        "kernel": vector.get("kernel"),
        "status": "FAIL",
        "outcome": None,
        "failures": [],
        "expected": exp,
        "response": None,
    }
    if family == "native":
        resp, err = invoke(argv, native_request(root, path, vector, did_docs), timeout)
    else:
        resp, err = invoke(argv, enforce_request(root, path, vector, "as-committed"), timeout)
    entry["response"] = resp
    if err:
        entry["failures"] = [err]
        return entry

    if family == "native":
        fails = check_native(resp, exp)
    elif vector["kernel"] == "enforce_check":
        fails = check_enforce_check(resp, exp)
        if not fails:
            # Determinism: the same input with every object's keys reversed must produce the
            # same core digest, as examples/enforce-verify.py requires of itself.
            again, err2 = invoke(argv, enforce_request(root, path, vector, "keys-reversed"),
                                 timeout)
            entry["response_keys_reversed"] = again
            if err2:
                fails = [f"keys-reversed run: {err2}"]
            elif not isinstance(again.get("core_digest"), str):
                fails = ["keys-reversed run: response.core_digest missing"]
            elif again["core_digest"] != resp["core_digest"]:
                fails = [f"core_digest depends on key order ({again['core_digest']} with keys "
                         f"reversed): canonicalization is not RFC 8785"]
    else:
        fails = check_ratify(resp, exp)

    entry["failures"] = fails
    if not fails:
        entry["status"] = "PASS"
        entry["outcome"] = outcome_text(family, vector, resp)
    return entry


# ------------------------------------------------------------------------- CLI

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="python -m aae_conformance",
        description="Run an AAE implementation against the conformance vectors "
                    "(protocol " + PROTOCOL + ").")
    ap.add_argument("--impl", required=True,
                    help="command that starts the implementation under test, split like a "
                         "POSIX shell (no shell expansion), e.g. \"python3 my_adapter.py\"")
    ap.add_argument("--family", choices=("native", "enforce", "all"), default="all")
    ap.add_argument("--json", metavar="REPORT", help="also write a JSON report to this path")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECONDS",
                    help=f"per-invocation timeout (default {DEFAULT_TIMEOUT:g})")
    ap.add_argument("--vector", action="append", default=[], metavar="PATTERN",
                    help="only run vectors whose id equals PATTERN or whose file name "
                         "contains it; repeatable")
    ap.add_argument("--vectors-root", metavar="DIR",
                    help="repository root holding vectors/ and testkeys/ (default: found "
                         "from the runner location, then the working directory)")
    ap.add_argument("--version", action="version",
                    version=f"aae-conformance {RUNNER_VERSION} ({RUNNER_NAME}), {PROTOCOL}")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        try:
            impl_argv = shlex.split(args.impl)
        except ValueError as exc:
            raise UsageError(f"--impl: {exc}")
        if not impl_argv:
            raise UsageError("--impl is empty")
        if not args.timeout > 0:
            raise UsageError("--timeout must be positive")
        root = find_root(args.vectors_root)
        vectors = [v for v in load_vectors(root, args.family) if selected(v[1], v[2], args.vector)]
        if not vectors:
            raise UsageError("no vectors selected")
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    did_docs = load_did_documents(root)
    print(f"AAE conformance runner {RUNNER_VERSION} ({RUNNER_NAME}), protocol {PROTOCOL}")
    print(f"implementation: {args.impl}")
    print(f"vectors: {root}")
    print()

    results = []
    for family, path, vector in vectors:
        entry = run_vector(impl_argv, root, family, path, vector, did_docs, args.timeout)
        results.append(entry)
        name = os.path.basename(path)
        if entry["status"] == "PASS":
            print(f"PASS  {family:8s} {name:{NAME_WIDTH}s} {entry['outcome']}")
        else:
            print(f"FAIL  {family:8s} {name}")
            for f in entry["failures"]:
                print(f"        {f}")
        sys.stdout.flush()

    families = {}
    for fam in ("native", "enforce"):
        rows = [r for r in results if r["family"] == fam]
        if rows:
            families[fam] = {"passed": sum(r["status"] == "PASS" for r in rows),
                             "total": len(rows)}
    passed = sum(r["status"] == "PASS" for r in results)
    total = len(results)
    print()
    for fam, c in families.items():
        print(f"{fam:8s} {c['passed']}/{c['total']} passed")
    print(f"{passed}/{total} passed")

    if args.json:
        report = {
            "runner": RUNNER_NAME,
            "runner_version": RUNNER_VERSION,
            "protocol": PROTOCOL,
            "implementation": args.impl,
            "vectors_root": root,
            "families": families,
            "passed": passed,
            "total": total,
            "ok": passed == total,
            "results": results,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    return EXIT_OK if passed == total else EXIT_FAIL
