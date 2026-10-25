#!/usr/bin/env python3
"""Reference adapter: the two reference verifiers behind the runner protocol.

Wraps examples/python-verify.py (native vectors, draft -00 Section 5) and
examples/enforce-verify.py (enforce vectors, draft -02 enforce kernel 3.0) without
changing either. Reads one request from stdin, writes one response to stdout; see
docs/RUNNER-PROTOCOL.md.

Requires `cryptography` and `jcs`:

    python -m aae_conformance --impl "python3 adapters/python-reference/adapter.py"
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def handle_native(req: dict) -> dict:
    pv = _load("python_verify", "examples/python-verify.py")
    # Resolve DIDs from the documents the runner sent rather than from the module's own
    # directory scan. For this repository the two are the same set.
    pv.DID_DOCS.clear()
    pv.DID_DOCS.update(req["did_documents"])
    inp = req["input"]
    return pv.verify(inp["secured_aae"], inp["context"])


def handle_enforce(req: dict) -> dict:
    ev = _load("enforce_verify", "examples/enforce-verify.py")
    inp = req["input"]
    if req["kernel"] == "enforce_check":
        got = ev.enforce_check(inp.get("mandate"), inp.get("transaction"),
                               inp.get("prev_core_digest"))
        return {"verdict": got["verdict"], "core_digest": got["core_digest"],
                "grant_index": got["grant_index"], "reason": got["reason"],
                "trace": got["trace"], "core": got["core"]}
    if req["kernel"] == "ratify":
        try:
            got = ev.ratify(inp.get("prior_record"), inp.get("decision"),
                            inp.get("authority_proof"), inp.get("prev_core_digest"))
        except ev.RatifyError as exc:
            return {"caller_error": f"RatifyError: {exc}"}
        return {"status": got["status"], "decision": got["decision"],
                "ratifies": got["ratifies"], "authority": got["authority"],
                "core_digest": got["core_digest"], "reason": got["reason"],
                "trace": got["trace"], "core": got["core"]}
    return {"error": f"unknown kernel {req['kernel']!r}"}


def main() -> int:
    req = json.loads(sys.stdin.read())
    if req.get("family") == "native":
        resp = handle_native(req)
    elif req.get("family") == "enforce":
        resp = handle_enforce(req)
    else:
        resp = {"error": f"unknown family {req.get('family')!r}"}
    json.dump(resp, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
