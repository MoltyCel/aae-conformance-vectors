#!/usr/bin/env python3
"""A deliberately broken adapter for the runner tests.

    python3 runner/test-adapters/faulty.py MODE

Each MODE breaks the protocol, or the answer, in one specific way. Modes that answer at
all start from the reference adapter's response and then damage it, so every failure the
runners report is the one the mode introduced.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "adapters", "python-reference")))

import adapter as reference  # noqa: E402


def reference_response(req: dict) -> dict:
    if req["family"] == "native":
        return reference.handle_native(req)
    return reference.handle_enforce(req)


def main() -> int:
    mode = sys.argv[1]
    raw = sys.stdin.read()

    if mode == "timeout":
        time.sleep(60)
        return 0
    if mode == "crash":
        print("adapter blew up on purpose", file=sys.stderr)
        return 3
    if mode == "malformed":
        sys.stdout.write("this is not JSON\n")
        return 0
    if mode == "empty":
        return 0
    if mode == "not-object":
        sys.stdout.write("[1, 2, 3]\n")
        return 0
    if mode == "error":
        json.dump({"error": "not implemented"}, sys.stdout)
        return 0

    req = json.loads(raw)
    resp = reference_response(req)

    if mode == "wrong-result":
        if req["family"] == "native":
            resp["result"] = "REJECT" if resp["result"] == "ACCEPT" else "ACCEPT"
        elif "verdict" in resp:
            resp["verdict"] = "PERMIT" if resp["verdict"] != "PERMIT" else "DENY"
        elif "status" in resp:
            resp["status"] = "REJECTED" if resp["status"] == "RATIFIED" else "RATIFIED"
        else:
            resp = {"status": "RATIFIED", "core_digest": "sha256:" + "0" * 64,
                    "ratifies": "sha256:" + "0" * 64, "authority": None}
    elif mode == "wrong-step":
        if req["family"] == "native":
            resp["verification_step"] += 1
    elif mode == "wrong-digest":
        if "core_digest" in resp:
            resp["core_digest"] = "sha256:" + "0" * 64
    elif mode == "missing-field":
        resp.pop("verification_step", None)
        resp.pop("core_digest", None)
    elif mode == "string-step":
        if "verification_step" in resp:
            resp["verification_step"] = str(resp["verification_step"])
    elif mode == "key-order":
        # Digest over the input as serialised, not canonicalised: depends on key order.
        if req.get("kernel") == "enforce_check":
            blob = json.dumps(req["input"], separators=(",", ":")).encode()
            if req["variant"] == "as-committed":
                pass  # keep the correct digest so only the determinism check can catch it
            else:
                resp["core_digest"] = "sha256:" + hashlib.sha256(blob).hexdigest()
    else:
        print(f"unknown mode {mode}", file=sys.stderr)
        return 2

    json.dump(resp, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
