#!/usr/bin/env python3
"""Run the negative controls in interop/psea/negative-controls.json.

Each control mutates ONE input of a committed vector, in memory, and asserts the
seven rows the checker must then report. Nothing on disk is modified.

The three composition vectors alone cannot show that the checker's branches are
live: all three reach EQUIVALENT on action_linkage and differ only at
principal_linkage. The controls reach NOT_EQUIVALENT, INDETERMINATE, REJECT, and
DIVERGENT-from-the-same-inputs-that-otherwise-yield-UNRESOLVED.

Comparison is row by row, like examples/composition-verify.py: every differing
row is reported, not just the first.

Exits non-zero if any control's rows differ from its baseline.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
INTEROP = os.path.join(ROOT, "interop", "psea")
BASELINE = os.path.join(INTEROP, "negative-controls.json")
FIXTURE = os.path.join(INTEROP, "psea-fixture-v0.json")


def load_checker():
    """Import examples/composition-verify.py as a module and reuse it as-is."""
    path = os.path.join(ROOT, "examples", "composition-verify.py")
    spec = importlib.util.spec_from_file_location("composition_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def apply_mutation(vector: dict, mutation: dict, cv) -> dict:
    """Return a mutated copy of `vector`. One input, one change, no side effects."""
    v = copy.deepcopy(vector)
    op = mutation["op"]

    if op == "set_current_time":
        v["input"]["context"]["current_time"] = mutation["value"]

    elif op == "flip_digest_octet":
        entry = v["input"]["join_what"][mutation["target"]]
        raw = bytearray(cv.decode_digest(entry))
        raw[mutation["index"]] ^= 0x01
        prefix = "sha-256:" if entry["value"].startswith("sha-256:") else ""
        if entry["encoding"] == "base64url-nopad":
            body = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
        elif entry["encoding"] == "base64-pad":
            body = base64.b64encode(bytes(raw)).decode("ascii")
        else:
            body = bytes(raw).hex()
        entry["value"] = prefix + body

    elif op == "add_resolution_entry":
        table = v["input"]["join_who"]["principal_resolution"][mutation["side"]]
        table[mutation["key"]] = mutation["value"]

    elif op == "tamper_token_signature":
        header, payload, sig = v["input"]["secondary_artifact"]["token"].split(".")
        sig = ("A" if sig[0] != "A" else "B") + sig[1:]
        v["input"]["secondary_artifact"]["token"] = f"{header}.{payload}.{sig}"

    else:
        raise SystemExit(f"unknown mutation op: {op!r}")

    return v


def main() -> int:
    cv = load_checker()
    aae_verifier = cv.load_aae_verifier()
    with open(FIXTURE) as fh:
        fixture = json.load(fh)
    with open(BASELINE) as fh:
        baseline = json.load(fh)

    if list(baseline["stage_order"]) != list(cv.STAGE_ORDER):
        print("baseline stage_order differs from the checker's STAGE_ORDER")
        return 1

    print("stages: " + " | ".join(cv.STAGE_ORDER))
    print()

    passed = 0
    controls = baseline["controls"]
    for control in controls:
        base_path = os.path.join(INTEROP, "vectors", control["base_vector"])
        with open(base_path) as fh:
            vector = json.load(fh)

        mutated = apply_mutation(vector, control["mutation"], cv)
        got = cv.compose(mutated, fixture, aae_verifier)
        diffs = cv.compare_stages(got["stages"], control["expected"]["stages"])

        label = f"{control['id']}  {control['name']}"
        if diffs:
            print(f"FAIL  {label}")
            for d in diffs:
                print(f"        {d}")
            for line in got["trace"]:
                print(f"        trace: {line}")
        else:
            passed += 1
            print(f"PASS  {label}")
        print(f"        {cv.format_stages(got['stages'])}")

    print(f"\n{passed}/{len(controls)} negative controls passed (row-by-row)")
    return 0 if passed == len(controls) else 1


if __name__ == "__main__":
    sys.exit(main())
