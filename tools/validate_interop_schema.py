#!/usr/bin/env python3
"""Validate every composition vector under interop/*/vectors/ against
schema/interop-composition-vector-schema.json.

Beyond JSON Schema this checks three invariants the schema cannot express:

  - integers-only, lexically. JSON Schema sees a parsed number, so 2500.00 and
    2.5e3 both validate as integer-valued. The raw bytes are re-parsed with a
    Decimal float hook, and any non-integer numeric literal inside
    join_what.payload is a failure (draft-yossif-psea-02 Section 2.5).
  - digest octet length. Every declared encoding must decode to exactly 32
    octets, and both declared digests must decode to the SAME octets when the
    vector expects the WHAT-join to hold.
  - fixture integrity. Every secondary_artifact.source.sha256 must match the
    committed fixture file it names.

Exits non-zero on any failure. The 15 AAE-native vectors in vectors/ are not
read here; tools/validate_schema.py continues to govern those unchanged.
"""
from __future__ import annotations

import base64
import decimal
import glob
import hashlib
import json
import os
import sys

import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SCHEMA = os.path.join(ROOT, "schema", "interop-composition-vector-schema.json")
INTEROP = os.path.join(ROOT, "interop")


def decode_digest(entry: dict) -> bytes:
    value = entry["value"]
    if value.startswith("sha-256:"):
        value = value[len("sha-256:"):]
    encoding = entry["encoding"]
    if encoding == "base64url-nopad":
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if encoding == "base64-pad":
        return base64.b64decode(value)
    if encoding == "hex":
        return bytes.fromhex(value)
    raise ValueError(f"undeclared digest encoding {encoding!r}")


def scan_non_integer(obj, path: str) -> list[str]:
    """Report every numeric literal that is not an integer."""
    bad: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            bad += scan_non_integer(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            bad += scan_non_integer(v, f"{path}[{i}]")
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (float, decimal.Decimal)):
        bad.append(f"{path} carries the non-integer literal {obj} "
                   "(psea-02 Section 2.5 allows integers only)")
    return bad


def check_vector(path: str, validator) -> list[str]:
    errors: list[str] = []
    raw = open(path, "rb").read()
    vector = json.loads(raw.decode("utf-8"))

    for e in sorted(validator.iter_errors(vector), key=lambda x: list(x.path)):
        errors.append(f"schema: {'/'.join(str(p) for p in e.path)}: {e.message}")

    # lexical integers-only over the raw bytes
    lexical = json.loads(raw.decode("utf-8"), parse_float=decimal.Decimal)
    payload = lexical.get("input", {}).get("join_what", {}).get("payload")
    if payload is not None:
        errors += scan_non_integer(payload, "input.join_what.payload")

    join_what = vector.get("input", {}).get("join_what")
    if join_what:
        try:
            aae = decode_digest(join_what["aae_digest"])
            sec = decode_digest(join_what["secondary_digest"])
            for label, raw_octets, entry in (("aae_digest", aae, join_what["aae_digest"]),
                                             ("secondary_digest", sec, join_what["secondary_digest"])):
                if len(raw_octets) != 32:
                    errors.append(
                        f"input.join_what.{label} decodes to {len(raw_octets)} octets, not 32")
                if len(raw_octets) != entry["octets"]:
                    errors.append(
                        f"input.join_what.{label} declares {entry['octets']} octets "
                        f"but decodes to {len(raw_octets)}")
            expects_mismatch = vector.get("expected", {}).get("reason") == "join_mismatch"
            if aae != sec and not expects_mismatch:
                errors.append(
                    "input.join_what: the two digests differ on the octets but the vector "
                    "does not expect join_mismatch")
            if aae == sec and expects_mismatch:
                errors.append(
                    "input.join_what: the vector expects join_mismatch but both digests "
                    "decode to identical octets")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"input.join_what: {exc}")

    source = vector.get("input", {}).get("secondary_artifact", {}).get("source")
    if source:
        fixture_path = os.path.join(os.path.dirname(os.path.dirname(path)),
                                    os.path.basename(source["path"]))
        if not os.path.exists(fixture_path):
            errors.append(f"secondary_artifact.source: {fixture_path} is not committed")
        else:
            actual = hashlib.sha256(open(fixture_path, "rb").read()).hexdigest()
            if actual != source["sha256"]:
                errors.append(
                    f"secondary_artifact.source.sha256 pin {source['sha256']} "
                    f"!= committed fixture {actual}")

    # a vector whose join_who is still a proposal must not claim confirmed status
    join_who = vector.get("input", {}).get("join_who", {})
    if join_who.get("status", "").startswith("proposed") and vector.get("status") != "proposed":
        errors.append("join_who is a proposed convention but the vector status is not 'proposed'")

    return errors


def main() -> int:
    with open(SCHEMA) as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema)

    files = sorted(glob.glob(os.path.join(INTEROP, "*", "vectors", "*.json")))
    if not files:
        print("no composition vectors found")
        return 1

    failed = 0
    for path in files:
        rel = os.path.relpath(path, ROOT)
        errors = check_vector(path, validator)
        if errors:
            failed += 1
            print(f"FAIL  {rel}")
            for e in errors:
                print(f"        {e}")
        else:
            print(f"OK    {rel}")

    print(f"\n{len(files) - failed}/{len(files)} composition vectors valid against schema")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
