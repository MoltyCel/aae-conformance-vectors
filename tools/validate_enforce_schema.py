#!/usr/bin/env python3
"""Validate every enforce vector under vectors/enforce/ against
schema/enforce-vector-schema.json.

Beyond JSON Schema this checks two invariants the schema cannot express:

  - filename ordinal matches the vector id (01-*.json -> aae-enforce-vector-01),
    the same cross-cutting rule tools/validate_schema.py applies to the native set.
  - declared domain tags are vendor-neutral and match the kernel the vector names.
    A vector built against a kernel that still tagged its digests `moltrust:` would
    validate structurally while being unreproducible; the tag is part of the digest,
    so it has to be stated and checked.

Digest recomputation is NOT done here. It belongs to a verifier, not to a schema
check, and lives in examples/enforce-verify.py — the same split the native set uses
between tools/validate_schema.py and examples/python-verify.py.

An empty vectors/enforce/ is not a failure: the schema can land before the vectors
that use it.

Exits non-zero on any failure. The 15 AAE-native vectors in vectors/ and the
composition vectors under interop/*/vectors/ are not read here; they keep their own
schemas and their own validators.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
VECTORS = os.path.join(ROOT, "vectors", "enforce")
SCHEMA = os.path.join(ROOT, "schema", "enforce-vector-schema.json")

# The kernel writes one core per machine, each under its own tag family.
_EXPECTED_TAG_PREFIX = {
    "enforce_check": "aae:enforce-",
    "ratify": "aae:enforce-ratify-",
}


def main() -> int:
    with open(SCHEMA) as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema)

    paths = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
    if not paths:
        print(f"no enforce vectors under {os.path.relpath(VECTORS, ROOT)}/ — schema only")
        return 0

    failures = 0
    for path in paths:
        name = os.path.basename(path)
        with open(path) as fh:
            vector = json.load(fh)

        errors = sorted(validator.iter_errors(vector), key=lambda e: e.path)
        for err in errors:
            location = "/".join(str(p) for p in err.absolute_path) or "(root)"
            print(f"FAIL  {name}  {location}: {err.message}")
            failures += len(errors)

        ordinal = re.match(r"^(\d{2})-", name)
        if not ordinal:
            print(f"FAIL  {name}: filename does not start with a two-digit ordinal")
            failures += 1
        elif vector.get("id") != f"aae-enforce-vector-{ordinal.group(1)}":
            print(f"FAIL  {name}: id {vector.get('id')!r} does not match the filename ordinal")
            failures += 1

        prefix = _EXPECTED_TAG_PREFIX.get(vector.get("kernel"), "")
        for role, tag in (vector.get("domain_tags") or {}).items():
            if tag.startswith("moltrust:"):
                print(f"FAIL  {name}: domain tag {role} is still vendor-scoped ({tag})")
                failures += 1
            elif prefix and not tag.startswith(prefix):
                print(f"FAIL  {name}: domain tag {role} ({tag}) does not belong to kernel "
                      f"{vector['kernel']!r}")
                failures += 1

        if not errors:
            print(f"PASS  {name}")

    print(f"\n{len(paths) - failures if failures <= len(paths) else 0}/{len(paths)} "
          f"enforce vectors valid" if not failures else f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
