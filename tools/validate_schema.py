#!/usr/bin/env python3
"""Validate every vector in vectors/ against schema/vector-schema.json.

Also checks the cross-cutting invariant that the filename ordinal matches the
vector id (01-*.json -> aae-vector-01). Exits non-zero on any failure.
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
VECTORS = os.path.join(ROOT, "vectors")
SCHEMA = os.path.join(ROOT, "schema", "vector-schema.json")


def main() -> int:
    with open(SCHEMA) as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema)

    files = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
    if not files:
        print("no vectors found")
        return 1
    failed = 0
    for path in files:
        name = os.path.basename(path)
        with open(path) as fh:
            vector = json.load(fh)
        errors = sorted(validator.iter_errors(vector), key=lambda e: e.path)
        ordinal = re.match(r"^(\d{2})-", name)
        if ordinal and vector.get("id") != f"aae-vector-{ordinal.group(1)}":
            errors.append(jsonschema.ValidationError(
                f"filename ordinal {ordinal.group(1)} != id {vector.get('id')}"))
        if errors:
            failed += 1
            print(f"FAIL  {name}")
            for e in errors:
                print(f"        {e.message}")
        else:
            print(f"OK    {name}")
    print(f"\n{len(files) - failed}/{len(files)} vectors valid against schema")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
