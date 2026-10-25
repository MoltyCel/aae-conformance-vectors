#!/usr/bin/env python3
"""Recompute an enforce vector's outcome and core digest from its input, step by step.

    python3 tools/explain_enforce.py vectors/enforce/01-type-form-matches-permit.json
    python3 tools/explain_enforce.py vectors/enforce/*.json

For every vector it prints the digests over the input, the predicate trace with its
reasons, the core exactly as it is canonicalized (RFC 8785), and the core digest next to
the value the vector expects. It changes nothing: it calls the kernel functions of
examples/enforce-verify.py and shows their intermediate values. Exits 1 if any recomputed
value differs from the vector.

Requires `jcs` and `cryptography`, like examples/enforce-verify.py.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ev = _load("enforce_verify", "examples/enforce-verify.py")


def tag_text(tag: bytes) -> str:
    return tag[:-1].decode("ascii") + "\\0"


def show_digest(label: str, tag: bytes, of: str, value, width: int = 20) -> str:
    d = ev.digest(tag, value)
    print(f"  {label:{width}s} = sha256(\"{tag_text(tag)}\" || JCS({of}))")
    print(f"  {'':{width}s} = {d}")
    return d


def verdict_line(ok: bool) -> str:
    return "MATCH" if ok else "DIFFERS"


def show_trace(trace) -> None:
    for i, e in enumerate(trace):
        field = "" if e["field"] is None else f" field={e['field']}"
        print(f"  [{i}] {e['predicate']:22s} {e['result']:4s}{field}  -- {e['reason']}")


def show_core(core) -> None:
    print("  JCS(core), the exact bytes that are hashed after the tag:")
    print("  " + ev.jcs.canonicalize(core).decode("utf-8"))


def explain_enforce_check(vector) -> bool:
    inp, exp = vector["input"], vector["expected"]
    mandate, tx = inp.get("mandate"), inp.get("transaction")
    print("1. Digests over the input. Each is sha256 over the domain tag (ASCII, then one")
    print("   0x00 byte) followed by the RFC 8785 canonical form of the value.")
    show_digest("mandate_digest", ev.TAG_MANDATE, "input.mandate", mandate)
    show_digest("transaction_digest", ev.TAG_TRANSACTION, "input.transaction", tx)
    action = tx.get("action") if isinstance(tx, dict) else None
    show_digest("action_digest", ev.TAG_ACTION, "input.transaction.action", action)
    print("   A grant addresses the action when its action_binding equals action_digest.")

    got = ev.enforce_check(mandate, tx, inp.get("prev_core_digest"))
    print()
    print("2. Evaluation (draft -02 Sections 2.2.3, 2.5, 6.1). Trace, with the reasons that")
    print("   stay out of the core:")
    show_trace(got["trace"])
    print(f"  verdict {got['verdict']}, grant_index {json.dumps(got['grant_index'])}")

    print()
    print("3. The core: enforce_version, the three input digests, verdict, grant_index, the")
    print("   trace entries reduced to predicate/field/value/bound/result, prev_core_digest.")
    show_core(got["core"])

    print()
    print("4. Core digest")
    d = show_digest("core_digest", ev.TAG_CORE, "core", got["core"], width=12)
    ok_d = d == exp["core_digest"]
    ok_v = got["verdict"] == exp["verdict"]
    print(f"  {'expected':12s} = {exp['core_digest']}  {verdict_line(ok_d)}")
    print(f"  verdict {got['verdict']}, expected {exp['verdict']}  {verdict_line(ok_v)}")
    return ok_d and ok_v


def explain_ratify(vector) -> bool:
    inp, exp = vector["input"], vector["expected"]
    prior = inp.get("prior_record") or {}
    print("1. The record being ratified. Its core digest is recomputed, never trusted:")
    d = show_digest("ratifies", ev.TAG_CORE, "prior_record.core", prior.get("core"), width=12)
    print(f"  {'claimed':12s} = {prior.get('core_digest')}  "
          f"{verdict_line(d == prior.get('core_digest'))}")

    print()
    print("2. Guards and authority (draft -02 Sections 6.3 and 6.4)")
    try:
        got = ev.ratify(prior, inp.get("decision"), inp.get("authority_proof"),
                        inp.get("prev_core_digest"))
    except ev.RatifyError as exc:
        print(f"  caller error: {exc}")
        print("  No record is produced, so there is no core and no digest.")
        ok = "error" in exp
        print(f"  expected: {'a caller error' if ok else exp.get('status')}  "
              f"{verdict_line(ok)}")
        return ok
    proof = inp.get("authority_proof") or {}
    authority = proof.get("authority")
    if authority is not None:
        stmt = ev.statement_bytes(d, inp.get("decision"), authority)
        print("  The authority signs, with the key the mandate holds for it:")
        print(f"  \"{tag_text(ev.TAG_RATIFY_STATEMENT)}\" || "
              f"{stmt[len(ev.TAG_RATIFY_STATEMENT):].decode('utf-8')}")
    show_trace(got["trace"])
    print(f"  status {got['status']}, authority {json.dumps(got['authority'])}")

    print()
    print("3. The ratification core (trace entries without reason)")
    show_core(got["core"])

    print()
    print("4. Core digest")
    rd = show_digest("core_digest", ev.TAG_RATIFY_CORE, "core", got["core"], width=12)
    if "error" in exp:
        print(f"  expected a caller error, got status {got['status']}  DIFFERS")
        return False
    ok_d = rd == exp["core_digest"]
    ok_s = got["status"] == exp["status"]
    print(f"  {'expected':12s} = {exp['core_digest']}  {verdict_line(ok_d)}")
    print(f"  status {got['status']}, expected {exp['status']}  {verdict_line(ok_s)}")
    return ok_d and ok_s


def main(argv) -> int:
    if not argv:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    all_ok = True
    for i, path in enumerate(argv):
        with open(path, encoding="utf-8") as fh:
            vector = json.load(fh)
        if i:
            print("\n" + "=" * 78 + "\n")
        print(f"{vector['id']}  {vector['name']}")
        print(f"kernel {vector['kernel']} {vector['kernel_version']}, {vector['section_ref']}")
        print()
        if vector["kernel"] == "enforce_check":
            ok = explain_enforce_check(vector)
        else:
            ok = explain_ratify(vector)
        all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
