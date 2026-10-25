#!/usr/bin/env python3
"""Adapter skeleton: copy this file and connect your AAE implementation.

The runner starts this program once per vector, writes one JSON request to stdin and
reads one JSON response from stdout (docs/RUNNER-PROTOCOL.md). Replace the three
functions marked TODO with calls into your implementation. Until you do, every vector
fails with "not implemented", which is the expected starting point.

    python -m aae_conformance --impl "python3 path/to/adapter.py"

Write diagnostics to stderr, never to stdout: stdout must carry the one JSON response.
"""
import json
import sys


def verify_native(secured_aae: str, context: dict, did_documents: dict) -> dict:
    """Native vectors (draft -00, Section 5).

    secured_aae    the AAE as a compact JWS
    context        current_time, requested_action, action_context, subject_binding,
                   consumed_ids, revocation_responses, delegation_chain (as present)
    did_documents  DID -> DID document; resolve every kid against these, offline

    Return {"result": "ACCEPT" | "REJECT", "verification_step": 1..9} and optionally
    "rejection_reason" (shown in the output, not compared).
    """
    raise NotImplementedError("native verify")  # TODO


def enforce_check(mandate, transaction, prev_core_digest) -> dict:
    """Enforce vectors, kernel "enforce_check" (draft -02, enforce kernel 3.0).

    Return {"verdict": "PERMIT" | "DENY" | "PENDING", "core_digest": "sha256:<hex>",
    "grant_index": int | None} and optionally "trace" and "reason".
    """
    raise NotImplementedError("enforce_check")  # TODO


def ratify(prior_record, decision, authority_proof, prev_core_digest) -> dict:
    """Enforce vectors, kernel "ratify" (draft -02, Sections 6.3 and 6.4).

    Return {"status": "RATIFIED" | "REJECTED", "core_digest": ..., "ratifies": ...,
    "authority": str | None}. When a guard refuses the request (nothing to record),
    return {"caller_error": "<message>"} instead.
    """
    raise NotImplementedError("ratify")  # TODO


def handle(req: dict) -> dict:
    inp = req["input"]
    if req["family"] == "native":
        return verify_native(inp["secured_aae"], inp["context"], req["did_documents"])
    if req["kernel"] == "enforce_check":
        return enforce_check(inp.get("mandate"), inp.get("transaction"),
                             inp.get("prev_core_digest"))
    return ratify(inp.get("prior_record"), inp.get("decision"),
                  inp.get("authority_proof"), inp.get("prev_core_digest"))


def main() -> int:
    req = json.loads(sys.stdin.read())
    try:
        resp = handle(req)
    except NotImplementedError as exc:
        resp = {"error": f"not implemented: {exc}"}
    json.dump(resp, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
