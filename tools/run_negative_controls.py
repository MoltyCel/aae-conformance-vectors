#!/usr/bin/env python3
"""Run the negative controls in interop/psea/negative-controls.json.

Each control changes ONE input of a committed vector, in memory, and asserts the
seven rows the checker must then report. Nothing on disk is modified. C7 is the
exception to "mutate": it substitutes a committed, separately signed envelope, so
the checker meets real signed bytes rather than a run-time patch.

The six composition vectors alone cannot show that the checker's branches are
live: all six reach ACCEPT and EQUIVALENT on the first two rows and differ only
from principal_linkage onward. The controls reach NOT_EQUIVALENT, three distinct
causes of INDETERMINATE on action_linkage, REJECT on aae_native, and
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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

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

    elif op == "set_payload_member":
        # Change one member of join_what.payload. The declared aae_digest and the
        # signed action_binding stay in step, so the binding check passes and the
        # recomputation is what catches the payload.
        v["input"]["join_what"]["payload"][mutation["key"]] = mutation["value"]

    elif op == "use_envelope":
        # Substitute a committed, separately signed envelope. The JWS is minted by
        # tools/build_interop_psea.py with the committed test keys, so the checker
        # meets real signed bytes rather than a run-time patch.
        path = os.path.join(INTEROP, "aae-envelopes", mutation["file"])
        with open(path) as fh:
            envelope = json.load(fh)
        v["input"]["secured_aae"] = envelope["secured_aae"]

    elif op == "resign_token_with_key":
        # Re-sign the PSEA token with a key that is not enrolled, and embed that
        # key's public half in the payload, while leaving the protected header's
        # kid pointing at the enrolled key. A verifier that took key material from
        # the artifact would accept; one that resolves kid against the enrolled
        # record rejects on the signature.
        #
        # Signing is RFC 6979 deterministic, so the forged token is byte-identical
        # on every run and a second implementation can recompute it. Nothing is
        # committed for this control beyond the key itself.
        with open(os.path.join(ROOT, "testkeys", mutation["key"])) as fh:
            attacker = json.load(fh)["jwk"]

        def b64u(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        def b64u_dec(text: str) -> bytes:
            return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

        header_b64, payload_b64, _ = v["input"]["secondary_artifact"]["token"].split(".")
        claims = json.loads(b64u_dec(payload_b64))
        claims[mutation.get("embed_as", "cnf")] = {
            "jwk": {k: attacker[k] for k in ("kty", "crv", "x", "y")}
        }
        forged_payload = b64u(json.dumps(claims, separators=(",", ":")).encode("utf-8"))

        private = ec.derive_private_key(
            int.from_bytes(b64u_dec(attacker["d"]), "big"), ec.SECP256R1())
        der = private.sign(f"{header_b64}.{forged_payload}".encode("ascii"),
                           ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s_ = decode_dss_signature(der)
        signature = b64u(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))
        v["input"]["secondary_artifact"]["token"] = (
            f"{header_b64}.{forged_payload}.{signature}")

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
