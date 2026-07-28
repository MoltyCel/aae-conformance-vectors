#!/usr/bin/env python3
"""Reference composition checker for interop/psea composition vectors.

Composes an AAE (draft-kroehl-agentic-trust-aae-00) with one artifact from
another profile and returns a composition verdict. It calls the unmodified AAE
reference verifier, python-verify.py, as a building block; that file is not
touched and its Section 5 behaviour is not reimplemented here.

The composition layer answers a question neither profile answers alone: did the
SAME human both mandate the action and approve it. That needs two joins.

  WHAT  both sides commit to the same action    - 32-octet digest comparison
  WHO   both sides name the same principal      - declared resolution table

Order of operations, fail-closed at every step:

  1. AAE native, Section 5. Must ACCEPT; a native REJECT is propagated.
  2. Secondary artifact native. Must verify; a native failure is propagated.
  3. WHAT-join. Digests are decoded to raw octets and compared as octets.
     No match -> INDETERMINATE(join_mismatch), stop.
  4. WHO-join. Both identifiers are resolved through the vector's declared
     principal_resolution table.
       one side unresolved              -> INDETERMINATE(unresolved_binding)
       both resolved, same canonical    -> AUTHORIZED
       both resolved, different         -> REFUSE(principal_divergence)

REFUSE and INDETERMINATE never collapse. REFUSE means a conflict was observed.
INDETERMINATE means an input needed to decide was missing. A checker that
returns REFUSE for both reports a conflict it never saw, and a reviewer cannot
tell the two failure modes apart from the result.

Usage:
    pip install cryptography jsonschema
    python3 composition-verify.py
"""
from __future__ import annotations

import base64
import glob
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
INTEROP = os.path.join(ROOT, "interop", "psea")
VECTORS = os.path.join(INTEROP, "vectors")
FIXTURE = os.path.join(INTEROP, "psea-fixture-v0.json")

AUTHORIZED = "AUTHORIZED"
REFUSE = "REFUSE"
INDETERMINATE = "INDETERMINATE"


def load_aae_verifier():
    """Import python-verify.py as a module. That file is used as-is."""
    path = os.path.join(HERE, "python-verify.py")
    spec = importlib.util.spec_from_file_location("aae_reference_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_digest(entry: dict) -> bytes:
    """Decode a declared digest to raw octets. The encoding is read from the
    vector, never sniffed. A profile-specific 'sha-256:' prefix is stripped."""
    value = entry["value"]
    if value.startswith("sha-256:"):
        value = value[len("sha-256:"):]
    encoding = entry["encoding"]
    if encoding == "base64url-nopad":
        raw = b64url_decode(value)
    elif encoding == "base64-pad":
        raw = base64.b64decode(value)
    elif encoding == "hex":
        raw = bytes.fromhex(value)
    else:
        raise ValueError(f"undeclared digest encoding: {encoding!r}")
    if len(raw) != entry["octets"]:
        raise ValueError(
            f"digest decodes to {len(raw)} octets, vector declares {entry['octets']}")
    return raw


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_psea_proof(artifact: dict, fixture: dict, now: datetime) -> tuple[bool, str]:
    """Native verification of a draft-yossif-psea-02 proof: ES256 over the JWS
    signing input, against the enrolled JWK the fixture publishes for the kid in
    the protected header, inside the token's own iat/exp window.

    Only what the fixture supplies is used. No key material, claim, or verdict is
    synthesized here.
    """
    token = artifact["token"]
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        claims = json.loads(b64url_decode(p_b64))
    except Exception:
        return False, "malformed_token"

    if header.get("alg") != "ES256":
        return False, f"unexpected alg {header.get('alg')!r}"
    if header.get("typ") != "psea-proof+jwt":
        return False, f"unexpected typ {header.get('typ')!r}"

    kid = header.get("kid")
    if kid != artifact["signer_kid"]:
        return False, "kid in protected header differs from the vector's signer_kid"

    jwk = next((k for k in fixture["enrolled_keys"] if k.get("kid") == kid), None)
    if jwk is None:
        return False, f"kid {kid!r} is not an enrolled key in the fixture"
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return False, "enrolled key is not an EC P-256 key"

    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url_decode(jwk["x"]), "big"),
        int.from_bytes(b64url_decode(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()

    raw_sig = b64url_decode(s_b64)
    if len(raw_sig) != 64:
        return False, "ES256 signature is not 64 octets"
    der = encode_dss_signature(int.from_bytes(raw_sig[:32], "big"),
                               int.from_bytes(raw_sig[32:], "big"))
    try:
        public.verify(der, f"{h_b64}.{p_b64}".encode("ascii"),
                      ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "invalid_signature"

    epoch = int(now.timestamp())
    if "iat" in claims and epoch < claims["iat"]:
        return False, "not_yet_valid_iat"
    if "exp" in claims and epoch > claims["exp"]:
        return False, "expired_exp"

    # The artifact must commit to the same digest the vector records for it.
    committed = claims.get("psea_payload_hash")
    if committed is None:
        return False, "token carries no psea_payload_hash"
    try:
        if base64.b64decode(committed) != decode_digest(artifact["payload_digest"]):
            return False, "token payload hash differs from the vector's payload_digest"
    except Exception:
        return False, "token payload hash is not decodable"

    return True, "verified"


def resolve(identifier: str, table: dict) -> str | None:
    """Resolve an identifier through the declared table. No entry -> unresolved.
    Nothing is inferred from the shape of the identifier."""
    return table.get(identifier)


def compose(vector: dict, fixture: dict, aae_verifier) -> dict:
    ctx = vector["input"]["context"]
    now = parse_time(ctx["current_time"])
    artifact = vector["input"]["secondary_artifact"]
    trace: list[str] = []

    # --- 1. AAE native, Section 5 (unmodified reference verifier) -----------------
    aae_native = aae_verifier.verify(vector["input"]["secured_aae"], ctx)
    trace.append(f"1 aae_native={aae_native['result']}@{aae_native['verification_step']}")
    if aae_native["result"] != "ACCEPT":
        return {
            "composition_verdict": REFUSE,
            "reason": "aae_native_reject",
            "aae_native": aae_native,
            "secondary_native": None,
            "trace": trace,
        }

    # --- 2. Secondary artifact native --------------------------------------------
    ok, detail = verify_psea_proof(artifact, fixture, now)
    secondary_native = {"result": "VERIFIED" if ok else "FAILED",
                        "detail": None if ok else detail}
    trace.append(f"2 secondary_native={secondary_native['result']}")
    if not ok:
        return {
            "composition_verdict": REFUSE,
            "reason": "secondary_native_reject",
            "aae_native": aae_native,
            "secondary_native": secondary_native,
            "trace": trace,
        }

    result = {
        "aae_native": aae_native,
        "secondary_native": secondary_native,
        "trace": trace,
    }

    # --- 3. WHAT-join: 32-octet comparison ---------------------------------------
    join_what = vector["input"]["join_what"]
    aae_octets = decode_digest(join_what["aae_digest"])
    secondary_octets = decode_digest(join_what["secondary_digest"])
    trace.append(f"3 join_what aae={aae_octets.hex()} secondary={secondary_octets.hex()}")
    if aae_octets != secondary_octets:
        result.update({"composition_verdict": INDETERMINATE, "reason": "join_mismatch"})
        return result

    # --- 4. WHO-join: declared principal resolution -------------------------------
    join_who = vector["input"]["join_who"]
    table = join_who["principal_resolution"]

    aae_payload = json.loads(b64url_decode(vector["input"]["secured_aae"].split(".")[1]))
    aae_principal_did = aae_payload["credentialSubject"]["aae"]["mandate"].get("principal_did")

    aae_canonical = resolve(aae_principal_did, table["aae"])
    secondary_canonical = resolve(artifact["enrollment_binding"], table["secondary"])
    trace.append(
        f"4 join_who aae={aae_principal_did!r}->{aae_canonical!r} "
        f"secondary={artifact['enrollment_binding']!r}->{secondary_canonical!r}")

    if aae_canonical is None or secondary_canonical is None:
        result.update({"composition_verdict": INDETERMINATE, "reason": "unresolved_binding"})
        return result
    if aae_canonical == secondary_canonical:
        result.update({"composition_verdict": AUTHORIZED, "reason": None})
        return result
    result.update({"composition_verdict": REFUSE, "reason": "principal_divergence"})
    return result


def main() -> int:
    aae_verifier = load_aae_verifier()
    with open(FIXTURE) as fh:
        fixture = json.load(fh)

    files = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
    if not files:
        print("no composition vectors found")
        return 1

    passed = 0
    for path in files:
        name = os.path.basename(path)
        with open(path) as fh:
            vector = json.load(fh)
        got = compose(vector, fixture, aae_verifier)
        want = vector["expected"]

        mismatches = []
        if got["composition_verdict"] != want["composition_verdict"]:
            mismatches.append(
                f"verdict expected {want['composition_verdict']} got {got['composition_verdict']}")
        if got["reason"] != want.get("reason"):
            mismatches.append(
                f"reason expected {want.get('reason')!r} got {got['reason']!r}")
        if "aae_native" in want and got["aae_native"]["result"] != want["aae_native"]["result"]:
            mismatches.append(
                f"aae_native expected {want['aae_native']['result']} "
                f"got {got['aae_native']['result']}")
        if "secondary_native" in want and got["secondary_native"] is not None and \
                got["secondary_native"]["result"] != want["secondary_native"]["result"]:
            mismatches.append(
                f"secondary_native expected {want['secondary_native']['result']} "
                f"got {got['secondary_native']['result']}")

        label = f"{got['composition_verdict']}"
        if got["reason"]:
            label += f" / {got['reason']}"
        if mismatches:
            print(f"FAIL  {name:38} {label}")
            for m in mismatches:
                print(f"        {m}")
            for line in got["trace"]:
                print(f"        trace: {line}")
        else:
            passed += 1
            print(f"PASS  {name:38} {label}")

    print(f"\n{passed}/{len(files)} composition vectors passed")
    return 0 if passed == len(files) else 1


if __name__ == "__main__":
    sys.exit(main())
