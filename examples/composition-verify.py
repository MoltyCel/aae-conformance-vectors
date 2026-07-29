#!/usr/bin/env python3
"""Reference composition checker for interop/psea composition vectors.

Composes an AAE (draft-kroehl-agentic-trust-aae-00) with one artifact from
another profile and reports a STAGED result. It calls the unmodified AAE
reference verifier, python-verify.py, as a building block; that file is not
touched and its Section 5 behaviour is not reimplemented here.

The composition layer answers a question neither profile answers alone: did the
SAME human both mandate the action and approve it. That needs two joins.

  WHAT  both sides commit to the same action    - 32-octet digest comparison
  WHO   both sides name the same principal      - declared resolution table

The result is seven rows, not one verdict. Each row carries a value from its own
closed enum and an optional reason:

  aae_native             ACCEPT | REJECT
  action_linkage         EQUIVALENT | NOT_EQUIVALENT | INDETERMINATE
  principal_linkage      SAME | DIVERGENT | UNRESOLVED
  evidence_satisfaction  SATISFIED | UNSATISFIED | NOT_EVALUATED
  decision               AUTHORIZED | REFUSED
  admission              NONE | RESERVED | CONSUMED | DISPATCH_PENDING | INVOKED
  outcome                EXECUTED | FAILED | INDETERMINATE | NONE

Why rows rather than a verdict: a single column has to render a divergence and a
missing binding with the same token, and a reader cannot recover which happened.
Here both end REFUSED at `decision` and are told apart one row earlier, at
principal_linkage DIVERGENT against UNRESOLVED. The enums also keep unlike
uncertainties apart by construction - INDETERMINATE on `action_linkage` (the
linkage could not be established) is a different fact from INDETERMINATE on
`outcome` (what happened could not be established), and neither is UNRESOLVED on
`principal_linkage`.

Evaluation order, fail-closed at every step. Failing a step does not suppress
the rows below it: every row is reported, and a row a failure prevented from
being established says so with its own not-established value rather than being
omitted or guessed.

  1. AAE native, Section 5.
       REJECT -> nothing downstream is admitted: action_linkage INDETERMINATE,
       principal_linkage UNRESOLVED, evidence NOT_EVALUATED, decision REFUSED.
  2. Secondary artifact native (ES256 against the fixture's enrolled JWK).
       failure -> the artifact's commitments are untrusted: action_linkage
       INDETERMINATE, principal_linkage UNRESOLVED (its kid claim is
       unauthenticated), evidence UNSATISFIED, decision REFUSED.
  3. WHAT-join. Both digests are decoded to raw octets and compared as octets.
       equal -> EQUIVALENT; different -> NOT_EQUIVALENT; undecodable ->
       INDETERMINATE.
  4. WHO-join. Both identifiers are resolved through the vector's declared
     principal_resolution table.
       both resolve, equal      -> SAME
       both resolve, different  -> DIVERGENT      (an observed conflict)
       either has no entry      -> UNRESOLVED     (a missing input)

`decision` is AUTHORIZED only when aae_native ACCEPT, action_linkage EQUIVALENT,
principal_linkage SAME, and evidence_satisfaction SATISFIED all hold. Otherwise
REFUSED, with the locating reason on the row that produced it.

`admission` and `outcome` describe what a relying party did with the decision and
what came back. This checker decides but never admits or executes, so it reports
NONE for both. They are in the row set so that a profile which does act can
report it in the same shape, and so that a spent admission with an unknown result
has somewhere to be recorded other than the decision column.

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

STAGE_ORDER = (
    "aae_native",
    "action_linkage",
    "principal_linkage",
    "evidence_satisfaction",
    "decision",
    "admission",
    "outcome",
)


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


def _row(value: str, reason: str | None = None, **extra) -> dict:
    row = {"value": value}
    if reason is not None:
        row["reason"] = reason
    row.update(extra)
    return row


def compose(vector: dict, fixture: dict, aae_verifier) -> dict:
    """Return the seven staged rows. Every row is always present."""
    ctx = vector["input"]["context"]
    now = parse_time(ctx["current_time"])
    artifact = vector["input"]["secondary_artifact"]
    trace: list[str] = []

    # admission and outcome: this checker decides, it never admits or executes.
    tail = {"admission": _row("NONE"), "outcome": _row("NONE")}

    # --- 1. AAE native, Section 5 (unmodified reference verifier) -----------------
    native = aae_verifier.verify(vector["input"]["secured_aae"], ctx)
    step = native.get("verification_step")
    trace.append(f"1 aae_native={native['result']}@{step}")
    aae_row = _row("ACCEPT" if native["result"] == "ACCEPT" else "REJECT",
                   native.get("rejection_reason"),
                   **({"verification_step": step} if step is not None else {}))

    if native["result"] != "ACCEPT":
        # The grant was not admitted, so nothing downstream is established.
        # Reporting EQUIVALENT or SAME here would claim a fact off an artifact
        # the verifier just refused.
        return {"stages": {
            "aae_native": aae_row,
            "action_linkage": _row("INDETERMINATE", "aae_not_admitted"),
            "principal_linkage": _row("UNRESOLVED", "aae_not_admitted"),
            "evidence_satisfaction": _row("NOT_EVALUATED", "aae_not_admitted"),
            "decision": _row("REFUSED", "aae_native_reject"),
            **tail,
        }, "trace": trace}

    # --- 2. Secondary artifact native ---------------------------------------------
    ok, detail = verify_psea_proof(artifact, fixture, now)
    trace.append(f"2 secondary_native={'VERIFIED' if ok else 'FAILED'}"
                 + ("" if ok else f" ({detail})"))
    if not ok:
        # An unauthenticated artifact commits to nothing and its kid claim
        # carries no principal, so both linkages are unestablished rather than
        # negative. The evidence itself is a definite failure.
        return {"stages": {
            "aae_native": aae_row,
            "action_linkage": _row("INDETERMINATE", "secondary_unauthenticated"),
            "principal_linkage": _row("UNRESOLVED", "secondary_unauthenticated"),
            "evidence_satisfaction": _row("UNSATISFIED", detail),
            "decision": _row("REFUSED", "secondary_native_reject"),
            **tail,
        }, "trace": trace}

    # --- 3. WHAT-join: 32-octet comparison ----------------------------------------
    join_what = vector["input"]["join_what"]
    try:
        aae_octets = decode_digest(join_what["aae_digest"])
        secondary_octets = decode_digest(join_what["secondary_digest"])
    except Exception as exc:  # noqa: BLE001 - an undecodable digest is not a mismatch
        trace.append(f"3 action_linkage=INDETERMINATE ({exc})")
        return {"stages": {
            "aae_native": aae_row,
            "action_linkage": _row("INDETERMINATE", "digest_undecodable"),
            "principal_linkage": _row("UNRESOLVED", "action_linkage_unestablished"),
            "evidence_satisfaction": _row("NOT_EVALUATED", "action_linkage_unestablished"),
            "decision": _row("REFUSED", "action_linkage_unestablished"),
            **tail,
        }, "trace": trace}

    equivalent = aae_octets == secondary_octets
    trace.append(f"3 action_linkage aae={aae_octets.hex()} secondary={secondary_octets.hex()}")
    action_row = _row("EQUIVALENT") if equivalent else _row("NOT_EQUIVALENT", "join_mismatch")

    # --- 4. WHO-join: declared principal resolution --------------------------------
    # Computed independently of step 3: the principal identifiers do not depend on
    # which action the artifacts commit to, and a reader is owed both facts.
    table = vector["input"]["join_who"]["principal_resolution"]
    aae_payload = json.loads(b64url_decode(vector["input"]["secured_aae"].split(".")[1]))
    aae_principal_did = aae_payload["credentialSubject"]["aae"]["mandate"].get("principal_did")

    aae_canonical = resolve(aae_principal_did, table["aae"])
    secondary_canonical = resolve(artifact["enrollment_binding"], table["secondary"])
    trace.append(
        f"4 principal_linkage aae={aae_principal_did!r}->{aae_canonical!r} "
        f"secondary={artifact['enrollment_binding']!r}->{secondary_canonical!r}")

    if aae_canonical is None or secondary_canonical is None:
        principal_row = _row("UNRESOLVED", "unresolved_binding")
        evidence_row = _row("NOT_EVALUATED", "unresolved_binding")
        decision_reason = "unresolved_binding"
    elif aae_canonical == secondary_canonical:
        principal_row = _row("SAME")
        evidence_row = (_row("SATISFIED") if equivalent
                        else _row("UNSATISFIED", "evidence_covers_a_different_action"))
        decision_reason = None if equivalent else "join_mismatch"
    else:
        principal_row = _row("DIVERGENT", "principal_divergence")
        evidence_row = _row("UNSATISFIED", "principal_divergence")
        decision_reason = "principal_divergence"

    authorized = (equivalent
                  and principal_row["value"] == "SAME"
                  and evidence_row["value"] == "SATISFIED")
    decision_row = _row("AUTHORIZED") if authorized else _row("REFUSED", decision_reason)

    return {"stages": {
        "aae_native": aae_row,
        "action_linkage": action_row,
        "principal_linkage": principal_row,
        "evidence_satisfaction": evidence_row,
        "decision": decision_row,
        **tail,
    }, "trace": trace}


def compare_stages(got: dict, want: dict) -> list[str]:
    """Row-by-row comparison. Reports every differing row, not just the first."""
    diffs = []
    for stage in STAGE_ORDER:
        g = got.get(stage, {})
        w = want.get(stage, {})
        if g.get("value") != w.get("value"):
            diffs.append(f"{stage:22} expected {w.get('value')!r} got {g.get('value')!r}")
        if "reason" in w and w.get("reason") != g.get("reason"):
            diffs.append(f"{stage:22} reason expected {w.get('reason')!r} "
                         f"got {g.get('reason')!r}")
        if "verification_step" in w and w["verification_step"] != g.get("verification_step"):
            diffs.append(f"{stage:22} verification_step expected "
                         f"{w['verification_step']} got {g.get('verification_step')}")
    return diffs


def format_stages(stages: dict) -> str:
    parts = []
    for stage in STAGE_ORDER:
        row = stages.get(stage, {})
        cell = row.get("value", "?")
        if row.get("reason"):
            cell += f"({row['reason']})"
        parts.append(cell)
    return " | ".join(parts)


def main() -> int:
    aae_verifier = load_aae_verifier()
    with open(FIXTURE) as fh:
        fixture = json.load(fh)

    files = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
    if not files:
        print("no composition vectors found")
        return 1

    print("stages: " + " | ".join(STAGE_ORDER))
    print()

    passed = 0
    for path in files:
        name = os.path.basename(path)
        with open(path) as fh:
            vector = json.load(fh)
        got = compose(vector, fixture, aae_verifier)
        diffs = compare_stages(got["stages"], vector["expected"]["stages"])

        if diffs:
            print(f"FAIL  {name}")
            for d in diffs:
                print(f"        {d}")
            for line in got["trace"]:
                print(f"        trace: {line}")
        else:
            passed += 1
            print(f"PASS  {name}")
        print(f"        {format_stages(got['stages'])}")

    print(f"\n{passed}/{len(files)} composition vectors passed (row-by-row)")
    return 0 if passed == len(files) else 1


if __name__ == "__main__":
    sys.exit(main())
