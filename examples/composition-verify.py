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

The result is eight rows, not one verdict. Each row carries a value from its own
closed enum and an optional reason:

  aae_native             ACCEPT | REJECT
  action_linkage         EQUIVALENT | NOT_EQUIVALENT | INDETERMINATE
  principal_linkage      SAME | DIVERGENT | UNRESOLVED
  evidence_satisfaction  SATISFIED | UNSATISFIED | NOT_EVALUATED
  freshness              WELL_FORMED | CLAIMS_MALFORMED | NOT_EVALUATED
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
  3. WHAT-join. The AAE side's own commitment is checked first: the declared
     join_what.aae_digest must equal mandate.action_binding.payload_digest from
     the envelope authenticated in step 1. Absent -> INDETERMINATE
     (aae_binding_absent); different -> INDETERMINATE (aae_binding_mismatch).
     Only then are both declared digests decoded to raw octets and compared as
     octets: equal -> EQUIVALENT; different -> NOT_EQUIVALENT; undecodable ->
     INDETERMINATE. The declared digest is then recomputed from
     join_what.payload by RFC 8785 canonicalization and SHA-256; a payload whose
     digest differs -> NOT_EQUIVALENT (payload_digest_mismatch), a payload
     outside the I-JSON subset -> INDETERMINATE (payload_not_i_json).
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
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone

# Hard import on purpose. A fallback to json.dumps(sort_keys=True) would let the
# checker verify a digest under a canonicalization other than the one it was
# built with, and agree by accident on the payloads where the two coincide.
import jcs

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
    "freshness",
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


MAX_SAFE_INTEGER = 2 ** 53 - 1


def valid_unicode_scalars(text: str) -> bool:
    """Reject lone surrogates. A Python str parsed from JSON can hold one; RFC 8785
    canonicalizes Unicode scalar values, and a lone surrogate is not one."""
    index = 0
    while index < len(text):
        code = ord(text[index])
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 >= len(text) or not (0xDC00 <= ord(text[index + 1]) <= 0xDFFF):
                return False
            index += 2
            continue
        if 0xDC00 <= code <= 0xDFFF:
            return False
        index += 1
    return True


def check_i_json(value, path: str = "payload", seen: set | None = None) -> None:
    """Gate the payload to the I-JSON subset this exchange uses, mirroring the
    counterpart implementation's canonicalize() in reperform.mjs.

    This is not a general RFC 8785 conformance check and does not claim to be. It
    admits exactly the subset both sides agreed the exchange stays inside:
    integers within the safe range, strings and member names over Unicode scalars,
    no cycles. Anything else is refused here rather than canonicalized into a
    digest whose reproducibility across implementations is unknown.
    """
    seen = set() if seen is None else seen
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if not valid_unicode_scalars(value):
            raise ValueError(f"{path}: invalid Unicode scalar")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: number outside the safe integer range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: non-integer number")
    if isinstance(value, (dict, list)):
        if id(value) in seen:
            raise ValueError(f"{path}: cyclic JSON")
        seen.add(id(value))
        try:
            if isinstance(value, list):
                for i, item in enumerate(value):
                    check_i_json(item, f"{path}[{i}]", seen)
            else:
                for key, item in value.items():
                    if not isinstance(key, str) or not valid_unicode_scalars(key):
                        raise ValueError(f"{path}: invalid member name")
                    check_i_json(item, f"{path}.{key}", seen)
        finally:
            seen.discard(id(value))
        return
    raise ValueError(f"{path}: value is not JSON")


def recompute_action_digest(payload) -> bytes:
    """SHA-256 over the RFC 8785 canonical form of the payload. Raises ValueError
    if the payload leaves the I-JSON subset."""
    check_i_json(payload)
    return hashlib.sha256(jcs.canonicalize(payload)).digest()


def check_replay_claims(claims: dict) -> tuple[str, str | None]:
    """Well-formedness of the counterpart profile's replay-defence claims.

    draft-yossif-psea Section 3.11 anchors replay defence in psea_counter
    (ordering), the global uniqueness of jti, and an OPTIONAL eat_nonce when the
    verifier issued a challenge. Section 3.5 makes psea_counter and jti REQUIRED.

    Checked here: presence and shape, from the token this checker has already
    authenticated. psea_counter first, because it is the ordering anchor and a
    missing one leaves the sequence undefined; jti second, as the uniqueness key.
    The order is fixed so two implementations name the same failure on a token
    that breaks both.

    Not checked here, and not reachable from one presentation: whether the counter
    advanced, whether the jti was already spent, whether a nonce answers an
    outstanding challenge. Those are state across presentations.

    iat and exp are also present in the token. They are verified during native
    verification and stay out of this row: temporal validity of the authorization
    is the AAE VALIDITY axis, and folding a second window into this stage would
    put one fact on two rows.
    """
    counter = claims.get("psea_counter")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        return "CLAIMS_MALFORMED", "counter_malformed"
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti.strip():
        return "CLAIMS_MALFORMED", "jti_malformed"
    return "WELL_FORMED", None


def _row(value: str, reason: str | None = None, **extra) -> dict:
    row = {"value": value}
    if reason is not None:
        row["reason"] = reason
    row.update(extra)
    return row


def compose(vector: dict, fixture: dict, aae_verifier) -> dict:
    """Return the eight staged rows. Every row is always present."""
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
            "freshness": _row("NOT_EVALUATED", "aae_not_admitted"),
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
            "freshness": _row("NOT_EVALUATED", "secondary_unauthenticated"),
            "decision": _row("REFUSED", "secondary_native_reject"),
            **tail,
        }, "trace": trace}

    # --- 3. WHAT-join: bind the digest to the signed envelope, then compare octets -
    join_what = vector["input"]["join_what"]
    aae_payload = json.loads(b64url_decode(vector["input"]["secured_aae"].split(".")[1]))
    aae_mandate = aae_payload["credentialSubject"]["aae"]["mandate"]

    def unestablished(reason: str) -> dict:
        """Step 3 could not establish the linkage. Nothing downstream may claim a
        fact that depends on knowing which action the artifacts commit to."""
        return {"stages": {
            "aae_native": aae_row,
            "action_linkage": _row("INDETERMINATE", reason),
            "principal_linkage": _row("UNRESOLVED", "action_linkage_unestablished"),
            "evidence_satisfaction": _row("NOT_EVALUATED", "action_linkage_unestablished"),
            "freshness": _row("NOT_EVALUATED", "action_linkage_unestablished"),
            "decision": _row("REFUSED", "action_linkage_unestablished"),
            **tail,
        }, "trace": trace}

    try:
        aae_octets = decode_digest(join_what["aae_digest"])
        secondary_octets = decode_digest(join_what["secondary_digest"])
    except Exception as exc:  # noqa: BLE001 - an undecodable digest is not a mismatch
        trace.append(f"3 action_linkage=INDETERMINATE ({exc})")
        return unestablished("digest_undecodable")

    # The AAE side must itself commit to the digest the vector declares for it.
    # Step 1 authenticated the envelope, so mandate.action_binding is signed bytes;
    # anchoring join_what.aae_digest to it removes the gap where a vector could
    # declare a digest unrelated to the envelope it ships. This is the mirror of
    # the check verify_psea_proof already performs on psea_payload_hash.
    #
    # This step tests the binding only. The payload is recanonicalized and rehashed
    # further down, after the binding holds.
    binding = aae_mandate.get("action_binding")
    if not isinstance(binding, dict) or not isinstance(binding.get("payload_digest"), str):
        trace.append("3 action_linkage=INDETERMINATE (mandate carries no action_binding)")
        return unestablished("aae_binding_absent")

    signed = binding["payload_digest"]
    if signed.startswith("sha-256:"):
        signed = signed[len("sha-256:"):]
    try:
        signed_octets = b64url_decode(signed)
    except Exception:  # noqa: BLE001 - folded into mismatch, see below
        signed_octets = b""
    # An undecodable, wrong-length or wrong-algorithm binding is folded into
    # mismatch: each is a case of the envelope not committing to the declared
    # digest, and splitting them would multiply reasons without adding a fact.
    if binding.get("alg") != "sha-256" or len(signed_octets) != 32 or signed_octets != aae_octets:
        trace.append(f"3 action_linkage=INDETERMINATE (signed {signed_octets.hex() or '-'} "
                     f"!= declared {aae_octets.hex()})")
        return unestablished("aae_binding_mismatch")

    # The declared digest is bound to the envelope. Now check it is the digest of
    # the payload the vector carries, by recanonicalizing and rehashing. This runs
    # AFTER the binding check on purpose: a declared digest that matches neither
    # the envelope nor the payload is first of all not bound to the envelope, and
    # reporting it as a payload mismatch would name the second symptom of the same
    # desynchronization.
    try:
        recomputed = recompute_action_digest(join_what["payload"])
    except ValueError as exc:
        trace.append(f"3 action_linkage=INDETERMINATE (payload outside I-JSON: {exc})")
        return unestablished("payload_not_i_json")

    if recomputed != aae_octets:
        trace.append(f"3 action_linkage=NOT_EQUIVALENT (recomputed {recomputed.hex()} "
                     f"!= declared {aae_octets.hex()})")
        equivalent = False
        linkage_reason = "payload_digest_mismatch"
        action_row = _row("NOT_EQUIVALENT", linkage_reason)
    else:
        equivalent = aae_octets == secondary_octets
        trace.append(f"3 action_linkage recomputed=signed=declared={aae_octets.hex()} "
                     f"secondary={secondary_octets.hex()}")
        linkage_reason = None if equivalent else "join_mismatch"
        action_row = _row("EQUIVALENT") if equivalent else _row("NOT_EQUIVALENT", linkage_reason)

    # --- 4. WHO-join: declared principal resolution --------------------------------
    # Computed independently of step 3: the principal identifiers do not depend on
    # which action the artifacts commit to, and a reader is owed both facts.
    table = vector["input"]["join_who"]["principal_resolution"]
    aae_principal_did = aae_mandate.get("principal_did")

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
        if equivalent:
            evidence_row = _row("SATISFIED")
        elif linkage_reason == "payload_digest_mismatch":
            # The AAE's own declaration disagrees with its payload, so nothing is
            # known about which action the evidence would have to cover.
            evidence_row = _row("UNSATISFIED", "payload_digest_mismatch")
        else:
            evidence_row = _row("UNSATISFIED", "evidence_covers_a_different_action")
        decision_reason = linkage_reason
    else:
        principal_row = _row("DIVERGENT", "principal_divergence")
        evidence_row = _row("UNSATISFIED", "principal_divergence")
        decision_reason = "principal_divergence"

    # --- 5. Freshness: replay-defence claim shape, from the authenticated token ---
    # The token verified in step 2, so re-decoding its payload reads authenticated
    # bytes. verify_psea_proof returns a verdict rather than the claims, and
    # re-decoding here keeps that signature unchanged.
    psea_claims = json.loads(b64url_decode(artifact["token"].split(".")[1]))
    fresh_value, fresh_reason = check_replay_claims(psea_claims)
    trace.append(f"5 freshness={fresh_value}" + (f" ({fresh_reason})" if fresh_reason else ""))
    freshness_row = _row(fresh_value, fresh_reason)

    authorized = (equivalent
                  and principal_row["value"] == "SAME"
                  and evidence_row["value"] == "SATISFIED"
                  and fresh_value == "WELL_FORMED")
    if decision_reason is None and fresh_value != "WELL_FORMED":
        decision_reason = fresh_reason
    decision_row = _row("AUTHORIZED") if authorized else _row("REFUSED", decision_reason)

    return {"stages": {
        "aae_native": aae_row,
        "action_linkage": action_row,
        "principal_linkage": principal_row,
        "evidence_satisfaction": evidence_row,
        "freshness": freshness_row,
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
