#!/usr/bin/env python3
"""Reference AAE verifier + conformance-vector harness.

Implements the draft-kroehl-agentic-trust-aae-00 Section 5 verification
algorithm and runs it against vectors/*.json, comparing each result against the
vector's expected field.

This is a reference implementation skeleton, not production code. It exists to
show one correct interpretation of the algorithm and to give implementers an
objective target: an implementation claiming AAE conformance should classify
all vectors the same way (result + verification_step).

Facts that cannot be reproduced inside a static vector — live subject-binding
challenge-response (step 4), DID resolution over the network, and revocation
endpoint responses (step 8) — are supplied through each vector's "context"
object. DID documents are resolved offline from testkeys/did-documents/.

Standard library + `cryptography` only. Run: python3 examples/python-verify.py
"""
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
VECTORS_DIR = os.path.join(ROOT, "vectors")
DIDDOCS_DIR = os.path.join(ROOT, "testkeys", "did-documents")

RECOGNIZED_CONSTRAINTS = {"max_transaction_value", "allowed_domains", "rate_limit"}
NUMERIC_UPPER_BOUND = {"max_transaction_value"}
CURRENCY_VALUED = {"max_transaction_value"}
ALLOWLIST_CONSTRAINTS = {"allowed_domains"}


class Reject(Exception):
    def __init__(self, step: int, reason: str):
        super().__init__(reason)
        self.step = step
        self.reason = reason


# --- helpers -----------------------------------------------------------------

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_did_documents() -> dict:
    docs = {}
    for path in glob.glob(os.path.join(DIDDOCS_DIR, "*.json")):
        with open(path) as fh:
            doc = json.load(fh)
        docs[doc["id"]] = doc
    return docs


DID_DOCS = load_did_documents()


def resolve_assertion_key(kid: str, step: int) -> Ed25519PublicKey:
    """Resolve a kid DID URL to the Ed25519 public key of the referenced
    verification method, requiring assertionMethod authorization (§5 step 1)."""
    if not isinstance(kid, str) or "#" not in kid:
        raise Reject(step, "kid_not_did_url")
    signing_did = kid.split("#", 1)[0]
    doc = DID_DOCS.get(signing_did)
    if doc is None:
        raise Reject(step, "signing_did_unresolvable")
    if kid not in doc.get("assertionMethod", []):
        raise Reject(step, "vm_not_authorized_assertionMethod")
    vm = next((m for m in doc.get("verificationMethod", []) if m.get("id") == kid), None)
    if vm is None:
        raise Reject(step, "verification_method_absent")
    jwk = vm.get("publicKeyJwk", {})
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise Reject(step, "key_not_ed25519")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


def verify_signature(jws: str, step: int = 1) -> tuple[dict, dict, str]:
    """§5 step 1 signature verification. Returns (header, payload, signing_did)."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise Reject(step, "malformed_jws")
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64))
    except Exception:
        raise Reject(step, "malformed_header")
    if header.get("alg") != "EdDSA":
        raise Reject(step, "alg_not_eddsa")
    kid = header.get("kid")
    pub = resolve_assertion_key(kid, step)
    try:
        pub.verify(b64url_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
    except InvalidSignature:
        raise Reject(step, "invalid_signature")
    try:
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        raise Reject(step, "payload_not_json")
    return header, payload, kid.split("#", 1)[0]


def check_schema(header: dict, vc: dict, step: int = 2) -> None:
    """§5 step 2 payload/schema/cty validation."""
    if header.get("cty") != "aae+json":
        raise Reject(step, "cty_not_aae_json")
    if not isinstance(vc, dict):
        raise Reject(step, "payload_not_object")
    if not isinstance(vc.get("id"), str) or not isinstance(vc.get("issuer"), str):
        raise Reject(step, "missing_id_or_issuer")
    cs = vc.get("credentialSubject")
    if not isinstance(cs, dict) or not isinstance(cs.get("id"), str):
        raise Reject(step, "missing_credentialSubject")
    aae = cs.get("aae")
    if not isinstance(aae, dict) or not all(k in aae for k in ("mandate", "constraints", "validity")):
        raise Reject(step, "missing_aae_blocks")


def check_signing_authority(vc: dict, signing_did: str, step: int = 1) -> None:
    """§5 step 1 signing-authority rule."""
    deleg = vc["credentialSubject"]["aae"]["mandate"].get("delegation")
    issuer = vc["issuer"]
    if deleg is None:
        # non-delegated: signing DID MUST equal issuer
        if signing_did != issuer:
            raise Reject(step, "signing_authority_mismatch")
    else:
        # delegated, case (a): signing DID == delegator_did and issuer == delegator_did
        delegator = deleg.get("delegator_did")
        if not (signing_did == delegator and issuer == delegator):
            # case (b) (DID-document-authorized delegate) is not modelled by these vectors
            raise Reject(step, "signing_authority_mismatch")


def check_temporal(validity: dict, now: datetime, valid_from: str | None, step: int) -> None:
    """§5 step 3 temporal validity (also honours validFrom per §2.4)."""
    nb = validity.get("not_before")
    na = validity.get("not_after")
    lower = parse_time(nb) if nb else None
    if valid_from:
        vf = parse_time(valid_from)
        lower = vf if (lower is None or vf > lower) else lower
    if lower is not None and now < lower:
        raise Reject(step, "not_yet_valid_not_before")
    if na is not None and now > parse_time(na):
        raise Reject(step, "expired_not_after")


def check_revocation(vc: dict, ctx: dict, step: int, revoked_reason: str = "revoked") -> None:
    """§5 step 8 / §2.4 revocation. Endpoint responses are supplied via context."""
    validity = vc["credentialSubject"]["aae"]["validity"]
    if "revocation_check" not in validity:
        return
    resp = (ctx.get("revocation_responses") or {}).get(vc["id"])
    if resp is None:
        # MUST query; if status cannot be determined, fail closed
        raise Reject(step, "revocation_status_indeterminate")
    status = resp.get("http_status", 200)
    if status >= 500 or resp.get("unparseable"):
        raise Reject(step, "revocation_status_indeterminate")
    if resp.get("revoked") is True:
        raise Reject(step, revoked_reason)


def check_constraints(aae: dict, action_ctx: dict, step: int = 7) -> None:
    """§5 step 7 / §2.3 constraint evaluation."""
    constraints = aae.get("constraints", {})
    for ctype, c in constraints.items():
        required = c.get("required", True)
        if ctype not in RECOGNIZED_CONSTRAINTS:
            if required:
                raise Reject(step, "unrecognized_required_constraint")
            continue  # required:false unrecognized -> MAY ignore
        if ctype == "max_transaction_value":
            amount = action_ctx.get("amount")
            if amount is None:
                if required:
                    raise Reject(step, "constraint_unevaluable")
                continue
            if action_ctx.get("currency") != c.get("currency"):
                raise Reject(step, "currency_mismatch")
            if amount > c["value"]:
                raise Reject(step, "max_transaction_value_exceeded")
        elif ctype == "allowed_domains":
            domain = action_ctx.get("domain")
            if domain is None:
                if required:
                    raise Reject(step, "constraint_unevaluable")
                continue
            allow = {d.lower() for d in c.get("value", [])}
            if domain.lower() not in allow:
                raise Reject(step, "domain_not_in_allowlist")
        elif ctype == "rate_limit":
            count = action_ctx.get("rate_count")
            if count is None:
                if required:
                    raise Reject(step, "constraint_unevaluable")
                continue
            if count >= c["value"]:
                raise Reject(step, "rate_limit_exceeded")


def jws_hash(jws: str) -> str:
    return "sha-256:" + base64.urlsafe_b64encode(
        hashlib.sha256(jws.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def effective_depth(vc: dict) -> int:
    deleg = vc["credentialSubject"]["aae"]["mandate"].get("delegation")
    return deleg["depth"] if deleg else 0


def effective_max_depth(vc: dict) -> int | None:
    aae = vc["credentialSubject"]["aae"]
    deleg = aae["mandate"].get("delegation")
    if deleg:
        return deleg.get("max_depth")
    policy = aae["mandate"].get("delegation_policy")
    return policy.get("max_depth") if policy else None


def check_link(child_vc: dict, parent_vc: dict, step: int = 9) -> None:
    """§3 monotonicity + depth rules for one delegation link."""
    child = child_vc["credentialSubject"]["aae"]
    parent = parent_vc["credentialSubject"]["aae"]
    deleg = child["mandate"]["delegation"]

    if parent_vc["credentialSubject"]["id"] != deleg.get("delegator_did"):
        raise Reject(step, "delegator_did_mismatch")

    # optional parent-hash binding
    # (the secured parent JWS is rehashed by the caller; see verify())

    # actions subset
    child_actions = set(child["mandate"].get("actions", []))
    parent_actions = set(parent["mandate"].get("actions", []))
    if not child_actions.issubset(parent_actions):
        raise Reject(step, "delegated_actions_not_subset")

    # depth rules
    p_eff_depth = effective_depth(parent_vc)
    p_eff_max = effective_max_depth(parent_vc)
    if deleg.get("depth") != p_eff_depth + 1:
        raise Reject(step, "delegation_depth_inconsistent")
    if deleg.get("max_depth") is None or (p_eff_max is not None and deleg["max_depth"] > p_eff_max):
        raise Reject(step, "delegation_max_depth_exceeds_parent")
    if deleg["depth"] > deleg["max_depth"]:
        raise Reject(step, "delegation_depth_exceeded")

    # constraint monotonicity
    pc = parent.get("constraints", {})
    cc = child.get("constraints", {})
    for ctype, p in pc.items():
        if p.get("required", True) and ctype not in cc:
            raise Reject(step, "required_parent_constraint_dropped")
    for ctype, c in cc.items():
        p = pc.get(ctype)
        if p is None:
            continue
        if ctype in CURRENCY_VALUED and c.get("currency") != p.get("currency"):
            raise Reject(step, "delegation_currency_mismatch")
        if ctype in NUMERIC_UPPER_BOUND and c.get("value", 0) > p.get("value", 0):
            raise Reject(step, "delegated_constraint_relaxed")
        if ctype in ALLOWLIST_CONSTRAINTS and not set(c.get("value", [])).issubset(set(p.get("value", []))):
            raise Reject(step, "delegated_allowlist_not_subset")

    # validity window must be within parent
    cv, pv = child["validity"], parent["validity"]
    if cv.get("not_before") and pv.get("not_before") and parse_time(cv["not_before"]) < parse_time(pv["not_before"]):
        raise Reject(step, "delegated_validity_widened")
    if cv.get("not_after") and pv.get("not_after") and parse_time(cv["not_after"]) > parse_time(pv["not_after"]):
        raise Reject(step, "delegated_validity_widened")


def verify_delegation(presented_vc: dict, ctx: dict, now: datetime, step: int = 9) -> None:
    """§5 step 9 delegation chain verification."""
    chain = ctx.get("delegation_chain", [])
    # verify each ancestor's signature + schema + temporal + revocation, build VC list
    ancestors = []
    for jws in reversed(chain):  # immediate parent first
        header, vc, signing_did = verify_signature(jws, step=step)
        check_schema(header, vc, step=step)
        check_signing_authority(vc, signing_did, step=step)
        check_temporal(vc["credentialSubject"]["aae"]["validity"], now, vc.get("validFrom"), step=step)
        check_revocation(vc, ctx, step=step, revoked_reason="ancestor_revoked")
        ancestors.append((jws, vc))

    # cycle detection: AAE id MUST NOT appear more than once in the path
    path_ids = [presented_vc["id"]] + [vc["id"] for _, vc in ancestors]
    if len(set(path_ids)) != len(path_ids):
        raise Reject(step, "delegation_cycle_detected")

    # depth limit on the presented delegated AAE itself
    deleg = presented_vc["credentialSubject"]["aae"]["mandate"]["delegation"]
    if deleg["depth"] > deleg["max_depth"]:
        raise Reject(step, "delegation_depth_exceeded")

    # walk links from presented upward
    child_vc = presented_vc
    for jws, parent_vc in ancestors:
        # optional parent-hash binding
        child_deleg = child_vc["credentialSubject"]["aae"]["mandate"]["delegation"]
        h = child_deleg.get("delegator_aae_hash")
        if h is not None and h != jws_hash(jws):
            raise Reject(step, "delegator_aae_hash_mismatch")
        check_link(child_vc, parent_vc, step=step)
        child_vc = parent_vc


def verify(secured_aae: str, ctx: dict) -> dict:
    """Run the Section 5 algorithm. Returns {result, verification_step, rejection_reason}."""
    now = parse_time(ctx["current_time"])
    try:
        # Step 1 — signature + signing authority
        header, vc, signing_did = verify_signature(secured_aae, step=1)
        check_signing_authority(vc, signing_did, step=1)
        # Step 2 — payload / schema / cty
        check_schema(header, vc, step=2)
        aae = vc["credentialSubject"]["aae"]
        # Step 3 — temporal validity
        check_temporal(aae["validity"], now, vc.get("validFrom"), step=3)
        # Step 4 — subject binding (challenge-response result supplied via context)
        if not (ctx.get("subject_binding", {}) or {}).get("challenge_response_valid", False):
            raise Reject(4, "subject_binding_failed")
        # Step 5 — single-use
        if aae["validity"].get("single_use") and vc["id"] in (ctx.get("consumed_ids") or []):
            raise Reject(5, "single_use_already_consumed")
        # Step 6 — action check
        if ctx.get("requested_action") not in aae["mandate"].get("actions", []):
            raise Reject(6, "action_not_in_mandate")
        # Step 7 — constraints
        check_constraints(aae, ctx.get("action_context", {}), step=7)
        last_step = 7
        # Step 8 — revocation (conditional)
        if "revocation_check" in aae["validity"]:
            check_revocation(vc, ctx, step=8)
            last_step = 8
        # Step 9 — delegation chain (conditional)
        if aae["mandate"].get("delegation") is not None:
            verify_delegation(vc, ctx, now, step=9)
            last_step = 9
        return {"result": "ACCEPT", "verification_step": last_step, "rejection_reason": None}
    except Reject as r:
        return {"result": "REJECT", "verification_step": r.step, "rejection_reason": r.reason}


def main() -> int:
    files = sorted(glob.glob(os.path.join(VECTORS_DIR, "*.json")))
    passed = 0
    failures = []
    mode_counts = {"runtime": 0, "structural": 0}
    for path in files:
        with open(path) as fh:
            vector = json.load(fh)
        got = verify(vector["input"]["secured_aae"], vector["input"]["context"])
        exp = vector["expected"]
        # verification_mode is surfaced for visibility only; it does not affect
        # the verdict (which is derived purely by the Section 5 algorithm above).
        mode = vector.get("verification_mode", "?")
        if mode in mode_counts:
            mode_counts[mode] += 1
        ok = (got["result"] == exp["result"]
              and got["verification_step"] == exp.get("verification_step"))
        name = os.path.basename(path)
        if ok:
            passed += 1
            print(f"PASS  {name:42s} {got['result']} @ step {got['verification_step']}  [{mode}]"
                  + (f" ({got['rejection_reason']})" if got["rejection_reason"] else ""))
        else:
            failures.append((name, exp, got))
            print(f"FAIL  {name:42s} expected {exp['result']}@{exp.get('verification_step')} "
                  f"got {got['result']}@{got['verification_step']} ({got['rejection_reason']})  [{mode}]")
    total = len(files)
    print(f"\n{passed}/{total} vectors passed  "
          f"({mode_counts['runtime']} runtime, {mode_counts['structural']} structural)")
    if failures:
        print("\nTo claim AAE conformance against draft-kroehl-agentic-trust-aae-00, all vectors must pass.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
