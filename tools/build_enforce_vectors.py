#!/usr/bin/env python3
"""Build the enforce vector set under vectors/enforce/.

Deterministic: no clock, no randomness, no network. The signing key for the ratification
vectors is the committed `testkeys/issuer-test-key-1.json`, so re-running reproduces every
file byte for byte — the same property CI checks for the native and composition sets.

Expected digests come from examples/enforce-verify.py, which implements the enforce kernel
of draft-kroehl-agentic-trust-aae-02 from the draft text. They are cross-checked against a
second, separately written implementation — the deployed kernel behind
POST https://api.moltrust.ch/enforce/check — and the run is recorded in
vectors/enforce/RESULTS.md. Neither implementation was derived from the other.

THE TEST KEY IS PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "examples"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "enforce_verify", os.path.join(ROOT, "examples", "enforce-verify.py"))
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = os.path.join(ROOT, "vectors", "enforce")
SECTION = "draft-kroehl-agentic-trust-aae-02"

TAGS_CHECK = {
    "action": "aae:enforce-action:v1",
    "mandate": "aae:enforce-mandate:v1",
    "transaction": "aae:enforce-transaction:v1",
    "core": "aae:enforce-core:v1",
}
TAGS_RATIFY = {
    "statement": "aae:enforce-ratify-statement:v1",
    "core": "aae:enforce-ratify-core:v1",
}

PAY = {"verb": "transfer", "asset": "USDC", "chain": "base"}
TF = ["verb", "asset", "chain"]
ADDR = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"
ADDR_VANITY = "0xABCDEF0123456789ABCDEF0123456789ABCDEFff"


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def principal_key():
    with open(os.path.join(ROOT, "testkeys", "issuer-test-key-1.json")) as fh:
        k = json.load(fh)
    sk = Ed25519PrivateKey.from_private_bytes(b64url_decode(k["jwk"]["d"]))
    return k["did"], sk, sk.public_key().public_bytes_raw().hex()


PRINCIPAL_DID, PRINCIPAL_SK, PRINCIPAL_PK = principal_key()
STRANGER_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
STRANGER_DID = "did:web:example.com:stranger"


_UNSET = object()   # "not supplied" — distinguishable from an explicitly null action


def grant(disposition="allow", constraints=(), type_fields=None, action=_UNSET):
    act = PAY if action is _UNSET else action
    return {"action_binding": ev.digest(ev.TAG_ACTION, act),
            "type_fields": list(TF if type_fields is None else type_fields),
            "disposition": disposition,
            "constraints": list(constraints)}


def mandate(*grants, principal=False):
    m = {"mandate_version": "1.0"}
    if principal:
        m["principal"] = {"did": PRINCIPAL_DID, "public_key": PRINCIPAL_PK}
    m["grants"] = list(grants)
    return m


def tx(action=_UNSET, **rest):
    t = {"action": PAY if action is _UNSET else action}
    t.update(rest or {"to": ADDR, "amount": 500, "region": "CH"})
    return t


def check_vector(n, name, description, m, transaction, rationale,
                 trace=None, reason_contains=None, grant_index=None):
    got = ev.enforce_check(m, transaction)
    v = {
        "id": f"aae-enforce-vector-{n:02d}",
        "name": name,
        "description": description,
        "section_ref": SECTION,
        "kernel": "enforce_check",
        "kernel_version": ev.ENFORCE_VERSION,
        "domain_tags": TAGS_CHECK,
        "input": {"mandate": m, "transaction": transaction},
        "expected": {"verdict": got["verdict"], "core_digest": got["core_digest"]},
        "rationale": rationale,
    }
    if grant_index is not None:
        v["expected"]["grant_index"] = got["grant_index"]
    if reason_contains:
        assert reason_contains in got["reason"], (n, got["reason"])
        v["expected"]["reason_contains"] = reason_contains
    if trace:
        v["expected"]["trace"] = trace
    return v


def ratify_vector(n, name, description, prior, decision, proof, rationale,
                  prev=None, trace=None, reason_contains=None, expect_error=False):
    v = {
        "id": f"aae-enforce-vector-{n:02d}",
        "name": name,
        "description": description,
        "section_ref": SECTION,
        "kernel": "ratify",
        "kernel_version": ev.RATIFY_VERSION,
        "domain_tags": TAGS_RATIFY,
        "input": {"prior_record": prior, "decision": decision, "authority_proof": proof},
        "expected": {},
        "rationale": rationale,
    }
    if prev is not None:
        v["input"]["prev_core_digest"] = prev
    if expect_error:
        try:
            ev.ratify(prior, decision, proof, prev)
        except ev.RatifyError as exc:
            v["expected"]["error"] = "RatifyError"
            assert reason_contains in str(exc), (n, str(exc))
            v["expected"]["reason_contains"] = reason_contains
            return v
        raise AssertionError(f"vector {n}: expected RatifyError, got a record")
    got = ev.ratify(prior, decision, proof, prev)
    v["expected"] = {"status": got["status"], "decision": got["decision"],
                     "ratifies": got["ratifies"], "authority": got["authority"],
                     "core_digest": got["core_digest"]}
    if reason_contains:
        assert reason_contains in got["reason"], (n, got["reason"])
        v["expected"]["reason_contains"] = reason_contains
    if trace:
        v["expected"]["trace"] = trace
    return v


def record(result):
    return {"core": result["core"], "core_digest": result["core_digest"]}


def proof_for(m, did, sk, prior_digest, decision):
    sig = sk.sign(ev.statement_bytes(prior_digest, decision, did)).hex()
    return {"mandate": m, "authority": did, "signature": sig}


def build():
    RANGE = {"type": "range", "field": "amount", "lo": 0, "hi": 1000}
    EXACT = {"type": "exact", "field": "to", "value": ADDR}
    ENUM = {"type": "enum", "field": "region", "values": ["CH", "DE"]}
    out = []

    # --- the type form (Section 2.2.1 / 2.2.2) ----------------------------------------
    out.append(check_vector(
        1, "Type form matches — permit",
        "The action carries exactly the grant's type_fields and every constraint holds.",
        mandate(grant("allow", [EXACT, RANGE])), tx(),
        "The positive case the rest are measured against. PERMIT requires a bound grant, "
        "all constraints holding, and disposition allow — nothing else reaches it.",
        trace=[{"predicate": "type_fields", "result": "PASS"},
               {"predicate": "action_binding", "result": "PASS"},
               {"predicate": "disposition", "result": "PASS"}],
        reason_contains="all constraints hold", grant_index=True))

    out.append(check_vector(
        2, "Instance value inside the action — deny",
        "The action carries `amount`, which the grant's type_fields do not name.",
        mandate(grant("allow", [EXACT, RANGE])), tx(action=dict(PAY, amount=500)),
        "An amount inside the action would be part of the digest, so every payment would "
        "be a different action and one grant could bind at most one of them. The type form "
        "keeps instance values outside, where constraints bound them.",
        trace=[{"predicate": "type_fields", "result": "FAIL"}],
        reason_contains="outside type_fields ['amount']"))

    out.append(check_vector(
        3, "Type field missing from the action — deny",
        "The grant names verb, asset and chain; the action omits chain.",
        mandate(grant("allow")), tx(action={"verb": "transfer", "asset": "USDC"}),
        "A partial action is not the action the grant bound. Both directions of the set "
        "comparison have to fail closed, not just the extra-field one.",
        trace=[{"predicate": "type_fields", "result": "FAIL"}],
        reason_contains="missing type_fields ['chain']"))

    for i, (label, action) in enumerate([
        ("a string", "pay"), ("an array", ["pay"]), ("a number", 42), ("null", None)], start=4):
        out.append(check_vector(
            i, f"Action is {label} — deny",
            f"The transaction's action is {label} rather than an object.",
            mandate(grant("allow")), tx(action=action),
            "A non-object action canonicalizes cleanly and yields a well-formed digest, so "
            "a verifier that only compared digests would report it as merely unaddressed. "
            "The type form names it: an action that is not an object satisfies no type.",
            trace=[{"predicate": "type_fields", "result": "FAIL"}],
            reason_contains="action is not an object"))

    g_no_tf = grant("allow")
    del g_no_tf["type_fields"]
    out.append(check_vector(
        8, "Grant without type_fields — deny",
        "The grant omits type_fields entirely.",
        mandate(g_no_tf), tx(),
        "type_fields is REQUIRED. A grant without it is malformed, and a mandate whose only "
        "grant is malformed carries nothing — it does not fall back to binding on the "
        "digest alone.",
        trace=[{"predicate": "mandate_present", "result": "FAIL"}],
        reason_contains="type_fields"))

    out.append(check_vector(
        9, "type_fields without verb — deny",
        "type_fields lists asset and chain but not verb.",
        mandate(grant("allow", type_fields=["asset", "chain"])), tx(),
        "Without a verb there is no action, only arguments. verb is the one member the "
        "draft requires by name.",
        trace=[{"predicate": "mandate_present", "result": "FAIL"}],
        reason_contains="type_fields"))

    out.append(check_vector(
        10, "Duplicate name in type_fields — deny",
        "type_fields repeats verb.",
        mandate(grant("allow", type_fields=["verb", "verb", "asset", "chain"])), tx(),
        "The comparison against the action is over sets. A list with a duplicate claims a "
        "field count it does not have, so it is malformed rather than merely redundant.",
        trace=[{"predicate": "mandate_present", "result": "FAIL"}],
        reason_contains="type_fields"))

    # --- the constraint language (Section 2.5) ----------------------------------------
    out.append(check_vector(
        11, "exact holds — permit",
        "The transaction's `to` equals the constraint value byte for byte.",
        mandate(grant("allow", [EXACT])), tx(),
        "The positive half of exact. Constant-time comparison, no normalization.",
        trace=[{"predicate": "exact", "field": "to", "result": "PASS"}]))

    out.append(check_vector(
        12, "exact fails on a vanity prefix — deny",
        "The transaction's `to` shares the first 38 characters with the expected address.",
        mandate(grant("allow", [EXACT])), tx(to=ADDR_VANITY, amount=500, region="CH"),
        "The attack exact exists to stop: an address that looks right at a glance. There is "
        "no prefix matching and no case folding, so it fails.",
        trace=[{"predicate": "exact", "field": "to", "result": "FAIL"}]))

    out.append(check_vector(
        13, "enum holds — permit", "The region is a listed member.",
        mandate(grant("allow", [ENUM])), tx(),
        "The positive half of enum. Every member is compared; the position of the match is "
        "not observable.",
        trace=[{"predicate": "enum", "field": "region", "result": "PASS"}]))

    out.append(check_vector(
        14, "enum fails — deny", "The region is outside the enumeration.",
        mandate(grant("allow", [ENUM])), tx(to=ADDR, amount=500, region="US"),
        "The negative half of enum.",
        trace=[{"predicate": "enum", "field": "region", "result": "FAIL"}]))

    out.append(check_vector(
        15, "range holds at the upper bound — permit",
        "The amount equals `hi`, which the closed interval includes.",
        mandate(grant("allow", [RANGE])), tx(to=ADDR, amount=1000, region="CH"),
        "Both bounds are inclusive. The boundary is where an off-by-one would show, so the "
        "positive case sits on it rather than in the middle.",
        trace=[{"predicate": "range", "field": "amount", "result": "PASS"}]))

    out.append(check_vector(
        16, "range fails one over the bound — deny", "The amount is `hi` plus one.",
        mandate(grant("allow", [RANGE])), tx(to=ADDR, amount=1001, region="CH"),
        "The other side of the same boundary.",
        trace=[{"predicate": "range", "field": "amount", "result": "FAIL"}]))

    out.append(check_vector(
        17, "Unknown constraint type — deny",
        "The grant carries a constraint of type `regex`, which the closed set does not define.",
        mandate(grant("allow", [{"type": "regex", "field": "to", "value": "^0xABC"}])), tx(),
        "The set of three is closed. What a verifier cannot evaluate, it does not permit — "
        "an unrecognized type is a failed predicate, never an ignored one.",
        trace=[{"predicate": "regex", "result": "FAIL"}],
        reason_contains="no matching grant satisfied its constraints"))

    out.append(check_vector(
        18, "Field path with an empty segment — deny",
        "The constraint names the path `action..verb`.",
        mandate(grant("allow", [{"type": "exact", "field": "action..verb",
                                 "value": "transfer"}])), tx(),
        "An empty path segment is rejected outright rather than skipped. Skipping it would "
        "make `a..b` and `a.b` the same path, and two verifiers could then disagree about "
        "which field a constraint names.",
        trace=[{"predicate": "exact", "field": "action..verb", "result": "FAIL"}]))

    # --- the verdict vocabulary (Section 6.1) -----------------------------------------
    out.append(check_vector(
        19, "Explicit hold — pending",
        "A bound grant whose constraints hold carries disposition hold.",
        mandate(grant("hold", [EXACT])), tx(),
        "PENDING is reachable only from an explicit hold. It says the mandate defers this "
        "action, not that the verifier was unsure.",
        trace=[{"predicate": "disposition", "result": "PASS"}],
        reason_contains="disposition=hold"))

    out.append(check_vector(
        20, "Unaddressed action is never pending — deny",
        "The mandate holds a `transfer` grant; the transaction attempts `withdraw`.",
        mandate(grant("hold", [EXACT])),
        tx(action={"verb": "withdraw", "asset": "USDC", "chain": "base"}),
        "Silence in a mandate is not a route to authorization. If an unaddressed action "
        "could come back PENDING, waiting would be the way around the mandate — no grant "
        "needed, just patience.",
        trace=[{"predicate": "action_binding", "result": "FAIL"}],
        reason_contains="unaddressed action"))

    out.append(check_vector(
        21, "forbid outranks an allowing grant — deny",
        "Two grants bind the same action: the first allows, the second forbids.",
        mandate(grant("allow", [EXACT, RANGE]), grant("forbid")), tx(),
        "A prohibition takes precedence over a permission for the same action, and the "
        "forbidding grant's own constraints are not evaluated — there is no condition under "
        "which a forbid becomes an allow.",
        trace=[{"predicate": "disposition", "result": "FAIL"}],
        reason_contains="disposition=forbid", grant_index=True))

    # --- ratification (Section 6.3 / 6.4) ---------------------------------------------
    m_p = mandate(grant("allow", [{"type": "range", "field": "amount", "lo": 0, "hi": 100}]),
                  principal=True)
    deny = ev.enforce_check(m_p, tx(to=ADDR, amount=500, region="CH"))
    assert deny["verdict"] == ev.DENY
    prior_deny = record(deny)

    out.append(ratify_vector(
        22, "Ratified by the issuing principal",
        "The principal named in the mandate approves a DENY.",
        prior_deny, "APPROVED",
        proof_for(m_p, PRINCIPAL_DID, PRINCIPAL_SK, prior_deny["core_digest"], "APPROVED"),
        "History is corrected by appending. The prior record keeps its verdict and its "
        "digest; the ratification is a second record that refers to it.",
        trace=[{"predicate": "mandate_binding", "result": "PASS"},
               {"predicate": "authority_in_mandate", "result": "PASS"},
               {"predicate": "authority_signature", "result": "PASS"}],
        reason_contains="ratified by principal"))

    out.append(ratify_vector(
        23, "Stranger with a valid signature — rejected",
        "A party not named in the mandate signs a correct statement with its own key.",
        prior_deny, "APPROVED",
        proof_for(m_p, STRANGER_DID, STRANGER_SK, prior_deny["core_digest"], "APPROVED"),
        "Witness, not ruler. The key is read from the mandate, never from the proof, so a "
        "signature that verifies under the signer's own key establishes nothing. REJECTED "
        "is a result with a trace, not an error: the prior record keeps its status.",
        trace=[{"predicate": "mandate_binding", "result": "PASS"},
               {"predicate": "authority_in_mandate", "result": "FAIL"}],
        reason_contains="authority does not derive from the mandate"))

    permit = ev.enforce_check(mandate(grant("allow", [EXACT, RANGE]), principal=True), tx())
    assert permit["verdict"] == ev.PERMIT
    out.append(ratify_vector(
        24, "A PERMIT is not ratifiable — caller error",
        "The record offered for ratification is a PERMIT.",
        record(permit), "APPROVED",
        proof_for(mandate(grant("allow", [EXACT, RANGE]), principal=True), PRINCIPAL_DID,
                  PRINCIPAL_SK, permit["core_digest"], "APPROVED"),
        "Guard 2. A PERMIT has no status to change, so the request is malformed rather than "
        "unauthorized — it raises instead of producing a REJECTED record.",
        reason_contains="not ratifiable", expect_error=True))

    out.append(ratify_vector(
        25, "Chain link pointing elsewhere — caller error",
        "prev_core_digest is well formed but names a record other than the one ratified.",
        prior_deny, "APPROVED",
        proof_for(m_p, PRINCIPAL_DID, PRINCIPAL_SK, prior_deny["core_digest"], "APPROVED"),
        "Guard 3. A ratification is a statement about one specific prior record. A chain "
        "link pointing anywhere else would describe a different history than the one the "
        "ratification asserts, and there is nothing to record when the question itself does "
        "not line up.",
        prev="sha256:" + "e" * 64,
        reason_contains="prev_core_digest must equal", expect_error=True))

    out.append(ratify_vector(
        26, "Chain link set explicitly to the ratified record",
        "prev_core_digest is supplied and equals the prior record's core digest.",
        prior_deny, "DISAPPROVED",
        proof_for(m_p, PRINCIPAL_DID, PRINCIPAL_SK, prior_deny["core_digest"], "DISAPPROVED"),
        "The permitted half of Guard 3, and the DISAPPROVED half of the decision "
        "vocabulary. Supplying the link explicitly is allowed and yields the same record as "
        "leaving it out, because the fallback inserts the same value.",
        prev=prior_deny["core_digest"],
        reason_contains="prior DENY -> DISAPPROVED"))

    return out


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    vectors = build()
    for v in vectors:
        n = int(v["id"].rsplit("-", 1)[1])
        slug = v["name"].lower()
        for ch in " ,—'`":
            slug = slug.replace(ch, "-")
        slug = "-".join(p for p in slug.split("-") if p)[:52]
        path = os.path.join(OUT, f"{n:02d}-{slug}.json")
        for stale in os.listdir(OUT):
            if stale.startswith(f"{n:02d}-") and stale != os.path.basename(path):
                os.remove(os.path.join(OUT, stale))
        with open(path, "w") as fh:
            json.dump(v, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    print(f"wrote {len(vectors)} enforce vectors to {os.path.relpath(OUT, ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
