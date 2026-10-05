"""Input-hardening tests for the reference verifier, examples/python-verify.py.

The verifier implements draft-kroehl-agentic-trust-aae-00. Section numbers below
are -00 numbers; where -02 differs it is noted. The sections cited here (§2.3,
§3, §5 steps 7 and 9) carry the same numbers in -02.

Signed inputs are built from the committed TEST keys in testkeys/ with the
helpers of tools/build_vectors.py, so they are signed exactly as the
conformance vectors are. These keys are public and for testing only.

Run from the repository root:

    pip install cryptography pytest
    python3 -m pytest tests/
"""
from __future__ import annotations

import importlib.util
import os

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = _load("python_verify", "examples/python-verify.py")
bv = _load("build_vectors", "tools/build_vectors.py")

ROOT_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000a0"
CHILD_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000b1"
OTHER_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000ff"

_UNSET = object()


def _context(**extra) -> dict:
    ctx = {
        "current_time": bv.NOON,
        "requested_action": "read",
        "action_context": {"amount": 50, "currency": "USD", "domain": "flights.example.com"},
        "subject_binding": {"challenge_response_valid": True},
    }
    ctx.update(extra)
    return ctx


def _root_aae(constraints: dict) -> str:
    """A non-delegated root AAE signed by the registry test key."""
    aae = {
        "mandate": bv.root_mandate(["read", "book"]),
        "constraints": constraints,
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    }
    return bv.sign_jws(bv.vc(ROOT_ID, bv.REGISTRY, bv.AGENT_001, aae), bv.REGISTRY_KEY)


def _chain(delegation_policy=_UNSET, delegator_aae_id: str = ROOT_ID) -> tuple[str, list[str]]:
    """registry -> agent-a (root, depth 0) -> agent-b (depth 1).

    Returns (presented child JWS, delegation_chain). With the defaults this is
    a valid depth-1 chain shaped like vector 06.
    """
    policy = {"max_depth": 2} if delegation_policy is _UNSET else delegation_policy
    root = bv.vc(ROOT_ID, bv.REGISTRY, bv.AGENT_A, {
        "mandate": bv.root_mandate(["read", "book"], delegation_policy=policy),
        "constraints": {"max_transaction_value": bv.max_tx(500, "USD")},
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    })
    root_jws = bv.sign_jws(root, bv.REGISTRY_KEY)
    child = bv.vc(CHILD_ID, bv.AGENT_A, bv.AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": bv.AGENT_A,
                "delegator_aae_id": delegator_aae_id,
                "delegator_aae_uri": "https://aae.example/p/" + delegator_aae_id,
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": bv.max_tx(300, "USD")},
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    })
    return bv.sign_jws(child, bv.AGENT_A_KEY), [root_jws]


def _reject(step: int, reason: str) -> dict:
    return {"result": "REJECT", "verification_step": step, "rejection_reason": reason}


# --- control -----------------------------------------------------------------

def test_control_valid_depth1_chain_accepts():
    """The chain builder yields an accepted chain when nothing is broken, so the
    rejections below are caused by the one field each test changes."""
    child_jws, chain = _chain()
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None}


# --- fix (a): constraint value that is not an object -------------------------

@pytest.mark.parametrize("constraints, reason", [
    # Unrecognized key whose value is a bare string. A string cannot carry
    # `required: false`, so the -00 §2.3 default (required: true) applies and
    # the unrecognized constraint MUST be rejected (-00 §5 step 7).
    ({"max_transaction_value": {"value": 500, "currency": "USD", "required": True},
      "resource": "repo:acme/*"},
     "unrecognized_required_constraint"),
    # Recognized key whose value is a bare string: required by default, and it
    # cannot be evaluated, so the AAE MUST be rejected (-00 §2.3, §5 step 7).
    ({"max_transaction_value": "500 USD"},
     "constraint_unevaluable"),
], ids=["unrecognized-key-string-value", "recognized-key-string-value"])
def test_string_constraint_value_rejected_at_step7(constraints, reason):
    got = verifier.verify(_root_aae(constraints), _context())
    assert got == _reject(7, reason)


# --- fix (b): delegation from a root without a usable delegation_policy ------

@pytest.mark.parametrize("policy", [
    None,                  # no delegation_policy member at all
    {},                    # object without max_depth
    {"max_depth": -1},     # max_depth not non-negative
    {"max_depth": "2"},    # max_depth not an integer
    {"max_depth": True},   # JSON boolean is not an integer
    "max_depth=2",         # delegation_policy not an object
], ids=["absent", "empty-object", "negative", "string", "boolean", "not-object"])
def test_delegation_from_root_without_delegation_policy_rejected(policy):
    """-00 §3 (-02 §3): "A root AAE that authorizes onward delegation MUST
    include a delegation_policy object in its MANDATE block with a non-negative
    integer max_depth member" and a relying party "MUST reject any delegation
    whose parent is a root AAE that has no delegation_policy"; checked per link
    in §5 step 9."""
    child_jws, chain = _chain(delegation_policy=policy)
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == _reject(9, "root_delegation_policy_missing")


# --- fix (c): delegator_aae_id must name the supplied parent -----------------

def test_delegator_aae_id_mismatch_rejected():
    """-00 §3 (-02 §3): delegator_aae_id is "The id of the parent AAE"; the link
    is checked in §5 step 9 (-02 §5 step 9 makes it explicit:
    "mandate.delegation.delegator_aae_id names the parent")."""
    child_jws, chain = _chain(delegator_aae_id=OTHER_ID)
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == _reject(9, "delegator_aae_id_mismatch")


# --- fix (a), reached through examples/composition-verify.py -----------------

def test_composition_verify_string_constraint_value_rejected():
    """composition-verify.py runs python-verify.verify() unmodified as its
    aae_native stage (composition-verify.py, compose()), with no exception
    handling around it, so the step-7 AttributeError surfaced there as well."""
    import copy
    import json

    composition = _load("composition_verify", "examples/composition-verify.py")
    with open(os.path.join(ROOT, "interop/psea/vectors/xp-1-aligned-principal.json")) as fh:
        vector = json.load(fh)
    with open(os.path.join(ROOT, "interop/psea/psea-fixture-v0.json")) as fh:
        fixture = json.load(fh)
    vector = copy.deepcopy(vector)
    vector["input"]["secured_aae"] = _root_aae(
        {"max_transaction_value": bv.max_tx(500, "USD"), "resource": "repo:acme/*"})
    vector["input"]["context"].update(_context())
    stages = composition.compose(vector, fixture, composition.load_aae_verifier())["stages"]
    assert stages["aae_native"] == {
        "value": "REJECT", "reason": "unrecognized_required_constraint", "verification_step": 7}
    assert stages["decision"]["value"] == "REFUSED"
