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


def _chain(delegation_policy=_UNSET, delegator_aae_id: str = ROOT_ID,
           root_constraints: dict | None = None) -> tuple[str, list[str]]:
    """registry -> agent-a (root, depth 0) -> agent-b (depth 1).

    Returns (presented child JWS, delegation_chain). With the defaults this is
    a valid depth-1 chain shaped like vector 06.
    """
    policy = {"max_depth": 2} if delegation_policy is _UNSET else delegation_policy
    root = bv.vc(ROOT_ID, bv.REGISTRY, bv.AGENT_A, {
        "mandate": bv.root_mandate(["read", "book"], delegation_policy=policy),
        "constraints": root_constraints or {"max_transaction_value": bv.max_tx(500, "USD")},
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


def _reject(step: int, reason: str, detail: str | None = None) -> dict:
    out = {"result": "REJECT", "verification_step": step, "rejection_reason": reason}
    if detail is not None:
        out["detail"] = detail
    return out


# --- control -----------------------------------------------------------------

def test_control_valid_depth1_chain_accepts():
    """The chain builder yields an accepted chain when nothing is broken, so the
    rejections below are caused by the one field each test changes."""
    child_jws, chain = _chain()
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None,
                   "root_issuer": bv.REGISTRY}


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

NO_POLICY = "node 0 (root) has no delegation_policy"
BAD_MAX_DEPTH = "node 0 (root) has a delegation_policy without a non-negative integer max_depth"


@pytest.mark.parametrize("policy, detail", [
    (None, NO_POLICY),                    # no delegation_policy member at all
    ("max_depth=2", NO_POLICY),           # delegation_policy not an object
    ({}, BAD_MAX_DEPTH),                  # object without max_depth
    ({"max_depth": -1}, BAD_MAX_DEPTH),   # max_depth not non-negative
    ({"max_depth": "2"}, BAD_MAX_DEPTH),  # max_depth not an integer
    ({"max_depth": True}, BAD_MAX_DEPTH), # JSON boolean is not an integer
], ids=["absent", "not-object", "empty-object", "negative", "string", "boolean"])
def test_delegation_from_root_without_delegation_policy_rejected(policy, detail):
    """-00 §3 (-02 §3): "A root AAE that authorizes onward delegation MUST
    include a delegation_policy object in its MANDATE block with a non-negative
    integer max_depth member" and a relying party "MUST reject any delegation
    whose parent is a root AAE that has no delegation_policy"; checked per link
    in §5 step 9."""
    child_jws, chain = _chain(delegation_policy=policy)
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == _reject(9, "delegation_policy_missing", detail)


# --- fix (c): delegator_aae_id must name the supplied parent -----------------

def test_delegator_aae_id_naming_an_unsupplied_parent_rejected():
    """-00 §3 (-02 §3): delegator_aae_id is "The id of the parent AAE", and
    -02 §5 step 9: "mandate.delegation.delegator_aae_id names the parent; if no
    supplied ancestor carries that id, the verdict is DENY". The supplied root
    carries a different id, so it is not on the path and the parent is missing."""
    child_jws, chain = _chain(delegator_aae_id=OTHER_ID)
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == _reject(9, "delegation_ancestor_missing",
                          f"parent AAE {OTHER_ID!r} is not in delegation_chain")


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


def test_detail_names_nodes_from_the_root_at_depth_2():
    """Node indices count from the root: in registry -> agent-a -> agent-b ->
    agent-c the presented AAE is node 2, its parent node 1 and the root node 0."""
    _, chain = _chain()
    mid = bv.vc(CHILD_ID, bv.AGENT_A, bv.AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": bv.AGENT_A, "delegator_aae_id": ROOT_ID,
                "delegator_aae_uri": "https://aae.example/p/" + ROOT_ID,
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": "300 USD"},
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    })
    leaf = _leaf(CHILD_ID)
    got = verifier.verify(leaf, _context(delegation_chain=chain + [bv.sign_jws(mid, bv.AGENT_A_KEY)]))
    assert got == _reject(9, "constraint_unevaluable",
                          "node 1 constraint 'max_transaction_value' is not an object")


# --- fix (a) for ancestors: non-object constraint value during the step-9 walk

@pytest.mark.parametrize("root_constraints, reason, ctype", [
    ({"max_transaction_value": {"value": 500, "currency": "USD", "required": True},
      "resource": "repo:acme/*"},
     "unrecognized_required_constraint", "resource"),
    ({"max_transaction_value": "500 USD"},
     "constraint_unevaluable", "max_transaction_value"),
], ids=["unrecognized-key-string-value", "recognized-key-string-value"])
def test_ancestor_string_constraint_value_rejected_at_step9(root_constraints, reason, ctype):
    """Ancestors do not pass through step 7 (-00 §5 step 9 applies steps 1-3
    and 8 to them), so a non-object constraint value in an ancestor reached the
    §3 monotonicity comparison in check_link and raised AttributeError. It is
    rejected at step 9 with the same code mapping as fix (a): the value cannot
    carry required:false, so the §2.3 default required:true applies."""
    child_jws, chain = _chain(root_constraints=root_constraints)
    got = verifier.verify(child_jws, _context(delegation_chain=chain))
    assert got == _reject(9, reason, f"node 0 constraint {ctype!r} is not an object")


# --- AAE-F1: the step-9 walk must end at a root AAE ---------------------------
#
# Step 9 follows delegator_aae_id from the presented AAE (-02 §5 step 9: the
# relying party "MUST walk the chain by following
# mandate.delegation.delegator_aae_id from the presented AAE outward"). Before
# the fix only the links between supplied envelopes were checked, so each case
# below was accepted at step 9.

LEAF_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000c2"
X_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000e1"
Y_ID = "urn:uuid:7e570000-0000-4000-8000-0000000000e2"


def _delegated(vc_id, delegator, subject, parent_id, depth, cap=100, actions=("read",)):
    return bv.vc(vc_id, delegator, subject, {
        "mandate": {
            "actions": list(actions),
            "delegation": {
                "delegator_did": delegator, "delegator_aae_id": parent_id,
                "delegator_aae_uri": "https://aae.example/p/" + parent_id,
                "depth": depth, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": bv.max_tx(cap, "USD")},
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    })


def _leaf(parent_id: str = CHILD_ID) -> str:
    """agent-c's depth-2 AAE, delegated by agent-b."""
    return bv.sign_jws(_delegated(LEAF_ID, bv.AGENT_B, bv.AGENT_C, parent_id, 2), bv.AGENT_B_KEY)


def _honest_depth2() -> tuple[str, str, str]:
    """(leaf, mid, root) of a valid registry -> agent-a -> agent-b -> agent-c chain."""
    mid_jws, (root_jws,) = _chain()
    return _leaf(), mid_jws, root_jws


def _cases():
    leaf, mid, root = _honest_depth2()
    a, b = bv.AGENT_A_KEY, bv.AGENT_B_KEY
    orphan = bv.sign_jws(_delegated("urn:uuid:7e570000-0000-4000-8000-0000000000d1", bv.AGENT_A,
                                    bv.AGENT_B, ROOT_ID, 1, 1000000, ("read", "book", "pay")), a)
    x = bv.sign_jws(_delegated(X_ID, bv.AGENT_A, bv.AGENT_B, Y_ID, 2), a)
    y = bv.sign_jws(_delegated(Y_ID, bv.AGENT_B, bv.AGENT_A, X_ID, 1, 300), b)
    me = bv.sign_jws(_delegated(X_ID, bv.AGENT_A, bv.AGENT_B, X_ID, 1), a)
    return {
        "1-no-ancestors": (orphan, [], "delegation_ancestor_missing"),
        "1-depth2-empty-chain": (leaf, [], "delegation_ancestor_missing"),
        "2-root-omitted": (leaf, [mid], "delegation_ancestor_missing"),
        "3-mutual-counterpart-supplied": (x, [y], "delegation_cycle_detected"),
        "3-mutual-counterpart-absent": (x, [], "delegation_ancestor_missing"),
        "4-self-parent": (me, [], "delegation_cycle_detected"),
        "4-self-parent-also-supplied": (me, [me], "delegation_cycle_detected"),
    }


@pytest.mark.parametrize("case", sorted(_cases()))
def test_reported_chains_rejected_at_step9(case):
    presented, chain, reason = _cases()[case]
    got = verifier.verify(presented, _context(delegation_chain=chain))
    assert (got["result"], got["verification_step"], got["rejection_reason"]) == ("REJECT", 9, reason)


def test_silence_probe_honest_depth2_chain_accepts_with_root_issuer():
    leaf, mid, root = _honest_depth2()
    got = verifier.verify(leaf, _context(delegation_chain=[root, mid]))
    assert got == {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None,
                   "root_issuer": bv.REGISTRY}


def test_chain_order_does_not_matter():
    """-02 §5 step 9: the supplied ancestors are not ordered; the walk indexes them by id."""
    leaf, mid, root = _honest_depth2()
    got = verifier.verify(leaf, _context(delegation_chain=[mid, root]))
    assert got["result"] == "ACCEPT" and got["root_issuer"] == bv.REGISTRY


def _off_path_extras():
    other_root = bv.vc(OTHER_ID, bv.REGISTRY, bv.AGENT_A, {
        "mandate": bv.root_mandate(["read"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": bv.max_tx(500, "USD")},
        "validity": {"not_before": bv.NB, "not_after": bv.NA, "single_use": False},
    })
    good = bv.sign_jws(other_root, bv.REGISTRY_KEY)
    h, p, sig = good.split(".")
    bad_sig = f"{h}.{p}.{sig[:-4]}AAAA"
    expired = bv.vc(OTHER_ID, bv.REGISTRY, bv.AGENT_A, dict(
        other_root["credentialSubject"]["aae"],
        validity={"not_before": bv.NB, "not_after": bv.NB, "single_use": False}))
    return {
        "valid-unrelated-root": [good],
        "bad-signature": [bad_sig],
        "expired": [bv.sign_jws(expired, bv.REGISTRY_KEY)],
        "not-a-jws": ["not-a-jws"],
        "revoked-ancestor-off-path": [good],
    }


@pytest.mark.parametrize("extra", sorted(_off_path_extras()))
def test_off_path_ancestors_do_not_change_an_accept(extra):
    leaf, mid, root = _honest_depth2()
    chain = [root] + _off_path_extras()[extra] + [mid]
    ctx = _context(delegation_chain=chain)
    if extra == "revoked-ancestor-off-path":
        ctx["revocation_responses"] = {OTHER_ID: {"revoked": True}}
    got = verifier.verify(leaf, ctx)
    assert got == {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None,
                   "root_issuer": bv.REGISTRY}


@pytest.mark.parametrize("extra", sorted(_off_path_extras()))
def test_off_path_ancestors_do_not_change_a_reject(extra):
    leaf, mid, root = _honest_depth2()
    got = verifier.verify(leaf, _context(delegation_chain=[mid] + _off_path_extras()[extra]))
    assert got == _reject(9, "delegation_ancestor_missing",
                          f"parent AAE {ROOT_ID!r} is not in delegation_chain")


def test_parent_supplied_twice_is_rejected_not_picked():
    """-02 §5 step 9: two ancestors claiming one identity make the chain
    ambiguous, and the relying party MUST reject rather than pick one."""
    leaf, mid, root = _honest_depth2()
    got = verifier.verify(leaf, _context(delegation_chain=[root, mid, mid]))
    assert got == _reject(9, "delegation_cycle_detected",
                          f"parent AAE {CHILD_ID!r} is supplied more than once")


def test_root_aae_accept_names_its_own_issuer():
    got = verifier.verify(_root_aae({"max_transaction_value": bv.max_tx(500, "USD")}), _context())
    assert got == {"result": "ACCEPT", "verification_step": 7, "rejection_reason": None,
                   "root_issuer": bv.REGISTRY}
