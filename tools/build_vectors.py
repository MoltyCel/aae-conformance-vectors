#!/usr/bin/env python3
"""Build the 15 AAE conformance vectors.

Loads the committed test keys (tools/genkeys.py), constructs an AAE Verifiable
Credential for each vector, signs it as a JWS in compact serialization, and
writes vectors/NN-*.json. Deterministic given the committed keys: re-running
reproduces byte-identical signatures.

Spec: draft-kroehl-agentic-trust-aae-00 (content == internal -04).

THESE KEYS ARE PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TESTKEYS = os.path.join(ROOT, "testkeys")
VECTORS = os.path.join(ROOT, "vectors")

REGISTRY = "did:web:example.com:registry"
AGENT_001 = "did:web:example.com:agent-001"
AGENT_A = "did:web:example.com:agent-a"
AGENT_B = "did:web:example.com:agent-b"
AGENT_C = "did:web:example.com:agent-c"
PRINCIPAL = "did:web:example.com:enterprise-corp"

CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://moltrust.ch/contexts/aae/v1",
]
VC_TYPE = ["VerifiableCredential", "AgentAuthorizationEnvelope"]

NB = "2026-05-20T08:00:00Z"
NA = "2026-05-20T16:00:00Z"
NOON = "2026-05-20T12:00:00Z"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_key(filename: str) -> dict:
    with open(os.path.join(TESTKEYS, filename)) as fh:
        return json.load(fh)


def signer(key: dict) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64url_decode(key["jwk"]["d"]))


def sign_jws(payload: dict, key: dict, cty: str = "aae+json", kid: str | None = None) -> str:
    """Sign a payload as an EdDSA JWS in compact serialization."""
    header = {"alg": "EdDSA", "cty": cty, "kid": kid or key["kid"]}
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = signer(key).sign(signing_input)
    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def jws_hash(jws: str) -> str:
    """sha-256:<base64url> over the exact ASCII octets of the parent JWS (draft §3)."""
    digest = hashlib.sha256(jws.encode("ascii")).digest()
    return "sha-256:" + b64url(digest)


def vc(vc_id: str, issuer: str, subject: str, aae: dict, valid_from: str = NB) -> dict:
    return {
        "@context": CONTEXT,
        "type": VC_TYPE,
        "id": vc_id,
        "issuer": issuer,
        "validFrom": valid_from,
        "credentialSubject": {"id": subject, "aae": aae},
    }


def max_tx(value: int, currency: str = "USD", required: bool = True) -> dict:
    return {"value": value, "currency": currency, "required": required}


# --- per-vector construction -------------------------------------------------

REGISTRY_KEY = load_key("issuer-test-key-1.json")
AGENT_A_KEY = load_key("agent-a-key.json")
AGENT_B_KEY = load_key("agent-b-key.json")


def root_mandate(actions, delegation_policy=None):
    m = {
        "actions": actions,
        "purpose": "Business travel booking",
        "scope": "travel-vertical",
        "principal_did": PRINCIPAL,
    }
    if delegation_policy is not None:
        m["delegation_policy"] = delegation_policy
    return m


def vectors():
    out = []

    # 01 — valid root AAE, baseline accept
    aae = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {
            "max_transaction_value": max_tx(500, "USD"),
            "allowed_domains": {"value": ["flights.example.com", "hotels.example.com"], "required": True},
        },
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    }
    jws = sign_jws(vc("urn:uuid:00000001-0000-4000-8000-000000000001", REGISTRY, AGENT_001, aae), REGISTRY_KEY)
    out.append({
        "id": "aae-vector-01",
        "name": "Valid root AAE — baseline accept",
        "description": "Root AAE issued by the registry, within the temporal window, no delegation. Exercises Section 5 steps 1-7.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §5 steps 1-7",
        "input": {"secured_aae": jws, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD", "domain": "flights.example.com"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "ACCEPT", "verification_step": 7, "rejection_reason": None},
        "rationale": "All required checks pass: valid EdDSA signature whose signing DID equals the issuer (§5 step 1), well-formed payload with cty aae+json (step 2), current time inside not_before/not_after (step 3), subject binding satisfied (step 4), action 'book' present in mandate.actions (step 6), and both required constraints satisfied (step 7). No revocation_check and no delegation, so steps 8-9 do not apply.",
    })

    # 02 — expired (not_after)
    jws = sign_jws(vc("urn:uuid:00000002-0000-4000-8000-000000000002", REGISTRY, AGENT_001, aae), REGISTRY_KEY)
    out.append({
        "id": "aae-vector-02",
        "name": "Expired AAE — current time after not_after",
        "description": "Well-formed root AAE evaluated after its not_after instant.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.4 (not_after), §5 step 3",
        "input": {"secured_aae": jws, "context": {
            "current_time": "2026-05-20T17:00:00Z",
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD", "domain": "flights.example.com"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "REJECT", "verification_step": 3, "rejection_reason": "expired_not_after"},
        "rationale": "Section 2.4 states relying parties MUST reject expired AAEs; §5 step 3 confirms current time is within not_before and not_after. 17:00Z is after the 16:00Z not_after, so the AAE is rejected at step 3.",
    })

    # 03 — too early (not_before)
    out.append({
        "id": "aae-vector-03",
        "name": "Not yet valid — current time before not_before",
        "description": "Well-formed root AAE evaluated before its not_before instant.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.4 (not_before, validFrom), §5 step 3",
        "input": {"secured_aae": jws, "context": {
            "current_time": "2026-05-20T07:00:00Z",
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD", "domain": "flights.example.com"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "REJECT", "verification_step": 3, "rejection_reason": "not_yet_valid_not_before"},
        "rationale": "Section 2.4 states the AAE MUST NOT be accepted before not_before, and not before the later of validFrom and not_before. 07:00Z precedes the 08:00Z not_before, so the AAE is rejected at step 3.",
    })

    # 04 — revocation endpoint 5xx -> fail-closed
    aae_rev = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {
            "not_before": NB, "not_after": NA, "single_use": False,
            "revocation_check": "https://api.example.com/aae/revocation/{id}",
        },
    }
    rev_id = "urn:uuid:00000004-0000-4000-8000-000000000004"
    jws = sign_jws(vc(rev_id, REGISTRY, AGENT_001, aae_rev), REGISTRY_KEY)
    out.append({
        "id": "aae-vector-04",
        "name": "Revocation endpoint 5xx — fail-closed reject",
        "description": "AAE with a revocation_check whose endpoint returns HTTP 503 (status indeterminate).",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.4 (revocation_check), §5 step 8",
        "input": {"secured_aae": jws, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "revocation_responses": {rev_id: {"http_status": 503}},
        }},
        "expected": {"result": "REJECT", "verification_step": 8, "rejection_reason": "revocation_status_indeterminate"},
        "rationale": "Section 2.4 requires that when revocation status cannot be determined — for example on an HTTP 5xx response — the relying party MUST reject the AAE. No locally configured fail-open policy applies, so the default fail-closed rule rejects at step 8.",
    })

    # 05 — single_use replay
    su_id = "urn:uuid:00000005-0000-4000-8000-000000000005"
    aae_su = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": True},
    }
    jws = sign_jws(vc(su_id, REGISTRY, AGENT_001, aae_su), REGISTRY_KEY)
    out.append({
        "id": "aae-vector-05",
        "name": "Single-use replay — id already consumed",
        "description": "AAE with single_use:true presented after a prior successful authorization recorded its id.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.4 (single_use), §5 step 5",
        "input": {"secured_aae": jws, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "consumed_ids": [su_id],
        }},
        "expected": {"result": "REJECT", "verification_step": 5, "rejection_reason": "single_use_already_consumed"},
        "rationale": "Section 2.4 and §5 step 5 require an atomic check-and-record keyed by the VC id when single_use is true; an id already recorded MUST be rejected. The context marks this id as already consumed, so the replay is rejected at step 5.",
    })

    # delegation chain: registry -> agent-a (root, depth 0) -> agent-b (depth 1) -> agent-c (depth 2)
    root_del_id = "urn:uuid:00000006-0000-4000-8000-0000000000a0"
    root_del = vc(root_del_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book", "pay"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    root_del_jws = sign_jws(root_del, REGISTRY_KEY)

    d1_id = "urn:uuid:00000006-0000-4000-8000-0000000000b1"
    d1 = vc(d1_id, AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read", "book"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": root_del_id,
                "delegator_aae_uri": "https://aae.example/p/" + root_del_id,
                "delegator_aae_hash": jws_hash(root_del_jws),
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    d1_jws = sign_jws(d1, AGENT_A_KEY)

    d2_id = "urn:uuid:00000006-0000-4000-8000-0000000000c2"
    d2 = vc(d2_id, AGENT_B, AGENT_C, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_B, "delegator_aae_id": d1_id,
                "delegator_aae_uri": "https://aae.example/p/" + d1_id,
                "delegator_aae_hash": jws_hash(d1_jws),
                "depth": 2, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(100, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    d2_jws = sign_jws(d2, AGENT_B_KEY)

    # 06 — valid delegation, depth 2
    out.append({
        "id": "aae-vector-06",
        "name": "Valid delegation chain — depth 2",
        "description": "Depth-2 delegated AAE (agent-c) presented with its ancestor chain (registry->agent-a->agent-b). Subset actions, monotonic value caps, depths within max_depth.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §3, §5 step 9",
        "input": {"secured_aae": d2_jws, "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [root_del_jws, d1_jws],
        }},
        "expected": {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None},
        "rationale": "Each link satisfies §3: delegated actions are subsets (read,book,pay -> read,book -> read), value caps are monotonically non-increasing (500 -> 300 -> 100 USD, same currency), each parent credentialSubject.id equals the child delegator_did, depths are 0/1/2 within max_depth 2, and each ancestor signature and signing authority verifies (§5 step 9).",
    })

    # 07 — delegation action superset (REJECT)
    d_super = vc("urn:uuid:00000007-0000-4000-8000-000000000007", AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read", "book", "pay"],  # 'pay' not granted to the child's parent below
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": "urn:uuid:00000007-0000-4000-8000-0000000000a7",
                "delegator_aae_uri": "https://aae.example/p/00000007-a7",
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    parent07 = vc("urn:uuid:00000007-0000-4000-8000-0000000000a7", REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-07",
        "name": "Delegation grants action not in parent — reject",
        "description": "Delegated AAE lists action 'pay' that its parent mandate (read, book) does not grant.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §3 (Actions subset), §5 step 9",
        "input": {"secured_aae": sign_jws(d_super, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [sign_jws(parent07, REGISTRY_KEY)],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegated_actions_not_subset"},
        "rationale": "Section 3 requires the delegated mandate.actions to be a subset of the parent. 'pay' is absent from the parent (read, book), so the delegated AAE is not strictly subordinate and is rejected at step 9.",
    })

    # 08 — delegation constraint relaxation (REJECT)
    d_relax = vc("urn:uuid:00000008-0000-4000-8000-000000000008", AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": "urn:uuid:00000008-0000-4000-8000-0000000000a8",
                "delegator_aae_uri": "https://aae.example/p/00000008-a8",
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(1000, "USD")},  # > parent 500
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    parent08 = vc("urn:uuid:00000008-0000-4000-8000-0000000000a8", REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-08",
        "name": "Delegation relaxes a numeric constraint — reject",
        "description": "Delegated max_transaction_value (1000 USD) exceeds the parent cap (500 USD).",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §3 (numeric upper-bound), §5 step 9",
        "input": {"secured_aae": sign_jws(d_relax, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [sign_jws(parent08, REGISTRY_KEY)],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegated_constraint_relaxed"},
        "rationale": "Section 3 requires a delegated numeric upper-bound constraint value to be less than or equal to the parent value. 1000 USD exceeds the parent's 500 USD, so the delegated AAE is not strictly subordinate and is rejected at step 9.",
    })

    # 09 — delegation depth exceeded (REJECT): depth 2 but max_depth 1
    d_depth = vc("urn:uuid:00000009-0000-4000-8000-000000000009", AGENT_B, AGENT_C, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_B, "delegator_aae_id": "urn:uuid:00000009-0000-4000-8000-0000000000b9",
                "delegator_aae_uri": "https://aae.example/p/00000009-b9",
                "depth": 2, "max_depth": 1,  # depth exceeds max_depth
            },
        },
        "constraints": {"max_transaction_value": max_tx(100, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    # parent at depth 1 (agent-a -> agent-b), max_depth 1
    p09_root_id = "urn:uuid:00000009-0000-4000-8000-0000000000a9"
    p09_root = vc(p09_root_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    p09_root_jws = sign_jws(p09_root, REGISTRY_KEY)
    p09_d1 = vc("urn:uuid:00000009-0000-4000-8000-0000000000b9", AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": p09_root_id,
                "delegator_aae_uri": "https://aae.example/p/00000009-a9",
                "depth": 1, "max_depth": 1,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-09",
        "name": "Delegation depth exceeds max_depth — reject",
        "description": "Depth-2 delegated AAE declares max_depth 1, so depth exceeds the permitted maximum for the branch.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §3 (Delegation depth), §5 step 9",
        "input": {"secured_aae": sign_jws(d_depth, AGENT_B_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [p09_root_jws, sign_jws(p09_d1, AGENT_A_KEY)],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegation_depth_exceeded"},
        "rationale": "Section 3 requires depth to not exceed max_depth, and §5 step 9 enforces depth limits. The presented AAE has depth 2 with max_depth 1, so it is rejected at step 9.",
    })

    # 10 — delegation cycle detection (REJECT): an ancestor reuses the presented id
    cyc_id = "urn:uuid:0000000a-0000-4000-8000-00000000000a"
    cyc_presented = vc(cyc_id, AGENT_B, AGENT_C, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_B, "delegator_aae_id": "urn:uuid:0000000a-0000-4000-8000-0000000000b1",
                "delegator_aae_uri": "https://aae.example/p/0000000a-b1",
                "depth": 2, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(100, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    cyc_d1 = vc("urn:uuid:0000000a-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": cyc_id,  # points back to the presented id
                "delegator_aae_uri": "https://aae.example/p/cycle",
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    # ancestor that reuses cyc_id -> id appears twice in the path
    cyc_loop = vc(cyc_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-10",
        "name": "Delegation cycle — repeated AAE id in path",
        "description": "The verification path revisits an AAE id already seen, indicating a cycle.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §5 step 9 (cycle detection)",
        "input": {"secured_aae": sign_jws(cyc_presented, AGENT_B_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [sign_jws(cyc_loop, REGISTRY_KEY), sign_jws(cyc_d1, AGENT_A_KEY)],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegation_cycle_detected"},
        "rationale": "Section 5 step 9 requires the relying party to maintain the set of AAE ids visited in the current path and to reject immediately if any id appears more than once. The presented id reappears among the ancestors, so the chain is rejected at step 9.",
    })

    # 11 — cascade revocation: an ancestor is revoked -> descendant invalid
    casc_root_id = "urn:uuid:0000000b-0000-4000-8000-0000000000a0"
    casc_root = vc(casc_root_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {
            "not_before": NB, "not_after": NA, "single_use": False,
            "revocation_check": "https://api.example.com/aae/revocation/{id}",
        },
    })
    casc_root_jws = sign_jws(casc_root, REGISTRY_KEY)
    casc_child_id = "urn:uuid:0000000b-0000-4000-8000-0000000000b1"
    casc_child = vc(casc_child_id, AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": casc_root_id,
                "delegator_aae_uri": "https://aae.example/p/" + casc_root_id,
                "delegator_aae_hash": jws_hash(casc_root_jws),
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-11",
        "name": "Delegation cascade revocation — revoked parent invalidates child",
        "description": "Depth-1 delegated AAE whose parent (root) AAE is revoked at its revocation endpoint.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §6.5 (Delegation Revocation), §5 step 9 (+ step 8 per ancestor)",
        "input": {"secured_aae": sign_jws(casc_child, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [casc_root_jws],
            "revocation_responses": {casc_root_id: {"revoked": True}},
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "ancestor_revoked"},
        "rationale": "Section 5 step 9 applies the revocation check to each ancestor AAE, and §6.5 states a relying party that determines a parent AAE has been revoked SHOULD treat all descendants as invalid. The parent endpoint reports revoked:true, so the descendant is rejected at step 9.",
    })

    # 12 — signing-authority mismatch (REJECT): root issuer=registry, signed by agent-a key
    aae12 = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    }
    vc12 = vc("urn:uuid:0000000c-0000-4000-8000-00000000000c", REGISTRY, AGENT_001, aae12)
    # sign with agent-a's key and agent-a kid, while issuer says registry
    jws12 = sign_jws(vc12, AGENT_A_KEY, kid=AGENT_A + "#key-1")
    out.append({
        "id": "aae-vector-12",
        "name": "Signing-authority mismatch — signing DID != issuer",
        "description": "Non-delegated AAE whose issuer is the registry but whose JWS is signed by a different DID's key.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §5 step 1 (signing authority)",
        "input": {"secured_aae": jws12, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "REJECT", "verification_step": 1, "rejection_reason": "signing_authority_mismatch"},
        "rationale": "Section 5 step 1 requires that for a non-delegated AAE the signing DID be identical to the Verifiable Credential issuer. The signature is cryptographically valid but the signing DID (agent-a) differs from the issuer (registry), so the AAE is rejected at step 1.",
    })

    # 13 — unrecognized required constraint (REJECT)
    aae13 = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {
            "max_transaction_value": max_tx(500, "USD"),
            "geo_fence": {"value": ["CH", "DE"], "required": True},  # unknown type, required
        },
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    }
    jws13 = sign_jws(vc("urn:uuid:0000000d-0000-4000-8000-00000000000d", REGISTRY, AGENT_001, aae13), REGISTRY_KEY)
    out.append({
        "id": "aae-vector-13",
        "name": "Unrecognized required constraint — reject",
        "description": "Constraints include a constraint type the relying party does not recognize, marked required:true.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.3, §5 step 7",
        "input": {"secured_aae": jws13, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "REJECT", "verification_step": 7, "rejection_reason": "unrecognized_required_constraint"},
        "rationale": "Section 2.3 and §5 step 7 require rejecting an AAE when an unrecognized constraint is marked required:true (or omits required, which defaults to true). 'geo_fence' is unrecognized and required, so the AAE is rejected at step 7.",
    })

    # 14 — cty header wrong (REJECT)
    aae14 = {
        "mandate": root_mandate(["read", "book", "pay"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    }
    jws14 = sign_jws(vc("urn:uuid:0000000e-0000-4000-8000-00000000000e", REGISTRY, AGENT_001, aae14),
                     REGISTRY_KEY, cty="application/json")
    out.append({
        "id": "aae-vector-14",
        "name": "Wrong cty protected-header — reject",
        "description": "JWS protected header sets cty to application/json instead of aae+json.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §2.1 (cty), §5 step 2",
        "input": {"secured_aae": jws14, "context": {
            "current_time": NOON,
            "requested_action": "book",
            "action_context": {"amount": 300, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
        }},
        "expected": {"result": "REJECT", "verification_step": 2, "rejection_reason": "cty_not_aae_json"},
        "rationale": "Section 2.1 requires the protected-header cty parameter to be aae+json, and §5 step 2 rejects the AAE if it is not. The signature is valid but cty is application/json, so the AAE is rejected at step 2.",
    })

    # 15 — currency mismatch in delegation (REJECT)
    d_cur = vc("urn:uuid:0000000f-0000-4000-8000-00000000000f", AGENT_A, AGENT_B, {
        "mandate": {
            "actions": ["read"],
            "delegation": {
                "delegator_did": AGENT_A, "delegator_aae_id": "urn:uuid:0000000f-0000-4000-8000-0000000000af",
                "delegator_aae_uri": "https://aae.example/p/0000000f-af",
                "depth": 1, "max_depth": 2,
            },
        },
        "constraints": {"max_transaction_value": max_tx(300, "EUR")},  # parent is USD
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    parent15 = vc("urn:uuid:0000000f-0000-4000-8000-0000000000af", REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"], delegation_policy={"max_depth": 2}),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    out.append({
        "id": "aae-vector-15",
        "name": "Delegation currency mismatch — reject",
        "description": "Delegated max_transaction_value is denominated in EUR while the parent is USD, with no conversion policy.",
        "section_ref": "draft-kroehl-agentic-trust-aae-00 §3 (currency-valued constraints), §5 step 9",
        "input": {"secured_aae": sign_jws(d_cur, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "EUR"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [sign_jws(parent15, REGISTRY_KEY)],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegation_currency_mismatch"},
        "rationale": "Section 3 requires a currency-valued delegated constraint to use the same currency as the parent unless an explicitly configured conversion policy exists; if the currencies differ and no such policy exists, the delegated AAE MUST be rejected. The child uses EUR against a USD parent, so it is rejected at step 9.",
    })

    return out


def main() -> None:
    os.makedirs(VECTORS, exist_ok=True)
    filenames = {
        "aae-vector-01": "01-valid-root-aae.json",
        "aae-vector-02": "02-expired-not-after.json",
        "aae-vector-03": "03-too-early-not-before.json",
        "aae-vector-04": "04-revocation-endpoint-5xx.json",
        "aae-vector-05": "05-single-use-replay.json",
        "aae-vector-06": "06-delegation-valid-depth-2.json",
        "aae-vector-07": "07-delegation-action-superset.json",
        "aae-vector-08": "08-delegation-constraint-relaxation.json",
        "aae-vector-09": "09-delegation-depth-exceeded.json",
        "aae-vector-10": "10-delegation-cycle-detection.json",
        "aae-vector-11": "11-delegation-cascade-revocation.json",
        "aae-vector-12": "12-signing-authority-mismatch.json",
        "aae-vector-13": "13-unrecognized-required-constraint.json",
        "aae-vector-14": "14-cty-header-wrong.json",
        "aae-vector-15": "15-currency-mismatch-delegation.json",
    }
    # verification_mode (#2, enum runtime|structural). Rule: runtime = the
    # determining check consults live external state (clock for §2.4 validity,
    # revocation lookup, single-use consumed-id); structural = the verdict is
    # determined by document-only properties. Cross-checked vs the #2 thread
    # (aeoess): 02/11 runtime, 07/08/15 structural.
    mode = {
        "aae-vector-01": "structural",  # ACCEPT baseline: doc-only verifier reaches correct ACCEPT
        "aae-vector-02": "runtime",     # step 3 expired_not_after — needs clock
        "aae-vector-03": "runtime",     # step 3 not_yet_valid — needs clock
        "aae-vector-04": "runtime",     # step 8 revocation indeterminate — needs lookup
        "aae-vector-05": "runtime",     # step 5 single-use replay — needs consumed-id state
        "aae-vector-06": "structural",  # ACCEPT valid chain: subset/monotonic caps/depth from docs
        "aae-vector-07": "structural",  # step 9 actions-not-subset — document compare
        "aae-vector-08": "structural",  # step 9 numeric constraint relaxed — document compare
        "aae-vector-09": "structural",  # step 9 depth exceeded — document field
        "aae-vector-10": "structural",  # step 9 cycle — visited-id set over path documents
        "aae-vector-11": "runtime",     # step 9 ancestor_revoked — needs revocation lookup
        "aae-vector-12": "structural",  # step 1 signing-authority — signature/issuer compare
        "aae-vector-13": "structural",  # step 7 unrecognized required constraint — document shape
        "aae-vector-14": "structural",  # step 2 cty header — document field
        "aae-vector-15": "structural",  # step 9 currency mismatch — document compare
    }
    for v in vectors():
        v["verification_mode"] = mode[v["id"]]
        fn = filenames[v["id"]]
        with open(os.path.join(VECTORS, fn), "w") as fh:
            json.dump(v, fh, indent=2)
            fh.write("\n")
        print(f"wrote vectors/{fn}  [{v['expected']['result']} @ step {v['expected']['verification_step']}, {v['verification_mode']}]")


if __name__ == "__main__":
    main()
