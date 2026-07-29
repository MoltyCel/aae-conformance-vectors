#!/usr/bin/env python3
"""Build the interop/psea composition vector set.

Reads the counterpart fixture (interop/psea/psea-fixture-v0.json, published by
yuthent/psea-spec) and the committed test keys, constructs the two AAE envelopes
for the cross-run, and writes interop/psea/{action-payload.json,aae-envelopes/*,
vectors/*}. Deterministic given the committed keys and the fixture: re-running
reproduces byte-identical output.

The 15 AAE-native vectors in vectors/ are NOT touched by this tool. Nor is the
delegator_aae_hash rule: that hashes the exact ASCII octets of a parent JWS with
JCS explicitly excluded (draft Section 3). The join key added here is a separate,
additive field, mandate.action_binding, and it hashes the shared ACTION PAYLOAD
with JCS per the counterpart profile's join-key definition.

THE TEST KEYS ARE PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TESTKEYS = os.path.join(ROOT, "testkeys")
INTEROP = os.path.join(ROOT, "interop", "psea")

FIXTURE = os.path.join(INTEROP, "psea-fixture-v0.json")
FIXTURE_SHA256 = "f7d89f4df629d0b7318131ddfd8274c58ea96308c8aa557616baa4b88e60d188"
FIXTURE_SOURCE = {
    "repository": "https://github.com/yuthent/psea-spec",
    "path": "conformance/interop-aae/psea-fixture-v0.json",
    "sha256": FIXTURE_SHA256,
}

# --- signing helpers, same conventions as tools/build_vectors.py ------------------


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
    header = {"alg": "EdDSA", "cty": cty, "kid": kid or key["kid"]}
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = signer(key).sign(f"{h_b64}.{p_b64}".encode("ascii"))
    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def canonicalize(obj) -> bytes:
    """RFC 8785 JCS. Uses the `jcs` package when available; the fallback below is
    only exercised for the flat, ASCII, integers-only payload this set uses."""
    try:
        import jcs  # noqa: WPS433
        return jcs.canonicalize(obj)
    except ImportError:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")


CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://moltrust.ch/contexts/aae/v1",
]
VC_TYPE = ["VerifiableCredential", "AgentAuthorizationEnvelope"]

AGENT_A = "did:web:example.com:agent-a"
AGENT_B = "did:web:example.com:agent-b"
AGENT_001 = "did:web:example.com:agent-001"

PRINCIPAL_A_DID = "did:web:example.com:principal-A"
PRINCIPAL_UNRESOLVED_DID = "did:web:example.com:principal-unresolved"
# A second AAE-side identifier the enrolled table maps onto the SAME canonical
# principal as PRINCIPAL_A_DID. Exercised by xp-6.
PRINCIPAL_A_ALIAS_DID = "did:web:example.com:principal-A-alias"

# The counterpart fixture's iat/exp window, 1785312000 .. 1785315600.
NB = "2026-07-29T08:00:00Z"
NA = "2026-07-29T09:00:00Z"
NOW = "2026-07-29T08:30:00Z"

AAE_DRAFT = "draft-kroehl-agentic-trust-aae-00"


def load_fixture() -> dict:
    raw = open(FIXTURE, "rb").read()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != FIXTURE_SHA256:
        raise SystemExit(
            f"fixture integrity pin failed\n  expected {FIXTURE_SHA256}\n  actual   {actual}")
    return json.loads(raw.decode("utf-8"))


def build_envelope(vc_id: str, issuer: str, subject: str, principal_did: str,
                   join_b64url: str) -> dict:
    return {
        "@context": CONTEXT,
        "type": VC_TYPE,
        "id": vc_id,
        "issuer": issuer,
        "validFrom": NB,
        "credentialSubject": {
            "id": subject,
            "aae": {
                "mandate": {
                    "actions": ["transfer", "payment.execute"],
                    "purpose": "PSEA/AAE interop cross-run - single outbound transfer",
                    "scope": "payments-vertical",
                    "principal_did": principal_did,
                    "action_binding": {
                        "alg": "sha-256",
                        "canonicalization": "JCS (RFC 8785)",
                        "payload_digest": "sha-256:" + join_b64url,
                    },
                },
                "constraints": {
                    # Integer minor units, no float / decimal / exponent.
                    # 500000 minor units CHF = 5 000.00 CHF; the action carries
                    # 250000 = 2 500.00 CHF.
                    "max_transaction_value": {
                        "value": 500000,
                        "currency": "CHF",
                        "required": True,
                    },
                },
                "validity": {
                    "not_before": NB,
                    "not_after": NA,
                    "single_use": False,
                },
            },
        },
    }


def secondary_artifact(fix: dict, artifact_id: str) -> dict:
    art = next(a for a in fix["artifacts"] if a["id"] == artifact_id)
    header = json.loads(b64url_decode(art["token"].split(".", 1)[0]))
    kid = header["kid"]
    return {
        "profile": fix["psea_profile"],
        "format": "JWS compact serialization, typ psea-proof+jwt, alg ES256",
        "artifact_id": art["id"],
        "token": art["token"],
        "signer_kid": kid,
        "enrollment_binding": fix["enrollment_bindings"][kid],
        "native_verdict": art["psea_native_verdict"],
        "payload_digest": {
            "alg": "sha-256",
            "encoding": "base64-pad",
            "value": fix["join_key"]["psea_wire_value"],
            "octets": 32,
        },
        "uv_anchoring": art["uv_anchoring"],
        "source": dict(FIXTURE_SOURCE),
    }


def join_who_for(table: dict, state_name: str) -> dict:
    """Derive a vector's join_who block for a named relying-party enrollment state.

    The derivation is DATA, not a literal in this file: principal-resolution.json
    carries the fully enrolled table plus a `states` map, and each state names the
    secondary entries the relying party has not enrolled yet. A checker still only
    ever looks identifiers up in the table it is handed.

    The default state is omitted from the emitted block, so a vector evaluated in
    it carries no resolution_state field and reads exactly as it did before states
    existed. A vector in any other state names it, so a reader can see why an
    entry is missing rather than inferring it from a gap.
    """
    state = table["states"][state_name]
    omits = set(state.get("secondary_omits", ()))
    block = {
        "status": table["status"],
        "canonical_space": table["canonical_space"],
        "unresolved_rule": table["unresolved_rule"],
    }
    if state_name != table["default_state"]:
        block["resolution_state"] = state_name
        block["state_note"] = state["note"]
    block["principal_resolution"] = {
        "aae": table["principal_resolution"]["aae"],
        "secondary": {k: v for k, v in table["principal_resolution"]["secondary"].items()
                      if k not in omits},
    }
    return block


def main() -> int:
    fix = load_fixture()
    payload = fix["action_payload_cleartext"]

    canon = canonicalize(payload)
    recorded = fix["action_payload_jcs_utf8"].encode("utf-8")
    if canon != recorded:
        raise SystemExit("JCS output differs from the fixture's recorded canonical form")

    digest = hashlib.sha256(canon).digest()
    if digest != bytes.fromhex(fix["join_key"]["octets_hex"]):
        raise SystemExit("join key octets differ from the fixture")
    join_b64url = b64url(digest)

    with open(os.path.join(INTEROP, "principal-resolution.json")) as fh:
        table = json.load(fh)

    join_what = {
        "definition": "SHA-256 over JCS (RFC 8785) of the action payload",
        "comparison_rule": "compare the 32 octets, never the encoded strings",
        "payload": payload,
        "payload_jcs_utf8": fix["action_payload_jcs_utf8"],
        "aae_digest": {
            "alg": "sha-256",
            "encoding": "base64url-nopad",
            "value": "sha-256:" + join_b64url,
            "octets": 32,
        },
        "secondary_digest": {
            "alg": "sha-256",
            "encoding": "base64-pad",
            "value": fix["join_key"]["psea_wire_value"],
            "octets": 32,
        },
    }

    e1 = build_envelope("urn:uuid:00000101-0000-4000-8000-0000000000a1",
                        AGENT_A, AGENT_001, PRINCIPAL_A_DID, join_b64url)
    e2 = build_envelope("urn:uuid:00000102-0000-4000-8000-0000000000b2",
                        AGENT_B, AGENT_001, PRINCIPAL_UNRESOLVED_DID, join_b64url)
    # Identical to e1 in issuer, subject, actions, purpose, scope, constraints,
    # validity and action_binding. The principal_did differs, and the vc id with
    # it so two distinct envelopes never share an identifier.
    e6 = build_envelope("urn:uuid:00000106-0000-4000-8000-0000000000c6",
                        AGENT_A, AGENT_001, PRINCIPAL_A_ALIAS_DID, join_b64url)
    jws1 = sign_jws(e1, load_key("agent-a-key.json"))
    jws2 = sign_jws(e2, load_key("agent-b-key.json"))
    jws6 = sign_jws(e6, load_key("agent-a-key.json"))

    os.makedirs(os.path.join(INTEROP, "aae-envelopes"), exist_ok=True)
    os.makedirs(os.path.join(INTEROP, "vectors"), exist_ok=True)

    for name, jws, doc, note in (
        ("E1-principal-A", jws1, e1,
         "AAE grant naming principal-A. Used by XP-1 and XP-2."),
        ("E2-unresolved", jws2, e2,
         "AAE grant naming a principal with no entry in the resolution table. Used by XP-3."),
        ("E3-principal-A-alias", jws6, e6,
         "AAE grant naming a second identifier that the enrolled table maps onto the same "
         "canonical principal as E1. Identical to E1 apart from id and principal_did. Used by XP-6."),
    ):
        write_json(os.path.join(INTEROP, "aae-envelopes", name + ".json"), {
            "name": name,
            "note": note,
            "signed_by": doc["issuer"],
            "secured_aae": jws,
            "decoded_payload": doc,
        })

    write_json(os.path.join(INTEROP, "action-payload.json"), {
        "note": "The single action both profiles bind to. Copied from the counterpart "
                "fixture, not re-derived. Integers only (psea-02 Section 2.5).",
        "source": dict(FIXTURE_SOURCE),
        "cleartext": payload,
        "jcs_utf8": fix["action_payload_jcs_utf8"],
        "jcs_utf8_octets": len(canon),
        "join_key": {
            "octets_hex": digest.hex(),
            "base64url_nopad": join_b64url,
            "base64_pad": base64.b64encode(digest).decode("ascii"),
        },
        "amount_unit": "integer minor units; amount_minor 250000 = 2 500.00 CHF",
        "aae_action_context_adapter": {
            "note": "The AAE Section 5 constraint evaluator reads action_context.amount "
                    "and action_context.currency. The shared payload names the amount "
                    "amount_minor. The adapter is a rename, not a conversion: the integer "
                    "value is carried across unchanged, still in minor units.",
            "amount_minor": "amount",
            "currency": "currency",
        },
    })

    action_ctx = {
        "amount": payload["amount_minor"],
        "currency": payload["currency"],
        "target": payload["target"],
        "sequence": payload["sequence"],
    }
    base_context = {
        "current_time": NOW,
        "requested_action": payload["operation"],
        "action_context": action_ctx,
        "subject_binding": {"challenge_response_valid": True},
    }

    vectors = [
        {
            "id": "xp-1",
            "file": "xp-1-aligned-principal.json",
            "name": "Aligned principal - composition authorizes",
            "description": "The AAE grant names principal-A and the PSEA proof is signed "
                           "by the key enrolled to principal-A. Both artifacts verify "
                           "natively and join on the same 32-octet action digest.",
            "secured_aae": jws1,
            "artifact": "PSEA-A",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "SAME"},
                    "evidence_satisfaction": {"value": "SATISFIED"},
                    "decision": {"value": "AUTHORIZED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "One human both mandated and approved. Both native verifications "
                         "pass, the WHAT-join holds on 32 identical octets, and both "
                         "principals resolve to urn:interop:aae-psea:principal:A. This is "
                         "the only case in the set where every gate is satisfied.",
        },
        {
            "id": "xp-2",
            "file": "xp-2-principal-divergence.json",
            "name": "Principal divergence - composition refuses",
            "description": "The AAE grant names principal-A; the PSEA proof is signed by "
                           "the key enrolled to principal-B. Both artifacts verify natively "
                           "and carry the same action digest, so every single-profile check "
                           "passes.",
            "secured_aae": jws1,
            "artifact": "PSEA-B",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "DIVERGENT",
                                          "reason": "principal_divergence"},
                    "evidence_satisfaction": {"value": "UNSATISFIED"},
                    "decision": {"value": "REFUSED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "No single human both mandated and approved the action. A relying "
                         "party performs two independent key-to-principal resolutions - "
                         "principal_did on the AAE side, kid via enrollment binding on the "
                         "PSEA side - and nothing requires them to agree. A composition that "
                         "ANDs 'grant valid?' with 'proof valid?' returns AUTHORIZED here, "
                         "which is wrong. This is the class neither native vector set "
                         "carries. The conflict is located at principal_linkage DIVERGENT, "
                         "one row above the refusal it causes.",
        },
        {
            "id": "xp-3",
            "file": "xp-3-unresolved-binding.json",
            "name": "Unresolved binding - refused on a missing input",
            "description": "The AAE grant names a principal with no entry in the resolution "
                           "table; the PSEA proof is signed by the key enrolled to "
                           "principal-A. Both artifacts verify natively and carry the same "
                           "action digest.",
            "secured_aae": jws2,
            "artifact": "PSEA-A",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "UNRESOLVED",
                                          "reason": "unresolved_binding"},
                    "evidence_satisfaction": {"value": "NOT_EVALUATED"},
                    "decision": {"value": "REFUSED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "The enrollment binding is not established on one side, so the "
                         "composition has no resolution to compare. Absence of a resolution "
                         "is not divergence of resolutions. XP-3 and XP-2 both end REFUSED "
                         "at the decision row, and that is exactly why the decision row is "
                         "not the whole result: they are told apart one row earlier, at "
                         "principal_linkage UNRESOLVED against DIVERGENT, and again at "
                         "evidence_satisfaction NOT_EVALUATED against UNSATISFIED. A "
                         "one-column verdict renders 'we cannot tell whose mandate this is' "
                         "and 'these artifacts name different humans' identically, and a "
                         "reviewer cannot recover the difference from the result.",
        },
        {
            "id": "xp-5a",
            "file": "xp-5a-enrollment-pending.json",
            "name": "Enrollment pending - binding not yet resolved",
            "description": "Identical AAE grant (principal-A) and identical PSEA-A proof as "
                           "the second pass. The relying party has not yet enrolled the PSEA "
                           "signer's key, so the secondary binding does not resolve. Same "
                           "32-octet action digest.",
            "secured_aae": jws1,
            "artifact": "PSEA-A",
            "resolution_state": "pending_enrollment",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "UNRESOLVED",
                                          "reason": "unresolved_binding"},
                    "evidence_satisfaction": {"value": "NOT_EVALUATED"},
                    "decision": {"value": "REFUSED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "The agent's identity is byte-identical to the second pass - same AAE "
                         "envelope, same PSEA proof. What is missing is the relying party's "
                         "enrollment of the signer key, so the secondary side has no "
                         "resolution and principal_linkage is UNRESOLVED, one row that "
                         "separates it from the DIVERGENT of xp-2. Evidence is NOT_EVALUATED "
                         "because there is no second resolution to compare. Paired with "
                         "xp-5b, this isolates enrollment as the only thing that changed "
                         "between refusal and authorization.",
        },
        {
            "id": "xp-5b",
            "file": "xp-5b-enrollment-complete.json",
            "name": "Enrollment complete - binding resolved",
            "description": "The same AAE grant and the same PSEA-A proof as xp-5a, evaluated "
                           "after the relying party has enrolled the signer key. Both sides "
                           "now resolve to the same principal.",
            "secured_aae": jws1,
            "artifact": "PSEA-A",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "SAME"},
                    "evidence_satisfaction": {"value": "SATISFIED"},
                    "decision": {"value": "AUTHORIZED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "Nothing on the wire changed from xp-5a - the AAE envelope and the "
                         "PSEA proof are the same bytes. Only the relying party's enrollment "
                         "table advanced, so the secondary binding now resolves to the same "
                         "principal as the AAE grant. The verdict moves from REFUSED to "
                         "AUTHORIZED on the binding evidence alone, a property a "
                         "single-snapshot vector cannot show.",
        },
        {
            "id": "xp-6",
            "file": "xp-6-alias-convergence.json",
            "name": "Alias convergence - two AAE labels, one principal",
            "description": "The AAE grant names did:web:example.com:principal-A-alias, a second "
                           "identifier the enrolled table maps onto the same canonical principal "
                           "as principal-A. The PSEA-A proof is unchanged. Same 32-octet action "
                           "digest as every other vector in the set.",
            "secured_aae": jws6,
            "artifact": "PSEA-A",
            "expected": {
                "stages": {
                    "aae_native": {"value": "ACCEPT", "verification_step": 7},
                    "action_linkage": {"value": "EQUIVALENT"},
                    "principal_linkage": {"value": "SAME"},
                    "evidence_satisfaction": {"value": "SATISFIED"},
                    "decision": {"value": "AUTHORIZED"},
                    "admission": {"value": "NONE"},
                    "outcome": {"value": "NONE"},
                },
            },
            "rationale": "Two AAE-side labels resolve to one canonical principal, so a "
                         "string comparison of principal_did against the PSEA enrollment label "
                         "reports a mismatch while the resolution reports SAME. The table decides, "
                         "and it is consulted rather than pattern-matched. This is the static "
                         "counterpart to the temporal case in xp-5a and xp-5b: there the same "
                         "identifier resolved differently at two times, here two identifiers "
                         "resolve identically at one time. Both hold principal_linkage apart from "
                         "the shape of the identifiers that feed it.",
        },
    ]

    for v in vectors:
        write_json(os.path.join(INTEROP, "vectors", v["file"]), {
            "id": v["id"],
            "name": v["name"],
            "description": v["description"],
            "status": "proposed",
            "section_ref": f"{AAE_DRAFT} Section 5 steps 1-7; "
                           f"{fix['psea_profile']} Sections 2.5, 3.8; "
                           "draft-yossif-enrollment-problem-00",
            "verification_mode": "structural",
            "input": {
                "secured_aae": v["secured_aae"],
                "context": base_context,
                "secondary_artifact": secondary_artifact(fix, v["artifact"]),
                "join_what": join_what,
                "join_who": join_who_for(
                    table, v.get("resolution_state", table["default_state"])),
            },
            "expected": v["expected"],
            "rationale": v["rationale"],
        })

    print(f"join key   {digest.hex()}")
    print(f"envelopes  {os.path.join(INTEROP, 'aae-envelopes')}")
    print(f"vectors    {len(vectors)} written to {os.path.join(INTEROP, 'vectors')}")
    return 0


def write_json(path: str, obj) -> None:
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


if __name__ == "__main__":
    sys.exit(main())
