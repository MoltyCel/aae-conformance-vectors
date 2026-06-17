#!/usr/bin/env python3
"""Generate the Ed25519 test keys and did:web DID documents for the AAE
conformance vectors.

Run once. The output JWK and DID-document files are committed to the repo as
fixed test fixtures so that vector signatures are reproducible. Re-running
overwrites the keys and therefore invalidates every signed vector; only do that
deliberately (followed by tools/build_vectors.py).

THESE KEYS ARE PUBLIC AND FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
TESTKEYS = os.path.normpath(os.path.join(HERE, "..", "testkeys"))
DIDDOCS = os.path.join(TESTKEYS, "did-documents")

# did -> (key filename, did-document filename)
# The registry issues root AAEs; the agents act as subjects and as delegators.
IDENTITIES = [
    ("did:web:example.com:registry", "issuer-test-key-1.json", "registry.json"),
    ("did:web:example.com:agent-001", "agent-001-key.json", "agent-001.json"),
    ("did:web:example.com:agent-a", "agent-a-key.json", "agent-a.json"),
    ("did:web:example.com:agent-b", "agent-b-key.json", "agent-b.json"),
    ("did:web:example.com:agent-c", "agent-c-key.json", "agent-c.json"),
]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_jwk(priv: Ed25519PrivateKey) -> dict:
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(pub_raw),
        "d": b64url(priv_raw),
    }


def did_document(did: str, jwk_pub: dict) -> dict:
    """Minimal did:web DID document exposing one verification method, {did}#key-1,
    authorized for both assertionMethod (to sign AAEs) and authentication (to
    answer subject-binding challenges)."""
    vm_id = f"{did}#key-1"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk_pub,
            }
        ],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    }


def main() -> None:
    os.makedirs(DIDDOCS, exist_ok=True)
    for did, key_file, doc_file in IDENTITIES:
        priv = Ed25519PrivateKey.generate()
        jwk = make_jwk(priv)
        jwk_pub = {k: v for k, v in jwk.items() if k != "d"}

        key_obj = {
            "did": did,
            "kid": f"{did}#key-1",
            "note": "TEST ONLY — public/private keypair committed for reproducible vectors. DO NOT USE IN PRODUCTION.",
            "jwk": jwk,
        }
        with open(os.path.join(TESTKEYS, key_file), "w") as fh:
            json.dump(key_obj, fh, indent=2)
            fh.write("\n")

        with open(os.path.join(DIDDOCS, doc_file), "w") as fh:
            json.dump(did_document(did, jwk_pub), fh, indent=2)
            fh.write("\n")
        print(f"wrote {key_file} + did-documents/{doc_file} for {did}")


if __name__ == "__main__":
    main()
