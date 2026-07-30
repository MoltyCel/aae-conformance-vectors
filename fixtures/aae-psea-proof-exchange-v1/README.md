# AAE × PSEA proof exchange, v1

The AAE side of the exchange, pinned to bytes. Six files: three carry the
artifacts, three carry what a verifier should get out of them.

| File | What it is |
|---|---|
| `aae-envelope.jws` | The AAE, EdDSA JWS in compact serialization. 1358 bytes. |
| `action-payload.json` | The action payload in RFC 8785 canonical form. 114 bytes. |
| `issuer-trust.json` | The DID document that resolves the signing key, plus the trust decision. Public key only. |
| `expected.json` | The native AAE verdict and the composed seven-row result. |
| `manifest.json` | Hashes, algorithm, provenance, and the WHO-axis status. |
| `README.md` | This file. |

Everything derives from vector `xp-1-aligned-principal` in
`interop/psea/vectors/`. Nothing was re-signed and nothing was re-serialized.

## Byte discipline

`aae-envelope.jws` and `action-payload.json` end without a newline. The hashes in
`manifest.json` cover the whole file, so appending one changes them. An editor
that adds a trailing newline on save will break the pins; check with
`shasum -a 256` after any edit.

`action-payload.json` holds the canonical bytes themselves rather than a
pretty-printed object. Its SHA-256 is therefore the action digest:

    d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606

which is the same value the counterpart fixture records as `join_key.octets_hex`,
and the same 32 octets `mandate.action_binding.payload_digest` carries inside the
signed envelope as `sha-256:1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY`.

## Reproducing the verdict

Tool: `examples/python-verify.py` from
[MoltyCel/aae-conformance-vectors](https://github.com/MoltyCel/aae-conformance-vectors),
at the `head_commit` recorded in `manifest.json`. It implements
draft-kroehl-agentic-trust-aae-00 Section 5 and performs real Ed25519
verification.

Recorded run used Python 3.9.6 with `cryptography` 49.0.0. Python 3.9 or later
works; the verifier has no other dependency.

```
pip install cryptography

python3 - <<'EOF'
import importlib.util, json, base64, hashlib

FIX = "fixtures/aae-psea-proof-exchange-v1"

spec = importlib.util.spec_from_file_location("pv", "examples/python-verify.py")
pv = importlib.util.module_from_spec(spec); spec.loader.exec_module(pv)

# Resolve DIDs from the fixture instead of the repository's testkeys directory.
trust = json.load(open(f"{FIX}/issuer-trust.json"))
pv.DID_DOCS = {doc["id"]: doc for doc in trust["did_documents"]}

jws = open(f"{FIX}/aae-envelope.jws", "rb").read().decode("ascii")
ctx = {
    "current_time": "2026-07-29T08:30:00Z",
    "requested_action": "transfer",
    "action_context": {"amount": 250000, "currency": "CHF",
                       "target": "iban:CH9300762011623852957", "sequence": 1},
    "subject_binding": {"challenge_response_valid": True},
}
print(json.dumps(pv.verify(jws, ctx)))

payload = open(f"{FIX}/action-payload.json", "rb").read()
print("action payload sha256:", hashlib.sha256(payload).hexdigest())
p = jws.split(".")[1]; p += "=" * (-len(p) % 4)
mandate = json.loads(base64.urlsafe_b64decode(p))["credentialSubject"]["aae"]["mandate"]
print("signed action_binding:", mandate["action_binding"]["payload_digest"])
EOF
```

Expected output:

```
{"result": "ACCEPT", "verification_step": 7, "rejection_reason": null}
action payload sha256: d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606
signed action_binding: sha-256:1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY
```

The `current_time` above matters: the grant is valid from 2026-07-29T08:00:00Z to
09:00:00Z, and a clock outside that window yields
`REJECT @ 3 (expired_not_after)` or `(not_yet_valid_not_before)`. The
`action_context` supplies the amount and currency the grant's
`max_transaction_value` constraint is evaluated against, in integer minor units.
`subject_binding` supplies the step-4 challenge-response outcome, which a static
file cannot reproduce live.

Verifying without the surrounding repository means supplying `python-verify.py`
yourself; the fixture pins the artifacts, not the tool.

## The trust decision

`issuer-trust.json` carries the DID document for
`did:web:example.com:agent-a`, which resolves the `kid`
`did:web:example.com:agent-a#key-1` in the JWS protected header. Section 5 step 1
requires the signing DID to equal the credential issuer, and the verifier
enforces that. Whether `did:web:example.com:agent-a` is an acceptable issuer at
all is the relying party's own decision, recorded in `trust_decision` so the
reproduction is complete.

The keys are the committed test keys of the conformance-vector repository. They
are public and for testing. No private key material appears in this fixture.

## Status of the composed result

`expected.json` records two layers. The AAE verdict comes from the draft's own
algorithm and stands on its own. The seven-row composed result depends on a
principal-resolution table that the counterpart profile has not yet confirmed,
so `principal_linkage` carries `"status": "PROPOSED"`, and the two rows that
follow from it — `evidence_satisfaction` and `decision` — inherit that standing.

`aae_native` and `action_linkage` are unaffected. The AAE verdict is the draft's,
and the action digest was recomputed independently on both sides and agrees on
all 32 octets.

Confirmation of the WHO axis removes the `PROPOSED` marker. It changes no byte in
this directory.

## Scope

`admission` and `outcome` read `NONE`. The reference checker decides; it neither
admits nor executes, and this fixture exercises no value beyond `NONE` on either
row.

Recomputing the action digest from the payload is outside the reproduction above.
The commands check that the declared digest is bound to the signed envelope and
that the payload file hashes to the same value. Running a JCS implementation over
the payload and comparing is a further step, and a peer whose canonicalizer
differs on null-valued or empty members would diverge there.
