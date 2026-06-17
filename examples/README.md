# Reference verifier

`python-verify.py` is a reference implementation skeleton of the
draft-kroehl-agentic-trust-aae-00 Section 5 verification algorithm. It reads
every file in `../vectors/`, runs the algorithm, and compares the result against
each vector's `expected` field.

It is not production code. It exists to show one correct interpretation of the
algorithm and to give implementers an objective target. An implementation
claiming AAE conformance against draft-kroehl-agentic-trust-aae-00 should pass
all vectors — the `result` and, for rejections, the `verification_step` must
match.

## Running

```
pip install cryptography
python3 python-verify.py
```

Expected output ends with `15/15 vectors passed` and a zero exit code.

## What it does and does not do

It performs real EdDSA (Ed25519) signature verification, resolving signing DIDs
offline from `../testkeys/did-documents/`. It implements the signing-authority
rule, schema and `cty` checks, temporal validity, single-use, action membership,
constraint evaluation including the `required`-default-true taxonomy, revocation
fail-closed handling, and delegation-chain verification with monotonicity, depth
limits, and cycle detection.

It does not open network connections, run a live subject-binding challenge, or
maintain persistent single-use state. Those facts are supplied per vector through
the `context` object, because a static vector cannot reproduce a live exchange.
A production verifier performs them directly.
