# AAE Conformance Vectors v1.1.0

Test vectors for the Agent Authorization Envelope (AAE) Internet-Draft,
[draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/).

An AAE is a W3C Verifiable Credential, secured as an EdDSA JWS, that states what
an autonomous agent is authorized to do (MANDATE), the limits on those actions
(CONSTRAINTS), and the time bounds (VALIDITY). The draft specifies a nine-step
verification algorithm in Section 5. These vectors turn that algorithm from a
set of abstract MUST statements into an objective target: a fixed input AAE plus
the verifier result it has to produce.

## Purpose

An implementation claiming AAE conformance can validate against these vectors.
Each vector specifies an input AAE (a signed JWS in compact serialization) and
the expected verifier result, with a reference to the section of the draft that
governs the case.

Coverage of the 15 vectors:

| # | Vector | Result | Step | Mode | Draft section |
|---|--------|--------|------|------|---------------|
| 01 | Valid root AAE | ACCEPT | 7 | structural | §5 steps 1-7 |
| 02 | Expired (not_after) | REJECT | 3 | runtime | §2.4, §5 step 3 |
| 03 | Not yet valid (not_before) | REJECT | 3 | runtime | §2.4, §5 step 3 |
| 04 | Revocation endpoint 5xx | REJECT | 8 | runtime | §2.4, §5 step 8 |
| 05 | Single-use replay | REJECT | 5 | runtime | §2.4, §5 step 5 |
| 06 | Valid delegation, depth 2 | ACCEPT | 9 | structural | §3, §5 step 9 |
| 07 | Delegation grants action not in parent | REJECT | 9 | structural | §3, §5 step 9 |
| 08 | Delegation relaxes numeric constraint | REJECT | 9 | structural | §3, §5 step 9 |
| 09 | Delegation depth exceeds max_depth | REJECT | 9 | structural | §3, §5 step 9 |
| 10 | Delegation cycle (repeated id) | REJECT | 9 | structural | §5 step 9 |
| 11 | Delegation cascade revocation | REJECT | 9 | runtime | §6.5, §5 step 9 |
| 12 | Signing authority mismatch | REJECT | 1 | structural | §5 step 1 |
| 13 | Unrecognized required constraint | REJECT | 7 | structural | §2.3, §5 step 7 |
| 14 | Wrong cty protected header | REJECT | 2 | structural | §2.1, §5 step 2 |
| 15 | Currency mismatch in delegation | REJECT | 9 | structural | §3, §5 step 9 |

See [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the full vector-to-section
mapping and the rationale per case.

## Usage

1. Clone the repo.
2. Run your verifier against each file in `vectors/`.
3. For each vector, compare your verifier's output against the `expected` field:
   `result` (ACCEPT or REJECT) and, for rejections, the `verification_step` at
   which the algorithm stops.
4. To claim conformance against draft-kroehl-agentic-trust-aae-00, all 15
   vectors must match.

A reference verifier is provided in
[`examples/python-verify.py`](examples/python-verify.py). It implements the
Section 5 algorithm, performs real Ed25519 signature verification (resolving
DIDs from the fixtures under `testkeys/did-documents/`), and reports how many
vectors pass.

```
$ python3 examples/python-verify.py
PASS  01-valid-root-aae.json                     ACCEPT @ step 7
...
15/15 vectors passed
```

Requirements: Python 3.9+ and the `cryptography` package
(`pip install cryptography`). Schema validation additionally uses `jsonschema`.

## Vector format

Each vector has eight fields: `id`, `name`, `description`, `section_ref`,
`verification_mode`, `input`, `expected`, and `rationale`. The format is defined
by [`schema/vector-schema.json`](schema/vector-schema.json).

The `input.context` object carries the facts a verifier needs but that a static
file cannot reproduce live: the current time (step 3), the requested action and
action attributes (steps 6-7), the subject-binding challenge-response outcome
(step 4), the set of already-consumed ids (step 5), revocation endpoint
responses keyed by AAE id (step 8), and the ordered ancestor chain for delegated
AAEs (step 9). DID resolution is offline against the documents in
`testkeys/did-documents/`.

## Verification mode

Each vector carries a required `verification_mode` of `structural` or `runtime`.
It records **how the expected verdict is reached**, closing an interop hazard
([#2](https://github.com/MoltyCel/aae-conformance-vectors/issues/2)): two
verifiers can return the same result on a vector for different reasons — one from
document structure, one from a runtime decision — and still diverge in
production.

- **structural** — the verdict is determined by document-only properties:
  signature, schema/`cty`, and the delegation checks that compare the presented
  AAE and its chain (actions subset, numeric/currency/allowlist monotonicity,
  depth, cycle). A verifier reaches the correct verdict from the documents alone.
- **runtime** — the verdict requires live external state the documents do not
  carry: the clock for the §2.4 validity window (`02`, `03`), a revocation lookup
  (`04`, and `11` for an ancestor), or single-use consumed-id tracking (`05`).

The line is sharp where it matters: `06` and `11` both stop at step 9, but `06`
is `structural` (chain shape) and `11` is `runtime` (ancestor revocation lookup).

**Disambiguation vs TechSpec v0.9 §17.** `verification_mode` is the *derivation*
axis — how a verifier computes the verdict. It is **orthogonal** to §17
enforcement, which is the *action* axis — whether a DENY verdict blocks (enforce)
or is logged (advisory). A `runtime` vector can be evaluated under an `advisory`
posture: you consult the clock/revocation to derive the verdict, then only log
it. The two never substitute for each other.

## Interoperability

An independent implementation (aeoess / APS) cross-encoded 6 overlapping delegation-verification
scenarios against the v1.1.0 `verification_mode` classification. The `runtime` / `structural`
labels match 6/6, and the cross-encoded vectors pass this repo's reference verifier.
Scope: a one-time cross-encoding (not a maintained set); alignment is at the label + verifier-verdict
level, not byte-identical vectors (APS encodes in its own canonical format).
Source: https://github.com/aeoess/aps-conformance-suite/tree/main/interop/aae-envelope/moltycel-format
Mapping: runtime = {02 expired-not-after, 11 cascade-revocation};
         structural = {06 valid-delegation, 07 action-superset, 08 constraint-relaxation, 15 currency-mismatch}.

## External conformance suites

External implementers of related specifications can contribute vectors under
`interop/<spec-name>/`. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Current external suites: (none yet — first PR pending)

## Test keys

The keypairs under `testkeys/` are committed so that the signed vectors are
reproducible. **These keys are public and for testing only. Do not use them in
production.** `tools/genkeys.py` regenerates them and `tools/build_vectors.py`
rebuilds and re-signs every vector from the keys.

## Versioning

Vector set version: 1.1.0. Tracks: draft-kroehl-agentic-trust-aae-00.

v1.1.0 adds the required `verification_mode` field (`runtime`|`structural`) to
all 15 vectors and the schema (#2). No vector result or `verification_step`
changed; this is additive metadata.

Later revisions are published as 1.1.0, 1.2.0, and so on, tracking draft
revisions. A change to the draft that alters a verifier outcome is a minor
version bump with the changed vectors noted in the release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for vector requirements, cross-spec
contributions, and the PR process.

## License

Apache 2.0. The vectors are free to use, modify, and redistribute. See
[LICENSE](LICENSE).

Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust).

## Spec

draft-kroehl-agentic-trust-aae-00:
https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/

## Contact

lars@moltrust.ch
