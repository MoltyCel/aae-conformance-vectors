# Contributing to AAE Conformance Vectors

## Scope

This repository accepts:

- AAE conformance vectors — additions to or refinements of the core 15-vector
  suite covering delegation, revocation, validity, and cycle detection
- Cross-spec contributions — vectors authored against AAE semantics by
  implementers of related specs (APS, x402, action_ref, etc.), filed under
  `interop/<spec-name>/`
- Schema improvements — proposals against `schema/vector-schema.json`, see open
  issues for current discussion (e.g. #2 for `verification_mode`)
- Reference verifier patches — fixes or extensions to `examples/python-verify.py`

Out of scope:

- Vendor-specific verification tooling
- Marketing material
- Spec changes to AAE itself (those go to the IETF draft track)

## Vector requirements

Every contributed vector must:

1. Validate against the schema — `python3 tools/validate_schema.py` passes with
   no errors. The validator checks every file in `vectors/` against
   `schema/vector-schema.json` and that each filename ordinal matches the vector
   `id`.
2. Be reproducible byte-for-byte — running `python3 tools/build_vectors.py`
   leaves `vectors/` unchanged (CI fails if a fresh rebuild differs from the
   committed files).
3. Use signed JWS compact serialization with the committed test keys under
   `testkeys/` (see the "Test keys" section of `README.md`). Cross-spec
   contributions may use ephemeral signing if the signing method is documented
   in the contribution's own README.
4. Pass the reference verifier — `python3 examples/python-verify.py` reports the
   vector as passing, i.e. the verifier produces the vector's `expected.result`
   (`ACCEPT` or `REJECT`) and, for rejections, the expected
   `expected.verification_step` (and documented `rejection_reason`).
5. Carry the required metadata — the schema-mandated fields `id`, `name`,
   `description`, `section_ref`, `input`, `expected`, and `rationale`, all
   populated.

## Cross-spec contributions

For specs other than AAE (APS, x402, action_ref, etc.):

- File under `interop/<spec-name>/` (one directory per external spec)
- Include a `README.md` or `CONFORMANCE.md` in the subdirectory documenting:
  spec assumptions, format differences from AAE-native vectors, signing
  conventions, any documented divergences in algorithmic outcomes
- Cross-reference the contribution in the top-level `README.md` under "External
  conformance suites"
- Use the same vector schema — cross-spec contributions test AAE-side behavior,
  so they must be encoded in AAE's signed-JWS format even when the source spec
  uses a different envelope

## PR process

1. Branch from `main`
2. Local validation:
   ```
   python3 tools/validate_schema.py
   python3 examples/python-verify.py
   python3 tools/build_vectors.py && git diff --quiet -- vectors/
   ```
3. Open PR against `main`
4. CI must pass (schema-validate + verifier 15/15 + byte-identical rebuild check)
5. Reviewer: @MoltyCel
6. Squash-merge is default

## Communication

Discussion of design decisions happens in the relevant issue (open one before
opening a large PR if the change is non-trivial). For questions about AAE
itself, the IETF draft (draft-kroehl-agentic-trust-aae-00) is the authoritative
reference.

## License

All contributions are licensed under Apache-2.0, matching the repository
LICENSE.
