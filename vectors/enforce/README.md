# Enforce vectors

Vectors against the enforce kernel of `draft-kroehl-agentic-trust-aae-02`: grants with
`type_fields`, the closed constraint language, the verdict vocabulary, and ratification.
Governed by [`../../schema/enforce-vector-schema.json`](../../schema/enforce-vector-schema.json)
and validated by [`../../tools/validate_enforce_schema.py`](../../tools/validate_enforce_schema.py).

Empty for now: the schema lands ahead of the vectors that use it, so the two can be
reviewed apart.

## How an enforce vector differs from a native one

A native vector in [`../`](../) hands a verifier one JWS and asks for ACCEPT or REJECT at a
numbered step of the Section 5 algorithm. An enforce vector hands it a mandate and a
transaction — no JWS, no step number — and asks for PERMIT, DENY or PENDING **plus the core
digest**. The digest is the conformance target: two implementations agree only if they
reproduce the same 32 octets from the same input, and that holds only because the kernel
reads no clock, no database and no stored state.

Because the digest covers a domain tag, a vector states the tag it was built under
(`domain_tags`) and the kernel version that wrote it (`kernel_version`). A kernel on a
different tag computes different digests over identical input, so a vector that did not say
which one it assumed would be unfalsifiable.
