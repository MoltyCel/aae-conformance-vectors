# Enforce vectors

Vectors against the enforce kernel of `draft-kroehl-agentic-trust-aae-02`: grants with
`type_fields`, the closed constraint language, the verdict vocabulary, ratification, and
grant attenuation across a delegation hop.
Governed by [`../../schema/enforce-vector-schema.json`](../../schema/enforce-vector-schema.json)
and validated by [`../../tools/validate_enforce_schema.py`](../../tools/validate_enforce_schema.py).

## The set

| # | File | Section | Expected |
|---|---|---|---|
| 01 | `01-type-form-matches-permit.json` | 2.2.1/2.2.2 | PERMIT |
| 02–07 | instance value in the action, missing type field, four non-object actions | 2.2.2 | DENY |
| 08–10 | grant without `type_fields`, without `verb`, with a duplicate | 2.2.1 | DENY |
| 11–18 | `exact`, `enum`, `range` holding and failing, unknown type, empty path segment | 2.5 | PERMIT / DENY |
| 19–21 | explicit hold, unaddressed action, `forbid` outranks `allow` | 6.1 | PENDING / DENY |
| 22–26 | ratification and its three guards | 6.3/6.4 | RATIFIED / REJECTED / RatifyError |
| 27 | `27-grant-widened-at-hop-deny.json` | 5 step 9 | DENY |
| 28 | `28-grant-narrowed-at-hop-permit.json` | 5 step 9 | PERMIT |
| 29 | `29-purpose-enum-grant-widened-deny.json` | 5 step 9 | DENY |

Vectors 27–29 carry an `ancestors` input: the parent mandates of the presented mandate, root
first. Each hop is recorded as a `grant_attenuation` predicate whose `value` and `bound` are
the child and parent mandate digests, so the core binds the chain it was decided over. A hop
that widens a grant is DENY before any grant of the presented mandate is evaluated. Without
`ancestors` the trace gains nothing and the core is unchanged, which is why 01–26 keep their
digests.

Vector 29 narrows a purpose the way draft -02 already allows: as an `enum` constraint on a
transaction field. `mandate.purpose` is a free-text audit field and is not evaluated.

What the hop vectors do not cover: the JWS, signatures and depth rules of the chain. Those
stay with the Section 5 walk over signed envelopes, which a static input file cannot carry.

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
