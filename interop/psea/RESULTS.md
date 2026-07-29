# Results — PSEA / AAE composition set

Recorded run of the six composition vectors, the negative controls behind
them, and the integrity pins a reviewer needs to reproduce both.

Run date: 2026-07-29. Vector set status: **proposed** (WHO-join unconfirmed).

Results are reported as seven staged rows rather than a single composition
verdict. See [CONFORMANCE.md](CONFORMANCE.md) for the row set, the evaluation
order, and the collapse to a coarser three-way view.

## Environment

    python        3.9.6
    cryptography  49.0.0
    jsonschema    4.25.1
    jcs           0.2.1        (RFC 8785; the library the MolTrust production
                                implementation uses in app/signature.py)

CI runs the same steps on Python 3.11 with `cryptography` and `jsonschema` from
`pip install`, plus `jcs` for the interop rebuild.

## Integrity pins

| Artifact | SHA-256 |
|---|---|
| `psea-fixture-v0.json` (counterpart side, byte-for-byte as published) | `f7d89f4df629d0b7318131ddfd8274c58ea96308c8aa557616baa4b88e60d188` |
| Join key (32 octets, both profiles) | `d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606` |
| `E1-principal-A` secured_aae (over the JWS ASCII octets) | `c2db119de3f04a775a7c11afd1b78a6d6e03780ad84fc09f76ccb2ccac7c2b9b` |
| `E2-unresolved` secured_aae (over the JWS ASCII octets) | `ed6fa37887e350298de43042ffd0f6438bb9088b0491ae0024e7b0fe40a069ca` |

Fixture source: `yuthent/psea-spec`, `conformance/interop-aae/psea-fixture-v0.json`,
default branch `main`. The committed copy here matches that file's own
`psea-fixture-v0.sha256` and the value published in its README.

## WHAT-join recomputation

Recomputed on the AAE side from the fixture's `action_payload_cleartext`, with
the RFC 8785 library named above. Nothing was re-derived from the fixture's
recorded values.

    payload      {"operation":"transfer","target":"iban:CH9300762011623852957",
                  "amount_minor":250000,"currency":"CHF","sequence":1}

    JCS UTF-8    {"amount_minor":250000,"currency":"CHF","operation":"transfer",
                  "sequence":1,"target":"iban:CH9300762011623852957"}
    length       114 octets
    matches the fixture's recorded action_payload_jcs_utf8 byte-for-byte : yes

    SHA-256 (AAE side)   d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606
    SHA-256 (fixture)    d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606
    lengths              32 / 32 octets
    32-octet comparison  MATCH

Same digest, three encodings, all decoding to those 32 octets:

    base64url no padding   1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY   (AAE wire form)
    base64 padded          1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ/dzqPyWCuWaxgY=  (PSEA wire form)
    hex                    d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606

Integers-only check on the payload, both parsed and lexical: `amount_minor` and
`sequence` are integers; no float, decimal fraction, or exponent literal.

## Native verification of the counterpart artifacts

ES256 against the enrolled JWKs the fixture publishes, at a timestamp inside the
token `iat`/`exp` window (1785312000 to 1785315600 = 2026-07-29T08:00:00Z to
09:00:00Z).

| Artifact | kid | ES256 | `psea_payload_hash` == join key | Fixture binding |
|---|---|---|---|---|
| PSEA-A | `psea-key-A` | verified | yes | `principal-A` |
| PSEA-B | `psea-key-B` | verified | yes | `principal-B` |

Both carry `psea_counter: 1` and the same `psea_payload_hash`. Their native
verdicts are the fixture's own (`VERIFIED`); this set consumes them rather than
restating them.

## Schema validation

    $ python3 tools/validate_interop_schema.py
    OK    interop/psea/vectors/xp-1-aligned-principal.json
    OK    interop/psea/vectors/xp-2-principal-divergence.json
    OK    interop/psea/vectors/xp-3-unresolved-binding.json
    OK    interop/psea/vectors/xp-5a-enrollment-pending.json
    OK    interop/psea/vectors/xp-5b-enrollment-complete.json
    OK    interop/psea/vectors/xp-6-alias-convergence.json

    6/6 composition vectors valid against schema

## Composition run

Comparison is row by row across all seven stages, not on a single field. Every
differing row is reported, not just the first.

    $ python3 examples/composition-verify.py
    stages: aae_native | action_linkage | principal_linkage | evidence_satisfaction | decision | admission | outcome

    PASS  xp-1-aligned-principal.json
            ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE
    PASS  xp-2-principal-divergence.json
            ACCEPT | EQUIVALENT | DIVERGENT(principal_divergence) | UNSATISFIED(principal_divergence) | REFUSED(principal_divergence) | NONE | NONE
    PASS  xp-3-unresolved-binding.json
            ACCEPT | EQUIVALENT | UNRESOLVED(unresolved_binding) | NOT_EVALUATED(unresolved_binding) | REFUSED(unresolved_binding) | NONE | NONE
    PASS  xp-5a-enrollment-pending.json
            ACCEPT | EQUIVALENT | UNRESOLVED(unresolved_binding) | NOT_EVALUATED(unresolved_binding) | REFUSED(unresolved_binding) | NONE | NONE
    PASS  xp-5b-enrollment-complete.json
            ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE
    PASS  xp-6-alias-convergence.json
            ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE

    6/6 composition vectors passed (row-by-row)

As a table:

| Vector | `aae_native` | `action_linkage` | `principal_linkage` | `evidence_satisfaction` | `decision` | `admission` | `outcome` |
|---|---|---|---|---|---|---|---|
| XP-1 | ACCEPT @7 | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE |
| XP-2 | ACCEPT @7 | EQUIVALENT | **DIVERGENT** | UNSATISFIED | REFUSED | NONE | NONE |
| XP-3 | ACCEPT @7 | EQUIVALENT | **UNRESOLVED** | NOT_EVALUATED | REFUSED | NONE | NONE |
| XP-5a | ACCEPT @7 | EQUIVALENT | **UNRESOLVED** | NOT_EVALUATED | REFUSED | NONE | NONE |
| XP-5b | ACCEPT @7 | EQUIVALENT | **SAME** | SATISFIED | AUTHORIZED | NONE | NONE |
| XP-6 | ACCEPT @7 | EQUIVALENT | **SAME** | SATISFIED | AUTHORIZED | NONE | NONE |

The first two rows are identical across all six vectors. Every native check
passes and every action digest joins; only the WHO-join separates them, which is
the property the set exists to demonstrate.

XP-5a and XP-5b are the same bytes twice. Recomputed from the committed files:

    secured_aae   sha256 c2db119de3f04a77…   identical in both
    PSEA-A token  sha256 785d5359c8deeaec…   identical in both
    aae_digest    sha-256:1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY   identical in both
    join_who.resolution_state   xp-5a: pending_enrollment   xp-5b: (omitted -> enrolled)
    join_who secondary table    xp-5a: [principal-B]        xp-5b: [principal-A, principal-B]

Nothing on the wire differs. The relying party's enrollment state is the only
variable, and the result moves from REFUSED to AUTHORIZED on it alone.

XP-6 carries a different envelope, and the difference is confined to one field:

    secured_aae   sha256 b13338ef2a6ff4ac…   (XP-1/5a/5b: c2db119de3f04a77…)
    principal_did did:web:example.com:principal-A-alias
    action_binding sha-256:1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY   identical
    PSEA-A token  sha256 785d5359c8deeaec…   identical
    aae table maps both principal-A and principal-A-alias to …:principal:A

Comparing `principal_did` against the enrollment label `principal-A` as strings
reports a mismatch. The resolution reports SAME.

XP-2 and XP-3 both read REFUSED at `decision`, and that is the point of reporting
rows rather than a verdict: they are told apart one row earlier, at
`principal_linkage`, and again at `evidence_satisfaction`. A conflict that was
observed and an input that was missing remain two different facts in the result.

Collapsed to the counterpart fixture's three-way view — `AUTHORIZED` from
decision AUTHORIZED, `REFUSE` from decision REFUSED with principal_linkage
DIVERGENT, `INDETERMINATE` from decision REFUSED with principal_linkage
UNRESOLVED — this reproduces its `expected_composition` labels exactly: XP-1
AUTHORIZED, XP-2 REFUSE, XP-3 INDETERMINATE.

Worth recording: run against the **unmodified** `examples/python-verify.py`,
both envelopes return `ACCEPT @ step 7`, including E2 with the unresolvable
principal. `grep principal examples/python-verify.py` returns nothing — the
Section 5 algorithm has no principal-resolution step. The difference between
XP-1, XP-2 and XP-3 is invisible to AAE alone, and symmetrically invisible to
PSEA alone. That is the gap.

## Negative controls

The six vectors alone would pass even if branches of the checker were dead:
all six reach `ACCEPT` and `EQUIVALENT` on the first two rows and differ only
from `principal_linkage` onward, so no vector ever produces `NOT_EQUIVALENT`,
`INDETERMINATE` or `REJECT`. The controls mutate one input at a time and pin the seven
rows that must follow. They run against in-memory copies; no committed vector is
modified. The baseline is committed at
[`negative-controls.json`](negative-controls.json) and CI runs it.

    $ python3 tools/run_negative_controls.py
    stages: aae_native | action_linkage | principal_linkage | evidence_satisfaction | decision | admission | outcome

    PASS  C1  One octet of the AAE-side digest flipped
            ACCEPT | NOT_EQUIVALENT(join_mismatch) | SAME | UNSATISFIED(evidence_covers_a_different_action) | REFUSED(join_mismatch) | NONE | NONE
    PASS  C2  XP-3's principal given a table entry resolving to a different principal
            ACCEPT | EQUIVALENT | DIVERGENT(principal_divergence) | UNSATISFIED(principal_divergence) | REFUSED(principal_divergence) | NONE | NONE
    PASS  C3  PSEA proof signature tampered
            ACCEPT | INDETERMINATE(secondary_unauthenticated) | UNRESOLVED(secondary_unauthenticated) | UNSATISFIED(invalid_signature) | REFUSED(secondary_native_reject) | NONE | NONE
    PASS  C4  Clock moved past the AAE not_after
            REJECT(expired_not_after) | INDETERMINATE(aae_not_admitted) | UNRESOLVED(aae_not_admitted) | NOT_EVALUATED(aae_not_admitted) | REFUSED(aae_native_reject) | NONE | NONE
    PASS  C5  Another instant inside both validity windows
            ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE

    5/5 negative controls passed (row-by-row)

Between them the controls reach every row value no vector produces:
`NOT_EQUIVALENT` and `INDETERMINATE` on `action_linkage`, `DIVERGENT` on
`principal_linkage`, `REJECT` on `aae_native`, and `UNSATISFIED` on
`evidence_satisfaction` from three different causes.

**C2 is the load-bearing one.** It takes XP-3 and adds a single table entry —
nothing else changes, same artifacts, same action digest — and the result moves
from `UNRESOLVED` / `NOT_EVALUATED` to `DIVERGENT` / `UNSATISFIED` while both
still read `REFUSED` at `decision`. Two conditions, two locations in the result,
one decision value. That is the separation a single verdict column cannot carry.

**C1 against C3** shows the two negative `action_linkage` values are not
interchangeable. C1 flips one octet: the two sides demonstrably mean different
actions, so `NOT_EQUIVALENT`. C3 breaks the signature: the artifact commits to
nothing that can be relied on, so `INDETERMINATE`. C1 also confirms the octet
comparison is real — a single flipped bit in one encoding is caught, which a
lenient string or prefix comparison would miss.

**C4** confirms the native rejection propagates without any downstream row
claiming a fact off a grant the verifier just refused. Each row below
`aae_native` reports its own not-established value rather than being omitted or
carried over.

## Native set unaffected

The 15 AAE-native vectors, their schema, and the reference verifier are
unchanged by this contribution.

    $ python3 tools/validate_schema.py
    15/15 vectors valid against schema

    $ python3 examples/python-verify.py
    15/15 vectors passed  (5 runtime, 10 structural)

    $ python3 tools/build_vectors.py && git diff --quiet -- vectors/
    vectors/ byte-identical after rebuild

    $ python3 tools/build_interop_psea.py
    interop/ byte-identical after rebuild

`schema/vector-schema.json` is untouched; the composition set is governed by the
separate `schema/interop-composition-vector-schema.json`. The
`delegator_aae_hash` rule — SHA-256 over the exact ASCII octets of a parent JWS,
JCS explicitly excluded — is untouched; the join key lives in a new additive
field, `mandate.action_binding`.

## What is not established

The WHO-join has been recomputed on one side only. Until the counterpart
implementation recomputes the resolution table and agrees to the canonical
space, these three verdicts are a proposal for discussion, not an agreed vector
set. The open items are listed at the end of [CONFORMANCE.md](CONFORMANCE.md).
