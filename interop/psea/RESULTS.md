# Results — PSEA / AAE composition set

Recorded run of the six composition vectors, the negative controls behind
them, and the integrity pins a reviewer needs to reproduce both.

Run date: 2026-07-29. Vector set status: **confirmed** — the WHO-join was confirmed at head `8bed788` by Mohamad Khalil-Yossif.

Results are reported as seven staged rows rather than a single composition
verdict. See [CONFORMANCE.md](CONFORMANCE.md) for the row set, the evaluation
order, and the collapse to a coarser three-way view.

## Result history

The digest of this file changes whenever the recorded run changes. A file cannot
contain its own digest, so every value in this table is a past one by
construction; the current value is whatever the file hashes to now.

| Vectors | Controls | Recorded at | Published |
|---|---|---|---|
| 6 | 9 | commit `662c93f` | AAE side re-performed by EMILIA Protocol at `e8c00e5` |
| 6 | 10 | this state — C10 added, uncommitted | — |

No vector or pre-existing control changed verdict or reason between the two
states. The suite grew; nothing in it moved.

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

    PASS  C1  One octet of the secondary-side digest flipped
            ACCEPT | NOT_EQUIVALENT(join_mismatch) | SAME | UNSATISFIED(evidence_covers_a_different_action) | REFUSED(join_mismatch) | NONE | NONE
    PASS  C2  XP-3's principal given a table entry resolving to a different principal
            ACCEPT | EQUIVALENT | DIVERGENT(principal_divergence) | UNSATISFIED(principal_divergence) | REFUSED(principal_divergence) | NONE | NONE
    PASS  C3  PSEA proof signature tampered
            ACCEPT | INDETERMINATE(secondary_unauthenticated) | UNRESOLVED(secondary_unauthenticated) | UNSATISFIED(invalid_signature) | REFUSED(secondary_native_reject) | NONE | NONE
    PASS  C4  Clock moved past the AAE not_after
            REJECT(expired_not_after) | INDETERMINATE(aae_not_admitted) | UNRESOLVED(aae_not_admitted) | NOT_EVALUATED(aae_not_admitted) | REFUSED(aae_native_reject) | NONE | NONE
    PASS  C5  Another instant inside both validity windows
            ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE
    PASS  C6  Declared aae_digest differs from the signed action_binding
            ACCEPT | INDETERMINATE(aae_binding_mismatch) | UNRESOLVED(action_linkage_unestablished) | NOT_EVALUATED(action_linkage_unestablished) | REFUSED(action_linkage_unestablished) | NONE | NONE
    PASS  C7  Signed envelope carries no action_binding
            ACCEPT | INDETERMINATE(aae_binding_absent) | UNRESOLVED(action_linkage_unestablished) | NOT_EVALUATED(action_linkage_unestablished) | REFUSED(action_linkage_unestablished) | NONE | NONE

    PASS  C8  Payload does not hash to the declared action digest
            ACCEPT | NOT_EQUIVALENT(payload_digest_mismatch) | SAME | UNSATISFIED(payload_digest_mismatch) | REFUSED(payload_digest_mismatch) | NONE | NONE
    PASS  C9  Payload leaves the I-JSON subset
            ACCEPT | INDETERMINATE(payload_not_i_json) | UNRESOLVED(action_linkage_unestablished) | NOT_EVALUATED(action_linkage_unestablished) | REFUSED(action_linkage_unestablished) | NONE | NONE

    PASS  C10  Token carries its own key material and claims an enrolled kid
            ACCEPT | INDETERMINATE(secondary_unauthenticated) | UNRESOLVED(secondary_unauthenticated) | UNSATISFIED(invalid_signature) | REFUSED(secondary_native_reject) | NONE | NONE

    10/10 negative controls passed (row-by-row)

Between them the controls reach every row value no vector produces:
`NOT_EQUIVALENT` on `action_linkage` and three distinct causes of `INDETERMINATE`
on it, `DIVERGENT` on `principal_linkage`, `REJECT` on `aae_native`, and
`UNSATISFIED` on `evidence_satisfaction` from three different causes.

**C6 and C7 anchor the WHAT-axis to signed bytes.** Before the envelope-binding
check existed, C6's flip produced `NOT_EQUIVALENT`, which reported a
vector-internal inconsistency as a disagreement between two profiles. C6 now
reads `aae_binding_mismatch` and C7, using the separately signed E4, reads
`aae_binding_absent`. C1 was retargeted from `aae_digest` to `secondary_digest`
for that reason: with the AAE side consistent with its envelope, the two joined
digests still differ and `NOT_EQUIVALENT` stays reachable.

**C2 is the load-bearing one.** It takes XP-3 and adds a single table entry —
nothing else changes, same artifacts, same action digest — and the result moves
from `UNRESOLVED` / `NOT_EVALUATED` to `DIVERGENT` / `UNSATISFIED` while both
still read `REFUSED` at `decision`. Two conditions, two locations in the result,
one decision value. That is the separation a single verdict column cannot carry.

**C1 against C3, C6 and C7** shows the negative `action_linkage` values are not
interchangeable. C1 flips one octet of the secondary declaration: the two sides
demonstrably mean different actions, so `NOT_EQUIVALENT`. C3 breaks the PSEA
signature, C6 desynchronizes the AAE declaration from its envelope, C7 removes
the envelope's commitment entirely — in all three nothing can be established
about which action is meant, so `INDETERMINATE`, with the reason naming which of
the three occurred. C1 also confirms the octet
comparison is real — a single flipped bit in one encoding is caught, which a
lenient string or prefix comparison would miss.

**C4** confirms the native rejection propagates without any downstream row
claiming a fact off a grant the verifier just refused. Each row below
`aae_native` reports its own not-established value rather than being omitted or
carried over.

## Confirmation status of the controls

Section 7 of draft-mih-sato-agent-accountability-composition-00 holds that a
vector freezes only after two independent implementations recompute it. The
controls are not all at the same point.

| Controls | Standing |
|---|---|
| C1 – C9 | Recomputed independently. The AAE side of the exchange was re-performed by EMILIA Protocol from the byte-pinned fixture, in JavaScript with its own RFC 8785 implementation, and the digest and native verdict agree. |
| **C10** | **New. Not yet recomputed by a second implementation.** The row below is this side's reading only. |

C10 carries `"status": "proposed - not yet recomputed by a second
implementation"` in `negative-controls.json`, so the distinction is in the data
rather than only in this file.

### C10 is a witness, and a weak one read alone

The control re-signs the PSEA token with `testkeys/psea-attacker-key.json` — a
key enrolled nowhere — embeds that key's public half in the payload as
`cnf.jwk`, and leaves the protected header's `kid` pointing at `psea-key-A`. A
verifier that took key material from the artifact would accept. This one
resolves `kid` against the fixture's `enrolled_keys` and never reads a key out
of the token, so the signature fails against the enrolled key.

The refusal is `invalid_signature`, which is the same code an ordinary broken
signature produces. There is no reason naming the embedded key, because the
checker never looks at it. **The evidence that the enrolled key was used is the
contrast with the unmutated run**, where the same token structure verifies:

    forged token   verify_psea_proof -> ok=False  detail='invalid_signature'
    unmutated      verify_psea_proof -> ok=True   detail='verified'

Read without that contrast, C10 is indistinguishable from C3. It is recorded as
a witness to existing behaviour, not as a check that was added; the resolution
path is unchanged.

Signing uses RFC 6979 deterministic ECDSA, so the forged token is byte-identical
on every run and a second implementation can recompute it:

    sha256(forged token)  306ae28f12b30fc1e34216c43a1e3389102b56a42f647942710e291e6dfda6e2

The attacker key is derivable rather than merely committed: its private scalar is
`sha256(b"aae-conformance-vectors/psea-attacker-key/v1")` reduced modulo the
P-256 group order, recorded in the key file. A reviewer can rebuild it without
trusting the committed bytes.

The class is not in Section 5.2 of the composition draft. It came from the
counterpart implementation's own row N16, resting on draft-yossif-psea-02
Section 6.3, "Enrollment Is the Root of Trust".

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
