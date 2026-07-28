# Results — PSEA / AAE composition set

Recorded run of the three composition vectors, the negative controls behind
them, and the integrity pins a reviewer needs to reproduce both.

Run date: 2026-07-28. Vector set status: **proposed** (WHO-join unconfirmed).

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

    3/3 composition vectors valid against schema

## Composition run

    $ python3 examples/composition-verify.py
    PASS  xp-1-aligned-principal.json             AUTHORIZED
    PASS  xp-2-principal-divergence.json          REFUSE / principal_divergence
    PASS  xp-3-unresolved-binding.json            INDETERMINATE / unresolved_binding

    3/3 composition vectors passed

Per-vector trace:

| Vector | 1 AAE native | 2 PSEA native | 3 WHAT-join | 4 WHO-join | Verdict |
|---|---|---|---|---|---|
| XP-1 | ACCEPT @ 7 | VERIFIED | 32 octets equal | `principal-A` → `:A` / `principal-A` → `:A` | AUTHORIZED |
| XP-2 | ACCEPT @ 7 | VERIFIED | 32 octets equal | `principal-A` → `:A` / `principal-B` → `:B` | REFUSE / `principal_divergence` |
| XP-3 | ACCEPT @ 7 | VERIFIED | 32 octets equal | `principal-unresolved` → no entry / `principal-A` → `:A` | INDETERMINATE / `unresolved_binding` |

Every native check passes in all three. Only the WHO-join separates them, which
is the property the set exists to demonstrate.

Worth recording: run against the **unmodified** `examples/python-verify.py`,
both envelopes return `ACCEPT @ step 7`, including E2 with the unresolvable
principal. `grep principal examples/python-verify.py` returns nothing — the
Section 5 algorithm has no principal-resolution step. The difference between
XP-1, XP-2 and XP-3 is invisible to AAE alone, and symmetrically invisible to
PSEA alone. That is the gap.

## Negative controls

The three vectors alone would pass even if some branches of the checker were
dead. These controls mutate one input at a time and confirm each branch is
reachable and lands where it should. They are run against in-memory copies; no
committed vector is modified.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| C1 | flip one octet of the AAE-side digest in XP-1 | INDETERMINATE / `join_mismatch` | INDETERMINATE / `join_mismatch` |
| C2 | add a table entry mapping XP-3's principal to canonical `:B` | REFUSE / `principal_divergence` | REFUSE / `principal_divergence` |
| C3 | tamper one character of the PSEA-A signature in XP-1 | REFUSE / `secondary_native_reject` | REFUSE / `secondary_native_reject` |
| C4 | move `current_time` in XP-1 past the AAE `not_after` | REFUSE / `aae_native_reject` | REFUSE / `aae_native_reject` |
| C5 | move `current_time` in XP-1 to another instant inside both windows | AUTHORIZED | AUTHORIZED |

C2 is the important one. It converts XP-3 from "unresolved" to "resolved and
divergent" by changing nothing but the table, and the verdict moves from
INDETERMINATE to REFUSE. The two outcomes are produced by different conditions,
not by one condition with two labels.

C1 also confirms the octet comparison is real: a single flipped bit in one
encoding is caught, which a lenient string or prefix comparison would miss.

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
