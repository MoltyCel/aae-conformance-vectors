# PSEA / AAE composition vectors

Three vectors that pair one AAE with one PSEA proof over the same action and
state what the composition of the two should return.

Counterpart profile: [draft-yossif-psea-02](https://github.com/yuthent/psea-spec),
whose side of the cross-run is `conformance/interop-aae/psea-fixture-v0.json`.
That file is committed here byte-for-byte as
[`psea-fixture-v0.json`](psea-fixture-v0.json), pinned at

    sha256  f7d89f4df629d0b7318131ddfd8274c58ea96308c8aa557616baa4b88e60d188

`tools/build_interop_psea.py` refuses to run if the pin fails, and
`tools/validate_interop_schema.py` re-checks every vector's `source.sha256`
against the committed file.

## Status

**Proposed. Not a conformance claim, and not frozen.** Section 7 of
draft-mih-sato-agent-accountability-composition-00 holds that a vector freezes
only after two independent implementations recompute it. Of the two join axes
below, one has been recomputed on both sides and one has not:

| Axis | What it joins | Status |
|---|---|---|
| **WHAT** | both profiles commit to the same action | **confirmed** — recomputed independently, 32 octets identical |
| **WHO** | both profiles name the same principal | **proposed** — awaiting confirmation from the PSEA side |

Every vector here carries `"status": "proposed"` for that reason, and the
validator fails any vector that claims otherwise while its `join_who` block is
still marked as a proposal.

## Axis 1 — the WHAT-join (confirmed)

    join key = SHA-256( JCS(RFC 8785) canonical form of the action payload )

Recomputed on the AAE side from the counterpart fixture's own
`action_payload_cleartext`, with the same RFC 8785 library the MolTrust
production implementation uses:

| | Value |
|---|---|
| JCS UTF-8 (114 octets) | `{"amount_minor":250000,"currency":"CHF","operation":"transfer","sequence":1,"target":"iban:CH9300762011623852957"}` |
| Octets (hex) | `d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606` |
| AAE wire form (base64url, no padding) | `sha-256:1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ_dzqPyWCuWaxgY` |
| PSEA wire form (base64, padded) | `1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ/dzqPyWCuWaxgY=` |

The canonical form matches the fixture's recorded `action_payload_jcs_utf8`
byte-for-byte, and the digest matches its `octets_hex` on all 32 octets.

**Compare the octets, never the strings.** The same 32 octets appear above in
two different encodings; a string comparison across them reports a mismatch on
identical data. Every digest in these vectors declares its encoding
(`base64url-nopad`, `base64-pad`, or `hex`) and its decoded length, and both the
checker and the validator decode before comparing.

On the AAE side the digest travels in a new, additive field,
`mandate.action_binding`. It does not disturb `delegator_aae_hash`: that rule
hashes the exact ASCII octets of a parent JWS with JCS explicitly excluded
(draft Section 3), and it is untouched. Two hashes over two different things.

### Integers only

draft-yossif-psea-02 Section 2.5 restricts the action payload to integers — no
floating-point numbers, no decimal fractions, no exponent notation. The amount
travels as `"amount_minor": 250000`, integer minor units, not `2500.00`. A peer
that puts a JSON float in the payload falls outside the canonicalization
guarantee and the join key will not reproduce.

The constraint is pinned twice, because one check is not enough. The schema
types every value in `join_what.payload` as integer-or-string-or-boolean. That
catches a parsed float but not a lexical one: JSON Schema never sees whether the
source wrote `250000` or `250000.00`. So `tools/validate_interop_schema.py`
re-parses the raw file bytes with a Decimal hook and fails on any non-integer
numeric literal.

### The amount adapter

The AAE Section 5 constraint evaluator reads `action_context.amount` and
`action_context.currency`. The shared payload names the amount `amount_minor`.
The vectors carry the rename explicitly:

    amount_minor  ->  amount        (integer value unchanged)
    currency      ->  currency

This is a rename, not a conversion. The value stays in **integer minor units**
on both sides, and the AAE constraint threshold is expressed in the same unit:
`max_transaction_value.value = 500000` is 5 000.00 CHF, against an action of
`250000` = 2 500.00 CHF. The native vector set leaves the unit of
`max_transaction_value.value` open; this set pins it, because a join key that
agrees while the units disagree would authorize the wrong amount.

## Axis 2 — the WHO-join (proposed, pending confirmation)

Neither profile fixes a shared principal identifier space. AAE names a principal
with a DID in `mandate.principal_did`. PSEA binds a `kid` to a deployment-issued
label. Both resolutions succeed on their own side, and nothing in either draft
requires them to agree — or even to be comparable.

[`principal-resolution.json`](principal-resolution.json) is the declared mapping
of both identifier forms onto one canonical space:

| Side | Source identifier | Canonical principal |
|---|---|---|
| AAE | `did:web:example.com:principal-A` | `urn:interop:aae-psea:principal:A` |
| AAE | `did:web:example.com:principal-B` | `urn:interop:aae-psea:principal:B` |
| PSEA | enrollment binding `principal-A` | `urn:interop:aae-psea:principal:A` |
| PSEA | enrollment binding `principal-B` | `urn:interop:aae-psea:principal:B` |

The `kid` to label hop is not restated here — it comes from the counterpart
fixture's own `enrollment_bindings`, and the vectors copy it rather than derive
it.

Two properties of the table matter:

**It is data, not inference.** A checker looks identifiers up; it never guesses
a principal from the shape of a DID or a kid. `did:web:example.com:principal-A`
and the label `principal-A` resolve to the same canonical principal because the
table says so, not because they look alike.

**An identifier with no entry is unresolved.** `did:web:example.com:principal-unresolved`
is deliberately absent. Absence is a missing input, not a conflict — it yields
INDETERMINATE, never REFUSE.

The table is the part awaiting confirmation. Until the PSEA side agrees to it,
the WHO-join is a proposal, and XP-1 through XP-3 are proposals with it.

## The three vectors

| ID | AAE grant principal | PSEA artifact | Composition | Reason |
|---|---|---|---|---|
| [XP-1](vectors/xp-1-aligned-principal.json) | `principal-A` | PSEA-A (`principal-A`) | **AUTHORIZED** | — |
| [XP-2](vectors/xp-2-principal-divergence.json) | `principal-A` | PSEA-B (`principal-B`) | **REFUSE** | `principal_divergence` |
| [XP-3](vectors/xp-3-unresolved-binding.json) | unresolved | PSEA-A (`principal-A`) | **INDETERMINATE** | `unresolved_binding` |

In all three, both artifacts verify natively and both carry the same action
digest. Every single-profile check passes in every case. What differs is only
the WHO-join.

**XP-1** — one human both mandated and approved.

**XP-2** — the case neither native vector set carries. A relying party accepting
a standing grant plus a per-action proof performs two independent
key-to-principal resolutions. Both succeed. They name different humans. A
composition that checks "grant valid?" and "proof valid?" and ANDs the answers
returns AUTHORIZED here, which is wrong.

**XP-3** — INDETERMINATE, not REFUSE, and the distinction is the point. The
binding is not established on one side, so there is nothing to compare.
Collapsing XP-2 and XP-3 into one outcome loses the difference between a
conflict that was observed and an input that was missing, and a reviewer cannot
recover it from the result.

## The two AAE envelopes

Both are signed with the committed test keys under `../../testkeys/`, using the
same EdDSA / `cty: aae+json` conventions as the native set. No new keys.

| File | Signed by | `mandate.principal_did` | Used by |
|---|---|---|---|
| [`aae-envelopes/E1-principal-A.json`](aae-envelopes/E1-principal-A.json) | `did:web:example.com:agent-a` | `did:web:example.com:principal-A` | XP-1, XP-2 |
| [`aae-envelopes/E2-unresolved.json`](aae-envelopes/E2-unresolved.json) | `did:web:example.com:agent-b` | `did:web:example.com:principal-unresolved` | XP-3 |

Both grant `["transfer", "payment.execute"]` over a validity window matching the
PSEA context's `iat`/`exp` (2026-07-29T08:00:00Z to 09:00:00Z), and both carry
the same `mandate.action_binding` digest.

The PSEA proofs are embedded exactly as the counterpart fixture published them —
not re-encoded, not re-signed, not normalized.

## Running

```
pip install cryptography jsonschema
python3 tools/validate_interop_schema.py     # 3/3 valid against the schema
python3 examples/composition-verify.py       # 3/3 composition vectors passed
python3 tools/build_interop_psea.py          # rebuild; output must be byte-identical
```

`examples/composition-verify.py` calls the unmodified
`examples/python-verify.py` for the AAE side. The Section 5 algorithm is not
reimplemented, and the native reference verifier is not edited.

Order of operations, fail-closed throughout:

1. AAE native (Section 5) — must ACCEPT, else the rejection propagates.
2. PSEA proof native — ES256 against the enrolled JWK the fixture publishes for
   the `kid`, inside the token's own `iat`/`exp` window, committing to the
   digest the vector records. Must verify, else the failure propagates.
3. WHAT-join — decode both digests, compare 32 octets. No match →
   INDETERMINATE(`join_mismatch`), stop.
4. WHO-join — resolve both identifiers through the table. One unresolved →
   INDETERMINATE(`unresolved_binding`). Both resolved and equal → AUTHORIZED.
   Both resolved and different → REFUSE(`principal_divergence`).

## What this set does not establish

PSEA's native verdict for PSEA-B in XP-2 is VERIFIED, and that is correct — it
is a valid PSEA proof. PSEA does not claim to identify a named human. The
divergence in XP-2 is not a PSEA verification failure and not an AAE
verification failure; it is a composition-layer failure that neither profile
detects alone. Nothing here should be read as either profile closing the
enrollment gap described in draft-yossif-enrollment-problem-00. It appears in
this set twice, in two different shapes.
