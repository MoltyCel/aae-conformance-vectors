# PSEA / AAE composition vectors

Six vectors that pair one AAE with one PSEA proof over the same action and state
what the composition of the two should return. Three are single snapshots of
different inputs. Two are the same inputs before and after the relying party
enrolls a binding. One has two AAE identifiers resolving to a single principal.

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
| **WHO** | both profiles name the same principal | **confirmed** — at head `8bed788` by Mohamad Khalil-Yossif; supplied, not derived |

Every vector here carries `"status": "confirmed"`. The validator fails any vector
that claims confirmed while its `join_who` block is still marked as a proposal, so
the two cannot drift apart.

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

## Axis 2 — the WHO-join (confirmed, supplied not derived)

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
| AAE | `did:web:example.com:principal-A-alias` | `urn:interop:aae-psea:principal:A` |

The last row is a second AAE identifier for the same canonical principal, which
XP-6 exercises: the mapping is many-to-one, so a checker that compares
identifiers as strings gets a different answer from one that resolves them.

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
`principal_linkage: UNRESOLVED`, never `DIVERGENT`.

**The table has enrollment states.** `principal_resolution` is the fully
enrolled table. `states` names the relying-party states a vector may be
evaluated in, each derived from it by omitting the secondary entries not
enrolled yet (`secondary_omits`). A vector names its state in
`join_who.resolution_state`; omitting the field means the default `enrolled`
state. The derivation is data in this file, never a literal in the builder, so
the vectors cannot drift from it. XP-5a is the only vector in a non-default
state.

All six vectors carry the full enrolled AAE table, including the alias entry, so
adding an identifier to it changes every vector's embedded copy. That is the
intended cost of a single source: the table is a property of the deployment, not
of one vector.

The table was the part awaiting confirmation. Mohamad Khalil-Yossif confirmed it
at head `8bed788`, with the limit stated in the confirmation itself: it
establishes WHO linkage, does not establish PSEA conformance, and does not
establish that the kid-to-principal mapping is derivable from anything either
specification defines — it is supplied. See CONFORMANCE.md for the full
asymmetry.

## The staged result

A composition result is **eight rows, not one verdict**. Each row carries a value
from its own closed enum and an optional `reason` that locates the condition on
the row that produced it.

| Row | Values |
|---|---|
| `aae_native` | `ACCEPT` · `REJECT` |
| `action_linkage` | `EQUIVALENT` · `NOT_EQUIVALENT` · `INDETERMINATE` |
| `principal_linkage` | `SAME` · `DIVERGENT` · `UNRESOLVED` |
| `evidence_satisfaction` | `SATISFIED` · `UNSATISFIED` · `NOT_EVALUATED` |
| `decision` | `AUTHORIZED` · `REFUSED` |
| `admission` | `NONE` · `RESERVED` · `CONSUMED` · `DISPATCH_PENDING` · `INVOKED` |
| `outcome` | `EXECUTED` · `FAILED` · `INDETERMINATE` · `NONE` |

A single verdict column has to render a divergence and a missing binding with the
same token, and a reader cannot recover which happened. Here both end `REFUSED`
at `decision` and are told apart one row earlier.

The enums also keep unlike uncertainties apart by construction. `INDETERMINATE`
on `action_linkage` means the linkage could not be established. `INDETERMINATE`
on `outcome` means what happened could not be established — the case where an
admission was spent and the result is unknown. `UNRESOLVED` on
`principal_linkage` means an identifier had no entry. Three different facts,
three different rows, no shared token to confuse them.

Every row is always reported. A row that a failure upstream prevented from being
established says so with its own not-established value; it is never omitted, and
never carried over from a run that did not happen.

`decision` is `AUTHORIZED` only when `aae_native` is `ACCEPT`, `action_linkage`
is `EQUIVALENT`, `principal_linkage` is `SAME`, and `evidence_satisfaction` is
`SATISFIED`. The schema enforces that, and enforces the propagation rules: a
divergence forces `UNSATISFIED` and `REFUSED`; an unresolved principal may never
read `SATISFIED`; a refusal admits and executes nothing; nothing executes without
an admission.

`admission` and `outcome` are `NONE` throughout this set. The reference checker
decides but never admits or executes. They are in the row set so a profile that
does act can report it in the same shape — and so that a spent admission with an
unknown result has a row of its own rather than being forced into the decision
column.

## The six vectors

| ID | AAE grant | PSEA artifact | `aae_native` | `action_linkage` | `principal_linkage` | `evidence_satisfaction` | `decision` | `admission` | `outcome` |
|---|---|---|---|---|---|---|---|---|---|
| [XP-1](vectors/xp-1-aligned-principal.json) | `principal-A` | PSEA-A (`principal-A`) | ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE |
| [XP-2](vectors/xp-2-principal-divergence.json) | `principal-A` | PSEA-B (`principal-B`) | ACCEPT | EQUIVALENT | **DIVERGENT** | UNSATISFIED | REFUSED | NONE | NONE |
| [XP-3](vectors/xp-3-unresolved-binding.json) | unresolved | PSEA-A (`principal-A`) | ACCEPT | EQUIVALENT | **UNRESOLVED** | NOT_EVALUATED | REFUSED | NONE | NONE |
| [XP-5a](vectors/xp-5a-enrollment-pending.json) | `principal-A` | PSEA-A (`principal-A`) | ACCEPT | EQUIVALENT | **UNRESOLVED** | NOT_EVALUATED | REFUSED | NONE | NONE |
| [XP-5b](vectors/xp-5b-enrollment-complete.json) | `principal-A` | PSEA-A (`principal-A`) | ACCEPT | EQUIVALENT | **SAME** | SATISFIED | AUTHORIZED | NONE | NONE |
| [XP-6](vectors/xp-6-alias-convergence.json) | `principal-A-alias` | PSEA-A (`principal-A`) | ACCEPT | EQUIVALENT | **SAME** | SATISFIED | AUTHORIZED | NONE | NONE |

XP-2 carries `reason: principal_divergence` on `principal_linkage`; XP-3 and
XP-5a carry `reason: unresolved_binding` on the same row.

In all six, both artifacts verify natively and both carry the same action
digest. Every single-profile check passes in every case, and the first two rows
are identical across all six. What differs is only the WHO-join.

**XP-1** — one human both mandated and approved.

**XP-2** — the case neither native vector set carries. A relying party accepting
a standing grant plus a per-action proof performs two independent
key-to-principal resolutions. Both succeed. They name different humans. A
composition that checks "grant valid?" and "proof valid?" and ANDs the answers
returns AUTHORIZED here, which is wrong.

**XP-3** — the binding is not established on one side, so there is nothing to
compare. XP-2 and XP-3 both end `REFUSED`, which is exactly why the decision row
is not the whole result: they separate at `principal_linkage`
(DIVERGENT / UNRESOLVED) and again at `evidence_satisfaction`
(UNSATISFIED / NOT_EVALUATED). A conflict that was observed and an input that was
missing stay two different facts.

**XP-5a and XP-5b** — the same question over time. The two vectors carry the
*same bytes*: identical AAE envelope (`c2db119d…`), identical PSEA-A proof
(`785d5359…`), identical 32-octet action digest. Nothing on the wire differs.
What differs is the relying party's own enrollment state, declared as data in
`principal-resolution.json` and named on the vector as
`join_who.resolution_state`. In `pending_enrollment` the signer key bound to
`principal-A` is not enrolled yet, so the secondary side has no resolution and
the result is REFUSED. In the default `enrolled` state it resolves and the same
artifacts are AUTHORIZED.

That pair is what a single-snapshot vector cannot show. Under a collapsed
verdict the transition reads `INDETERMINATE → AUTHORIZED` and stops there. The
rows say *which* stage moved — `principal_linkage` UNRESOLVED to SAME, carrying
`evidence_satisfaction` with it — and, just as importantly, which stages did
not: `aae_native` and `action_linkage` are unchanged, so nothing about the grant
or the action was ever in question. A refusal that a reviewer can attribute to
the relying party's own missing enrollment, rather than to the agent, is the
practical payoff of reporting stages.

It is also the first artifact in this set that exercises the enrollment gap of
draft-yossif-enrollment-problem-00 as a state transition instead of naming it.

**XP-6** — the same independence, held from the other side. The AAE grant names
`did:web:example.com:principal-A-alias`, a second identifier the enrolled table
maps onto the canonical principal `urn:interop:aae-psea:principal:A`. Comparing
`principal_did` against the PSEA enrollment label as strings reports a mismatch.
The resolution reports SAME, because the table decides and a checker consults it
rather than pattern-matching identifiers. XP-5 shows one identifier resolving
differently at two times; XP-6 shows two identifiers resolving identically at one
time. `action_linkage` stays EQUIVALENT in both.

## Crosswalk — the rows are framework-neutral

The eight rows are a spine, not a proprietary result format. They are chosen so
that a profile with its own stage vocabulary maps onto them without renaming its
concepts, and so that a profile with a coarser result can be expressed as a
collapse of them rather than a translation.

| Consumer | Relationship to the rows |
|---|---|
| This set | Reports all eight directly. |
| **Mohamad's three-way result** (`AUTHORIZED` / `REFUSE` / `INDETERMINATE`) | A **collapsed view**, not a different model. See the collapse below. |
| **EMILIA** (CAID / AEC / AEB) | Maps its own stage names onto these rows. |
| **PSEA / WEXP** | Map their own stages onto these rows. |

The collapse for the three-way view is exact and mechanical:

    AUTHORIZED     <- decision AUTHORIZED
    REFUSE         <- decision REFUSED and principal_linkage DIVERGENT
    INDETERMINATE  <- decision REFUSED and principal_linkage UNRESOLVED
                      or action_linkage INDETERMINATE

Applied to this set it reproduces the earlier three-way labels exactly: XP-1
AUTHORIZED, XP-2 REFUSE, XP-3 INDETERMINATE. The collapse is lossy in one
direction only — the rows determine the three-way label, the label does not
determine the rows. That is the whole reason for the change: `REFUSE` alone
cannot say whether the conflict was in the action, the principal, or the
evidence, and `INDETERMINATE` alone cannot say whether the linkage or the
execution was the unknown.

**The EMILIA and PSEA/WEXP rows above state an intent, not a confirmed mapping.**
Neither mapping has been supplied by its authors, and this set does not assert
one on their behalf. What is offered is the row set and the rule for mapping onto
it: name the stage in your profile that establishes the same fact, and if no row
carries a fact your profile distinguishes, that is a gap in the spine worth
raising rather than a value to overload onto an existing row.

The `principal_linkage` values are **confirmed** in the sense the join_who table
is: the counterpart profile agreed the correspondence at head `8bed788`, which is
agreement on a supplied mapping rather than a recomputation. The `action_linkage`
values are **confirmed** in the stronger sense — they come from the 32-octet join,
recomputed independently on both sides.

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
pip install cryptography jsonschema jcs
python3 tools/validate_interop_schema.py     # 6/6 valid against the schema
python3 examples/composition-verify.py       # 6/6 passed, row by row
python3 tools/run_negative_controls.py       # 11/11 passed, row by row
python3 tools/build_interop_psea.py          # rebuild; output must be byte-identical
```

`examples/composition-verify.py` calls the unmodified
`examples/python-verify.py` for the AAE side. The Section 5 algorithm is not
reimplemented, and the native reference verifier is not edited.

Evaluation order, fail-closed throughout. Failing a step does not suppress the
rows below it — each is reported with its own not-established value:

1. **AAE native** (Section 5). `REJECT` → nothing downstream is admitted:
   `action_linkage INDETERMINATE`, `principal_linkage UNRESOLVED`,
   `evidence_satisfaction NOT_EVALUATED`, `decision REFUSED`.
2. **PSEA proof native** — ES256 against the enrolled JWK the fixture publishes
   for the `kid`, inside the token's own `iat`/`exp` window, committing to the
   digest the vector records. A failure leaves the artifact's commitments
   untrusted: `action_linkage INDETERMINATE`, `principal_linkage UNRESOLVED`
   (its `kid` claim is unauthenticated), `evidence_satisfaction UNSATISFIED`
   (the evidence definitively does not hold), `decision REFUSED`.
3. **WHAT-join** — decode both digests, compare 32 octets. Equal →
   `EQUIVALENT`; different → `NOT_EQUIVALENT`; undecodable → `INDETERMINATE`.
4. **WHO-join** — resolve both identifiers through the table. Both resolve and
   are equal → `SAME`; both resolve and differ → `DIVERGENT`; either has no
   entry → `UNRESOLVED`.

Step 4 is computed independently of step 3: the principal identifiers do not
depend on which action the artifacts commit to, and a reader is owed both facts.

### Negative controls

The six vectors alone cannot show the checker's branches are live — all six
reach `ACCEPT` and `EQUIVALENT` on the first two rows and differ only from
`principal_linkage` onward, so `NOT_EQUIVALENT`, `INDETERMINATE` and `REJECT`
are never produced by any of them.
[`negative-controls.json`](negative-controls.json) pins eleven controls. Each
changes one input of a committed vector and asserts the eight rows that must
follow; C7 substitutes a committed, separately signed envelope rather than
patching one. `tools/run_negative_controls.py` runs them, and CI runs it too.

| # | Mutation | Reaches |
|---|---|---|
| C1 | one octet of the secondary-side digest flipped | `action_linkage NOT_EQUIVALENT` |
| C2 | XP-3's principal given a table entry resolving to a different principal | `principal_linkage DIVERGENT` from the inputs that otherwise yield `UNRESOLVED` |
| C3 | PSEA proof signature tampered | `action_linkage INDETERMINATE`, distinct from C1's `NOT_EQUIVALENT` |
| C4 | clock moved past the AAE `not_after` | `aae_native REJECT` and clean propagation |
| C5 | another instant inside both windows | `AUTHORIZED` — the positive control |
| C6 | declared `aae_digest` differs from the signed `action_binding` | `action_linkage INDETERMINATE` / `aae_binding_mismatch` |
| C7 | signed envelope (E4) carries no `action_binding` | `action_linkage INDETERMINATE` / `aae_binding_absent` |
| C8 | payload changed, declared digest and envelope left in step | `action_linkage NOT_EQUIVALENT` / `payload_digest_mismatch` |
| C9 | non-integer number in the payload | `action_linkage INDETERMINATE` / `payload_not_i_json` |
| C10 | token re-signed with a non-enrolled key that it also embeds | `evidence_satisfaction UNSATISFIED` / `invalid_signature` — a witness to the enrolled-key path, see RESULTS.md |

C2 is the load-bearing one: same artifacts, same digest, one added table entry,
and the result moves from `UNRESOLVED`/`NOT_EVALUATED` to
`DIVERGENT`/`UNSATISFIED` while both still read `REFUSED` at `decision`. Two
conditions, two locations, one decision value.

## What this set does not establish

PSEA's native verdict for PSEA-B in XP-2 is VERIFIED, and that is correct — it
is a valid PSEA proof. PSEA does not claim to identify a named human. The
divergence in XP-2 is not a PSEA verification failure and not an AAE
verification failure; it is a composition-layer failure that neither profile
detects alone. Nothing here should be read as either profile closing the
enrollment gap described in draft-yossif-enrollment-problem-00. It appears in
this set twice, in two different shapes.
