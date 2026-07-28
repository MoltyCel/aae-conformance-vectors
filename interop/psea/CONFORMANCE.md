# Conformance — PSEA / AAE composition set

Maps each composition vector to the sections it exercises on both sides, and
records what a conforming composition layer has to reproduce.

- AAE: [draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/)
- PSEA: draft-yossif-psea-02, [yuthent/psea-spec](https://github.com/yuthent/psea-spec)
- Composition framing: draft-mih-sato-agent-accountability-composition-00
- Enrollment gap: draft-yossif-enrollment-problem-00

## Scope

The native 15-vector set answers "is this AAE valid for this action?". The PSEA
suite answers "is this proof a valid approval of this action?". Neither answers
"did the same human both mandate the action and approve it?" — that question
only exists once two artifacts are on the table.

This set tests that third question. It does not restate either profile's native
verdict; it consumes them.

## The composition algorithm

Four checks in order, fail-closed at each.

| Step | Check | On failure |
|---|---|---|
| 1 | AAE native, Section 5 steps 1-9 | propagate: REFUSE / `aae_native_reject` |
| 2 | Secondary artifact native (ES256 against the enrolled JWK, inside `iat`/`exp`, committing to the recorded digest) | propagate: REFUSE / `secondary_native_reject` |
| 3 | WHAT-join: decode both digests, compare 32 octets | INDETERMINATE / `join_mismatch` |
| 4 | WHO-join: resolve both identifiers through the declared table | see below |

Step 4 has three outcomes:

| Resolution | Verdict | Reason |
|---|---|---|
| at least one identifier has no table entry | INDETERMINATE | `unresolved_binding` |
| both resolve, same canonical principal | AUTHORIZED | — |
| both resolve, different canonical principals | REFUSE | `principal_divergence` |

Steps 1 and 2 run before either join. A composition verdict is only meaningful
over two artifacts that are individually valid; if one is not, the composition
layer never ran and its rejection is what gets reported.

## Vector to section mapping

| Vector | Verdict | Reason | AAE sections | PSEA sections | What it tests |
|---|---|---|---|---|---|
| xp-1-aligned-principal | AUTHORIZED | — | §5 steps 1-7 | §2.5, §3.8 | Both natives pass, digests join on 32 identical octets, both principals resolve to the same canonical principal. The only case where every gate is satisfied. |
| xp-2-principal-divergence | REFUSE | `principal_divergence` | §5 steps 1-7 | §2.5, §3.8 | Both natives pass and both artifacts carry the same action digest, yet the two independent key-to-principal resolutions name different humans. A composition that ANDs the two native verdicts returns AUTHORIZED here and is wrong. |
| xp-3-unresolved-binding | INDETERMINATE | `unresolved_binding` | §5 steps 1-7 | §2.5, §3.8 | One side's principal has no entry in the resolution table. There is no resolution to compare, so the composition cannot decide. |

All three are `structural` in the derivation sense the native set uses: given the
documents, the declared resolution table, and the vector's `current_time`, the
verdict follows without live external state. That is orthogonal to enforcement
posture — a composition layer may run these in advisory mode and only log.

## Why XP-2 and XP-3 must stay distinguishable

XP-2 reports a conflict that was observed: two resolutions succeeded and
disagreed. XP-3 reports an input that was missing: one resolution did not
succeed at all.

An implementation that returns REFUSE for both is not more conservative in any
useful sense. It claims to have seen a conflict it never saw, and a reviewer
reading the result cannot tell which of the two happened. The schema enforces
the split: `principal_divergence` is only valid under REFUSE, `unresolved_binding`
only under INDETERMINATE, and the two enums do not overlap.

## What a conforming implementation must reproduce

1. All three composition verdicts, with the matching `reason`.
2. The WHAT-join by **octet** comparison. The two digests in every vector are
   carried in different encodings — base64url without padding on the AAE side,
   padded standard base64 on the PSEA side. An implementation comparing encoded
   strings fails all three vectors on identical data.
3. The integers-only property of the action payload. An implementation that
   accepts a float in the payload, or that reserializes the payload through a
   float-capable path before hashing, will not reproduce the join key.
4. The unit convention: `amount_minor` and `max_transaction_value.value` are
   both integer minor units. The rename to `action_context.amount` carries the
   value unchanged.
5. The resolution table as **data**. An implementation that infers a principal
   from the lexical shape of a DID or a `kid` passes XP-1 by accident and gives
   the wrong answer on XP-3.

## Reference implementation

`examples/composition-verify.py` implements the four steps above. It imports
`examples/python-verify.py` unmodified for step 1 and does not reimplement
Section 5. It performs real ES256 verification for step 2 against the enrolled
JWKs the counterpart fixture publishes.

Result on this set: **3/3**. See [RESULTS.md](RESULTS.md) for the run, the
negative controls, and the integrity pins.

## Status of the two axes

| Axis | Recomputed by | Status |
|---|---|---|
| WHAT-join (JCS digest) | PSEA side (`conformance/src/jcs.py`, per its README) and AAE side (RFC 8785 library, this set) | **confirmed** — 32 octets identical |
| WHO-join (principal resolution) | AAE side only | **proposed** — awaiting PSEA-side confirmation |

Per Section 7 of draft-mih-sato-agent-accountability-composition-00, a vector
freezes only after two independent implementations recompute it. The WHAT-join
meets that bar. The WHO-join does not yet, so all three vectors carry
`"status": "proposed"` and this set is not a conformance claim.

## Open items for the counterpart side

1. **Confirm or amend the resolution table.** The canonical space
   `urn:interop:aae-psea:principal` and the two mappings in
   `principal-resolution.json` are this side's proposal. The AAE-side DID form
   (`did:web:example.com:principal-A`) is a choice, not something the counterpart
   fixture fixes — it binds `kid`s to bare labels.
2. **Confirm the unit convention.** `amount_minor` as integer minor units on the
   payload, and `max_transaction_value.value` in the same unit on the AAE side.
3. **Confirm the propagation reasons.** `aae_native_reject` and
   `secondary_native_reject` are this side's encoding of "a native check failed,
   so the composition never ran". No vector in this set exercises them; the
   negative controls in RESULTS.md do.
