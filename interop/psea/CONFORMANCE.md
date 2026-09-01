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

## The staged result

A composition result is eight rows, not one verdict. Each carries a value from
its own closed enum and an optional `reason` on the row that produced the
condition.

| Row | Values | What it establishes |
|---|---|---|
| `aae_native` | ACCEPT · REJECT | What the unmodified Section 5 algorithm returns for the AAE. |
| `action_linkage` | EQUIVALENT · NOT_EQUIVALENT · INDETERMINATE | Whether both artifacts demonstrably commit to the same action. |
| `principal_linkage` | SAME · DIVERGENT · UNRESOLVED | Whether both sides name the same principal, through the declared table. |
| `evidence_satisfaction` | SATISFIED · UNSATISFIED · NOT_EVALUATED | Whether the approval evidence satisfies the requirement for this action by this principal. |
| `freshness` | WELL_FORMED · CLAIMS_MALFORMED · NOT_EVALUATED | Whether the replay-defence claims the counterpart profile requires are present and well-formed. |
| `decision` | AUTHORIZED · REFUSED | The authorization decision, binary by construction. |
| `admission` | NONE · RESERVED · CONSUMED · DISPATCH_PENDING · INVOKED | What the relying party did with a consumable admission. |
| `outcome` | EXECUTED · FAILED · INDETERMINATE · NONE | What the executing system reported back. |

Uncertainty is never expressed at `decision`. It is expressed on the row that
carries it, and the enums do not share a token across rows that would let two
unlike uncertainties collapse:

- `action_linkage: INDETERMINATE` — the linkage could not be established.
- `outcome: INDETERMINATE` — what happened could not be established, the case
  where an admission was spent and the result is unknown.
- `principal_linkage: UNRESOLVED` — an identifier had no entry.

Three facts about three stages. A result format with one uncertainty token has
to pick one of them and lose the other two.

## Evaluation order

Four checks, fail-closed at each. Failing a check does not suppress the rows
below it: every row is reported, and a row a failure prevented from being
established says so with its own not-established value rather than being omitted
or guessed.

| Step | Check | On failure |
|---|---|---|
| 1 | AAE native, Section 5 steps 1-9 | `aae_native REJECT` → `action_linkage INDETERMINATE`, `principal_linkage UNRESOLVED`, `evidence_satisfaction NOT_EVALUATED`, `decision REFUSED` / `aae_native_reject` |
| 2 | Secondary artifact native (ES256 against the enrolled JWK, inside `iat`/`exp`, committing to the recorded digest) | `action_linkage INDETERMINATE`, `principal_linkage UNRESOLVED`, `evidence_satisfaction UNSATISFIED`, `decision REFUSED` / `secondary_native_reject` |
| 3 | WHAT-join: bind `join_what.aae_digest` to `mandate.action_binding` in the signed envelope, recompute it from `join_what.payload`, then compare 32 octets against `secondary_digest` | binding absent → `INDETERMINATE` / `aae_binding_absent`; binding differs → `INDETERMINATE` / `aae_binding_mismatch`; payload outside I-JSON → `INDETERMINATE` / `payload_not_i_json`; recomputed digest differs → `NOT_EQUIVALENT` / `payload_digest_mismatch`; digests equal → `EQUIVALENT`; different → `NOT_EQUIVALENT` / `join_mismatch`; undecodable → `INDETERMINATE` / `digest_undecodable` |
| 4 | WHO-join: resolve both identifiers through the declared table | see below |

Step 4:

| Resolution | `principal_linkage` | `evidence_satisfaction` | Reason |
|---|---|---|---|
| both resolve, same canonical principal | SAME | SATISFIED (if the action linkage holds) | — |
| both resolve, different canonical principals | DIVERGENT | UNSATISFIED | `principal_divergence` |
| at least one has no table entry | UNRESOLVED | NOT_EVALUATED | `unresolved_binding` |

`decision` is AUTHORIZED only when `aae_native` ACCEPT, `action_linkage`
EQUIVALENT, `principal_linkage` SAME, and `evidence_satisfaction` SATISFIED all
hold. Otherwise REFUSED.

Step 4 is computed independently of step 3. The principal identifiers do not
depend on which action the artifacts commit to, and a reader is owed both facts
rather than the first one that failed.

## Vector to section mapping

| Vector | `aae_native` | `action_linkage` | `principal_linkage` | `evidence_satisfaction` | `decision` | `admission` | `outcome` | AAE | PSEA |
|---|---|---|---|---|---|---|---|---|---|
| xp-1-aligned-principal | ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |
| xp-2-principal-divergence | ACCEPT | EQUIVALENT | DIVERGENT | UNSATISFIED | REFUSED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |
| xp-3-unresolved-binding | ACCEPT | EQUIVALENT | UNRESOLVED | NOT_EVALUATED | REFUSED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |
| xp-5a-enrollment-pending | ACCEPT | EQUIVALENT | UNRESOLVED | NOT_EVALUATED | REFUSED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |
| xp-5b-enrollment-complete | ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |
| xp-6-alias-convergence | ACCEPT | EQUIVALENT | SAME | SATISFIED | AUTHORIZED | NONE | NONE | §5 steps 1-7 | §2.5, §3.8 |

What each tests:

- **xp-1** — both natives pass, the digests join on 32 identical octets, both
  principals resolve to the same canonical principal. The only case where every
  upstream row establishes its fact positively.
- **xp-2** — both natives pass and both artifacts carry the same action digest,
  yet the two independent key-to-principal resolutions name different humans. A
  composition that ANDs the two native verdicts returns AUTHORIZED here and is
  wrong. The conflict is located at `principal_linkage`, one row above the
  refusal it causes.
- **xp-3** — one side's principal has no table entry. There is no resolution to
  compare.
- **xp-6** — two AAE-side identifiers that the enrolled table maps onto one
  canonical principal. A string comparison of `principal_did` against the PSEA
  enrollment label reports a mismatch; the resolution reports SAME. The static
  counterpart to the temporal case below.
- **xp-5a / xp-5b** — the same artifacts, twice, across a change in the relying
  party's own state. Both carry the same AAE envelope, the same PSEA-A proof and
  the same 32-octet digest; only `join_who.resolution_state` differs
  (`pending_enrollment` against the default `enrolled`). The pair isolates
  enrollment as the sole variable between a refusal and an authorization.

All six are `structural` in the derivation sense the native set uses: given the
documents, the declared resolution table, and the vector's `current_time`, every
row follows without live external state. That holds for xp-5a and xp-5b too: the
enrollment state each is evaluated in is declared in the vector, not looked up
live. That is orthogonal to enforcement
posture — a composition layer may run these in advisory mode and only log.

## Why the rows, and not a verdict

xp-2 and xp-3 both read REFUSED at `decision`. That is not a loss of
information, because `decision` is not the result — the eight rows are. They
separate at `principal_linkage` (DIVERGENT against UNRESOLVED) and again at
`evidence_satisfaction` (UNSATISFIED against NOT_EVALUATED).

xp-2 reports a conflict that was observed: two resolutions succeeded and
disagreed. xp-3 reports an input that was missing: one resolution did not succeed
at all.

xp-5a and xp-5b make the same argument over time rather than across inputs. The
two carry identical bytes — same envelope, same proof, same digest — and differ
only in the relying party's enrollment state. Collapsed to a single column the
transition reads `INDETERMINATE -> AUTHORIZED` and stops there. The rows say
which stage moved, `principal_linkage` from UNRESOLVED to SAME, and equally which
stages did not: `aae_native` and `action_linkage` are unchanged, so nothing about
the grant or the action was ever in question. A relying party can attribute the
first refusal to its own missing enrollment rather than to the agent, which a
verdict column cannot support. Under a single verdict column those two either share a token — and a
reviewer cannot tell which happened — or they are given different tokens and the
column starts encoding stage information without saying which stage. The rows say
which stage.

The schema enforces the split rather than leaving it to convention: a DIVERGENT
principal forces UNSATISFIED evidence and a REFUSED decision and requires a
reason on its own row; an UNRESOLVED principal may never read SATISFIED; an
AUTHORIZED decision requires all four upstream rows positive; a REFUSED decision
admits and executes nothing; and nothing executes without an admission.

## Boundaries of what each row establishes

### Canonicalization

`action_linkage: EQUIVALENT` holds for the pinned fixture, the mapping profile
declared in the vector, and the digest construction the vector names. RFC 8785
and jcs-n produce the same digest over these particular bytes because the action
payload contains no null-valued and no empty members. Introduce such a member and
the two canonicalizers diverge, and a vector built under one will fail against a
peer using the other. Nothing here establishes a general equivalence between PSEA
canonicalization and jcs-n.

The checker recomputes the digest rather than trusting the declaration. It
canonicalizes `join_what.payload` with RFC 8785 and hashes it, and the recomputed
octets have to equal the declared `aae_digest`. `jcs` is a hard import: a fallback
to `json.dumps(sort_keys=True)` would let the checker verify a digest under a
canonicalization other than the one it was built with, agreeing by accident on the
payloads where the two coincide.

Recomputation is gated to the I-JSON subset this exchange stays inside — integers
within the safe range, strings and member names over Unicode scalars, no cycles.
A payload outside it yields `INDETERMINATE` / `payload_not_i_json` rather than a
digest whose reproducibility across implementations is unknown. That gate mirrors
the counterpart implementation's `canonicalize()`; both accept and refuse the same
inputs on the eight cases checked, including non-integer numbers, unsafe integers
and lone surrogates.

The null-valued and empty-member caveat above is untouched by this. Both
implementations accept such members and agree on them; what diverges is RFC 8785
against jcs-n, and no vector here carries one. The recomputation proves the
digest for the payloads in this set, not the equivalence of two canonicalizers in
general.

The checker also tests that each side's declared digest is bound to a
signed artifact. `join_what.secondary_digest` has to match `psea_payload_hash`
inside the ES256-verified token, and `join_what.aae_digest` has to match
`mandate.action_binding.payload_digest` inside the envelope verified at step 1.
The WHAT-axis is anchored on both sides to bytes someone signed, which closes the
case where a vector declares a digest unrelated to the artifacts it ships:
`aae_binding_absent` and `aae_binding_mismatch` on `action_linkage` cover it, and
controls C6 and C7 exercise both.

The binding check runs before the recomputation. A declared digest matching
neither the envelope nor the payload is first of all not bound to the envelope,
and reporting it as a payload mismatch would name the second symptom of one
desynchronization. C6 and C8 separate the two.

### Principal identity

PSEA user verification proves that a human interacted with an enrolled
authenticator. The identity of that human is a separate matter: the binding from
an authenticator to a named person is deployment-specific and out of PSEA's
scope, per draft-yossif-enrollment-problem-00. `principal_linkage` consumes that
binding as a relying-party input, supplied here by the declared resolution table,
and reports only whether two resolutions agree.

The two sides name a principal in forms that do not convert into one another. AAE
carries `mandate.principal_did`, a DID resolvable through a DID document.
draft-yossif-psea defines no principal identifier form at all: its per-proof
subject commitment (Section 3.8) is audit attribution, and a verifier makes no
authorization decision on it. What the `kid` binds to is a deployment-issued
enrollment label the profile does not specify. Neither form is derivable from the
other, and neither specification defines the correspondence.

The resolution table bridges that by declaration. It is **supplied, not
derived** — data handed to the checker, not an inference either document
supports. The DID form used here is this side's choice. The counterpart profile
has the same shape elsewhere: Section 3.13.4 states that the expected `psea_op`
and `psea_tier` values are "deployment-defined and agreed out of band", which is
the same kind of binding, agreed the same way.

The confirmation of the table is therefore a confirmation that the correspondence
is the intended one, not that it follows from anything. Mohamad Khalil-Yossif,
confirming at head `8bed788`, put the limit in the confirmation itself: it
"confirms the resolution mapping at head 8bed788 and establishes WHO linkage. It
does not establish PSEA conformance, and it does not establish that the
kid-to-principal mapping is derivable from anything either specification defines
- it is supplied."

Two states of this repository record the axis differently, and both are correct.
The exchange fixture under `fixtures/aae-psea-proof-exchange-v1/` preserves the
state at commit `e8c00e5`, where WHO was proposed; it is a frozen record pinned
by hash in an independent re-performance, and its `PROPOSED` markers are
deliberately left standing. The live vector set carries the axis forward from
`8bed788`. A frozen record and a live set disagreeing about a status is the
expected result of pinning one and continuing the other.

The row is independent of `action_linkage` and of `evidence_satisfaction` by
construction, which xp-6 and the xp-5 pair demonstrate from two directions. In
xp-6 two AAE labels resolve to one canonical principal while a string comparison
of the identifiers would report a mismatch. In xp-5a and xp-5b one identifier
resolves differently at two times, with the artifacts unchanged. Both cases leave
`action_linkage` at EQUIVALENT throughout.

### Freshness

draft-yossif-psea Section 3.11 anchors replay defence in three places: the
monotonic `psea_counter` for ordering, the global uniqueness of `jti` so an action
finalizes once, and an OPTIONAL `eat_nonce` binding a proof to a challenge the
verifier issued. Section 3.5 makes the first two REQUIRED claims.

The freshness stage establishes claim well-formedness only: `psea_counter` is an
integer at or above zero and `jti` is a non-empty string, read from the token this
checker has already authenticated. `psea_counter` is checked first, as the
ordering anchor whose absence leaves the sequence undefined, and `jti` second as
the uniqueness key; the order is fixed so two implementations name the same
failure on a token that breaks both.

The token also carries `iat` and `exp`. Those are checked during native
verification and stay out of this row on purpose. Temporal validity of the
authorization is the AAE VALIDITY axis, checked at Section 5 step 3, and putting a
second window on this row would place one fact in two places. `eat_nonce` is
optional, applies only when a verifier issued a challenge, and is absent from this
set's tokens; it is not checked here.

Cross-presentation replay and counter monotonicity are outside this row.
Establishing that a counter advanced or that a `jti` was not already spent is
state across presentations, not a property of the token in hand. It belongs to a
separate step that a relying party can verify independently, and this set does not
carry it.

Section 5.2 of the composition draft requires a verifier to keep signature
validation, digest recomputation, quorum evaluation and freshness as separate
results, and forbids collapsing them into one opaque boolean. This row is that
separation for the part a single presentation can support. In the counterpart's
terms the row sits in the status-freshness family — the `not_after` side of the
question — rather than condition liveness.

### Admission and replay

An approval bound to an exact action bounds the action, not the effects that
follow from it. Custody over those effects lives on the `admission` row, and a
proof that verifies natively can still be refused there: its `jti` may be spent,
or its counter may have rolled back. The counterpart profile's counter and `jti`
commitment precedes any admission a gate grants, so a gate that admits before
consulting it grants custody it cannot revoke.

`admission` therefore stays a row of its own rather than a consequence of
`decision`. A refusal grounded in a spent admission reports CONSUMED on that row
with `already_consumed` as its reason, and `outcome` stays NONE because this
decision executed nothing.

### Outcome

AAE acceptance describes an authorization. PSEA verification describes an
approval. Neither is evidence that an external effect occurred. `EXECUTED`,
`FAILED` and `INDETERMINATE` require a later record from the system of record or
from an independent observer, and a composition layer that infers any of them
from its own decision is reporting its intent as an outcome.

## Rows this set does not reach

`admission` beyond NONE and `outcome` beyond NONE are schema-valid and unreached.
No vector and no negative control in this set produces CONSUMED, RESERVED,
INVOKED, DISPATCH_PENDING, EXECUTED or FAILED. The reference checker decides and
stops: `examples/composition-verify.py` emits NONE for both rows unconditionally.

Those two rows are the gate and custody side of the composition, and they belong
to the counterpart profile's scope as much as to this one. Their values are a
proposal to be negotiated, not a tested target, and an implementer should read
them as reserved rather than conformant.

`xp-4` is deliberately unused: the case it was to carry collapses into xp-1
(Iman, 2026-07-29).

## Crosswalk

The rows are a framework-neutral spine. A coarser result is a collapse of them,
not a different model:

    AUTHORIZED     <- decision AUTHORIZED
    REFUSE         <- decision REFUSED and principal_linkage DIVERGENT
    INDETERMINATE  <- decision REFUSED and principal_linkage UNRESOLVED
                      or action_linkage INDETERMINATE

Applied to this set that reproduces the counterpart fixture's three-way
`expected_composition` labels exactly — XP-1 AUTHORIZED, XP-2 REFUSE, XP-3
INDETERMINATE. The collapse runs one way: the rows determine the label, the label
does not determine the rows.

Profiles with their own stage vocabulary (EMILIA's CAID / AEC / AEB, PSEA and
WEXP stages) are expected to map onto the same rows. Those mappings have not been
supplied by their authors and this set does not assert one on their behalf. The
rule for mapping is: name the stage in your profile that establishes the same
fact, and if no row carries a fact your profile distinguishes, raise it as a gap
in the spine rather than overloading an existing row.

## Reference implementation

`examples/composition-verify.py` implements the four steps above. It imports
`examples/python-verify.py` unmodified for step 1 and does not reimplement
Section 5. It performs real ES256 verification for step 2 against the enrolled
JWKs the counterpart fixture publishes.

### The counterpart verifier is no longer a single implementation

The PSEA verification decisions this set consumes were, until recently, one
author's reading of his own draft. Songbo Bu has since cross-run an independent
PSEA verifier against psea-spec commit `c0b3c385`, covering the 13 REQUIRED claim
checks, header policy, enrolled-key resolution, action binding, freshness, replay
and user-verification anchoring. The verdict distribution matches the reference,
with no verifier disagreement across the 31 scenarios. The archive digest
reported for that run is
`37385e5f0b61f2ed105192072906743f481569180ba6f06d43801f686a5b4cbb`.

Its scope, stated by its author: an independent implementation cross-run over the
supplied suite, not conformance, not endorsement.

The commit is verified to exist in `yuthent/psea-spec`. The archive digest is
recorded as reported and has not been recomputed here.

## Reference implementation, this side

Result on this set: **6/6**, compared row by row rather than on a single field.
The eleven negative controls in `negative-controls.json` reach the row values no
vector produces — two distinct causes of `NOT_EQUIVALENT` on `action_linkage`
(`join_mismatch`, `payload_digest_mismatch`), four of `INDETERMINATE` on it
(`secondary_unauthenticated`, `aae_binding_mismatch`, `aae_binding_absent`,
`payload_not_i_json`), `REJECT` on `aae_native`, and `DIVERGENT` from the same
inputs that otherwise yield `UNRESOLVED` — and pass 11/11. None of them has been
recomputed by a second implementation; see [RESULTS.md](RESULTS.md). Vectors and controls are complementary: the
vectors cover what a relying party legitimately encounters, the controls cover
the branches nothing legitimate reaches. See [RESULTS.md](RESULTS.md) for both
runs and the integrity pins.

## Status of the two axes

| Axis | Recomputed by | Status |
|---|---|---|
| WHAT-join (JCS digest) | PSEA side (`conformance/src/jcs.py`, per its README) and AAE side (RFC 8785 library, this set) | **confirmed** — 32 octets identical |
| WHO-join (principal resolution) | AAE side, confirmed by the counterpart profile | **confirmed** — at head `8bed788` by Mohamad Khalil-Yossif |

Per Section 7 of draft-mih-sato-agent-accountability-composition-00, a vector
freezes only after two independent implementations recompute it. The WHAT-join
meets that bar. The WHO-join now meets it differently: the counterpart profile
confirmed the resolution mapping rather than recomputing it, because the mapping
is supplied rather than derived and there is nothing to recompute. All six vectors
carry `"status": "confirmed"`. This set is still not a conformance claim — the
confirmation establishes WHO linkage and explicitly does not establish PSEA
conformance.

## Open items for the counterpart side

1. **Confirm or amend the resolution table, including its states.** The canonical
   space `urn:interop:aae-psea:principal` and the two mappings in
   `principal-resolution.json` are this side's proposal, as is the `states` map
   that models a relying party partway through enrollment (`secondary_omits`).
   xp-5a/xp-5b turn the enrollment gap of draft-yossif-enrollment-problem-00 into
   a state transition, so whether enrollment state belongs in a conformance
   vector at all is part of what needs agreeing. The AAE-side DID form
   (`did:web:example.com:principal-A`) is a choice, not something the counterpart
   fixture fixes — it binds `kid`s to bare labels.
2. **Confirm the unit convention.** `amount_minor` as integer minor units on the
   payload, and `max_transaction_value.value` in the same unit on the AAE side.
3. **Confirm the reason vocabulary.** Stage values are a closed enum; reasons are
   deliberately open, so every token below is this side's naming rather than
   something the drafts fix. The counterpart implementation has said that a second
   implementation disagreeing on a refusal code indicates an ambiguity in the
   specification rather than an error, which needs the full list to act on.

   | Reason | Rows it appears on | Produced by | Standing |
   |---|---|---|---|
   | `principal_divergence` | principal_linkage, evidence_satisfaction, decision | xp-2, C2 | interpretation — the WHO comparison this set proposes |
   | `unresolved_binding` | principal_linkage | xp-3, xp-5a | interpretation — absence of a table entry |
   | `aae_binding_absent` | action_linkage | C7 | interpretation — see below |
   | `aae_binding_mismatch` | action_linkage | C6 | interpretation — see below |
   | `payload_digest_mismatch` | action_linkage, evidence_satisfaction, decision | C8 | recomputation disagrees with the declaration |
   | `payload_not_i_json` | action_linkage | C9 | interpretation — see below |
   | `join_mismatch` | action_linkage, decision | C1 | the two declared digests differ on the octets |
   | `evidence_covers_a_different_action` | evidence_satisfaction | C1 | consequence of `join_mismatch` |
   | `expired_not_after` | aae_native | C4 | propagated verbatim from the AAE Section 5 verifier |
   | `invalid_signature` | evidence_satisfaction | C3, C10 | native PSEA signature failure |
   | `secondary_unauthenticated` | action_linkage, principal_linkage | C3, C10 | an unauthenticated artifact commits to nothing |
   | `secondary_native_reject` | decision | C3, C10 | propagation: a native check failed |
   | `aae_native_reject` | decision | C4 | propagation: a native check failed |
   | `aae_not_admitted` | action_linkage, principal_linkage, evidence_satisfaction | C4 | propagation: the grant was refused |
   | `action_linkage_unestablished` | principal_linkage, evidence_satisfaction, decision | C6, C7, C9 | propagation: the linkage was not established |

   Four of these carry a judgement worth disagreeing with:

   - `aae_binding_absent` and `aae_binding_mismatch` sit on `action_linkage` as
     INDETERMINATE, not NOT_EQUIVALENT. An envelope that does not commit to the
     declared digest establishes nothing about which action it authorizes, which
     this side reads as a different fact from two sides meaning different actions.
     The corresponding class is `NOT_REPRESENTABLE` against the counterpart
     profile, since its digest is a claim inside the signed payload; on the AAE
     side it is constructible, so the naming is ours alone.
   - `payload_not_i_json` treats a payload outside the I-JSON subset as
     unestablished rather than as a mismatch, because a digest whose
     reproducibility across implementations is unknown is not evidence of
     disagreement. The counterpart raises `PAYLOAD_NON_CONFORMING` for the same
     inputs, from its canonicalizer rather than its verifier, before any digest is
     computed, on any payload outside the integers-only subset of
     draft-yossif-psea Section 2.5. The two map onto each other cleanly: both
     report the linkage as unestablished rather than as a mismatch. A decimal value
     is rejected on the counterpart side before any join is attempted, which
     matters because a payload reaching the join would read as a composition
     failure instead of a payload defect.
   - `principal_divergence` and `unresolved_binding` are the two values that
     separate the WHO axis at all, and they depend on the table in item 1.
     Confirming the table without confirming these leaves the axis half-agreed.

4. **The secondary declaration is unexercised against its artifact.**
   `join_what.aae_digest` is checked against `mandate.action_binding` in the signed
   envelope; `join_what.secondary_digest` has no equivalent check against
   `psea_payload_hash` in the token. The asymmetry is deliberate rather than
   overlooked. Binding both sides would leave `NOT_EQUIVALENT` unreachable, because
   the fixture supplies one token committing to one digest, and every declaration
   pinned to its signed source would then agree by construction. C1 reaches
   `NOT_EQUIVALENT` only because the secondary declaration is free to diverge.

   This is recorded as unexercised, not as covered. The counterpart suite carries
   five rows as not-representable for the same class of reason — a construct the
   profile does not define cannot be tested against it — and this row belongs to
   the same category rather than to a list of passes.

   Exercising it later needs a second action payload, which changes the digest
   without touching key material. A second token would not serve: it would change
   what is signed, and the point is to vary the action while the signer stays
   fixed.

   An earlier revision of item 3 claimed no vector exercises these reasons.
   That was written when the set had three vectors and five controls, and it is
   no longer true: xp-2, xp-3 and xp-5a produce `principal_divergence` and
   `unresolved_binding` directly. The propagation reasons in the last four rows
   are still control-only.
