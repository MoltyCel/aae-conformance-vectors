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

A composition result is seven rows, not one verdict. Each carries a value from
its own closed enum and an optional `reason` on the row that produced the
condition.

| Row | Values | What it establishes |
|---|---|---|
| `aae_native` | ACCEPT · REJECT | What the unmodified Section 5 algorithm returns for the AAE. |
| `action_linkage` | EQUIVALENT · NOT_EQUIVALENT · INDETERMINATE | Whether both artifacts demonstrably commit to the same action. |
| `principal_linkage` | SAME · DIVERGENT · UNRESOLVED | Whether both sides name the same principal, through the declared table. |
| `evidence_satisfaction` | SATISFIED · UNSATISFIED · NOT_EVALUATED | Whether the approval evidence satisfies the requirement for this action by this principal. |
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
| 3 | WHAT-join: decode both digests, compare 32 octets | equal → `EQUIVALENT`; different → `NOT_EQUIVALENT` / `join_mismatch`; undecodable → `INDETERMINATE` |
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

All three are `structural` in the derivation sense the native set uses: given the
documents, the declared resolution table, and the vector's `current_time`, every
row follows without live external state. That is orthogonal to enforcement
posture — a composition layer may run these in advisory mode and only log.

## Why the rows, and not a verdict

xp-2 and xp-3 both read REFUSED at `decision`. That is not a loss of
information, because `decision` is not the result — the seven rows are. They
separate at `principal_linkage` (DIVERGENT against UNRESOLVED) and again at
`evidence_satisfaction` (UNSATISFIED against NOT_EVALUATED).

xp-2 reports a conflict that was observed: two resolutions succeeded and
disagreed. xp-3 reports an input that was missing: one resolution did not succeed
at all. Under a single verdict column those two either share a token — and a
reviewer cannot tell which happened — or they are given different tokens and the
column starts encoding stage information without saying which stage. The rows say
which stage.

The schema enforces the split rather than leaving it to convention: a DIVERGENT
principal forces UNSATISFIED evidence and a REFUSED decision and requires a
reason on its own row; an UNRESOLVED principal may never read SATISFIED; an
AUTHORIZED decision requires all four upstream rows positive; a REFUSED decision
admits and executes nothing; and nothing executes without an admission.

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

Result on this set: **3/3**, compared row by row rather than on a single field.
The five negative controls in `negative-controls.json` reach the row values the
three vectors do not — `NOT_EQUIVALENT`, `INDETERMINATE`, `REJECT`, and
`DIVERGENT` from the same inputs that otherwise yield `UNRESOLVED` — and pass
5/5. See [RESULTS.md](RESULTS.md) for both runs and the integrity pins.

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
