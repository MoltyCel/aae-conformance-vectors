# Results — enforce vector set

Recorded run of the 26 enforce vectors and the cross-check that gives them their standing.

Run date: 2026-09-05. Vector set version: 1.4.0. Tracks
`draft-kroehl-agentic-trust-aae-02`, enforce kernel 3.0.

## What changed against 1.3.0

Nothing but the digests. Kernel 3.0 keeps `reason` out of both cores — the verdict core and
the ratification core — and out of every predicate entry inside them; a core trace entry
carries `predicate`, `field`, `value`, `bound` and `result`, and nothing else. `reason` is
still returned, still read, just not digested: free text whose wording two implementations do
not have to agree on has no place in a value they must hit byte for byte.

So all 26 expected core digests moved and `kernel_version` went 2.0 → 3.0 with them. No
vector was added or removed, no input changed, no verdict or status changed, and the domain
tags are the same `aae:…` family they were. Vectors 22 to 26 also carry new signatures and a
new `ratifies`, because the prior record they ratify is itself a core that lost its free
text. The v1.3.0 tag holds the pre-3.0 state.

## Why there are two implementations

The expected values in these vectors were produced by
[`examples/enforce-verify.py`](../../examples/enforce-verify.py), which implements the
enforce kernel from the draft text. A vector whose expected value comes only from the
implementation that will later be checked against it proves nothing — it restates itself.

So every vector was also run against a second implementation: the kernel behind
`POST https://api.moltrust.ch/enforce/check` and `/enforce/ratify`. That is separate code in
a separate repository, written against the same draft sections without reference to the
verifier here. The two agree on all 26 verdicts and, where a record is produced, on all 24
core digests byte for byte.

This is the same bar the WHAT-join in `interop/psea/` meets and the WHO-join does not: a
value recomputed by two implementations, not a value supplied by one and confirmed by
agreement.

## The run

    tools/validate_enforce_schema.py   26/26 enforce vectors valid
    examples/enforce-verify.py         26/26 enforce vectors passed
    cross-check vs deployed kernel     26/26 vectors reproduced

The cross-check runs the deployed kernel twice over: imported as a module, and called over
the wire at `POST /enforce/check` and `POST /enforce/ratify`. Both routes reproduce all 26.

Reproducibility: `tools/build_enforce_vectors.py` rewrites all 26 files byte for byte. The
ratification signatures use the committed `testkeys/issuer-test-key-1.json`, so nothing in
the set depends on a clock or a random source.

## Cross-check, vector by vector

| # | Vector | Outcome | Deployed kernel |
|---|---|---|---|
| 01 | Type form matches | PERMIT | reproduced |
| 02 | Instance value inside the action | DENY | reproduced |
| 03 | Type field missing from the action | DENY | reproduced |
| 04 | Action is a string | DENY | reproduced |
| 05 | Action is an array | DENY | reproduced |
| 06 | Action is a number | DENY | reproduced |
| 07 | Action is null | DENY | reproduced |
| 08 | Grant without `type_fields` | DENY | reproduced |
| 09 | `type_fields` without `verb` | DENY | reproduced |
| 10 | Duplicate name in `type_fields` | DENY | reproduced |
| 11 | `exact` holds | PERMIT | reproduced |
| 12 | `exact` fails on a vanity prefix | DENY | reproduced |
| 13 | `enum` holds | PERMIT | reproduced |
| 14 | `enum` fails | DENY | reproduced |
| 15 | `range` holds at the upper bound | PERMIT | reproduced |
| 16 | `range` fails one over the bound | DENY | reproduced |
| 17 | Unknown constraint type | DENY | reproduced |
| 18 | Field path with an empty segment | DENY | reproduced |
| 19 | Explicit hold | PENDING | reproduced |
| 20 | Unaddressed action is never pending | DENY | reproduced |
| 21 | `forbid` outranks an allowing grant | DENY | reproduced |
| 22 | Ratified by the issuing principal | RATIFIED | reproduced |
| 23 | Stranger with a valid signature | REJECTED | reproduced |
| 24 | A PERMIT is not ratifiable | RatifyError | HTTP 422 |
| 25 | Chain link pointing elsewhere | RatifyError | HTTP 422 |
| 26 | Chain link set to the ratified record | RATIFIED | reproduced |

Vectors 24 and 25 expect a caller error rather than a record: the guards raise instead of
producing a REJECTED core, because there is nothing to record when the question itself does
not line up. On the endpoint that surfaces as HTTP 422, which is what the cross-check
compares.

## Determinism

Every vector is a determinism vector. `examples/enforce-verify.py` evaluates each input
twice — once as committed, once with every object's keys in reverse order — and requires the
same core digest from both. An implementation that serialised in insertion order rather than
canonicalizing under RFC 8785 fails on the first vector rather than on some later one that
happens to expose it. The cross-check applies the same two evaluations to the deployed
kernel, so the property is shown on both implementations rather than asserted on one.

## `reason` is outside the digest

Shown rather than stated: on vectors 01 (PERMIT), 16 (DENY), 19 (PENDING) and 22 (RATIFIED)
the deployed kernel was made to write a different wording into every predicate entry, and the
core digest came out unchanged and equal to the value the vector expects. A kernel that still
digested the free text would have moved.

## What the set does not cover

- The relying-party side of revocation. It is deferred to a future draft revision and has no
  deployed implementation to check against.
- Anything from `interop/psea/`. The composition vectors use an untagged action digest, a
  different construction from the tagged one here; the two do not meet.
- The native 15. They exercise the Section 5 nine-step algorithm over a JWS, which the
  enforce kernel does not touch.
