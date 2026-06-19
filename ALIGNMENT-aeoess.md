# ALIGNMENT — aeoess/aps-conformance-suite ↔ AAE

Cross-validation of four APS delegation scenarios against the AAE reference
vectors, performed by @aeoess on 2026-06-19 and documented in their repo at
`interop/aae-envelope/` (canonical `V1`–`V4`, a one-time cross-encoding under
`moltycel-format/`, and the writeup in `ALIGNMENT-moltycel.md`).

This document mirrors that work from the AAE side. APS's `V1`–`V4` remain the
source of truth on their side; the cross-encoding into the AAE signed-JWS vector
format is a one-time artifact, not a maintained parallel set.

## Scenario mapping

| aeoess APS scenario (`V1`–`V4`) | AAE vector | Algorithm step | Outcome | Reject cause |
|---|---|---|---|---|
| narrowing-valid (`V1`)    | `06-delegation-valid-depth-2`      | step 9                   | ACCEPT | —                              |
| widened-scope (`V2`)      | `07-delegation-action-superset`    | step 9                   | REJECT | `delegated_actions_not_subset` |
| expired-parent (`V3`)     | `02-expired-not-after`             | step 3 (§2.4 `not_after`)| REJECT | `expired_not_after`            |
| revoked-parent (`V4`)     | `11-delegation-cascade-revocation` | step 9                   | REJECT | `ancestor_revoked`             |

All four scenarios produced aligned outcomes against the AAE reference verifier
(`examples/python-verify.py`) with the committed test keys. ACCEPT/REJECT and the
rejection causes match in every row.

> **Step-number nuance (not a disagreement).** AAE vector `02-expired-not-after`
> rejects at **step 3** because the *presented root* AAE is itself expired,
> whereas aeoess `V3` (and its cross-encoding) rejects at **step 9
> `expired_not_after`** because the *parent* is expired while the presented child
> is still current — a cascade. Same expiry outcome; the step differs only by
> where the expired credential sits in the chain. Both sides apply the cascade
> **at check time** (AAE §5 step 9 runs the validity/revocation check against each
> ancestor); neither defers to a later lookup.

## Documented differences

### 1. Envelope format

AAE spec: signed JWS compact serialization (EdDSA), with signing keys resolved
from DID documents (`testkeys/did-documents/`) and a per-step signing-authority
check (§5 step 1).

aeoess test fixtures: unsigned AAE-shape JSON (`{"chain":[parent,child]}`); their
`verify.ts` adapter signs internally with ephemeral keys, and the cross-encoding
under `moltycel-format/` re-signs the four scenarios against the committed AAE
public test keys at verify-time.

Both produce the same algorithmic outcomes. The unsigned fixture format is a
legitimate test-side simplification for cross-stack interop without re-signing
infrastructure.

### 2. Cascade revocation strength

AAE §6.5 specifies cascade revocation as **SHOULD** (the AAE reference verifier
implements that SHOULD as a step-9 reject).

aeoess **enforces** it as MUST — the verifier rejects the chain whenever an
ancestor is revoked or expired; it is not optional.

Same algorithmic outcome on the four scenarios. Logged for the **AAE -01
revision**: an independent running implementation exceeding the spec floor is a
signal the floor should rise (candidate to promote §6.5 SHOULD → MUST).

### 3. Constraint-monotonicity coverage

AAE conformance vectors `08-delegation-constraint-relaxation` (cap-relaxing) and
`15-currency-mismatch-delegation` (currency-change) cover constraint-monotonicity
violations. aeoess's four current APS scenarios exercise only action-narrowing,
expiry, and revocation, so the cross-encoded files carry empty `constraints`.

Open coordination point: an APS-shaped parallel would close the gap on the APS
side. The AAE-envelope path already exercised can serve as the canonical
encoding for such a vector — either repo can host it.

## Reference

- A2A #1716 thread (chain-envelope discussion):
  https://github.com/a2aproject/A2A/issues/1716
- aeoess artifact:
  https://github.com/aeoess/aps-conformance-suite/tree/main/interop/aae-envelope
- aeoess writeup (`ALIGNMENT-moltycel.md`):
  https://github.com/aeoess/aps-conformance-suite/blob/main/interop/aae-envelope/ALIGNMENT-moltycel.md
- AAE draft (IETF Datatracker):
  https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/
