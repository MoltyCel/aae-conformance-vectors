# Conformance

This document maps each vector to the draft section it exercises and records the
conformance status of known AAE implementations.

Spec: [draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/)
(content identical to the internal `-04` working revision).

## Verification algorithm (Section 5)

A relying party runs nine checks in order. Steps 1-7 are required; steps 8-9 are
conditional on the presence of `validity.revocation_check` and
`mandate.delegation` respectively.

1. Signature verification and signing authority
2. Payload, schema, and `cty` validation
3. Temporal validity (`not_before` / `not_after`)
4. Subject binding (challenge-response under `credentialSubject.id`)
5. Single-use check
6. Action check (requested action in `mandate.actions`)
7. Constraint evaluation
8. Revocation check (conditional)
9. Delegation chain verification (conditional)

The `verification_step` field in each vector records the step at which a
rejection occurs, or the last step reached for an acceptance.

## Vector to section mapping

| Vector | Result | Step | Section | What it tests |
|--------|--------|------|---------|---------------|
| 01-valid-root-aae | ACCEPT | 7 | §5 steps 1-7 | A correctly formed root AAE inside its validity window is accepted. |
| 02-expired-not-after | REJECT | 3 | §2.4, §5.3 | Current time after `not_after` is rejected. |
| 03-too-early-not-before | REJECT | 3 | §2.4, §5.3 | Current time before `not_before` (and `validFrom`) is rejected. |
| 04-revocation-endpoint-5xx | REJECT | 8 | §2.4, §5.8 | A revocation endpoint returning HTTP 503 leaves status indeterminate; the verifier fails closed. |
| 05-single-use-replay | REJECT | 5 | §2.4, §5.5 | A `single_use:true` AAE whose id was already recorded is rejected on replay. |
| 06-delegation-valid-depth-2 | ACCEPT | 9 | §3, §5.9 | A depth-2 chain with subset actions, monotonic caps, and valid depths is accepted. |
| 07-delegation-action-superset | REJECT | 9 | §3, §5.9 | A delegated AAE granting an action absent from its parent is rejected. |
| 08-delegation-constraint-relaxation | REJECT | 9 | §3, §5.9 | A delegated `max_transaction_value` above the parent cap is rejected. |
| 09-delegation-depth-exceeded | REJECT | 9 | §3, §5.9 | `delegation.depth` greater than `delegation.max_depth` is rejected. |
| 10-delegation-cycle-detection | REJECT | 9 | §5.9 | An AAE id appearing twice in the verification path is rejected as a cycle. |
| 11-delegation-cascade-revocation | REJECT | 9 | §6.5, §5.9 | A revoked ancestor invalidates its descendants. |
| 12-signing-authority-mismatch | REJECT | 1 | §5.1 | A non-delegated AAE whose signing DID differs from its issuer is rejected, even with a valid signature. |
| 13-unrecognized-required-constraint | REJECT | 7 | §2.3, §5.7 | An unrecognized constraint marked `required:true` is rejected. |
| 14-cty-header-wrong | REJECT | 2 | §2.1, §5.2 | A protected header with `cty` other than `aae+json` is rejected. |
| 15-currency-mismatch-delegation | REJECT | 9 | §3, §5.9 | A delegated currency-valued constraint in a different currency than the parent is rejected. |

## Reference implementation

`examples/python-verify.py` implements the Section 5 algorithm, including real
EdDSA signature verification against the DID-document fixtures. It passes all 15
vectors (`15/15`). This is the reference-implementation pass for vector set
v1.0.0.

The reference verifier supplies out-of-band facts (the step-4 challenge-response
outcome, revocation responses, the consumed-id set) from each vector's `context`
object. A production verifier performs those checks live; the vectors fix their
results so the algorithm's branching is what gets tested.

## Production implementation status

Two MolTrust production components evaluate authorization envelopes. Neither is a
drop-in runner for these vectors today; their alignment with draft-00 is recorded
here as an honest baseline, not as a conformance pass. Closing the gaps is tracked
as a follow-up sprint (see below).

### moltrust-api Python evaluator (`app/enforcement/`)

The primary production path: FastAPI `POST /vc/aae/submit` (acceptance gate) and
`POST /vc/aae/evaluate` (constraint and validity evaluation). It uses the draft-00
schema (`mandate.actions`, `max_transaction_value{value,currency,required}`,
`validity.not_before/not_after/single_use/revocation_check`) and its source cites
the draft directly.

| §5 step | Status | Note |
|---------|--------|------|
| 1 signature + signing authority | Partial | EdDSA-only allowlist, strict `kid` validation, exact-signed-bytes, non-delegated signing-DID equals issuer. Resolves `did:moltrust` only (`did:web` deferred); delegated signing-authority case (b) not yet handled. |
| 2 payload / schema / cty | Full | `cty` must be `aae+json`; required members and duplicate-key rejection enforced. |
| 3 temporal | Full | `not_before` / `not_after` with a clock-skew tolerance. |
| 4 subject binding | Divergent | Client replay-nonce plus `(agent_did, nonce)` uniqueness, not the spec's server-minted-nonce challenge-response with `aud`. |
| 5 single-use | Full | Check-and-record keyed by id, serialized with an advisory transaction lock. |
| 6 action check | Gap | Action-membership against `mandate.actions` not enforced. |
| 7 constraints | Full | `required`-default-true taxonomy, currency match, integer-minor-unit hardening, exact-domain match, windowed rate limit, unknown-required rejection. |
| 8 revocation | Divergent (fail-closed) | Presence of `revocation_check` causes a fail-closed reject; live endpoint query deferred to an egress-proxy component. |
| 9 delegation chain | Gap | No chain walk, monotonicity, or cycle detection in production; gated behind the delegation-enforcement work item. |

Summary: steps 2, 3, 5, 7 align fully; step 1 aligns for the non-delegated
`did:moltrust` path; steps 4 and 8 diverge but fail closed; steps 6 and 9 are
gaps. Running the public vectors directly is additionally blocked because this
component resolves only `did:moltrust` issuers registered in its `agents` table,
whereas the vectors use `did:web` test issuers.

### moltguard TypeScript evaluator (`@moltrust/aae` v1.0.0)

A secondary Hono service (`/vc/aae/evaluate`) using a different, earlier data
model (`allowedActions`, `limits`, `duration`, `obligations`). It takes an
unsigned object and performs attribute-based action, resource, jurisdiction, and
amount checks. It does not verify a JWS, resolve a DID, enforce single-use,
query revocation, or walk a delegation chain. Conceptual overlap with draft-00 is
limited to temporal and constraint evaluation under non-matching field names.

## Tracked follow-up

Aligning a production verifier to draft-00 well enough to pass these vectors is a
separate work item, out of scope for vector set v1.0.0:

- `did:web` resolution in the acceptance gate (step 1).
- Delegated signing-authority case (b) (step 1).
- Action-membership enforcement (step 6).
- Server-minted-nonce challenge-response for subject binding (step 4).
- Delegation chain verification: monotonicity, depth limits, cycle detection
  (step 9).
- Live revocation endpoint query behind the egress proxy (step 8).

When a production verifier passes the vectors, its status is recorded here and in
the release notes. Until then, the reference verifier is the only documented
conformance pass.
