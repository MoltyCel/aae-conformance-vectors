# Resume scenarios from "Permission to Retry", read against AAE -02

This directory states, for each of the 14 resume schedules and three provider profiles of
arXiv:2610.31916v1, which outcome draft-kroehl-agentic-trust-aae-02 lets a reader derive.
The 42 cells are encoded as runner vectors in [`vectors/resume/`](../../vectors/resume/),
one file per cell id (`R01-P1` … `R14-P3`), built from this table and LUECKEN.md by
`tools/build_resume_vectors.py`. Each file is the presentation -02 decides for the cell,
with the result the "repeat dispatch" column states; the history outcome and the gaps are
carried in its `cell` member and not compared by the runner.

    PYTHONPATH=runner/python python3 -m aae_conformance \
      --impl "python3 adapters/python-reference/adapter.py" --family resume

The 39 native-shaped vectors present the envelope of item 2 below without its grant and pin
the amount with `max_transaction_value` instead. The reason is the reference verifier: it
implements §5 of -00 and does not evaluate grants, and -02 §2.2.1 requires a relying party
that does not evaluate grants to reject an envelope carrying them. The steps these vectors
stop at read the same in -00 and -02 (steps 5 and 8 word for word; -02 step 3 adds a
reminder of the `validFrom` rule of §2.4, which the reference verifier applies). The grant
of item 2 is exercised by the three R05 vectors, which go through the enforce kernel.

Where -02 gives no answer for a cell, the cell says **not specified** and names the gap.
The gaps are listed in [LUECKEN.md](LUECKEN.md). Both files describe -02 as published;
neither proposes text for the draft.

## Sources

| Source | Identifier | Retrieved | SHA-256 |
|---|---|---|---|
| D. Marla, K. Bhatnagar (Arya.ai), "Permission to Retry: A Study of Authorization and Recovery in AI Agent Workflows" | [arXiv:2610.31916v1](https://arxiv.org/abs/2610.31916v1), submitted 2026-10-22, PDF 413,248 bytes | 2026-10-27 | `d7651b65c1fcbbbba0f57440ec43de30c4a1f3548e81972a08792ba1971b2a1d` (PDF) |
| L. K. Kroehl, "Agent Authorization Envelope (AAE)" | [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/), posted 2026-09-06 | 2026-10-27 | `08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c` (`.txt` from the IETF archive) |

Paper sections used: §2 (provider profiles P1, P2, P3; repeat-freshness rule), §3 (model),
§4.2 (corpus: 14 schedules), §5.2 (observation boundary) and Figure 2 (row labels and the
per-cell outcomes of the paper's ledger-reconciliation policy, shown below as the paper's
reference outcome). Section numbers for AAE refer to -02.

## Provider profiles (paper §2, in our words)

- **P1** — the provider deduplicates a request carrying the same stable key, but only within
  a declared time horizon.
- **P2** — the provider answers outcome lookups, but neither deduplicates nor cancels.
- **P3** — the provider gives no way to learn the outcome of a request.

## How a cell is read

The paper scores a whole history: a worker admits a refund, dispatches it to a provider,
observes the result and settles; a fault interrupts the worker and a replacement resumes.
AAE -02 specifies how a relying party evaluates an envelope when a request is presented.
To lay one over the other, every cell uses the same mapping:

1. **Relying party.** The admission point in front of the provider call is the AAE relying
   party. Every dispatch, first or repeated, is a presentation of the envelope and runs the
   §5 verification algorithm and, for grants, §2.2.3.
2. **Envelope profile.** One AAE per history, for the paper's single synthetic refund with a
   one-effect allowance:
   - `mandate.actions` = `["pay"]`, with one grant, disposition `allow`, whose constraints
     pin the instance: `exact` on the recipient, `range` with `lo` = `hi` on the amount
     (§2.2.1, §2.5.1);
   - `validity.single_use` = `true` (§2.4), as the closest -02 member to a one-effect
     allowance;
   - `validity.not_after` set; `validity.revocation_check` present (§2.4).
3. **Replacement worker.** The replacement is another node of the same relying party. §2.4
   requires single-use state to be "shared across all nodes that can accept the AAE".
4. **Revocation.** Where a schedule revokes authority, the relying party learns it from the
   `revocation_check` response `revoked: true` (§2.4). How that discovery is made at
   evaluation time is deferred in -02 (§5.2, §7.5, §9); see gap L10.
5. **Outcome.** C = completion with a checked effect, D = denial, U = open reservation,
   NS = not specified. A cell gets C or U only if -02 states what evidence closes the
   history or what state an unresolved outcome keeps. It states neither (gaps L5, L6), so no
   cell is C or U under -02. A cell is D where -02 rejects the first admission.

The column "repeat dispatch" records what -02 does say about the replacement's attempt to
send again, even where the history outcome is not specified.

## The matrix

| Row | Schedule (paper label) | Scenario, in our words | Repeat dispatch under -02 | P1 | P2 | P3 | Paper reference, ledger policy (P1/P2/P3) |
|---|---|---|---|---|---|---|---|
| R01 | completed reopen | The refund was committed and settled; a worker opens the finished workflow again. | A second presentation of the same envelope is rejected: §2.4 `single_use`, §5 step 5. | NS | NS | NS | C / C / C |
| R02 | initial revocation | The principal's authority is revoked before the first admission. | No first admission: §2.4 `revoked: true` MUST reject; §5 step 8. | D | D | D | D / D / D |
| R03 | initial policy epoch | The governing policy changes after the authorization was issued and before the first admission. | -02 has no policy-epoch member. Unless the issuer revokes, the envelope still verifies; §2.4 says its members "do not make it fresh". | NS | NS | NS | D / D / D |
| R04 | initial approval expiry | The approval lapses before the first admission. | Expired envelope MUST be rejected: §2.4 `not_after`, §5 step 3. | D | D | D | D / D / D |
| R05 | initial action drift | The action presented for admission differs from the one that was approved. | Under the envelope profile the drifted value fails an `exact` or `range` predicate: §2.2.3 step 7, DENY. | D | D | D | D / D / D |
| R06 | preparation crash revoked | The worker stops before it prepares the admission; authority is revoked before the replacement starts. | The first admission happens after revocation and is rejected: §2.4, §5 step 8. No single-use state was consumed, since none succeeded. | D | D | D | D / D / D |
| R07 | lost ack benign | The provider commits the refund but the acknowledgement is lost; authority is unchanged when the replacement resumes. | Rejected: the first presentation already succeeded (§2.4 `single_use`, §5 step 5). | NS | NS | NS | C / C / U |
| R08 | lost ack revoked | As R07, but authority is revoked before the replacement resumes. | Rejected: revocation (§5 step 8) and single use (§5 step 5). | NS | NS | NS | C / C / U |
| R09 | pending then empty | The first request is still in flight; the replacement's lookup comes back empty; the request commits afterwards. | Rejected: single use (§5 step 5). | NS | NS | NS | U / U / U |
| R10 | observation crash benign | The worker received and the host persisted the provider's confirmation; the worker stops before settlement; authority unchanged. | No dispatch is needed; if attempted, rejected by single use (§5 step 5). | NS | NS | NS | C / C / C |
| R11 | observation crash revoked | As R10, but authority is revoked before the replacement settles. | As R10; revocation also rejects (§5 step 8). | NS | NS | NS | C / C / C |
| R12 | settlement crash benign | Settlement was written, the worker stops before the host records its acknowledgement; authority unchanged. | As R10. | NS | NS | NS | C / C / C |
| R13 | settlement crash revoked | As R12, but authority is revoked before the replacement resumes. | As R11. | NS | NS | NS | C / C / C |
| R14 | deduplication expired | The acknowledgement is lost and the replacement resends after the provider's deduplication horizon has passed (only P1 deduplicates at all). | Rejected: single use (§5 step 5). -02 names an idempotency key as one acceptable means (§7.1) but no horizon for it. | NS | NS | NS | C / C / U |

Totals under -02: 12 cells D (R02, R04, R05, R06), 30 cells NS, no cell C or U.
Paper reference, ledger policy: 21 C, 15 D, 6 U per host (paper Table I and Figure 2).

## Per-row derivation and gaps

- **R01** — The second presentation is refused, so -02 prevents a duplicate effect at a
  relying party that keeps single-use state. Whether the reopened history counts as
  completed depends on retained evidence of the earlier effect and its settlement; -02
  defines no such record (§6.2 verdict records record decisions, not effects). Gaps: L5.
- **R02** — Derivable: D in every profile, because rejection precedes any dispatch and the
  provider contract never comes into play. Discovery of the revocation at evaluation time:
  L10.
- **R03** — Not specified. An envelope issued before a policy change verifies unchanged
  until `not_after` unless it is revoked. §2.4 (last paragraph) and §9 ("Freshness and
  condition liveness") place this outside -02. Gap: L7.
- **R04** — Derivable: D, with the approval expressed as the envelope's `not_after`. If the
  approval is instead expressed as a §6.3 ratification of a PENDING verdict, -02 gives that
  ratification no validity bound. Gap: L9.
- **R05** — Derivable: D under the envelope profile, which pins the instance with `exact`
  and `range` constraints. A grant alone binds an action *type*, and §2.2.2 places binding
  to an action *instance* outside the specification; an envelope that does not pin the
  values would permit a drifted amount inside its range. Not a gap in this matrix, recorded
  as a condition of the profile.
- **R06** — Derivable: D in every profile. The interruption consumed no admission, so the
  replacement's attempt is the first presentation and meets the revocation.
- **R07** — Not specified. -02 refuses the repeat, which removes the duplicate the paper
  scores as a violation, but it also refuses a legitimate repeat where P1 would deduplicate.
  It has no rule distinguishing the repeat of an admitted action from a new one (L2), no
  record that closes the history (L5) and no unresolved state for P3 (L6).
- **R08** — Not specified. Additionally, settling the earlier effect after revocation needs
  a lookup, and -02 gives no read permission that survives revocation (L4); the earlier
  delivery may still commit after revocation (L3).
- **R09** — Not specified. An empty lookup does not prove absence while a request is in
  flight; -02 has no state for an outcome that is still open (L6) and says nothing on a
  delivery that commits after the replacement acted (L3).
- **R10, R12** — Not specified. The confirmation is already held, so completion needs no
  further provider write; -02 has no rule on what held evidence permits settlement (L5).
- **R11, R13** — Not specified, as R10 and R12, plus settlement after revocation (L4).
- **R14** — Not specified. Single use refuses the resend; the idempotency key of §7.1 has no
  stated horizon, so -02 does not address an expired deduplication window (L8), and the
  history outcome rests on L5 and L6.

## What the matrix shows

Read against -02, the provider profile never changes a cell: -02 decides admission of a
presented envelope and does not model the provider contract, the effect or its settlement.
The 12 derivable cells are the four admission-time denials; R03, the fifth admission-time
row in the paper, depends on a freshness property that -02 lists as future work. For every
row after admission, -02 answers the first of the paper's three resume questions (§8) in
part, through single use and revocation, and does not answer the other two.
