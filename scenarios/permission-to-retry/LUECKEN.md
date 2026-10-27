# Gaps in draft-kroehl-agentic-trust-aae-02 for the resume scenarios

Each entry names a question one or more cells of the [scenario matrix](README.md) depend on
and that draft-kroehl-agentic-trust-aae-02 (SHA-256 `08e202ec…a473b4c`, see README) leaves
open. An entry states what -02 says and where it stops. It does not propose text.

Scenario source: arXiv:2610.31916v1 (Marla, Bhatnagar), §2, §4.2, §8 and Figure 2.

| Id | Question left open by -02 | What -02 says | Cells |
|---|---|---|---|
| L1 | How many effects one envelope authorizes | `single_use` (§2.4) counts successful authorizations of one envelope id at one relying party; `rate_limit` (§2.3) counts accepted actions per window; §7.1: a `range` constraint "bounds each transfer, never their sum". No member states an effect count, and nothing relates an authorization to the number of effects at the provider. | all rows after admission (R01, R07–R14) |
| L2 | Whether a repeated dispatch of an already admitted action is a new action | §7.1: "A PERMIT is not a single-use authorization"; a relying party MUST establish freshness and consumption "by its own means" (a nonce, a spent identifier, or an idempotency key). -02 does not choose among them and has no rule that separates a repeat of an admitted action from a fresh one. | R07, R08, R09, R14 |
| L3 | Whether a delivery admitted before revocation may still take effect | Revocation (§2.4, §5 step 8, §7.5) governs whether a relying party accepts an envelope. §2.4: invalidation "does not invalidate the AAE globally". Nothing is said about a delivery already admitted and in flight. | R08, R09 |
| L4 | Whether reading the provider to reconcile an earlier effect is permitted after revocation | `read` is an action in the same mandate (§4, Table 1); a revoked envelope is rejected as a whole (§2.4). No capability for reconciliation is separated from the write authority. | R08, R11, R13 |
| L5 | What evidence closes a history as completed | §6.2 verdict records are immutable records of a decision over mandate and transaction; the §2.5.3 core carries no effect, receipt or settlement. -02 defines no execution record; the term Agent Execution Record does not occur in the -02 text. | R01, R07–R14 |
| L6 | What state an unresolved outcome keeps | The verdict vocabulary (§6.1) is PERMIT, DENY, PENDING. PENDING defers a decision about an action before it is taken; no state exists for an action whose external outcome is unknown, and -02 does not say that an empty lookup fails to prove absence. | R07, R08, R09, R14 |
| L7 | Whether a policy change invalidates an issued envelope | §2.4, last paragraph: the validity members "bound the authorization in time; they do not make it fresh". §9 lists "Freshness and condition liveness" as future work. -02 has no policy-epoch member; a policy change takes effect only if the issuer revokes. | R03 |
| L8 | How long an idempotency key protects against a duplicate | §7.1 names an idempotency key as one acceptable means of consumption. No horizon, scope or expiry is stated for it. | R14 |
| L9 | Whether a ratification expires | §6.3 and §6.4: a ratification binds `ratifies`, `decision` and `authority` and authorizes one transaction. Neither the signed statement nor the ratification core carries a time bound. Relevant where an approval is expressed as a ratification of PENDING. | R04 (alternative reading) |
| L10 | How a relying party learns of a revocation at evaluation time | §7.5: a relying party SHOULD NOT dereference a revocation endpoint at evaluation time in -02; §5.2 defers revocation checking and requires a fail-closed rejection of an envelope carrying `revocation_check` where the lookup cannot be performed. §9 states the condition under which discovery becomes normative. The consequence of a known revocation is normative (§7.5). | R02, R06, R08, R11, R13 |

L7 and L10 are gaps that -02 itself declares in §9. The others are not mentioned in -02.
