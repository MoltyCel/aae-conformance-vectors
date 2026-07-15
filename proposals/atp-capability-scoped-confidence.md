# Capability-scoped confidence for ATP

**Proposal for discussion — w3c-cg/atp#1**
Lars Kroehl, MolTrust / CryptoKRI GmbH — 15 July 2026

Pinned against: ATP `specs/atp-trust/index.html` @ f75bb4d (2026-06-30) · ATP `specs/atp-conformance/index.html` @ f75bb4d · `draft-kroehl-agentic-trust-aae-00` (IETF Datatracker).

---

## The problem

ATP scores an agent as a single scalar and maps it to one of five bands: PRIVILEGED at s ≥ 0.9, TRUSTED at 0.7 ≤ s < 0.9, VERIFIED at 0.4 ≤ s < 0.7, BASIC at 0.2 ≤ s < 0.4, UNKNOWN below 0.2. The score is derived from four evidence factors: identity verification, the count of verified credentials, the success/failure ratio of recorded interactions, and net reputation (endorsements minus violations, each term capped).

Monotonicity is normative: additional successful interactions, endorsements, or verified credentials MUST NOT lower the score; additional failed interactions or violations MUST NOT raise it.

The score therefore rises with volume. The spec's seeded example — identity verified, four credentials, 500 successful interactions, zero failures, 20 endorsements, zero violations — reaches the PRIVILEGED/TRUSTED band. The input carries no field distinguishing 500 interactions of one low-risk action type against a single counterparty from 500 varied interactions against independent counterparties. It carries no field distinguishing 20 endorsements from unrelated parties from 20 endorsements originating in one cluster.

A relying party deciding whether to let an agent move funds needs a claim about that capability. The global band reports standing across all capabilities at once, so a high score earned on low-risk volume reads the same as one earned on the capability in question.

## The proposal

Express confidence per capability instead of as a single global band.

Evidence accumulates within a stated capability frame: which action, under what scope, under whose authority, for how long. Confidence applies to the capabilities the evidence covers. Capabilities without covering evidence stay at none. The global band is no longer the elevation mechanism; where it remains, it reports identity and standing, not authorization.

Three changes to the model:

**1. Bind evidence to a capability frame.** A trust signal carries the capability it was earned under. Evidence for one action type raises confidence for that action type. ATP does not define a capability frame today. The authorization-envelope layer models one: in `draft-kroehl-agentic-trust-aae-00`, MANDATE defines the scope and action allowlist, CONSTRAINTS implement least-privilege and value bounds, VALIDITY enforces time-bound non-transferable authorization, and the delegation chain structure records authority provenance. ATP can reference an external frame of that shape without adopting AAE. The requirement is that a frame is stated and checkable, not which spec supplies it.

**2. Move the band on evidence quality rather than count.** Monotonicity as written is correct within a factor and stays. The addition: count alone does not move the band across levels. Three qualities gate movement — independence of the evidence sources, recency, and whether each recorded outcome resolves to something a verifier can recompute. Recompute is already ATP's notion. The conformance layer defines audit-store integrity as an append-only hash chain in which a verifier recomputes each event's SHA-256 hash. The mechanism exists; the scoring factors do not reference it.

**3. Gate endorsement weight on independence.** Endorsers sharing a funding source or a mutual-endorsement edge collapse to one effective endorser. An endorsement set moves a band only with at least three independent endorsers. Recency decays exponentially with a 90-day half-life. Both figures are proposed starting parameters, not derived optima, and are adjustable by the group.

Under these rules the seeded example does not reach a privileged band. Its 20 endorsements collapse to one effective endorser, below the threshold, and contribute nothing. Its 500 same-type low-risk interactions raise confidence for that one capability. The global band rests on identity and credentials alone, which constrains it below TRUSTED and no higher than VERIFIED. A second profile with fewer interactions across independent counterparties, backed by recomputable receipts, earns confidence for the capabilities those receipts cover.

## Unchanged

The five bands and their cut-points stay. The open ednote asking whether PRIVILEGED should require attested credentials in addition to a high score is a separate question and this proposal does not address it. The four evidence factors stay. Monotonicity stays, scoped as above. No scoring formula is proposed. The fixtures assert bands, per-capability confidence, and invariants rather than point scores; the numeric mapping is a separate decision.

## Open questions for the group

1. Does ATP express the capability frame itself, or reference an external authorization envelope and require only that one be stated?
2. Does per-capability confidence replace the global band as the authorization input, or sit alongside it?
3. Should the scoring layer require that outcomes resolve to conformance-layer audit events, or treat that as a profile?

The anti-gaming fixtures already in the issue exercise the model at both poles and are a starting set if the group takes this direction.
