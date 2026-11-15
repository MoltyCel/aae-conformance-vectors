# Changelog

Changes to the vector set and the reference verifiers. Releases before 1.7.0 are
described under "Release history" in [README.md](README.md#versioning).

## 1.7.0

### Fixed

- Reference verifier, step 9 (`examples/python-verify.py`): a delegated AAE was accepted
  when its chain did not end at a root AAE. The verifier checked only the links between
  the ancestors that were supplied in `delegation_chain`; it did not require each
  `delegator_aae_id` to name a supplied AAE, nor the last ancestor to be a root. A
  delegated AAE presented without ancestors, a chain with its root left out, two delegated
  AAEs naming each other as parent, and a delegated AAE naming itself as parent were all
  accepted at step 9. Step 9 now walks from the presented AAE over `delegator_aae_id` to
  the first AAE without `mandate.delegation`, as -02 §5 step 9 states and as the
  moltrust-api verifier already does. The production verifier was not affected.
  - A parent that no supplied AAE carries rejects at step 9 with the new reason code
    `delegation_ancestor_missing`.
  - An id that appears a second time on the path, or a parent id carried by more than one
    supplied AAE, rejects at step 9 with `delegation_cycle_detected`.
  - Supplied AAEs that are not on the path are ignored, whatever their content and order.

### Added

- Native vectors 16 to 19 for the four cases above:
  `16-delegation-no-ancestors`, `17-delegation-root-omitted`,
  `18-delegation-mutual-parents`, `19-delegation-self-parent`. All four are REJECT at
  step 9 and `structural`. The native family now has 19 vectors; all runs need 87/87.
- Optional field `root_issuer` on every ACCEPT of the reference verifier: the `issuer` of
  the root AAE that ends the verified chain (for a non-delegated AAE, its own issuer).
  `result`, `verification_step` and `rejection_reason` are unchanged, and conformance is
  still compared on `result` and `verification_step` only.

### Changed

- `docs/CONFORMANCE.md`: the step-9 row of the moltrust-api production status now
  reflects the chain walk in `app/enforcement/delegation_chain.py`; it read "Gap".
- Vectors 01 to 15 and their expected results are unchanged.

### Credit

Reported by Kai Karlstrom, Kirkaldy.
