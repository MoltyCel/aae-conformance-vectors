# State of this fixture

This fixture preserves the exchange state at upstream commit `e8c00e5`, at which
the WHO axis was `PROPOSED`. WHO was confirmed by Mohamad Khalil-Yossif at head
`8bed788` (see [`../../interop/psea/CONFORMANCE.md`](../../interop/psea/CONFORMANCE.md)).

The `PROPOSED` markers in the six files listed in `manifest.json` are the
historical state at re-performance time and are intentionally not updated. Those
six files, together with `interop/psea/vectors/xp-1-aligned-principal.json`, are
pinned by hash in EMILIA Protocol's independent return at commit `e004e217`;
editing any of them would invalidate that return without adding a fact.

The confirmation is recorded where it can be read without breaking a pin: in
`CONFORMANCE.md`, in `interop/psea/README.md`, and in
`interop/psea/principal-resolution.json`. Flipping the per-vector `status` fields
is deferred to a separate change, so that the counterpart can re-run against a
known head rather than discover the shift.

This file is not listed in `manifest.json` and is not pinned. It carries no
artifact and no hash that anything depends on.

## What that means for a reader

The six exchange files and this directory's `README.md` describe the WHO axis as
proposed. That describes the state at `e8c00e5`, not the state today. For the
current standing of either axis, read `CONFORMANCE.md`, which is the document a
conforming implementation checks against.
