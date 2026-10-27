# Testing your implementation

This guide connects your own AAE implementation to the vectors and runs it. You write a
small adapter that turns a request from the runner into a call into your code; a runner
sends every vector through it and tells you which ones pass.

- 15 native vectors, `vectors/*.json`: the Section 5 nine-step verification of a signed
  AAE, built against
  [draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/00/).
- 26 enforce vectors, `vectors/enforce/*.json`: the enforce kernel (grants, constraint
  language, verdicts, ratification) with a recomputable core digest, built against
  [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/),
  enforce kernel 3.0.
- 42 resume vectors, `vectors/resume/*.json`: the 14 resume schedules of arXiv:2610.31916v1
  under three provider profiles, each the presentation draft -02 decides for that cell
  (see [the scenario matrix](../scenarios/permission-to-retry/README.md)). 39 are native
  requests, the three R05 cells are `enforce_check` requests; your adapter answers them
  exactly as it answers the other two families.

You can test any family alone. The six composition vectors under `interop/` are not run
by the runners.

The exact wire format is in [RUNNER-PROTOCOL.md](RUNNER-PROTOCOL.md).

## 1. Get a runner

Both runners behave the same: same flags, same output lines, same exit status. Pick the
one that fits your toolchain.

**Python** (3.9 or later, standard library only):

    git clone https://github.com/MoltyCel/aae-conformance-vectors
    cd aae-conformance-vectors
    PYTHONPATH=runner/python python3 -m aae_conformance --help

or install it into a virtual environment: `pip install ./runner/python`, then
`python3 -m aae_conformance --help`.

**TypeScript** (Node 20 or later):

    cd runner/ts && npm ci && npm run build && cd ../..
    node runner/ts/dist/cli.js --help

The runners find the vector set from their own location. If you install or copy a runner
elsewhere, pass `--vectors-root path/to/aae-conformance-vectors`.

## 2. Write an adapter

An adapter is a program that reads one JSON request from stdin, calls your
implementation, and writes one JSON response to stdout. The runner starts it once per
vector. Start from a skeleton:

- Python: [`adapters/skeleton-python/adapter.py`](../adapters/skeleton-python/adapter.py)
- JavaScript (runs as is on Node, typed with JSDoc):
  [`adapters/skeleton-js/adapter.mjs`](../adapters/skeleton-js/adapter.mjs)

Copy one, then fill in the functions marked TODO:

| Function | Gets | Returns |
|---|---|---|
| native verify | `secured_aae` (compact JWS), `context`, `did_documents` | `{"result": "ACCEPT"\|"REJECT", "verification_step": 1..9}` |
| `enforce_check` | `mandate`, `transaction`, `prev_core_digest` | `{"verdict": "PERMIT"\|"DENY"\|"PENDING", "core_digest": "sha256:...", "grant_index": n\|null}` |
| `ratify` | `prior_record`, `decision`, `authority_proof`, `prev_core_digest` | `{"status": "RATIFIED"\|"REJECTED", "core_digest", "ratifies", "authority"}`, or `{"caller_error": "..."}` when a guard refuses |

Points that trip people up:

- **The vectors fix the facts a static file cannot hold.** The clock (`current_time`), the
  subject-binding challenge-response outcome, already consumed ids, revocation endpoint
  responses and the delegation chain all arrive in `input.context`. Your adapter has to
  feed them into your implementation instead of the live sources, for example through a
  fixed clock, a stub revocation client and an in-memory consumed-id store.
- **DIDs resolve offline** against `did_documents` in the request. Nothing in the vectors
  needs network access.
- **stdout is for the response only.** Log to stderr.
- **Return `error` only when you cannot answer.** `{"error": "..."}` fails the vector.
  A ratification your implementation refuses as a caller error is a valid answer and goes
  in `caller_error`.

The skeletons answer `{"error": "not implemented: ..."}` until you fill them in, so a
first run shows every vector as failed with that message. That confirms the wiring.

A complete adapter, the one CI runs, is
[`adapters/python-reference/adapter.py`](../adapters/python-reference/adapter.py). It puts
the two reference verifiers (`examples/python-verify.py`, `examples/enforce-verify.py`)
behind the protocol and passes all 83.

## 3. Run

    # Python runner
    PYTHONPATH=runner/python python3 -m aae_conformance --impl "python3 my_adapter.py"

    # TypeScript runner
    node runner/ts/dist/cli.js --impl "node my_adapter.mjs"

Either runner takes any `--impl` command; the adapter's language does not have to match
the runner's.

| Flag | Effect |
|---|---|
| `--impl CMD` | the command that starts your adapter (required) |
| `--family native\|enforce\|resume\|all` | which family to run (default `all`) |
| `--vector PATTERN` | only vectors whose id equals PATTERN or whose file name contains it; repeatable |
| `--timeout SECONDS` | per-invocation timeout (default 10) |
| `--json PATH` | also write a machine-readable report |
| `--vectors-root DIR` | where the vector set is, if the runner cannot find it |

## 4. Read the result

The reference adapter, through the Python runner:

    AAE conformance runner 1.1.0 (python), protocol aae-conformance-runner/1
    implementation: python3 adapters/python-reference/adapter.py
    vectors: /home/you/aae-conformance-vectors

    PASS  native   01-valid-root-aae.json                                     ACCEPT @ step 7
    PASS  native   02-expired-not-after.json                                  REJECT @ step 3 (expired_not_after)
    ...
    PASS  enforce  24-a-permit-is-not-ratifiable-caller-error.json            caller error
    ...
    PASS  resume   R03-P1-initial-policy-epoch.json                           ACCEPT @ step 8
    ...

    native   15/15 passed
    enforce  26/26 passed
    resume   42/42 passed
    83/83 passed

A failing vector lists every mismatch under it:

    FAIL  native   06-delegation-valid-depth-2.json
            result "REJECT", expected "ACCEPT"
    FAIL  enforce  16-range-fails-one-over-the-bound-deny.json
            core_digest "sha256:0000...0000", expected "sha256:8adafa0e...553980f"

(digests shortened here; the runner prints them in full)

The exit status is 0 only when every selected vector passed, 1 when any failed, and 2 for
a usage error. Use it in your CI. The `--json` report holds every request's response next
to the vector's `expected`, which is the quickest way to diff a failure.

## 5. When a core digest does not match

On the enforce family the verdict is not enough: the conformance target is the core
digest, because a verifier that returns the right verdict from the wrong core has guessed
the outcome rather than recomputed the decision. A digest mismatch with a matching verdict
is the most common first failure. To find it, recompute the vector step by step:

    python3 tools/explain_enforce.py vectors/enforce/16-range-fails-one-over-the-bound-deny.json

It prints the three input digests, the predicate trace, the canonical bytes of the core
and the digest over them, next to what the vector expects (requires `jcs` and
`cryptography`). Compare your core with that output field by field; the first difference
is the bug. Typical causes: a missing or extra trace entry, a `value` or `bound` with a
different shape, `reason` left in the core, keys serialized in insertion order instead of
RFC 8785, or a domain tag without its trailing `0x00`.

## 6. Recomputing a verdict and its digest from the input

Every expected value in the enforce family can be recomputed from the vector's `input`
alone. Nothing depends on a clock, a network or stored state, and nothing is taken on
trust from the vector. The construction:

**Digest function.** For a domain tag `T` (ASCII, as listed in the vector's
`domain_tags`) and a JSON value `v`:

    digest(T, v) = "sha256:" + lowercase_hex( SHA-256( T || 0x00 || JCS(v) ) )

`JCS` is the RFC 8785 canonical form. In Python:

```python
import hashlib, jcs   # pip install jcs

def digest(tag: str, value) -> str:
    return "sha256:" + hashlib.sha256(tag.encode("ascii") + b"\x00"
                                      + jcs.canonicalize(value)).hexdigest()
```

**`enforce_check` core.** An object with exactly these members:

| Member | Value |
|---|---|
| `enforce_version` | `"3.0"` |
| `mandate_digest` | `digest("aae:enforce-mandate:v1", input.mandate)` |
| `transaction_digest` | `digest("aae:enforce-transaction:v1", input.transaction)` |
| `action_digest` | `digest("aae:enforce-action:v1", input.transaction.action)`, a missing `action` counting as `null`; the member itself is `null` when the transaction is not an object |
| `verdict` | `PERMIT`, `DENY` or `PENDING` |
| `grant_index` | index of the deciding grant, or `null` |
| `trace` | the predicate trace, each entry reduced to `predicate`, `field`, `value`, `bound`, `result` |
| `prev_core_digest` | `input.prev_core_digest` if it is a string, else `null` |

`core_digest = digest("aae:enforce-core:v1", core)`.

**Verdict and trace** (draft -02 Sections 2.2.1 to 2.2.3, 2.5, 6.1). In this order, and
the first rule that decides ends the evaluation:

1. The mandate must be structurally valid (non-empty `grants`, each with a well-formed
   `action_binding`, a `disposition` of `allow`/`hold`/`forbid`, `type_fields` that are
   unique non-empty strings including `verb`, and a `constraints` array). If not: DENY.
2. The transaction must be an object and its `action` canonicalizable. If not: DENY.
3. Type form: a grant is a candidate only if the action carries exactly that grant's
   `type_fields`, no more and no fewer. No candidate: DENY.
4. Action binding: of the candidates, the grants whose `action_binding` equals
   `action_digest` are bound. None bound: DENY, never PENDING.
5. A bound grant with disposition `forbid` decides: DENY, `grant_index` = that grant.
6. Otherwise the bound grants are tried in order; each constraint (`exact`, `enum`,
   `range`; any other type fails) is evaluated against the transaction. The first grant
   whose constraints all pass decides: `allow` gives PERMIT, `hold` gives PENDING. If none
   passes: DENY.

Each check appends one trace entry. The exact entries (predicate names, and what goes in
`value` and `bound`) are those of the reference kernel in
[`examples/enforce-verify.py`](../examples/enforce-verify.py), `enforce_check()`; since
the trace is inside the digest, an implementation has to produce the same entries.
`tools/explain_enforce.py` prints them for any vector.

**`ratify` core** (draft -02 Sections 6.3, 6.4). First the guards, each of which refuses
with a caller error and produces no record: `decision` is `APPROVED` or `DISAPPROVED`;
`prior_record.core_digest` equals `digest("aae:enforce-core:v1", prior_record.core)`; the
prior verdict is DENY or PENDING (a PERMIT is not ratifiable); a given `prev_core_digest`
equals that digest. Then the authority: the supplied mandate must hash to the prior core's
`mandate_digest`, the claimed authority must be the mandate's `principal` or a named
`ratification_authorities` entry, and its Ed25519 signature (hex, key taken from the
mandate) must verify over

    "aae:enforce-ratify-statement:v1" || 0x00 || JCS({"ratify_version": "3.0",
        "ratifies": <prior core digest>, "decision": ..., "authority": <did>})

All three hold: RATIFIED, otherwise REJECTED. The core holds `ratify_version`,
`ratifies`, `prior_verdict`, `decision`, `status`, `authority` (`null` unless RATIFIED),
`mandate_digest`, `trace`, and `prev_core_digest` (the given one, else `ratifies`), and
`core_digest = digest("aae:enforce-ratify-core:v1", core)`.

**Checking it yourself.** `examples/enforce-verify.py` recomputes all 26 from the input
and compares; `tools/explain_enforce.py` shows the intermediate values for any of them.
Neither reads the expected digest to produce its own. If your implementation returns its
`core` alongside `core_digest`, anyone can recheck the digest from that core with the
four-line function above.

## 7. What you may claim

A conformance claim is per family and per revision, because the families track different
revisions of the draft:

| You pass | You may state |
|---|---|
| native 15/15 | conforms to the Section 5 verification algorithm of draft-kroehl-agentic-trust-aae-00, as tested by the native vectors |
| enforce 26/26 | conforms to the enforce kernel of draft-kroehl-agentic-trust-aae-02 (kernel 3.0), as tested by the enforce vectors |
| resume 42/42 | decides the admission and repeat-dispatch presentations of the 14 resume schedules as draft-kroehl-agentic-trust-aae-02 does; it says nothing about the history outcome, which -02 leaves unspecified in 30 of the 42 cells |

Fewer than all vectors of a family is not a conformance claim for that family; report the
count instead ("passes 12 of 15 native vectors"). Name what you ran, so the claim can be
reproduced:

> Passes the AAE conformance vectors v1.6.0, native family 15/15
> (draft-kroehl-agentic-trust-aae-00), runner 1.1.0, protocol aae-conformance-runner/1.

Keep the limits in view. The native vectors fix the subject-binding outcome, the
revocation responses and the consumed-id set through `context`, so passing them shows
that your algorithm branches correctly on those facts, not that your live challenge,
revocation query or replay store work. Passing the vectors is not a certification and is
not issued or endorsed by anyone; it is a result anyone can reproduce with the commands
above. The composition vectors carry no conformance claim at all.

Questions about a result: open an issue in this repository and attach the runner's
`--json` report.
