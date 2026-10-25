# Runner protocol `aae-conformance-runner/1`

How the conformance runners talk to an implementation under test. Both runners, Python
([`runner/python/`](../runner/python/)) and TypeScript ([`runner/ts/`](../runner/ts/)),
speak exactly this protocol, compare exactly the fields listed here, and print the same
result lines. An adapter written against this page works with either.

The protocol covers the 15 native vectors (`vectors/*.json`) and the 26 enforce vectors
(`vectors/enforce/*.json`). The composition vectors under `interop/` are not part of it;
they are checked row by row by `examples/composition-verify.py`.

The guide for connecting an implementation is
[TESTING-YOUR-IMPLEMENTATION.md](TESTING-YOUR-IMPLEMENTATION.md). This page is the
reference.

## Transport

- The runner is given a command with `--impl`, for example `--impl "python3 adapter.py"`.
  The string is split into arguments like a POSIX shell would split it (single and double
  quotes, backslash escapes) but nothing is expanded: no variables, globs, pipes or
  redirections. If the implementation needs a shell, say so: `--impl "sh -c '...'"`.
- **One process per vector.** For each vector the runner starts the command, writes one
  request (a single JSON object followed by a newline, UTF-8) to its stdin and closes
  stdin. The process writes one response (a single JSON object) to stdout and exits with
  status 0.
- Each enforce vector with kernel `enforce_check` is sent twice; see
  [Determinism](#determinism). Every other vector is sent once.
- stdout carries the response and nothing else. Diagnostics go to stderr. The runner shows
  the last three non-empty stderr lines when an invocation fails.
- The working directory is the runner's own; the environment is inherited.
- Per-invocation timeout: 10 seconds, changed with `--timeout SECONDS`. On timeout the
  runner kills the process (on POSIX the whole process group) and fails the vector.

One process per vector is slower than a long-lived process, and was chosen anyway: a crash,
a hang or leftover state in one vector cannot leak into the next, there is no framing to
get wrong, and an adapter is a plain filter from stdin to stdout. A run of all 41 vectors
starts the implementation 62 times (15 + 26 + 21 determinism re-runs).

## Request

Every request carries these members:

| Member | Value |
|---|---|
| `protocol` | `"aae-conformance-runner/1"` |
| `family` | `"native"` or `"enforce"` |
| `vector_id` | the vector's `id`, e.g. `"aae-vector-06"`, `"aae-enforce-vector-22"` |
| `vector_file` | path relative to the repository root, e.g. `"vectors/06-delegation-valid-depth-2.json"` |
| `section_ref` | the draft revision the vector was built against |
| `input` | the vector's `input` object, unchanged (except in the `keys-reversed` variant) |

The vector's `expected` object is never sent. `vector_id` and `vector_file` are there for
logging; an implementation must not branch on them.

### Native requests (`family: "native"`)

| Member | Value |
|---|---|
| `input.secured_aae` | the AAE as a compact JWS |
| `input.context` | the out-of-band facts: `current_time`, `requested_action`, `action_context`, `subject_binding`, and where the vector needs them `consumed_ids`, `revocation_responses`, `delegation_chain` |
| `did_documents` | object mapping each DID to its DID document, the full content of `testkeys/did-documents/*.json` |
| `did_documents_dir` | absolute path of `testkeys/did-documents/`, for implementations that prefer to read the files |

DID resolution is offline: every `kid` in the vectors resolves against `did_documents`.
The meaning of each `context` member is described in the README under *Vector format*.

### Enforce requests (`family: "enforce"`)

| Member | Value |
|---|---|
| `kernel` | `"enforce_check"` or `"ratify"` |
| `kernel_version` | `"3.0"`, the version the expected digests were computed under |
| `domain_tags` | the vector's `domain_tags`, ASCII without the trailing `0x00` |
| `variant` | `"as-committed"` or `"keys-reversed"` |
| `input` | `enforce_check`: `mandate`, `transaction`, optionally `prev_core_digest`. `ratify`: `prior_record`, `decision`, `authority_proof`, optionally `prev_core_digest` |

## Response

A JSON object. Members not listed for a family are ignored, so an implementation may
return its whole result. A response with a non-null `error` member means *the
implementation could not answer* and fails the vector, whatever else it contains.

### Native

| Member | Required | Compared |
|---|---|---|
| `result` | yes, `"ACCEPT"` or `"REJECT"` | equal to `expected.result` |
| `verification_step` | yes, integer 1-9 | equal to `expected.verification_step` |
| `rejection_reason` | no | not compared; printed next to the result |

This is the conformance target stated in [CONFORMANCE.md](CONFORMANCE.md): `result` plus
`verification_step`. The reason code is diagnostic; implementations may map their own
codes onto the table there.

### Enforce, kernel `enforce_check`

| Member | Required | Compared |
|---|---|---|
| `verdict` | yes, `"PERMIT"`, `"DENY"` or `"PENDING"` | equal to `expected.verdict` |
| `core_digest` | yes, `"sha256:<64 lowercase hex>"` | equal to `expected.core_digest`, byte for byte |
| `grant_index` | when the vector states one (01, 21) | equal to `expected.grant_index` |
| `trace` | no | if present: every entry of `expected.trace` must appear in order, with the same `predicate` and `result`, and the same `field`, `value`, `bound` where the vector states them |
| `reason` | no | not compared |

### Enforce, kernel `ratify`

A ratification either produces a record or, when a guard refuses the request, produces
nothing (vectors 24 and 25: a PERMIT is not ratifiable; the chain link points elsewhere).

Record:

| Member | Required | Compared |
|---|---|---|
| `status` | yes, `"RATIFIED"` or `"REJECTED"` | equal to `expected.status` |
| `core_digest` | yes | equal to `expected.core_digest`, byte for byte |
| `ratifies` | yes | equal to `expected.ratifies` |
| `authority` | when the vector states one | equal to `expected.authority` (may be `null`) |
| `trace` | no | as for `enforce_check` |
| `reason`, `decision` | no | not compared |

Refusal: `{"caller_error": "<non-empty message>"}` and no `status`. The message is not
compared. `caller_error` is deliberately a different member from `error`: an adapter that
answers every request with `{"error": "not implemented"}` must not pass the two refusal
vectors.

### What is not compared, and why

- **`reason`, and `reason_contains` in the vectors.** Enforce kernel 3.0 keeps `reason`
  out of every core: two implementations must agree on the decision, not on the wording
  that explains it. `examples/enforce-verify.py` checks `reason_contains` against its own
  wording as a self-check; the runners do not hold other implementations to it.
- **`rejection_reason`** on native vectors, for the reason given above.
- **The error message** of a caller error.
- **Anything in the trace beyond what the vector names.** The digest already commits to
  the full core trace (`predicate`, `field`, `value`, `bound`, `result` per entry), so a
  wrong trace shows up as a wrong `core_digest`. Returning `trace` only makes the failure
  easier to locate.

### Determinism

The reference verifier evaluates each `enforce_check` vector a second time with every
object's keys in reverse order and requires the same digest
([RESULTS.md](../vectors/enforce/RESULTS.md#determinism)). The runners do the same over
the protocol: once an `enforce_check` vector has passed, it is sent again with
`variant: "keys-reversed"`, where `input.mandate` and `input.transaction` carry their
keys in reverse order at every depth. The `core_digest` of the second response must
equal the first. An implementation that hashes its input in insertion order instead of
canonicalizing under RFC 8785 fails here.

(JSON objects whose keys look like array indices, such as `"0"`, cannot be reordered in
JavaScript. No vector has such keys.)

## Failure messages

Every failure is reported under the vector it belongs to. The process-level ones are:

| Message | Cause |
|---|---|
| `could not start the implementation: ...` | the command was not found or not executable |
| `timed out after Ns` | no exit within the timeout |
| `exited with status N (stderr: ...)` | non-zero exit status (negative: killed by signal N) |
| `stdout is empty` | exit 0 without output |
| `stdout is not a single JSON value: ...` | anything that does not parse as one JSON value |
| `response is not a JSON object` | parses, but is an array, string, number or literal |
| `implementation returned an error: ...` | the response has a non-null `error` member |
| `response.<member> missing` / `must be ...` | a required member is absent or of the wrong type |
| `keys-reversed run: ...` | the determinism re-run failed for one of the reasons above |

Mismatches read `<member> <got>, expected <want>` with both values as JSON.

## Exit status and report

| Exit status | Meaning |
|---|---|
| 0 | every selected vector passed |
| 1 | at least one vector failed |
| 2 | usage error: bad arguments, no vector set found, no vector selected |

`--json PATH` writes a report: `runner`, `runner_version`, `protocol`, `implementation`,
`vectors_root`, `families` (passed and total per family), `passed`, `total`, `ok`, and
`results`, one entry per vector with `family`, `file`, `vector_id`, `kernel`, `status`,
`outcome`, `failures`, the vector's `expected`, the `response`, and for re-run vectors
`response_keys_reversed`.

## Versioning

The protocol identifier changes only when a request or response member changes meaning or
a compared field is added. The runners are versioned on their own (1.0.0), independent of
the vector set version in the README.
