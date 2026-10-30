# Worked mapping: scope, refusal, and a check that cannot run

This page takes three cases a charter row on delegated authority has to cover and shows
each one against a published vector of this repository. Every value below comes from a
file and line in this repository or in the published draft, and every value can be
recomputed from the vector's input alone: no clock, no network, no stored state.

The cases follow the request on the agentproto list
([message](https://mailarchive.ietf.org/arch/msg/agentproto/L1MhmGSp5-bQpK1K_nsMx3BkGEc/)):

1. the in-scope check, recomputed independently from the envelope and the request;
2. a case where the action falls outside the grant;
3. what happens when the check cannot be run.

AAE establishes the scope of a grant. Precedence between parties is decided elsewhere.

Sources:

- vectors: `vectors/enforce/`, governed by `schema/enforce-vector-schema.json`, enforce
  kernel 3.0;
- draft: [draft-kroehl-agentic-trust-aae-02](https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-02.txt),
  sha256 `08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c`. Line numbers
  refer to that text file.

All digests below are `sha256( tag || 0x00 || JCS(value) )`, with JCS as in RFC 8785 and
the tag named in each vector's `domain_tags`.

## 1. In scope: the verdict recomputed from envelope and request

Vector `aae-enforce-vector-01`, file `vectors/enforce/01-type-form-matches-permit.json`.

| What | Value | Where |
|---|---|---|
| bound action type | `type_fields` `verb`, `asset`, `chain` | lines 20–24 |
| action binding in the grant | `sha256:8c2938c5…26cfb76` | line 19 |
| action in the request | `{"verb":"transfer","asset":"USDC","chain":"base"}` | lines 43–47 |
| per-instance values, outside the action | `to`, `amount`, `region` | lines 48–50 |
| constraints | `exact` on `to`, `range` 0–1000 on `amount` | lines 26–38 |
| disposition | `allow` | line 25 |
| expected verdict | `PERMIT` | line 54 |
| expected core digest | `sha256:92893c1fa6cf3033f70687dc3683857824979c0bde7b6e5eee97627d527b2c73` | line 55 |

The check, step by step:

1. The action digest is computed over the request's `action` object only, under the tag
   `aae:enforce-action:v1`. It is `sha256:8c2938c5…26cfb76`, equal to the grant's
   `action_binding`, so the grant addresses this action. Draft §2.2.3 step 3, lines 610–612.
2. The action carries exactly the grant's `type_fields`. The per-instance values `to`,
   `amount` and `region` stay outside the action and do not change the action digest; they
   are tested by constraints instead.
3. `to` equals the `exact` value, and `amount` 500 lies within 0–1000.
4. The disposition is `allow`, so the verdict is `PERMIT`. Draft §2.2.3 step 6, lines
   632–634.

The core digest is the conformance target. A verifier whose core differs has returned
`PERMIT` without recomputing it.

## 2. Outside the grant: the refusal

Vector `aae-enforce-vector-20`, file `vectors/enforce/20-unaddressed-action-is-never-pending-deny.json`.

| What | Value | Where |
|---|---|---|
| action binding in the grant | `sha256:8c2938c5…26cfb76`, the `transfer` action of case 1 | line 19 |
| disposition | `hold` | line 25 |
| action in the request | `verb` `withdraw` | lines 37–41 |
| expected verdict | `DENY` | line 48 |
| expected core digest | `sha256:b5e3eccb0a5bc006f02d4f92cfebb700d9478bd8cf4bae58937de5fde7c949b3` | line 49 |
| `expected.trace` | `action_binding` `FAIL` | lines 52–55 |

The request's action digest is `sha256:80cac1c6…e5dad5`, which no grant carries, so no
grant addresses the action and the verdict is `DENY` (draft §2.2.3 step 4, lines 621–623:
"If no grant matches, the verdict is DENY. An action that no grant addresses MUST NOT
produce PENDING.").

The grant here is a `hold` grant on purpose. An action that no grant addresses is refused
even where the grant that does exist would have deferred the decision. Silence in a
mandate never becomes `PENDING`.

The draft requires the trace to include the structural predicates, among them whether the
action bound to a grant (§2.5.2, lines 905–907). A `DENY` that names no failed predicate is
not a conforming verdict, so a refusal records which predicate failed.

## 3. A check that cannot be run

Vector `aae-enforce-vector-17`, file `vectors/enforce/17-unknown-constraint-type-deny.json`.

| What | Value | Where |
|---|---|---|
| constraint | type `regex` on `to` | lines 27–31 |
| action in the request | the `transfer` action of case 1, bound by the grant | lines 37–41 |
| expected verdict | `DENY` | line 48 |
| expected core digest | `sha256:eee568f6d36af5ef1fa5336b18392cda9102d2e8aee6ae9996fb836cedf2ad45` | line 49 |
| `expected.trace` | `regex` `FAIL` | lines 52–55 |

The draft, §2.5.1, lines 819–824, in full:

> A constraint is an object with a type member.  This document defines
> exactly three types, and the set is closed.  A relying party MUST
> evaluate a constraint whose type is exact, enum, or range as defined
> below, and MUST treat a constraint of any other type as failed.  An
> unrecognized type MUST NOT be ignored: what a verifier cannot
> evaluate, it does not permit.

`regex` is outside the closed set, so the verifier cannot evaluate it. It records the
predicate as failed, and with no grant left that satisfies all of its constraints, the
verdict is `DENY` (draft §2.2.3 step 7, lines 636–637).

A check that cannot be run never ends in `PERMIT`, under any input. The draft fixes that in
§2.5.1.

AAE has three verdicts, `PERMIT`, `DENY` and `PENDING`, and an unevaluable check ends in
`DENY`. A refusal on the merits ends in `DENY` as well. The two differ in the canonical
trace inside the core. In vector 17 the failed `regex` entry carries `field` `to`, `value`
`null` and `bound` `null`. In vector 16 (`16-range-fails-one-over-the-bound-deny.json`) the
failed `range` entry carries `field` `amount`, `value` `1001` and `bound`
`{"lo":0,"hi":1000}`. The `expected.trace` member of each vector file lists the failing
predicate, and at most its field; `value` and `bound` are visible by recomputing the core,
with the script below or with `tools/explain_enforce.py`.

A reader who needs "not established" as a third state reads it from these two members. AAE
gives it no verdict value.

The same holds for a request whose action cannot be read as an object: vectors 04 to 07
(`action` as a string, an array, a number, `null`) each end in `DENY`.

## Recompute it yourself

The repository's reference verifier checks all 26 enforce vectors:

    $ python3 examples/enforce-verify.py
    ...
    26/26 enforce vectors passed

`tools/explain_enforce.py` prints, for any vector, the input digests, the trace, the
canonical core bytes and the core digest next to the expected value.

To check the three cases without trusting either tool, the script below uses only
`hashlib` and an RFC 8785 serializer (`pip install jcs`). It implements the evaluation for
these three cases from the draft, builds the core of §2.5.3, and compares verdict and core
digest with the vector.

```python
import hashlib, json, sys
import jcs

def d(tag, obj):
    return "sha256:" + hashlib.sha256(tag.encode() + b"\x00" + jcs.canonicalize(obj)).hexdigest()

def entry(p, r, field=None, value=None, bound=None):
    return {"predicate": p, "field": field, "value": value, "bound": bound, "result": r}

def evaluate(mandate, tx):
    action, grants = tx["action"], mandate["grants"]
    adig = d("aae:enforce-action:v1", action)
    trace = [entry("mandate_present", "PASS")]
    tf = [i for i, g in enumerate(grants) if sorted(g["type_fields"]) == sorted(action)]
    trace.append(entry("type_fields", "PASS" if tf else "FAIL", "action",
                       sorted(action), grants[tf[0]]["type_fields"] if tf else None))
    bound = [i for i in tf if grants[i]["action_binding"] == adig]
    if not bound:
        trace.append(entry("action_binding", "FAIL", "action", adig))
        return "DENY", None, trace, adig
    trace.append(entry("action_binding", "PASS", "action", adig, grants[bound[0]]["action_binding"]))
    for i in bound:
        g, ok = grants[i], True
        for c in g["constraints"]:
            t, f = c["type"], c["field"]
            if t == "exact":
                v, b = tx[f], c["value"]; r = v == b
            elif t == "range":
                v, b = tx[f], {"lo": c["lo"], "hi": c["hi"]}; r = c["lo"] <= v <= c["hi"]
            elif t == "enum":
                v, b = tx[f], c["values"]; r = v in b
            else:  # closed set: an unknown type is a failed predicate
                v, b, r = None, None, False
            trace.append(entry(t, "PASS" if r else "FAIL", f, v, b))
            ok = ok and r
            if not r:
                break
        if ok:
            trace.append(entry("disposition", "PASS", None, g["disposition"]))
            return {"allow": "PERMIT", "hold": "PENDING"}[g["disposition"]], i, trace, adig
    return "DENY", None, trace, adig

for path in sys.argv[1:]:
    vec = json.load(open(path))
    m, tx = vec["input"]["mandate"], vec["input"]["transaction"]
    verdict, gi, trace, adig = evaluate(m, tx)
    core = {"enforce_version": vec["kernel_version"],
            "mandate_digest": d("aae:enforce-mandate:v1", m),
            "transaction_digest": d("aae:enforce-transaction:v1", tx),
            "action_digest": adig, "verdict": verdict, "grant_index": gi,
            "trace": trace, "prev_core_digest": None}
    cd = d("aae:enforce-core:v1", core)
    ok = verdict == vec["expected"]["verdict"] and cd == vec["expected"]["core_digest"]
    print(vec["id"], verdict, cd, "MATCH" if ok else "DIFFERS")
```

Run against the three vectors:

    aae-enforce-vector-01 PERMIT sha256:92893c1fa6cf3033f70687dc3683857824979c0bde7b6e5eee97627d527b2c73 MATCH
    aae-enforce-vector-20 DENY sha256:b5e3eccb0a5bc006f02d4f92cfebb700d9478bd8cf4bae58937de5fde7c949b3 MATCH
    aae-enforce-vector-17 DENY sha256:eee568f6d36af5ef1fa5336b18392cda9102d2e8aee6ae9996fb836cedf2ad45 MATCH

The script covers these three cases and is not a conforming verifier. It omits `forbid`,
dotted field paths and the structural checks of vectors 02 to 10. The names and order of
the structural trace entries follow enforce kernel 3.0, as recorded in the vectors.
